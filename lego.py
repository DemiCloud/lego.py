#!/usr/bin/env python3
"""lego.py - ACME certificate management using the lego CLI."""

import argparse
import csv
import dataclasses
import datetime
import enum
import hashlib
import json
import logging
import os
import pathlib
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import typing
import urllib.error
import urllib.request

__version__ = "0.3.0"
__prog__ = "lego.py"
__description__ = "ACME certificate management using the lego CLI"

# ---------------------------------------------------------------------------
# Paths and thresholds
# ---------------------------------------------------------------------------

ACME_DIR = pathlib.Path("/etc/acme")
ACME_CONF = ACME_DIR / "acme.conf"
ACME_WORK_DIR = pathlib.Path("/var/lib/acme")
CERT_DIR = ACME_WORK_DIR / "certificates"
SYSTEMD_DIR = pathlib.Path("/etc/systemd/system")

# TODO: update after repo is renamed on GitHub
WIKI_INSTALL_URL = "https://github.com/user/lego.py/wiki/Installation"

EXPIRY_WARN_DAYS = 30
EXPIRY_CRIT_DAYS = 15

# ---------------------------------------------------------------------------
# Embedded templates (keep in sync with the systemd/ directory in the repo)
# ---------------------------------------------------------------------------

# ExecStart calls back into lego.py itself (renew-exec), which detects the
# installed lego version and builds the correct command at *every* run —
# rather than freezing version-specific flags into this file at install time.
# This is what lets an unattended lego package upgrade (e.g. transactional-
# update on MicroOS bumping v4 -> v5) keep working without re-running
# 'lego.py install'. The {lego_py} placeholder is filled in by cmd_install()
# with the absolute path lego.py was invoked from.
_UNIT_SERVICE = """\
[Unit]
Description=ACME certificate renewal for %i using lego

[Service]
Type=oneshot
WorkingDirectory=/var/lib/acme
ExecStart={lego_py} renew-exec %i
"""

_UNIT_TIMER = """\
[Unit]
Description=ACME renewal timer for %i

[Timer]
OnCalendar=*-*-* 03:35
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
"""

_DEFAULT_CONF = """\
# lego.py — ACME configuration
# Edit this file before running 'lego.py issue <instance>'.
# See: """ + WIKI_INSTALL_URL + """

# ACME server URL.
# Let's Encrypt production (default when this line is absent):
#   https://acme-v02.api.letsencrypt.org/directory
# Let's Encrypt staging:
#   https://acme-staging-v02.api.letsencrypt.org/directory
# ZeroSSL (requires EAB settings below):
#   https://acme.zerossl.com/v2/DV90
LEGO_SERVER="https://acme-v02.api.letsencrypt.org/directory"

# Account email address
LEGO_EMAIL=""

# DNS provider name — see https://go-acme.github.io/lego/dns/
LEGO_DNS=""

# Override lego version detection if 'lego --version' can't be parsed
# (e.g. some distro-patched builds print no version number at all).
# One of: auto, 4, 5. Defaults to auto.
#LEGO_VERSION="auto"

# Resolver(s) for DNS-01 challenge verification (host:port, comma-separated).
# Defaults to Cloudflare's public DNS to avoid split-DNS issues where the
# system resolver is authoritative for internal zones.
LEGO_DNS_RESOLVERS="1.1.1.1:53"

# External Account Binding — required for ZeroSSL and some other CAs
LEGO_EAB=false
LEGO_EAB_KID=""
LEGO_EAB_HMAC=""

# Generate PKCS#12 (.pfx) alongside PEM files
LEGO_PFX=false
LEGO_PFX_PASSWORD=""
LEGO_PFX_FORMAT="SHA256"
"""

_SENSITIVE_RE = re.compile(
    r"(KEY|KID|HMAC|TOKEN|SECRET|PASSWORD|PASS)", re.IGNORECASE
)

# Patterns for parsing `lego list` output.
# NOTE: These are tightly coupled to lego's human-readable output format.
# If lego changes its output, these patterns will need updating.
_LIST_NAME_RE = re.compile(r"^\s+Certificate Name:\s+(.+)$")
_LIST_DOMAINS_RE = re.compile(r"^\s+Domains:\s+(.+)$")
_LIST_EXPIRY_RE = re.compile(r"^\s+Expiry Date:\s+(.+)$")
_LIST_PATH_RE = re.compile(r"^\s+Certificate Path:\s+(.+)$")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

log = logging.getLogger(__name__)


class _LogFormatter(logging.Formatter):
    """Plain-text formatter: INFO lines have no prefix; others show level."""

    _PREFIXES: typing.ClassVar[dict[int, str]] = {
        logging.DEBUG: "debug",
        logging.WARNING: "warning",
        logging.ERROR: "error",
        logging.CRITICAL: "fatal",
    }

    def format(self, record: logging.LogRecord) -> str:
        prefix = self._PREFIXES.get(record.levelno, "")
        msg = record.getMessage()
        return f"{prefix}: {msg}" if prefix else msg


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class OutputFormat(enum.StrEnum):
    AUTO = "auto"
    PLAIN = "plain"
    JSON = "json"
    CSV = "csv"


class CertState(enum.StrEnum):
    VALID = "valid"
    EXPIRING_SOON = "expiring_soon"          # EXPIRY_CRIT_DAYS <= days < EXPIRY_WARN_DAYS
    EXPIRING_CRITICAL = "expiring_critical"  # 0 <= days < EXPIRY_CRIT_DAYS
    EXPIRED = "expired"
    PENDING = "pending"      # .env exists, cert not yet issued
    UNMANAGED = "unmanaged"  # cert exists, no .env file


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class InstanceConfig:
    """Per-certificate configuration loaded from /etc/acme/<name>.env."""

    name: str
    domains: list[str]   # individual domain strings (without the -d flag)
    hook: str
    raw: dict[str, str]  # all parsed key=value pairs from the env file


@dataclasses.dataclass
class CertInfo:
    """Resolved state of a single certificate."""

    instance: str | None              # None when unmanaged
    primary_domain: str
    sans: list[str]                   # all domains including primary
    expiry: datetime.datetime | None  # None when cert not yet issued
    state: CertState
    timer_enabled: bool
    timer_active: bool


@dataclasses.dataclass
class _LegoCert:
    """Parsed entry from `lego list` output. Internal use only."""

    name: str
    domains: list[str]
    expiry: datetime.datetime
    cert_path: pathlib.Path


# ---------------------------------------------------------------------------
# Output protocol and implementations
# ---------------------------------------------------------------------------


class Output(typing.Protocol):
    """Structured-data output interface. stderr messages bypass this."""

    def table(
        self,
        headers: list[str],
        rows: list[list[str]],
        title: str = "",
        row_styles: list[str] | None = None,
    ) -> None: ...

    def key_value(self, data: dict[str, str], title: str = "") -> None: ...

    def value(self, val: str) -> None: ...

    def step(self, verb: str, message: str) -> None: ...


class PlainOutput:
    """ASCII-table output with no external dependencies."""

    def table(
        self,
        headers: list[str],
        rows: list[list[str]],
        title: str = "",
        row_styles: list[str] | None = None,
    ) -> None:
        all_rows: list[list[str]] = [headers, *rows]
        widths = [
            max(len(str(r[i])) for r in all_rows if i < len(r))
            for i in range(len(headers))
        ]

        def _fmt(row: list[str]) -> str:
            return " | ".join(str(c).ljust(w) for c, w in zip(row, widths))

        sep = "-+-".join("-" * w for w in widths)

        if title:
            print(f"\n{title}")
        print(_fmt(headers))
        print(sep)
        for row in rows:
            print(_fmt(row))

    def key_value(self, data: dict[str, str], title: str = "") -> None:
        if not data:
            return
        if title:
            print(f"\n{title}")
            print("-" * len(title))
        key_width = max(len(k) for k in data)
        for key, val in data.items():
            print(f"  {key.ljust(key_width)}  {val}")

    def value(self, val: str) -> None:
        print(val)

    def step(self, verb: str, message: str) -> None:
        if verb == "hint":
            print(f"  -> {message}")
        else:
            print(f"{verb}: {message}")


class RichOutput:
    """Rich-library output. Only instantiated when rich is importable."""

    _STEP_STYLES: typing.ClassVar[dict[str, tuple[str, str]]] = {
        "installed": ("green", "✓"),
        "updated":   ("green", "✓"),
        "created":   ("green", "✓"),
        "enabled":   ("green", "✓"),
        "directory": ("green", "✓"),
        "ok":        ("green", "✓"),
        "warning":   ("yellow", "⚠"),
        "warn":      ("yellow", "⚠"),
        "skipped":   ("dim", "–"),
        "skipping":  ("dim", "–"),
    }

    def __init__(self, console: typing.Any) -> None:
        self._console = console

    def table(
        self,
        headers: list[str],
        rows: list[list[str]],
        title: str = "",
        row_styles: list[str] | None = None,
    ) -> None:
        from rich.table import Table

        tbl = Table(title=title or None, show_header=True, header_style="bold")
        for header in headers:
            tbl.add_column(header)
        for i, row in enumerate(rows):
            style = row_styles[i] if row_styles and i < len(row_styles) else ""
            tbl.add_row(*row, style=style)
        self._console.print(tbl)

    def key_value(self, data: dict[str, str], title: str = "") -> None:
        from rich.table import Table

        tbl = Table(
            title=title or None, show_header=False, box=None, padding=(0, 2)
        )
        tbl.add_column("Key", style="bold")
        tbl.add_column("Value")
        for key, val in data.items():
            tbl.add_row(key, val)
        self._console.print(tbl)

    def value(self, val: str) -> None:
        self._console.print(val)

    def step(self, verb: str, message: str) -> None:
        if verb == "hint":
            self._console.print(f"   [dim]→ {message}[/]")
            return
        style, icon = self._STEP_STYLES.get(verb, ("", "·"))
        if style:
            self._console.print(
                f"  [{style}]{icon}[/]  [{style}]{verb:<9}[/]  {message}"
            )
        else:
            self._console.print(f"  {icon}  {verb:<9}  {message}")


class JsonOutput:
    """JSON output to stdout."""

    def table(
        self,
        headers: list[str],
        rows: list[list[str]],
        title: str = "",
        row_styles: list[str] | None = None,
    ) -> None:
        print(json.dumps([dict(zip(headers, row)) for row in rows], indent=2))

    def key_value(self, data: dict[str, str], title: str = "") -> None:
        print(json.dumps(data, indent=2))

    def value(self, val: str) -> None:
        print(json.dumps(val))

    def step(self, verb: str, message: str) -> None:
        print(f"{verb}: {message}", file=sys.stderr)


class CsvOutput:
    """CSV output to stdout via stdlib csv module."""

    def table(
        self,
        headers: list[str],
        rows: list[list[str]],
        title: str = "",
        row_styles: list[str] | None = None,
    ) -> None:
        writer = csv.writer(sys.stdout)
        writer.writerow(headers)
        writer.writerows(rows)

    def key_value(self, data: dict[str, str], title: str = "") -> None:
        writer = csv.writer(sys.stdout)
        writer.writerow(["key", "value"])
        for key, val in data.items():
            writer.writerow([key, val])

    def value(self, val: str) -> None:
        print(val)

    def step(self, verb: str, message: str) -> None:
        print(f"{verb}: {message}", file=sys.stderr)


def make_output(fmt: OutputFormat) -> Output:
    """Return the appropriate Output implementation for *fmt*."""
    if fmt == OutputFormat.JSON:
        return JsonOutput()
    if fmt == OutputFormat.CSV:
        return CsvOutput()
    if fmt == OutputFormat.PLAIN:
        return PlainOutput()
    # AUTO: prefer rich, fall back silently to plain
    try:
        from rich.console import Console

        return RichOutput(Console())
    except ImportError:
        log.debug("rich not available, using plain output")
        return PlainOutput()


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------


def parse_env_file(path: pathlib.Path) -> dict[str, str]:
    """Parse a shell-style key=value file into a dict.

    Ignores blank lines and ``#`` comments. Strips one layer of surrounding
    single or double quotes from values. Does not evaluate shell expressions.
    """
    result: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            log.debug("skipping non-assignment line in %s: %r", path, raw_line)
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        result[key.strip()] = value
    return result


def mask_sensitive(key: str, value: str) -> str:
    """Return ``****`` if *key* matches a sensitive-field pattern."""
    return "****" if _SENSITIVE_RE.search(key) else value


def _find_lego() -> pathlib.Path | None:
    """Locate the lego binary: PATH first, then next to lego.py itself.

    The fallback matters because 'install --download-lego' defaults to
    installing lego right next to lego.py, which only lands on PATH if
    lego.py's own directory does too.
    """
    binary = shutil.which("lego")
    if binary is not None:
        return pathlib.Path(binary)
    sibling = pathlib.Path(__file__).resolve().parent / "lego"
    if sibling.is_file() and os.access(sibling, os.X_OK):
        return sibling
    return None


def require_lego() -> pathlib.Path:
    """Return the path to the lego binary, or exit with an install hint."""
    binary = _find_lego()
    if binary is None:
        print(
            f"error: lego not found in PATH.\n"
            f"See {WIKI_INSTALL_URL} for installation instructions, or run "
            f"'lego.py install --download-lego' to fetch it automatically.",
            file=sys.stderr,
        )
        sys.exit(1)
    return binary


def require_root() -> None:
    """Exit with an error if the process is not running as root."""
    if os.geteuid() != 0:
        print("error: this command must be run as root.", file=sys.stderr)
        sys.exit(1)


def _lego_version(lego: pathlib.Path) -> tuple[int, int, int]:
    """Return (major, minor, patch) for the lego binary, or (0, 0, 0) on failure."""
    try:
        result = subprocess.run(
            [str(lego), "--version"],
            capture_output=True,
            text=True,
        )
        m = re.search(r"(\d+)\.(\d+)\.(\d+)", result.stdout + result.stderr)
        if m:
            return int(m.group(1)), int(m.group(2)), int(m.group(3))
    except FileNotFoundError:
        pass
    return (0, 0, 0)


def _resolve_lego_version(
    lego: pathlib.Path, override: str | None
) -> tuple[int, int, int]:
    """Return (major, minor, patch) for the lego binary.

    Honors an explicit LEGO_VERSION override ("4" or "5") for builds whose
    `--version` output can't be parsed — e.g. some distro-patched packages
    print "lego version dev" with no number at all. Falls back to detection
    via _lego_version() and warns if that also can't determine a version,
    since the caller then silently assumes v4 command syntax.
    """
    if override and override != "auto":
        try:
            return (int(override), 0, 0)
        except ValueError:
            log.warning(
                "invalid LEGO_VERSION %r in %s — ignoring, falling back to "
                "auto-detection",
                override,
                ACME_CONF,
            )

    detected = _lego_version(lego)
    if detected == (0, 0, 0):
        log.warning(
            "could not determine lego version from '%s --version' — "
            "assuming v4 command syntax. If lego is actually v5+, set "
            "LEGO_VERSION=5 in %s (see 'lego.py config set lego-version 5').",
            lego,
            ACME_CONF,
        )
    return detected


# ---------------------------------------------------------------------------
# Downloading lego from GitHub releases
# ---------------------------------------------------------------------------

_LEGO_GITHUB_REPO = "go-acme/lego"
_LEGO_RELEASES_API = f"https://api.github.com/repos/{_LEGO_GITHUB_REPO}/releases/latest"
_LEGO_RELEASE_DOWNLOAD_BASE = f"https://github.com/{_LEGO_GITHUB_REPO}/releases/download"

# lego's goreleaser matrix covers more OS/arch combos than this, but these
# are the only ones we've needed so far — extend as required.
_LEGO_ARCH_MAP: dict[str, str] = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "aarch64": "arm64",
    "arm64": "arm64",
}


def _fetch_latest_lego_tag() -> str:
    """Return the tag name (e.g. 'v5.4.0') of the latest lego GitHub release."""
    req = urllib.request.Request(
        _LEGO_RELEASES_API,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "lego.py"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())
    return data["tag_name"]


def _lego_release_asset_names(tag: str) -> tuple[str, str]:
    """Return (tarball_name, checksums_name) for *tag* on this host's platform.

    Raises ValueError if the host OS/arch isn't a supported download target.
    Note lego's checksums file omits the tag's leading 'v' while the tarball
    name keeps it — this mismatch is real, not a typo.
    """
    system = platform.system().lower()
    if system != "linux":
        raise ValueError(
            f"automatic download only supports Linux — this host reports {platform.system()!r}"
        )
    arch = _LEGO_ARCH_MAP.get(platform.machine())
    if arch is None:
        raise ValueError(
            f"automatic download doesn't recognize CPU architecture {platform.machine()!r} "
            f"— download lego manually from {_LEGO_RELEASE_DOWNLOAD_BASE}"
        )
    version = tag.lstrip("v")
    return f"lego_{tag}_{system}_{arch}.tar.gz", f"lego_{version}_checksums.txt"


def _extract_lego_binary(tarball_path: pathlib.Path) -> bytes | None:
    """Return the contents of the 'lego' binary inside *tarball_path*, or None if absent."""
    with tarfile.open(tarball_path, "r:gz") as tar:
        member = next(
            (
                m
                for m in tar.getmembers()
                if m.isfile() and pathlib.PurePosixPath(m.name).name == "lego"
            ),
            None,
        )
        if member is None:
            return None
        extracted = tar.extractfile(member)
        return extracted.read() if extracted is not None else None


def _download_lego(
    dest_dir: pathlib.Path, version: str | None, output: Output
) -> int:
    """Download, checksum-verify, and install the lego binary from GitHub releases.

    *version* may be a specific release (with or without a leading 'v'), or
    None for the latest release. Overwrites any existing binary at
    dest_dir/lego, so this also serves as the update path.
    """
    try:
        if version:
            tag = f"v{version.lstrip('v')}"
        else:
            output.step("checking", f"latest lego release ({_LEGO_GITHUB_REPO})")
            tag = _fetch_latest_lego_tag()
    except (urllib.error.URLError, json.JSONDecodeError, KeyError) as exc:
        log.error("could not determine latest lego version: %s", exc)
        return 1

    try:
        tarball_name, checksums_name = _lego_release_asset_names(tag)
    except ValueError as exc:
        log.error("%s", exc)
        return 1

    base = f"{_LEGO_RELEASE_DOWNLOAD_BASE}/{tag}"
    tarball_url = f"{base}/{tarball_name}"
    checksums_url = f"{base}/{checksums_name}"

    with tempfile.TemporaryDirectory() as tmp:
        tarball_path = pathlib.Path(tmp) / tarball_name

        output.step("downloading", tarball_url)
        try:
            with urllib.request.urlopen(tarball_url, timeout=120) as resp:
                tarball_path.write_bytes(resp.read())
            with urllib.request.urlopen(checksums_url, timeout=30) as resp:
                checksums_text = resp.read().decode("utf-8", errors="replace")
        except urllib.error.URLError as exc:
            log.error("download failed: %s", exc)
            return 1

        expected = next(
            (
                parts[0]
                for line in checksums_text.splitlines()
                if len(parts := line.split()) == 2 and parts[1] == tarball_name
            ),
            None,
        )
        if expected is None:
            log.error("checksum for %s not found in %s", tarball_name, checksums_name)
            return 1

        actual = hashlib.sha256(tarball_path.read_bytes()).hexdigest()
        if actual != expected:
            log.error(
                "checksum mismatch for %s: expected %s, got %s — aborting install",
                tarball_name,
                expected,
                actual,
            )
            return 1
        output.step("verified", f"sha256 checksum ({tag})")

        binary_data = _extract_lego_binary(tarball_path)
        if binary_data is None:
            log.error("'lego' binary not found inside %s", tarball_name)
            return 1

    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_path = dest_dir / "lego"
    dest_path.write_bytes(binary_data)
    dest_path.chmod(0o755)
    output.step("installed", f"{dest_path} ({tag})")
    return 0


# ---------------------------------------------------------------------------
# lego list parsing
# ---------------------------------------------------------------------------


def _parse_lego_expiry(expiry_str: str) -> datetime.datetime:
    """Parse lego's expiry format: ``2026-06-06 23:59:59 +0000 UTC``."""
    # Strip the redundant 'UTC' suffix — the numeric offset covers it.
    clean = re.sub(r"\s+UTC$", "", expiry_str.strip())
    return datetime.datetime.strptime(clean, "%Y-%m-%d %H:%M:%S %z")


def _parse_lego_list(raw: str) -> dict[str, _LegoCert]:
    """Parse the text output of ``lego list`` into a dict keyed by cert name."""
    certs: dict[str, _LegoCert] = {}
    current: dict[str, str] = {}

    for line in raw.splitlines():
        if m := _LIST_NAME_RE.match(line):
            current = {"name": m.group(1).strip()}
        elif m := _LIST_DOMAINS_RE.match(line):
            current["domains"] = m.group(1).strip()
        elif m := _LIST_EXPIRY_RE.match(line):
            current["expiry"] = m.group(1).strip()
        elif m := _LIST_PATH_RE.match(line):
            current["path"] = m.group(1).strip()
            # Certificate Path is always the last field — build the object now.
            if "name" not in current or "expiry" not in current:
                log.warning("incomplete cert block in lego list output, skipping")
                current = {}
                continue
            name = current["name"]
            domains = [
                d.strip() for d in current.get("domains", name).split(",")
            ]
            try:
                expiry = _parse_lego_expiry(current["expiry"])
            except ValueError:
                log.warning(
                    "could not parse expiry %r for cert %s — skipping",
                    current["expiry"],
                    name,
                )
                current = {}
                continue
            certs[name] = _LegoCert(
                name=name,
                domains=domains,
                expiry=expiry,
                cert_path=pathlib.Path(current["path"]),
            )
            current = {}

    return certs


def _run_lego_list(
    lego: pathlib.Path,
    lego_ver: tuple[int, int, int],
) -> dict[str, _LegoCert]:
    """Run ``lego [certificates] list`` and return parsed results."""
    if lego_ver >= (5, 0, 0):
        list_cmd = [str(lego), "certificates", "list", "--path", str(ACME_WORK_DIR)]
    else:
        list_cmd = [str(lego), "--path", str(ACME_WORK_DIR), "list"]
    try:
        result = subprocess.run(
            list_cmd,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        log.warning("lego binary not found at %s", lego)
        return {}

    if result.returncode != 0:
        log.warning(
            "lego list failed (exit %d): %s",
            result.returncode,
            result.stderr.strip(),
        )
        return {}

    return _parse_lego_list(result.stdout)


# ---------------------------------------------------------------------------
# Instance config
# ---------------------------------------------------------------------------


def _parse_domains(domains_str: str) -> list[str]:
    """Extract domain names from a DOMAINS value like ``-d foo -d bar``."""
    tokens = domains_str.split()
    return [
        tokens[i + 1]
        for i, t in enumerate(tokens)
        if t in ("-d", "--domains") and i + 1 < len(tokens)
    ]


def load_instance_configs() -> dict[str, InstanceConfig]:
    """Load all ``/etc/acme/*.env`` files. Returns a dict keyed by instance name."""
    if not ACME_DIR.is_dir():
        return {}
    configs: dict[str, InstanceConfig] = {}
    for env_file in sorted(ACME_DIR.glob("*.env")):
        name = env_file.stem
        try:
            raw = parse_env_file(env_file)
        except OSError as exc:
            log.warning("could not read %s: %s", env_file, exc)
            continue
        domains = _parse_domains(raw.get("DOMAINS", ""))
        if not domains:
            log.warning("no -d domains found in %s", env_file)
        configs[name] = InstanceConfig(
            name=name,
            domains=domains,
            hook=raw.get("HOOK", ""),
            raw=raw,
        )
    return configs


# ---------------------------------------------------------------------------
# Lego issue command builder
# ---------------------------------------------------------------------------


def _build_lego_run_cmd(
    lego: pathlib.Path,
    conf: dict[str, str],
    domains: list[str],
    hook: str,
    lego_ver: tuple[int, int, int],
    action: typing.Literal["issue", "renew"],
) -> list[str]:
    """Build the lego argument list to obtain or renew a certificate.

    lego v5 unified the old 'run' (issue) and 'renew' commands into a single
    idempotent 'run' — it renews if a cert exists and is due, issues if not —
    so *action* only affects v4, which still has them as distinct
    subcommands. v5 also moved all flags under that subcommand; v4 had them
    as global flags before it.

    DNS provider credentials are expected in the subprocess environment, not
    here — pass the merged config dict as ``env=`` when calling subprocess.run.
    """
    v5 = lego_ver >= (5, 0, 0)
    v4_subcommand = "run" if action == "issue" else "renew"

    if v5:
        cmd = [str(lego), "run", "--accept-tos", "--path", str(ACME_WORK_DIR)]
    else:
        cmd = [str(lego), "--accept-tos", "--path", str(ACME_WORK_DIR)]

    if server := conf.get("LEGO_SERVER"):
        cmd += ["--server", server]

    cmd += ["--email", conf["LEGO_EMAIL"]]

    for domain in domains:
        cmd += ["-d", domain]

    cmd += ["--dns", conf["LEGO_DNS"]]

    if conf.get("LEGO_EAB", "").lower() == "true":
        if v5:
            cmd += ["--eab", "--eab.kid", conf["LEGO_EAB_KID"], "--eab.hmac", conf["LEGO_EAB_HMAC"]]
        else:
            cmd += ["--eab", "--kid", conf["LEGO_EAB_KID"], "--hmac", conf["LEGO_EAB_HMAC"]]

    if conf.get("LEGO_PFX", "").lower() == "true":
        cmd += ["--pfx", "--pfx.password", conf.get("LEGO_PFX_PASSWORD", "")]

    for resolver in (
        r.strip()
        for r in conf.get("LEGO_DNS_RESOLVERS", "").split(",")
        if r.strip()
    ):
        cmd += ["--dns.resolvers", resolver]

    if v5:
        if hook:
            cmd += ["--deploy-hook", hook]
    else:
        cmd.append(v4_subcommand)
        if hook:
            cmd += ["--run-hook", hook]

    return cmd


# ---------------------------------------------------------------------------
# Config file management
# ---------------------------------------------------------------------------


def _quote_value(value: str) -> str:
    """Wrap *value* in double quotes, escaping any embedded double quotes."""
    return '"' + value.replace('"', '\\"') + '"'


def _config_update(path: pathlib.Path, key: str, value: str) -> None:
    """Update or append ``KEY="value"`` in a shell-style config file.

    The first uncommented line whose key matches is updated in place.
    Commented-out occurrences are left unchanged.
    If no matching uncommented line is found, the assignment is appended.
    """
    try:
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    except FileNotFoundError:
        lines = []

    key_re = re.compile(rf"^{re.escape(key)}\s*=")
    new_line = f"{key}={_quote_value(value)}\n"

    updated = False
    new_lines: list[str] = []
    for line in lines:
        if not updated and key_re.match(line):
            new_lines.append(new_line)
            updated = True
        else:
            new_lines.append(line)

    if not updated:
        if new_lines and not new_lines[-1].endswith("\n"):
            new_lines[-1] += "\n"
        new_lines.append(new_line)

    path.write_text("".join(new_lines), encoding="utf-8")


# ---------------------------------------------------------------------------
# Config schema
# ---------------------------------------------------------------------------


def _validate_email(v: str) -> str | None:
    return (
        None
        if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", v)
        else "expected an email address (user@domain)"
    )


def _validate_bool(v: str) -> str | None:
    return None if v.lower() in ("true", "false") else "expected 'true' or 'false'"


def _validate_https_url(v: str) -> str | None:
    return None if v.startswith("https://") else "expected an https:// URL"


def _validate_nonempty(v: str) -> str | None:
    return None if v.strip() else "value must not be empty"


def _validate_pfx_format(v: str) -> str | None:
    return (
        None
        if v.upper() in ("RC2", "DES", "SHA256")
        else "expected one of: RC2, DES, SHA256"
    )


def _validate_lego_version(v: str) -> str | None:
    return None if v == "auto" or v in ("4", "5") else "expected 'auto', '4', or '5'"


def _validate_dns_resolvers(v: str) -> str | None:
    parts = [p.strip() for p in v.split(",") if p.strip()]
    if not parts:
        return "expected one or more host:port addresses"
    for p in parts:
        if ":" not in p:
            return f"expected host:port format, got {p!r}"
    return None


@dataclasses.dataclass(frozen=True)
class _ConfigKey:
    key: str        # canonical env var: LEGO_EMAIL
    alias: str      # friendly name:    email
    description: str
    validator: typing.Callable[[str], str | None] | None
    sensitive: bool = False


_CONFIG_SCHEMA: list[_ConfigKey] = [
    _ConfigKey("LEGO_SERVER",       "server",       "ACME directory URL",              _validate_https_url),
    _ConfigKey("LEGO_EMAIL",        "email",        "account email address",           _validate_email),
    _ConfigKey("LEGO_DNS",          "dns",          "DNS provider name",               _validate_nonempty),
    _ConfigKey("LEGO_VERSION",      "lego-version", "override lego version detection (auto, 4, or 5)", _validate_lego_version),
    _ConfigKey("LEGO_EAB",          "eab",          "enable External Account Binding", _validate_bool),
    _ConfigKey("LEGO_EAB_KID",      "eab-kid",      "EAB key ID",                      _validate_nonempty, sensitive=True),
    _ConfigKey("LEGO_EAB_HMAC",     "eab-hmac",     "EAB HMAC key",                    _validate_nonempty, sensitive=True),
    _ConfigKey("LEGO_DNS_RESOLVERS", "dns-resolvers", "resolver(s) for DNS-01 verification (host:port, comma-separated)", _validate_dns_resolvers),
    _ConfigKey("LEGO_PFX",          "pfx",          "generate PKCS#12 file",           _validate_bool),
    _ConfigKey("LEGO_PFX_PASSWORD", "pfx-password", "PKCS#12 password",                None, sensitive=True),
    _ConfigKey("LEGO_PFX_FORMAT",   "pfx-format",   "PKCS#12 hash format (RC2/DES/SHA256)", _validate_pfx_format),
]

_CONFIG_BY_KEY:   dict[str, _ConfigKey] = {e.key:   e for e in _CONFIG_SCHEMA}
_CONFIG_BY_ALIAS: dict[str, _ConfigKey] = {e.alias: e for e in _CONFIG_SCHEMA}


def _resolve_config_key(name: str) -> _ConfigKey | None:
    """Look up a schema entry by alias or canonical key name."""
    return _CONFIG_BY_ALIAS.get(name) or _CONFIG_BY_KEY.get(name)


# ---------------------------------------------------------------------------
# Systemd helpers
# ---------------------------------------------------------------------------


def _systemctl_check(verb: str, unit: str) -> bool:
    """Return True if ``systemctl <verb> --quiet <unit>`` exits 0."""
    try:
        result = subprocess.run(
            ["systemctl", verb, "--quiet", unit],
            capture_output=True,
        )
        return result.returncode == 0
    except FileNotFoundError:
        log.debug("systemctl not found")
        return False


# ---------------------------------------------------------------------------
# Status helpers
# ---------------------------------------------------------------------------


def _cert_state(expiry: datetime.datetime) -> CertState:
    days = (expiry - datetime.datetime.now(datetime.UTC)).days
    if days < 0:
        return CertState.EXPIRED
    if days < EXPIRY_CRIT_DAYS:
        return CertState.EXPIRING_CRITICAL
    if days < EXPIRY_WARN_DAYS:
        return CertState.EXPIRING_SOON
    return CertState.VALID


def _row_style(state: CertState) -> str:
    match state:
        case CertState.VALID:
            return "green"
        case CertState.EXPIRING_SOON:
            return "yellow"
        case CertState.EXPIRING_CRITICAL | CertState.EXPIRED:
            return "bold red"
        case _:
            return "dim"


def _build_status_rows(
    cert_infos: list[CertInfo],
) -> tuple[list[list[str]], list[str]]:
    rows: list[list[str]] = []
    styles: list[str] = []

    for info in sorted(cert_infos, key=lambda c: c.primary_domain):
        instance_col = info.instance or "—"

        sans_other = [d for d in info.sans if d != info.primary_domain]
        sans_col = ", ".join(sans_other) if sans_other else "—"

        if info.expiry is not None:
            expiry_col = info.expiry.strftime("%Y-%m-%d")
            days = (info.expiry - datetime.datetime.now(datetime.UTC)).days
            days_col = str(days)
        else:
            expiry_col = "—"
            days_col = "—"

        if info.state in (CertState.PENDING, CertState.UNMANAGED):
            timer_col = "—"
        elif info.timer_enabled and info.timer_active:
            timer_col = "enabled / active"
        elif info.timer_enabled:
            timer_col = "enabled / inactive"
        else:
            timer_col = "disabled"

        rows.append(
            [
                instance_col,
                info.primary_domain,
                sans_col,
                expiry_col,
                days_col,
                timer_col,
            ]
        )
        styles.append(_row_style(info.state))

    return rows, styles


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------


def cmd_install(args: argparse.Namespace, output: Output) -> int:
    """Create directories and install systemd unit templates."""
    require_root()

    # Baked into ExecStart below so the systemd unit always calls back into
    # *this* lego.py, wherever it lives, rather than invoking lego directly
    # with flags frozen at install time.
    lego_py_path = pathlib.Path(__file__).resolve()

    if args.download_lego is not None:
        lego_dir = pathlib.Path(args.lego_dir) if args.lego_dir else lego_py_path.parent
        version = None if args.download_lego == "latest" else args.download_lego
        if _download_lego(lego_dir, version, output) != 0:
            return 1

    lego_bin = _find_lego()
    if lego_bin is None:
        output.step("warning", "lego not found in PATH — install it before issuing certificates.")
        output.step("hint", f"See: {WIKI_INSTALL_URL}")
        output.step("hint", "or re-run with --download-lego to fetch it automatically")
    else:
        version_override = None
        if ACME_CONF.exists():
            try:
                version_override = parse_env_file(ACME_CONF).get("LEGO_VERSION")
            except OSError:
                pass
        lego_ver = _resolve_lego_version(lego_bin, version_override)
        output.step("ok", f"lego {'.'.join(str(x) for x in lego_ver)} detected")

    unit_service = _UNIT_SERVICE.format(lego_py=lego_py_path)

    for directory, mode in (
        (ACME_DIR, 0o755),
        (ACME_WORK_DIR, 0o755),
    ):
        directory.mkdir(mode=mode, parents=True, exist_ok=True)
        output.step("directory", str(directory))

    for unit_name, content in (
        ("acme@.service", unit_service),
        ("acme@.timer", _UNIT_TIMER),
    ):
        dest = SYSTEMD_DIR / unit_name
        verb = "updated" if dest.exists() else "installed"
        dest.write_text(content, encoding="utf-8")
        output.step(verb, str(dest))

    if not ACME_CONF.exists():
        ACME_CONF.write_text(_DEFAULT_CONF, encoding="utf-8")
        ACME_CONF.chmod(0o600)
        output.step("created", str(ACME_CONF))
        output.step("hint", f"Edit {ACME_CONF} before issuing certificates")
    else:
        output.step("skipped", str(ACME_CONF))

    try:
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        output.step("ok", "systemctl daemon-reload")
    except subprocess.CalledProcessError as exc:
        log.error("systemctl daemon-reload failed: %s", exc)
        return 1
    except FileNotFoundError:
        output.step("warning", "systemctl not found — skipping daemon-reload")

    output.value("\nInstallation complete.")
    return 0


def cmd_update_lego(args: argparse.Namespace, output: Output) -> int:
    """Download (or re-download) the lego binary from GitHub releases."""
    require_root()

    lego_dir = (
        pathlib.Path(args.lego_dir)
        if args.lego_dir
        else pathlib.Path(__file__).resolve().parent
    )
    return _download_lego(lego_dir, args.version, output)


def _load_lego_conf(instance: str) -> tuple[dict[str, str], list[str]] | None:
    """Load and validate global + instance config for a lego issue/renew run.

    Returns (merged_conf, domains), or None (after logging an error) if the
    config is missing or invalid.
    """
    env_file = ACME_DIR / f"{instance}.env"

    if not ACME_CONF.exists():
        log.error(
            "no configuration file at %s — run 'lego.py install' first", ACME_CONF
        )
        return None
    if not env_file.exists():
        log.error("no instance config at %s", env_file)
        return None

    try:
        global_conf = parse_env_file(ACME_CONF)
        instance_raw = parse_env_file(env_file)
    except OSError as exc:
        log.error("could not read config: %s", exc)
        return None

    # Instance values override global ones, matching systemd EnvironmentFile order.
    conf = {**global_conf, **instance_raw}
    domains = _parse_domains(conf.get("DOMAINS", ""))

    if not domains:
        log.error("no -d domains found in %s", env_file)
        return None

    # Fail early on missing required fields.
    missing = [k for k in ("LEGO_EMAIL", "LEGO_DNS") if not conf.get(k)]
    if missing:
        log.error("required config missing: %s", ", ".join(missing))
        return None
    if conf.get("LEGO_EAB", "").lower() == "true":
        missing_eab = [
            k for k in ("LEGO_EAB_KID", "LEGO_EAB_HMAC") if not conf.get(k)
        ]
        if missing_eab:
            log.error(
                "LEGO_EAB=true but missing: %s", ", ".join(missing_eab)
            )
            return None

    return conf, domains


def _run_lego(
    lego: pathlib.Path,
    conf: dict[str, str],
    domains: list[str],
    action: typing.Literal["issue", "renew"],
) -> int:
    """Detect the lego version, build the command, and run it. Returns the exit status."""
    lego_ver = _resolve_lego_version(lego, conf.get("LEGO_VERSION"))
    cmd = _build_lego_run_cmd(lego, conf, domains, conf.get("HOOK", ""), lego_ver, action)
    log.debug("lego command: %s", " ".join(cmd))

    # Merge config into subprocess env so provider credentials are available.
    env = os.environ.copy()
    env.update(conf)

    try:
        subprocess.run(cmd, check=True, env=env)
    except subprocess.CalledProcessError as exc:
        log.error("lego %s failed (exit %d)", "run" if action == "issue" else "renew", exc.returncode)
        return 1
    return 0


def cmd_issue(args: argparse.Namespace, output: Output) -> int:
    """Perform initial certificate issuance for an instance."""
    require_root()
    lego = require_lego()

    instance = args.instance
    loaded = _load_lego_conf(instance)
    if loaded is None:
        return 1
    conf, domains = loaded

    # Warn if a cert already exists — lego run will refuse to overwrite.
    cert_file = CERT_DIR / f"{domains[0]}.crt"
    if cert_file.exists():
        log.error(
            "certificate already exists at %s — use 'lego.py renew %s' instead",
            cert_file,
            instance,
        )
        return 1

    log.info("issuing certificate for instance %r (%s)...", instance, domains[0])
    if _run_lego(lego, conf, domains, "issue") != 0:
        return 1

    # Enable and start the renewal timer now that a cert exists.
    try:
        subprocess.run(
            ["systemctl", "enable", "--now", f"acme@{instance}.timer"],
            check=True,
        )
        output.step("enabled", f"acme@{instance}.timer")
    except subprocess.CalledProcessError as exc:
        log.error("failed to enable timer: %s", exc)
        return 1

    output.value("Done. Certificate issued and renewal timer active.")
    return 0


def cmd_renew_exec(args: argparse.Namespace, output: Output) -> int:
    """Run the actual lego renewal for one instance.

    Invoked by acme@<instance>.service (installed by 'lego.py install'), not
    intended to be run directly. Detects the lego version fresh on every
    invocation so an unattended lego upgrade never leaves a stale command
    behind, unlike flags baked into the systemd unit at install time.
    """
    require_root()
    lego = require_lego()

    instance = args.instance
    loaded = _load_lego_conf(instance)
    if loaded is None:
        return 1
    conf, domains = loaded

    log.info("renewing certificate for instance %r (%s)...", instance, domains[0])
    return _run_lego(lego, conf, domains, "renew")


def cmd_renew(args: argparse.Namespace, output: Output) -> int:
    """Manually trigger renewal for an instance via systemctl."""
    require_root()

    instance = args.instance
    service = f"acme@{instance}.service"

    env_file = ACME_DIR / f"{instance}.env"
    if not env_file.exists():
        log.error("no instance config at %s", env_file)
        return 1

    log.info("triggering renewal for %r...", instance)
    try:
        subprocess.run(["systemctl", "start", service], check=True)
    except subprocess.CalledProcessError as exc:
        log.error("systemctl start %s failed (exit %d)", service, exc.returncode)
        return 1
    except FileNotFoundError:
        log.error("systemctl not found")
        return 1

    output.step("ok", f"Renewal triggered. Check logs with: journalctl -u {service}")
    return 0


def cmd_status(args: argparse.Namespace, output: Output) -> int:
    """Show expiry and timer status for all configured certificates."""
    lego = require_lego()
    version_override = None
    if ACME_CONF.exists():
        try:
            version_override = parse_env_file(ACME_CONF).get("LEGO_VERSION")
        except OSError:
            pass
    lego_ver = _resolve_lego_version(lego, version_override)

    issued = _run_lego_list(lego, lego_ver)
    instances = load_instance_configs()

    if not issued and not instances:
        log.info("No certificates or instance configs found.")
        log.info(
            "Run 'lego.py install' to set up directories,"
            " then 'lego.py issue <name>'."
        )
        return 0

    cert_infos: list[CertInfo] = []
    seen: set[str] = set()

    for name, config in instances.items():
        primary = config.domains[0] if config.domains else ""
        lego_cert = issued.get(primary)

        if lego_cert is None:
            cert_infos.append(
                CertInfo(
                    instance=name,
                    primary_domain=primary or name,
                    sans=[],
                    expiry=None,
                    state=CertState.PENDING,
                    timer_enabled=_systemctl_check(
                        "is-enabled", f"acme@{name}.timer"
                    ),
                    timer_active=_systemctl_check(
                        "is-active", f"acme@{name}.timer"
                    ),
                )
            )
        else:
            seen.add(primary)
            cert_infos.append(
                CertInfo(
                    instance=name,
                    primary_domain=primary,
                    sans=lego_cert.domains,
                    expiry=lego_cert.expiry,
                    state=_cert_state(lego_cert.expiry),
                    timer_enabled=_systemctl_check(
                        "is-enabled", f"acme@{name}.timer"
                    ),
                    timer_active=_systemctl_check(
                        "is-active", f"acme@{name}.timer"
                    ),
                )
            )

    for cert_name, lego_cert in issued.items():
        if cert_name not in seen:
            cert_infos.append(
                CertInfo(
                    instance=None,
                    primary_domain=cert_name,
                    sans=lego_cert.domains,
                    expiry=lego_cert.expiry,
                    state=CertState.UNMANAGED,
                    timer_enabled=False,
                    timer_active=False,
                )
            )

    rows, styles = _build_status_rows(cert_infos)
    headers = ["Instance", "Certificate", "SANs", "Expiry", "Days", "Timer"]
    output.table(headers, rows, title="Certificate Status", row_styles=styles)
    return 0


def cmd_config_show(args: argparse.Namespace, output: Output) -> int:
    """Display acme.conf with sensitive values masked."""
    if not ACME_CONF.exists():
        log.info("No configuration file found at %s.", ACME_CONF)
        log.info(
            "Run 'lego.py install' to create the default configuration."
        )
        return 0

    try:
        raw = parse_env_file(ACME_CONF)
    except OSError as exc:
        log.error("could not read %s: %s", ACME_CONF, exc)
        return 1

    headers = ["Setting", "Key", "Value"]
    rows: list[list[str]] = []
    styles: list[str] = []
    for key, val in raw.items():
        entry = _resolve_config_key(key)
        if entry:
            masked = "****" if entry.sensitive else val
            rows.append([entry.alias, entry.key, masked])
            styles.append("")
        else:
            masked = "****" if _SENSITIVE_RE.search(key) else val
            rows.append(["—", key, masked])
            styles.append("dim")
    output.table(headers, rows, title=str(ACME_CONF), row_styles=styles)
    return 0


def cmd_config_get(args: argparse.Namespace, output: Output) -> int:
    """Print the value of a single configuration key."""
    if not ACME_CONF.exists():
        log.error("no configuration file at %s", ACME_CONF)
        return 1

    try:
        raw = parse_env_file(ACME_CONF)
    except OSError as exc:
        log.error("could not read %s: %s", ACME_CONF, exc)
        return 1

    key = args.key
    if entry := _resolve_config_key(key):
        key = entry.key

    if key not in raw:
        log.error("key %r not found in %s", args.key, ACME_CONF)
        return 1

    output.value(raw[key])
    return 0


def cmd_config_set(args: argparse.Namespace, output: Output) -> int:
    """Set or add a key in acme.conf."""
    require_root()

    if args.raw:
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", args.key):
            log.error("invalid key name: %r", args.key)
            return 1
        canonical = args.key
    else:
        entry = _resolve_config_key(args.key)
        if entry is None:
            known = ", ".join(e.alias for e in _CONFIG_SCHEMA)
            log.error("unknown key %r — known keys: %s", args.key, known)
            log.error("use --raw to set arbitrary keys (e.g. provider credentials)")
            return 1
        if entry.validator is not None:
            error = entry.validator(args.value)
            if error:
                log.error("invalid value for %s: %s", entry.key, error)
                return 1
        canonical = entry.key

    ACME_DIR.mkdir(parents=True, exist_ok=True)

    if not ACME_CONF.exists():
        ACME_CONF.touch(mode=0o600)

    try:
        _config_update(ACME_CONF, canonical, args.value)
    except OSError as exc:
        log.error("could not write %s: %s", ACME_CONF, exc)
        return 1

    output.step("ok", f"Set {canonical} in {ACME_CONF}")
    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

try:
    from rich_argparse import RichHelpFormatter, RawDescriptionRichHelpFormatter
    _HelpFmt = RichHelpFormatter
    _RawDescFmt = RawDescriptionRichHelpFormatter
except ImportError:
    _HelpFmt = argparse.HelpFormatter
    _RawDescFmt = argparse.RawDescriptionHelpFormatter


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=__prog__,
        description=__description__,
        formatter_class=_HelpFmt,
        add_help=True,
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--format",
        choices=list(OutputFormat),
        default=OutputFormat.AUTO,
        dest="output_format",
        metavar="FORMAT",
        help="output format: auto, plain, json, csv  (default: auto)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="enable debug logging to stderr",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        metavar="COMMAND",
        title="commands",
    )

    # -- install --------------------------------------------------------------
    p_install = subparsers.add_parser(
        "install",
        help="install systemd units and create required directories",
        description=textwrap.dedent(
            """\
            Creates /etc/acme/ and /var/lib/acme/, installs the acme@.service
            and acme@.timer unit templates to /etc/systemd/system/, then runs
            systemctl daemon-reload.

            By default does not install or manage the lego binary itself —
            pass --download-lego to fetch it from GitHub releases instead
            (verified against lego's published sha256 checksums).

            Requires root.
            See: """
            + WIKI_INSTALL_URL
        ),
        formatter_class=_RawDescFmt,
    )
    p_install.add_argument(
        "--download-lego",
        nargs="?",
        const="latest",
        default=None,
        metavar="VERSION",
        help="fetch lego from GitHub releases (latest, or a specific version like 5.4.0)",
    )
    p_install.add_argument(
        "--lego-dir",
        metavar="DIR",
        help="directory to install the downloaded lego binary into (default: next to lego.py)",
    )
    p_install.set_defaults(func=cmd_install)

    # -- update-lego ------------------------------------------------------------
    p_update_lego = subparsers.add_parser(
        "update-lego",
        help="download or update the lego binary from GitHub releases",
        description=textwrap.dedent(
            """\
            Downloads lego from GitHub releases, verifies it against the
            release's published sha256 checksums, and installs it — replacing
            any existing binary at the destination. Equivalent to
            'install --download-lego' but usable on its own, without
            re-running the rest of 'install'.

            Requires root.
            """
        ),
        formatter_class=_RawDescFmt,
    )
    p_update_lego.add_argument(
        "version",
        nargs="?",
        default=None,
        help="specific lego version to install, e.g. 5.4.0 (default: latest)",
    )
    p_update_lego.add_argument(
        "--lego-dir",
        metavar="DIR",
        help="directory to install the lego binary into (default: next to lego.py)",
    )
    p_update_lego.set_defaults(func=cmd_update_lego)

    # -- issue ----------------------------------------------------------------
    p_issue = subparsers.add_parser(
        "issue",
        help="perform initial certificate issuance",
        description=textwrap.dedent(
            """\
            Issues a certificate for the given instance by calling the lego CLI
            directly with settings from /etc/acme/acme.conf and
            /etc/acme/<instance>.env.

            Requires root.
            """
        ),
        formatter_class=_RawDescFmt,
    )
    p_issue.add_argument("instance", help="certificate instance name")
    p_issue.set_defaults(func=cmd_issue)

    # -- renew ----------------------------------------------------------------
    p_renew = subparsers.add_parser(
        "renew",
        help="manually trigger certificate renewal",
        description=textwrap.dedent(
            """\
            Starts acme@<instance>.service via systemctl to trigger an immediate
            renewal. Automated renewal is handled by acme@<instance>.timer.

            Requires root.
            """
        ),
        formatter_class=_RawDescFmt,
    )
    p_renew.add_argument("instance", help="certificate instance name")
    p_renew.set_defaults(func=cmd_renew)

    # -- renew-exec (internal; no `help=` so it's omitted from --help) --------
    p_renew_exec = subparsers.add_parser(
        "renew-exec",
        description=textwrap.dedent(
            """\
            Detects the installed lego version and runs the actual renewal
            command for one instance. Invoked by acme@<instance>.service
            (installed by 'lego.py install'); not intended to be run directly
            — use 'lego.py renew <instance>' instead.

            Requires root.
            """
        ),
        formatter_class=_RawDescFmt,
    )
    p_renew_exec.add_argument("instance", help="certificate instance name")
    p_renew_exec.set_defaults(func=cmd_renew_exec)

    # -- status ---------------------------------------------------------------
    p_status = subparsers.add_parser(
        "status",
        help="show certificate status",
        description=textwrap.dedent(
            """\
            Displays expiry dates, days remaining, and timer state for all
            configured instances and any unmanaged certificates found in
            /var/lib/acme/certificates/.

            Note: reading certificate data requires access to /var/lib/acme/.
            Run as root if certificate details are missing.
            """
        ),
        formatter_class=_RawDescFmt,
    )
    p_status.set_defaults(func=cmd_status)

    # -- config ---------------------------------------------------------------
    p_config = subparsers.add_parser(
        "config",
        help="manage /etc/acme/acme.conf",
        description="Read and update global ACME configuration.",
        formatter_class=_HelpFmt,
    )
    p_config.set_defaults(func=lambda args, out: (p_config.print_help(), 1)[1])

    config_subs = p_config.add_subparsers(
        dest="config_command",
        metavar="COMMAND",
        title="config commands",
    )

    p_cfg_show = config_subs.add_parser(
        "show",
        help="display configuration (secrets masked)",
        description="Displays /etc/acme/acme.conf with sensitive values masked.",
        formatter_class=_HelpFmt,
    )
    p_cfg_show.set_defaults(func=cmd_config_show)

    p_cfg_get = config_subs.add_parser(
        "get",
        help="get a configuration value",
        description="Prints the value of the given key from /etc/acme/acme.conf.",
        formatter_class=_HelpFmt,
    )
    p_cfg_get.add_argument("key", help="configuration key name")
    p_cfg_get.set_defaults(func=cmd_config_get)

    known_keys = ", ".join(e.alias for e in _CONFIG_SCHEMA)
    p_cfg_set = config_subs.add_parser(
        "set",
        help="set a configuration value",
        description=textwrap.dedent(
            f"""\
            Sets a key in /etc/acme/acme.conf by friendly name or canonical
            env-var name. The value is validated before writing.

            Known keys: {known_keys}

            Use --raw to set arbitrary keys (e.g. DNS provider credentials
            like CLOUDFLARE_DNS_API_TOKEN) without schema validation.
            Requires root.
            """
        ),
        formatter_class=_RawDescFmt,
    )
    p_cfg_set.add_argument("key", help="key alias (e.g. email) or canonical name (e.g. LEGO_EMAIL)")
    p_cfg_set.add_argument("value", help="new value")
    p_cfg_set.add_argument(
        "--raw",
        action="store_true",
        help="skip alias resolution and validation; accept any key name",
    )
    p_cfg_set.set_defaults(func=cmd_config_set)

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    _handler = logging.StreamHandler(sys.stderr)
    _handler.setFormatter(_LogFormatter())
    logging.root.addHandler(_handler)
    logging.root.setLevel(logging.DEBUG if args.verbose else logging.INFO)

    if args.command is None:
        parser.print_help()
        return 1

    output = make_output(OutputFormat(args.output_format))
    return args.func(args, output)


if __name__ == "__main__":
    sys.exit(main())
