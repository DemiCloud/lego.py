# AGENTS.md

Developer and AI-agent reference for `lego.py`.

## Project Overview

`lego.py` is a single-file Python CLI for managing ACME certificates on
any Linux distro running systemd, using the
[lego](https://go-acme.github.io/lego/) CLI as the underlying ACME client.
It handles certificate issuance, renewal triggering, status reporting, and
configuration management of the surrounding systemd units and config files.

## Repository Layout

```
lego.py               Main script (single file, fully self-contained)
systemd/
  acme@.service       Reference copy of the renewal service template
  acme@.timer         Reference copy of the renewal timer template
AGENTS.md             This file
.wiki/                GitHub wiki source (gitignored, not committed here)
scratch/              Throwaway files and notes (gitignored)
```

The unit file contents are **embedded in `lego.py`** as `_UNIT_SERVICE` and
`_UNIT_TIMER` constants. The `systemd/` directory is reference only —
**if you update a unit file, update both the constant in `lego.py` and the
file in `systemd/`**. The script requires no external files at runtime.

## Language and Runtime

- **Python 3.11+** — minimum version, no exceptions.
- Shebang: `#!/usr/bin/env python3`
- No compiled extensions, no C dependencies.

## Code Style

- **PEP 8** compliant.
- **Black** formatted, 88-character line length.
- **isort** import ordering (standard library only, no third-party in
  imports except the optional `rich`).
- Type hints on all public functions and class attributes.
- `from __future__ import annotations` is NOT used; native 3.11 syntax
  (`X | Y`, `list[str]`, `dict[str, str]`) is preferred.

## Dependencies

| Package | Status   | Purpose                              |
|---------|----------|--------------------------------------|
| `rich`  | Optional | Enhanced table and colour output     |
| stdlib  | Required | Everything else                      |

`rich` is JIT-detected at startup via a `try/except ImportError`. If
absent the script falls back to `PlainOutput` automatically. **Never add
a `requirements.txt` or `pyproject.toml`** — there is no venv, no pip
install step. Install it via the distro's package manager instead — see
the README for per-distro commands.

## Architecture

### Output Abstraction

All structured output (tables, key-value pairs, single values) goes
through an `Output` protocol. Implementations are selected once at
startup via `--format` and injected into every subcommand handler.

```
Output (typing.Protocol)
├── RichOutput    --format auto   (when rich is available)
├── PlainOutput   --format plain  (or auto fallback)
├── JsonOutput    --format json
└── CsvOutput     --format csv
```

Informational messages (progress, warnings, errors) go to **stderr** via
the `logging` module and are always plain text regardless of `--format`.
Structured data goes to **stdout** through the `Output` instance.

### Config Files

| Path                        | Purpose                          |
|-----------------------------|----------------------------------|
| `/etc/acme/acme.conf`       | Global settings (shell key=value)|
| `/etc/acme/<instance>.env`  | Per-cert overrides and DOMAINS   |
| `/var/lib/acme/`            | lego working directory           |
| `/var/lib/acme/certificates/` | Issued certificate files       |

Config files are parsed by `parse_env_file()` — a small custom parser
that handles `KEY=value`, `KEY="value"`, comments, and blank lines. Do
**not** use `configparser` or shell `source` for these files.

### DOMAINS Format

The `DOMAINS` variable in per-instance env files uses lego's flag syntax
directly, e.g.:

```
DOMAINS="-d foo.example.com -d bar.example.com"
```

When building subprocess arguments, parse with:

```python
domains_args = DOMAINS.split()   # produces ["-d", "foo...", "-d", "bar..."]
```

This matches how systemd word-splits the variable in `ExecStart`.

### CertState

```python
class CertState(enum.StrEnum):
    VALID              = "valid"              # >= EXPIRY_WARN_DAYS (30) until expiry
    EXPIRING_SOON      = "expiring_soon"      # EXPIRY_CRIT_DAYS <= days < EXPIRY_WARN_DAYS
    EXPIRING_CRITICAL  = "expiring_critical"  # 0 <= days < EXPIRY_CRIT_DAYS (15)
    EXPIRED            = "expired"            # past expiry
    PENDING            = "pending"            # .env exists, no cert file yet
    UNMANAGED          = "unmanaged"          # cert exists, no .env file
```

Rich row colours: `VALID` → green, `EXPIRING_SOON` → yellow,
`EXPIRING_CRITICAL` / `EXPIRED` → bold red, `PENDING` / `UNMANAGED` → dim.

`status` uses `lego --path /var/lib/acme list` as its primary data source for
issued certs (name, domains, expiry). The output is human-readable text parsed
with `_LIST_*_RE` regex constants — if lego changes its output format these
patterns will need updating. Cross-references with `/etc/acme/*.env` to
identify PENDING and UNMANAGED certs.

### Privilege Model

Commands that write to `/etc/` or call `systemctl` require root.
Use `require_root()` at the top of those handlers. Read-only commands
(`status`, `config show`, `config get`) do not.

### Lego Detection

`require_lego()` (via `_find_lego()`) checks `PATH` first, then falls back
to a `lego` binary sitting next to `lego.py` itself
(`pathlib.Path(__file__).resolve().parent / "lego"`) — this is where
`install --download-lego` / `update-lego` put it by default. If neither is
found it exits with a message pointing to the wiki installation page and
the `--download-lego` flag.

`_download_lego()` fetches a release tarball directly from
`github.com/go-acme/lego/releases`, verifies its sha256 against the
release's own `*_checksums.txt` (lego publishes no GPG signature, so this
is the realistic integrity baseline — same trust boundary as downloading
the tarball by hand), extracts just the `lego` binary via `tarfile`
(searching all members for a file named `lego` rather than assuming a
fixed path, since we don't control the archive layout), and installs it.
Supports Linux amd64/arm64 only — `_LEGO_ARCH_MAP` extends this. lego's
asset naming is inconsistent between the tarball (`lego_v5.4.0_...`, with
the `v`) and the checksums file (`lego_5.4.0_checksums.txt`, without) —
`_lego_release_asset_names()` is the one place that has to know this.

lego's CLI syntax changed between v4 and v5 (v5 moved global flags under
the subcommand, and merged `renew` into `run`). `_lego_version()` parses
`lego --version`; some distro packages (e.g. Debian) print an unversioned
`lego version dev` that can't be parsed, in which case it returns
`(0, 0, 0)`. `_resolve_lego_version()` wraps this with an optional
`LEGO_VERSION` override from `acme.conf` (`auto`/`4`/`5`) and warns to
stderr whenever detection fails and it has to silently assume v4 syntax.
`_build_lego_run_cmd(action="issue"|"renew")` is the single place that
turns a version + action into the actual `lego` argv — v5 always uses
`run` regardless of action, since v5 dropped `renew` as a separate command.

### Renewal Execution

Critically, **version detection happens at execution time, not at
`install` time.** The systemd unit's `ExecStart` calls back into
`lego.py renew-exec <instance>` (a hidden subcommand — no `help=` on its
subparser, so it doesn't show in `--help`, but it's not otherwise special)
rather than invoking `lego` directly with flags baked into the unit file.
This matters because lego can be upgraded out from under an already-
installed unit by an unattended package upgrade (the bug report that
motivated this: MicroOS's `transactional-update` bumping v4→v5 on reboot)
— freezing version-specific flags into the unit at install time
means the unit silently goes stale on the next lego upgrade. Routing
through `lego.py` means every timer-triggered renewal re-detects the
version and rebuilds the command from scratch, same as `issue` already
did. `cmd_install()` bakes the *absolute path to lego.py itself*
(`pathlib.Path(__file__).resolve()`) into `ExecStart` — re-run
`lego.py install` if you move or reinstall lego.py to a new location.

### Challenge Types

`LEGO_CHALLENGE` is required, with **no default** — `_load_lego_conf()`
rejects a missing/invalid value outright rather than silently assuming
`dns-01` (this was a deliberate breaking change from the original
single-challenge design; pre-existing installs must explicitly run
`lego.py config set challenge dns-01` once to keep working). It selects
which ACME challenge `_build_lego_run_cmd()` builds flags for: `dns-01`
(`--dns`, needs `LEGO_DNS` + provider credentials in the env), `http-01`
(`--http`, optionally `--http.webroot`), or `dns-persist-01`
(`--dns-persist`, v5-only — gated in `_run_lego()` since the
`--dns-persist` flag and the `accounts` command group don't exist in lego
v4 at all). `_load_lego_conf()` only requires `LEGO_DNS` when the
challenge is `dns-01`.

DNS-PERSIST-01 ([draft-ietf-acme-dns-persist](https://datatracker.ietf.org/doc/html/draft-ietf-acme-dns-persist-01))
trades DNS-01's per-issuance TXT record for one persistent
`_validation-persist.<domain>` record binding the domain to a specific
ACME account — published once, out-of-band, and reused by every later
issuance/renewal with no further DNS changes. **lego.py deliberately never
creates, reads, or writes that record itself** — the design goal is zero
DNS provider credentials for this challenge. `cmd_account_register()`
(`lego.py account register`) exists solely to surface the one fact an
operator can't invent themselves: the account's URL (read back from the
`registration.accountURL` field lego writes to `account.json` after
`lego accounts register`), via `_account_file_path()` /
`_read_account_url()`, which mirror lego's own account storage layout
(see Account Key Relocation below). Left alone, lego's own fallback for a
missing/expired record is to prompt on stdin — fine when `issue` is run
interactively, but something to avoid relying on under the unattended
`renew-exec` timer path, where it fails fast instead of hanging (stdin is
`/dev/null` under systemd) rather than actually blocking.

### Account Key Relocation

lego has no flag to store just the account private key somewhere other
than under `--path` (`/var/lib/acme/accounts/<sanitized-server-host>/
<email>/<email>.key` — `_sanitize_host()` mirrors lego's own
`AccountsStorage.sanitizeHost()`, and lego.py never passes an explicit
account ID, so the effective ID is always the email). Setting
`LEGO_ACCOUNT_KEY_PATH` doesn't change what lego does — `_sync_account_key()`
instead pre-creates (or migrates an existing key into) that path and
leaves a symlink in lego's own expected location pointing to it, run
before every `_run_lego()` invocation and in `cmd_account_register()`.
lego reads/writes through the symlink transparently and never needs to
know. `_account_key_path()` computes lego's expected internal path; keep
it in sync with lego's `cmd/internal/storage/storage_accounts.go` if that
layout ever changes upstream.

## Subcommands

| Command              | Root? | Description                                 |
|----------------------|-------|---------------------------------------------|
| `install`            | Yes   | Create dirs, install systemd units          |
| `update-lego [ver]`  | Yes   | Download/update lego binary from GitHub     |
| `issue <instance>`   | Yes   | Initial cert issuance via lego CLI          |
| `renew <instance>`   | Yes   | `systemctl start acme@<instance>.service`   |
| `renew-exec <instance>` (hidden) | Yes | Actual lego invocation; called by the systemd unit, not users |
| `hook <instance>`    | Yes   | Manually run the instance's HOOK against its current cert |
| `account register`   | Yes   | Register the ACME account; print its URL + key path (requires lego v5+) |
| `status`             | No    | Cert expiry table across all instances      |
| `config show`        | No    | Display acme.conf (secrets masked)          |
| `config get <key>`   | No    | Print a single config value                 |
| `config set <k> <v>` | Yes   | Update or add a key in acme.conf            |

## CLI Conventions

- GNU-style flags: `-h/--help`, `-V/--version`, `-v/--verbose`.
- `--format FORMAT` is a global flag (before the subcommand).
- Each subcommand has its own `--help`; the top-level help only lists
  subcommand names.
- Exit codes: `0` success, `1` general error, `2` usage error (argparse
  default).

## Coding Notes

- All file I/O uses `pathlib.Path`.
- Subprocess calls use `subprocess.run(..., check=True)` by default;
  capture stdout/stderr where the output is needed programmatically.
- Do **not** use `shell=True` in subprocess calls.
- `openssl x509 -enddate -noout -in <cert>` is used for expiry parsing.
- Sensitive config keys (containing `KEY`, `HMAC`, `TOKEN`, `SECRET`,
  `PASSWORD`) must be masked in `config show` output.
- The `--format` flag affects only structured data output. Error and
  warning messages are always plain text on stderr.

## Common Pitfalls

- `DOMAINS` must be split with `.split()`, not passed as a single string
  to subprocess — otherwise lego receives one argument instead of many.
- `parse_env_file()` strips one layer of surrounding quotes only. Do not
  double-quote values in config files.
- `transactional-update` on MicroOS requires a reboot to take effect;
  `install` should warn the user if it detects a pending reboot.

## Release Process

Only commit or tag when explicitly asked, same as any other repo. When
asked to "cut a release":

1. **Bump `__version__` in lego.py.** Pre-1.0, treat any user-visible
   change — bug fix or new feature — as its own minor version bump (no
   patch-level increments used so far: `0.2.0` → `0.3.0` renewal fix →
   `0.4.0` download feature). If the version-bump lands with other
   changes already committed, give it its own small commit.
2. **Prefer one commit per logically distinct change**, even when they're
   implemented in the same session (e.g. a bug fix and an unrelated new
   feature) — don't squash unrelated work into one commit for
   convenience. Each commit should independently pass the test suite;
   verify before moving to the next one, not just at the end.
3. **Tag annotated, not lightweight**: `git tag -a vX.Y.Z -m "<bullet
   summary of changes>"`.
4. **A git tag alone is not a GitHub Release** — it won't show up on the
   repo's Releases page. Also run
   `gh release create vX.Y.Z --title vX.Y.Z --notes "..."`.
5. **Attach `lego.py` itself as a release asset**:
   `gh release upload vX.Y.Z lego.py`. Pull the exact tagged content
   first (`git show vX.Y.Z:lego.py > /path/to/lego.py`) rather than
   assuming the working tree still matches the tag, and diff the two
   before uploading. This matters because GitHub's auto-generated
   "Source code" archive is the *whole repo* (tests/, AGENTS.md,
   systemd/, ...) — not something to ever point users at. The correct
   one-liner for users is the standalone asset via the stable
   `github.com/<owner>/<repo>/releases/latest/download/lego.py` redirect
   (documented in the README's "Installing lego.py" section), which
   keeps working release over release without edits as long as every
   release attaches an asset literally named `lego.py`.
6. **Never `git push`** (commits or tags) unless explicitly asked, even
   after cutting a release — leave it to the user. Note: this sandboxed
   environment may not have working SSH credentials for the git remote
   (`git push` can fail with "Permission denied (publickey)") even
   though `gh` works fine (separate HTTPS token auth) for release/API
   calls — that's an environment limitation, not a real error to
   troubleshoot. Just hand the user the exact `git push` commands to run
   themselves from a session that has their key.
7. **Moving an already-pushed tag requires a force-push** — confirm with
   the user before doing this (e.g. "fold a follow-up docs commit into
   the existing release") rather than assuming; a new patch release is
   the lower-risk alternative and worth offering explicitly.

## Documentation Conventions

lego.py depends only on Python 3.11+ and systemd — nothing distro
specific. README/AGENTS.md framing (titles, intros, example ordering)
should reflect that and not center any one distro (this project used to
lead with OpenSUSE MicroOS; that's been genericized). Concrete,
factual per-distro notes are still fine and worth keeping — e.g. the
Debian/Ubuntu/Proxmox apt package's known issues, or MicroOS's
transactional-update reboot requirement — those are real technical
caveats, not framing bias.
