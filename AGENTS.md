# AGENTS.md

Developer and AI-agent reference for `lego.py`.

## Project Overview

`lego.py` is a single-file Python CLI for managing ACME certificates on
OpenSUSE MicroOS using the [lego](https://go-acme.github.io/lego/) CLI as
the underlying ACME client. It handles certificate issuance, renewal
triggering, status reporting, and configuration management of the
surrounding systemd units and config files.

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
install step. On MicroOS, `python3-rich` can be installed via:

```
transactional-update pkg install python3-rich
```

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

`require_lego()` calls `shutil.which("lego")`. If not found it exits
with a message pointing to the wiki installation page. The script never
installs lego itself.

## Subcommands

| Command              | Root? | Description                                 |
|----------------------|-------|---------------------------------------------|
| `install`            | Yes   | Create dirs, install systemd units          |
| `issue <instance>`   | Yes   | Initial cert issuance via lego CLI          |
| `renew <instance>`   | Yes   | `systemctl start acme@<instance>.service`   |
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
