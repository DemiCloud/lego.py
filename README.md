# lego.py

A single-file Python CLI for managing ACME certificates on OpenSUSE MicroOS,
using the [lego](https://go-acme.github.io/lego/) ACME client under the hood.

Handles certificate issuance, renewal scheduling via systemd timers, status
reporting, and configuration management — with no Python dependencies beyond
the standard library (optional `rich` for prettier output).

## Requirements

- Python 3.11+
- [lego](https://go-acme.github.io/lego/) binary in `PATH`
- systemd (for timer-based renewal)
- Root access for write operations

## Installing lego

**OpenSUSE MicroOS / Aeon / Kalpa** (requires reboot to apply):
```bash
sudo transactional-update pkg install lego
sudo systemctl reboot
```

**OpenSUSE Leap / Tumbleweed:**
```bash
sudo zypper install lego
```

**Fedora / RHEL / Rocky / Alma:**
```bash
sudo dnf install lego
```

**Debian / Ubuntu:**
```bash
sudo apt install lego
```

**macOS (Homebrew):**
```bash
brew install lego
```

Or download a pre-built binary from the
[lego releases page](https://github.com/go-acme/lego/releases) and place it
somewhere in your `PATH`.

## Quick Start

```bash
# 1. Install systemd unit templates and create directories
sudo lego.py install

# 2. Set global config (email, DNS provider, etc.)
sudo lego.py config set email you@example.com
sudo lego.py config set dns cloudflare
sudo lego.py config set --raw CLOUDFLARE_DNS_API_TOKEN yourtoken

# 3. Create a per-instance env file
sudo tee /etc/acme/mysite.env <<'EOF'
DOMAINS="-d mysite.example.com -d www.mysite.example.com"
HOOK="/usr/local/bin/deploy-cert.sh"
EOF

# 4. Issue the certificate (enables the renewal timer automatically)
sudo lego.py issue mysite

# 5. Check status
lego.py status
```

## Commands

| Command                  | Root | Description                                    |
|--------------------------|------|------------------------------------------------|
| `install`                | Yes  | Create dirs, install systemd unit templates    |
| `issue <instance>`       | Yes  | Initial certificate issuance via lego CLI      |
| `renew <instance>`       | Yes  | Immediately trigger renewal via systemctl      |
| `status`                 | No   | Show expiry and timer state for all certs      |
| `config show`            | No   | Display acme.conf with secrets masked          |
| `config get <key>`       | No   | Print a single config value                    |
| `config set <key> <val>` | Yes  | Set or update a key in acme.conf               |

Global flags (before the subcommand):

```
-v, --verbose       Debug logging to stderr
--format FORMAT     Output format: auto, plain, json, csv  (default: auto)
-V, --version       Show version
```

## Configuration

### Global config — `/etc/acme/acme.conf`

Created by `lego.py install`. Known keys (use the alias with `config set`):

| Alias           | Env var              | Description                              |
|-----------------|----------------------|------------------------------------------|
| `server`        | `LEGO_SERVER`        | ACME directory URL                       |
| `email`         | `LEGO_EMAIL`         | Account email address                    |
| `dns`           | `LEGO_DNS`           | lego DNS provider name                   |
| `dns-resolvers` | `LEGO_DNS_RESOLVERS` | Resolver(s) for DNS-01 (host:port)       |
| `eab`           | `LEGO_EAB`           | Enable External Account Binding          |
| `eab-kid`       | `LEGO_EAB_KID`       | EAB key ID                               |
| `eab-hmac`      | `LEGO_EAB_HMAC`      | EAB HMAC key                             |
| `pfx`           | `LEGO_PFX`           | Generate PKCS#12 alongside PEM files     |
| `pfx-password`  | `LEGO_PFX_PASSWORD`  | PKCS#12 password                         |
| `pfx-format`    | `LEGO_PFX_FORMAT`    | PKCS#12 hash format: RC2, DES, SHA256    |

Use `--raw` to set arbitrary keys (e.g. DNS provider credentials):

```bash
sudo lego.py config set --raw CLOUDFLARE_DNS_API_TOKEN abc123
```

### Per-instance config — `/etc/acme/<instance>.env`

Created manually. Instance values override the global config. Required fields:

```bash
DOMAINS="-d foo.example.com -d bar.example.com"
HOOK="/path/to/deploy-hook.sh"   # optional; runs after successful renewal
```

## Paths

| Path                          | Purpose                              |
|-------------------------------|--------------------------------------|
| `/etc/acme/acme.conf`         | Global settings                      |
| `/etc/acme/<instance>.env`    | Per-certificate overrides            |
| `/var/lib/acme/`              | lego working directory               |
| `/var/lib/acme/certificates/` | Issued certificate files             |
| `/etc/systemd/system/`        | systemd unit templates               |

## Renewal

`lego.py issue` enables `acme@<instance>.timer` automatically after issuance.
The timer fires daily at 03:35 with a 1-hour random delay. lego renews only
when the certificate is within 30 days of expiry.

To trigger an immediate renewal:

```bash
sudo lego.py renew mysite
journalctl -u acme@mysite.service
```

## Optional: rich output

Install `python3-rich` for coloured tables and progress indicators.
Falls back to plain ASCII tables if not available.

**OpenSUSE MicroOS / Aeon / Kalpa** (requires reboot):
```bash
sudo transactional-update pkg install python3-rich
```

**OpenSUSE Leap / Tumbleweed:**
```bash
sudo zypper install python3-rich
```

**Fedora / RHEL:**
```bash
sudo dnf install python3-rich
```

**Debian / Ubuntu:**
```bash
sudo apt install python3-rich
```
