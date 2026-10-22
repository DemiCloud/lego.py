# lego.py

A single-file Python CLI wrapping the [lego](https://go-acme.github.io/lego/)
ACME client for certificate management on any Linux distro running systemd.

Handles certificate issuance, renewal scheduling via systemd timers, status
reporting, and configuration management — with no Python dependencies beyond
the standard library (optional `rich` for prettier output).

## Requirements

- Python 3.11+
- [lego](https://go-acme.github.io/lego/) binary in `PATH`
- systemd (for timer-based renewal)
- Root access for write operations

## Installing lego.py

Fetch the script from the
[latest GitHub release](https://github.com/DemiCloud/lego.py/releases/latest)
and drop it somewhere on `PATH`:

```bash
sudo curl -fsSL -o /usr/local/bin/lego.py \
  https://github.com/DemiCloud/lego.py/releases/latest/download/lego.py
sudo chmod +x /usr/local/bin/lego.py
```

(`releases/latest/download/lego.py` is a permanent GitHub redirect to
whichever release is newest, so this URL doesn't need updating between
versions. Swap `latest/download` for `download/vX.Y.Z` to pin a specific
release instead.)

## Installing lego

Let `lego.py` fetch and verify it directly from GitHub releases — works the
same on every distro, and sidesteps outdated or broken distro packages (see
the known issue below):

```bash
# Fetch the latest lego release from GitHub, verified against its published
# sha256 checksums, installed next to lego.py by default (Linux amd64/arm64 only).
sudo lego.py install --download-lego

# Pin a specific version, or a different destination directory:
sudo lego.py install --download-lego 5.4.0 --lego-dir /usr/local/bin

# Update an already-downloaded lego later without re-running the rest of install:
sudo lego.py update-lego
```

`require_lego()` looks on `PATH` first, then falls back to checking next to
`lego.py` itself — so this only lands on `PATH` automatically if `lego.py`'s
own directory is already on `PATH` (e.g. `/usr/local/bin`).

Or install lego through your distro's package manager instead:

**Debian / Ubuntu:**
```bash
sudo apt install lego
```

**Fedora / RHEL / Rocky / Alma:**
```bash
sudo dnf install lego
```

**openSUSE Leap / Tumbleweed:**
```bash
sudo zypper install lego
```

**openSUSE MicroOS / Aeon / Kalpa** (requires reboot to apply):
```bash
sudo transactional-update pkg install lego
sudo systemctl reboot
```

**macOS (Homebrew):**
```bash
brew install lego
```

Or download a pre-built binary yourself from the
[lego releases page](https://github.com/go-acme/lego/releases) and place it
somewhere in your `PATH`.

> **Known issue — Debian/Ubuntu/Proxmox `apt` package:** the distro-packaged
> `lego` binary (as of 4.9.1-2) is a non-standard build: `lego -v` prints
> `lego version dev` with no parseable version, and it's often missing most
> DNS providers entirely (e.g. `unrecognized DNS provider: cloudflare`),
> even though the provider is supported upstream. This is a known packaging
> issue, not something `lego.py` can work around — the
> [lego maintainers recommend](https://github.com/go-acme/lego/discussions/1514)
> using the upstream binary release or building from source instead. Run
> `sudo lego.py install --download-lego` to fetch a proper upstream build
> automatically instead of relying on the distro package.

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
| `update-lego [version]`  | Yes  | Download/update the lego binary from GitHub    |
| `issue <instance>`       | Yes  | Initial certificate issuance via lego CLI      |
| `renew <instance>`       | Yes  | Immediately trigger renewal via systemctl      |
| `hook <instance>`        | Yes  | Manually run the instance's configured HOOK    |
| `account register`       | Yes  | Register the ACME account; print its URL + key path |
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

| Alias                  | Env var                             | Description                              |
|-------------------------|-------------------------------------|------------------------------------------|
| `server`                | `LEGO_SERVER`                       | ACME directory URL                       |
| `email`                 | `LEGO_EMAIL`                        | Account email address                    |
| `challenge`             | `LEGO_CHALLENGE`                    | ACME challenge type, **required**: `dns-01`, `http-01`, or `dns-persist-01` |
| `dns`                   | `LEGO_DNS`                          | lego DNS provider name (`dns-01` only)   |
| `lego-version`          | `LEGO_VERSION`                      | Override lego version detection: auto, 4, or 5 |
| `dns-resolvers`         | `LEGO_DNS_RESOLVERS`                | Resolver(s) for `dns-01`/`dns-persist-01` (host:port) |
| `http-webroot`          | `LEGO_HTTP_WEBROOT`                 | `http-01` only: serve from this webroot instead of a standalone server |
| `dns-persist-issuer`    | `LEGO_DNS_PERSIST_ISSUER_DOMAIN_NAME` | `dns-persist-01` only: override issuer-domain-name |
| `dns-persist-until`     | `LEGO_DNS_PERSIST_PERSIST_UNTIL`    | `dns-persist-01` only: optional RFC3339 expiry for the TXT record |
| `account-key-path`      | `LEGO_ACCOUNT_KEY_PATH`             | Store the account private key here instead of under `/var/lib/acme` |
| `eab`                   | `LEGO_EAB`                          | Enable External Account Binding          |
| `eab-kid`               | `LEGO_EAB_KID`                      | EAB key ID                               |
| `eab-hmac`              | `LEGO_EAB_HMAC`                     | EAB HMAC key                             |
| `pfx`                   | `LEGO_PFX`                          | Generate PKCS#12 alongside PEM files     |
| `pfx-password`          | `LEGO_PFX_PASSWORD`                 | PKCS#12 password                         |
| `pfx-format`            | `LEGO_PFX_FORMAT`                   | PKCS#12 hash format: RC2, DES, SHA256    |

Use `--raw` to set arbitrary keys (e.g. DNS provider credentials):

```bash
sudo lego.py config set --raw CLOUDFLARE_DNS_API_TOKEN abc123
```

### Challenge types

`LEGO_CHALLENGE` picks how lego proves domain control, per instance (it's
read from the merged global+instance config, same as every other key).
**There is no default** — `issue`/`renew-exec` refuse to run until it's
set to one of:

- **`dns-01`** — the original behaviour. Needs `LEGO_DNS` (a
  [provider name](https://go-acme.github.io/lego/dns/)) and that provider's
  API credentials, set with `config set --raw`. Supports wildcards; no
  public-facing service required.
- **`http-01`** — serves the challenge over port 80 (`lego`'s built-in
  standalone server), or from an existing web server's docroot if
  `LEGO_HTTP_WEBROOT` is set. No wildcard support. Nothing else to
  configure.
- **`dns-persist-01`** — see below. No DNS provider or API credentials at
  all.

### DNS-PERSIST-01

[DNS-PERSIST-01](https://letsencrypt.org/2026/02/18/dns-persist-01) is a
newer ACME challenge type (from
[draft-ietf-acme-dns-persist](https://datatracker.ietf.org/doc/html/draft-ietf-acme-dns-persist-01),
supported by lego v5+) built around a *persistent* TXT record instead of a
fresh one per issuance: you publish one `_validation-persist.<domain>`
record, authorizing your ACME account, and every later issuance or renewal
just re-checks that it's still there — no DNS changes, no DNS provider
credentials, ever, on lego.py's side.

**lego.py never creates, inspects, or modifies that record.** You deploy it
yourself, out-of-band, before running `lego.py issue`:

1. Set the challenge type and register the account:

   ```bash
   sudo lego.py config set challenge dns-persist-01
   sudo lego.py account register
   ```

   This prints the account's URL (and where its private key lives), e.g.:

   ```
   account-url: https://acme-v02.api.letsencrypt.org/acme/acct/1234567890
   key-path: /var/lib/acme/accounts/acme-v02.api.letsencrypt.org/you@example.com/you@example.com.key
   ```

2. Publish a TXT record at `_validation-persist.<domain>` containing that
   URL, in your DNS zone, using whatever means you normally manage that
   zone (lego.py is intentionally not involved here):

   ```
   _validation-persist.mysite.example.com. IN TXT "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1234567890"
   ```

   (`letsencrypt.org` is Let's Encrypt's issuer-domain-name per their own
   docs linked above — check your CA's documentation if using a different
   one. Add `; policy=wildcard` if you need wildcard certs under this name,
   or `; persistUntil=<unix-timestamp>` for an optional expiry — matching
   `LEGO_DNS_PERSIST_PERSIST_UNTIL` below if you set it.)

3. Once the record has propagated, issue normally:

   ```bash
   sudo lego.py issue mysite
   ```

If the record isn't in place yet when you run `issue`, lego falls back to
prompting on stdin for you to create it — which only works from a real
terminal, and will fail fast (not hang) under the unattended systemd timer.
Deploying it up front as above avoids that path entirely, for both the
first issuance and every renewal after.

### Per-instance config — `/etc/acme/<instance>.env`

Created manually. Instance values override the global config. Required fields:

```bash
DOMAINS="-d foo.example.com -d bar.example.com"
HOOK="/path/to/deploy-hook.sh"   # optional; runs after successful renewal
```

`HOOK` is invoked with these environment variables set, regardless of the
installed lego version (`lego.py` computes them itself rather than relying
on lego's own hook variables, which were renamed between v4 and v5):

| Variable                 | Value                                          |
|---------------------------|------------------------------------------------|
| `LEGO_PY_INSTANCE`        | Instance name (e.g. `mysite`)                  |
| `LEGO_PY_DOMAIN`          | Primary domain (first `-d` in `DOMAINS`)       |
| `LEGO_PY_CERT_PATH`       | Path to the issued certificate                 |
| `LEGO_PY_CERT_KEY_PATH`   | Path to the certificate's private key          |
| `LEGO_PY_CERT_ISSUER_PATH`| Path to the issuer (chain) certificate         |

Use `lego.py hook <instance>` to run the configured hook on demand against
the instance's current certificate — useful for testing a hook script
without waiting for (or forcing) an actual renewal.

### Relocating the account private key

By default lego keeps the ACME account private key under
`/var/lib/acme/accounts/...` alongside everything else. Setting
`LEGO_ACCOUNT_KEY_PATH` moves just that one file somewhere more tightly
controlled — e.g. a separate backup set, or a directory with narrower
access than the rest of the lego working directory:

```bash
sudo lego.py config set account-key-path /etc/acme/keys/letsencrypt.key
```

lego.py creates `/etc/acme/keys` (root-owned, `0700`) and the key file
itself (root-owned, `0600`) at that path, migrating an existing key there
if one already exists, and leaves a symlink in lego's own account
directory pointing to it — lego reads and writes through that symlink
transparently and never needs to know it moved. This runs automatically on
every `issue`/`renew-exec`/`account register` invocation; everything else
(`certificates/`, challenge state, etc.) stays under `/var/lib/acme/` as
usual.

## Paths

| Path                          | Purpose                              |
|-------------------------------|---------------------------------------|
| `/etc/acme/acme.conf`         | Global settings                      |
| `/etc/acme/<instance>.env`    | Per-certificate overrides            |
| `/etc/acme/keys/`             | Account key, if `LEGO_ACCOUNT_KEY_PATH` is set |
| `/var/lib/acme/`              | lego working directory               |
| `/var/lib/acme/certificates/` | Issued certificate files             |
| `/etc/systemd/system/`        | systemd unit templates               |


## Renewal

`lego.py issue` enables `acme@<instance>.timer` automatically after issuance.
The timer fires daily at 03:35 with a 1-hour random delay. lego renews only
when the certificate is within 30 days of expiry.

The systemd unit calls back into `lego.py` for the actual renewal, so it
re-detects the installed lego version on every run — an unattended lego
upgrade (e.g. via your package manager's automatic updates) won't leave a
stale unit behind. `lego.py install` bakes lego.py's own path into the
unit, though, so re-run it if you move or reinstall lego.py itself to a
new location.

To trigger an immediate renewal:

```bash
sudo lego.py renew mysite
journalctl -u acme@mysite.service
```

## Optional: rich output

Install `python3-rich` for coloured tables and progress indicators.
Falls back to plain ASCII tables if not available.

**Debian / Ubuntu:**
```bash
sudo apt install python3-rich
```

**Fedora / RHEL:**
```bash
sudo dnf install python3-rich
```

**openSUSE Leap / Tumbleweed:**
```bash
sudo zypper install python3-rich
```

**openSUSE MicroOS / Aeon / Kalpa** (requires reboot):
```bash
sudo transactional-update pkg install python3-rich
```
