<div align="center">

```
   ╱|、       ┬─┐┬ ┬┌─┐┌┬┐  ┌─┐┌─┐┬ ┬┬  ┌─┐
  (˚ˎ 。7     ├┬┘│ │└─┐ │   │  │ │├─┤│  ├┤
   |、˜〵      ┴└─└─┘└─┘ ┴   └─┘└─┘┴ ┴┴─┘└─┘
   じしˍ,)ノ
```

# rust cohle

**a fast, terminal-native osint & recon framework**

no registration · no subscription · no telemetry · one binary

[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)]()
[![Modules](https://img.shields.io/badge/modules-24-magenta.svg)]()

</div>

---

## what is this

most osint tools are either a python script that dies on the third request, or a
paid web service hiding behind a login. rust cohle is neither. it's a single
self-contained binary that runs 24 reconnaissance modules against a target — from
username hunting across 60+ networks to subdomain takeover detection — and prints
everything straight to your terminal.

- **written in rust** — fast, parallel, doesn't leak memory or crash mid-scan
- **fully async** — every module fans out its requests concurrently via tokio
- **no api keys required** for most modules (a couple optionally use them)
- **proxy & tor ready** — route everything through `socks5://127.0.0.1:9050`
- **rate-limit aware** — retries with exponential backoff, honors `Retry-After`
- **one binary** — drop it in your `$PATH` and go

> *"time is a flat circle."*

---

## install

### from source

you need the [rust toolchain](https://rustup.rs/) installed.

```bash
git clone https://github.com/anonyrecidivism-ux/rustcohle
cd rustcohle
cargo build --release
```

the binary lands at `target/release/rustcohle`. drop it somewhere on your path:

```bash
sudo cp target/release/rustcohle /usr/local/bin/
```

keep `sites.json` and `emails.json` next to the binary (they ship with the repo).
optionally copy `config.toml.example` to `config.toml` and add your api keys.

### arch linux

```bash
sudo pacman -S --needed openssl pkg-config
cargo build --release
```

---

## usage

run with no arguments for the interactive menu:

```bash
rustcohle
```

or call any module directly:

```bash
rustcohle username torvalds
rustcohle email someone@example.com
rustcohle ip 8.8.8.8
rustcohle git torvalds
rustcohle crt example.com
rustcohle reverse-ip 1.1.1.1
rustcohle asn AS15169
rustcohle favicon example.com
rustcohle permute "john doe"
rustcohle dorks example.com
rustcohle recon example.com
```

route everything through tor:

```bash
rustcohle --proxy socks5://127.0.0.1:9050 username torvalds
```

---

## modules

### people & accounts

| command | description |
|---------|-------------|
| `username <name>` | search **61** social networks in parallel, grouped into a correlation graph by category (dev / social / gaming / security / creative / music / content) |
| `email <addr>` | check whether an email is registered across **20** services, holehe-style |
| `hibp <addr>` | haveibeenpwned breach lookup (optional api key for full results) |
| `git <user>` | github deep recon — profile, repos, orgs, gists, **emails harvested from commits**, public ssh keys |
| `phone <number>` | carrier & country detection from prefix, plus lookup links |
| `permute <name>` | generate username variations (john.doe, jdoe, john_doe …) and quick-check key networks |

### infrastructure & domains

| command | description |
|---------|-------------|
| `ip <ip\|domain>` | geoip, asn, isp, reverse dns + threat flags (proxy / hosting / mobile) |
| `dns <domain>` | a, aaaa, mx, txt, ns, cname, soa, caa records |
| `whois <domain>` | rdap / whois — registrar, dates, nameservers, status |
| `crt <domain>` | subdomain enumeration (crt.sh + hackertarget + alienvault) **plus subdomain takeover detection** against 26 service fingerprints |
| `tls <domain>` | tls/cdn fingerprint — tries to surface the real ip hiding behind cloudflare |
| `reverse-ip <target>` | find other domains co-hosted on the same ip |
| `asn <as\|ip>` | announced bgp prefixes, holder, registry (via ripestat) |

### scanning & analysis

| command | description |
|---------|-------------|
| `ports <host>` | async port scanner — profiles: `common`, `web`, `full`, `top1000` |
| `banner <host>` | banner grab on web ports — server, x-powered-by, etc. |
| `site <url>` | full page analysis — security headers, tech stack (40+ signatures), links |
| `headers <url>` | http headers + waf/cdn detection + a security-header grade (A+ to F) |
| `favicon <url>` | hash a site's favicon (murmurhash3) for shodan/fofa pivoting — a reliable way to unmask servers behind a cdn |

### data & artifacts

| command | description |
|---------|-------------|
| `exif <path\|url>` | extract exif from an image — warns and drops a map link if gps coordinates are present |
| `meta <path\|url>` | document metadata from pdf / docx / png / jpeg — author, software, company, timestamps |
| `wayback <url>` | wayback machine snapshots with dates and archive links |
| `paste <query>` | search paste sites (psbdmp api) for an email, username, or domain |
| `dorks <domain>` | generate ready-to-click google / bing / shodan / censys dork links |

### everything at once

| command | description |
|---------|-------------|
| `recon <target>` | full chain: `ip → dns → whois → crt → tls → headers → reverse-ip → ports` |

---

## configuration

copy the example and fill in what you have — everything is optional:

```bash
cp config.toml.example config.toml
```

```toml
# config.toml — placed next to the binary, or at ~/.config/rustcohle/config.toml
hibp_api_key = "your_key"     # https://haveibeenpwned.com/API/Key
github_token = "your_token"   # https://github.com/settings/tokens (no scopes needed)
proxy        = ""             # socks5://127.0.0.1:9050 for tor
timeout_secs = 12             # per-request timeout
max_retries  = 3              # retries on 429 / 5xx with exponential backoff
```

environment variables override the config file:
`HIBP_API_KEY`, `GITHUB_TOKEN`, `RUSTCOHLE_PROXY`.

> **never commit your `config.toml`** — it's already in `.gitignore`. only the
> `.example` file belongs in the repo.

---

## how it works

every module is async and fans its requests out concurrently, so a 61-site
username scan finishes in roughly the time of the slowest single request rather
than the sum of all of them. the rate-limit-prone public endpoints (crt.sh, hibp,
ripestat) are wrapped in an exponential-backoff retry that respects the server's
`Retry-After` header, and the http client reuses a connection pool across the
many requests each module makes.

data sources are all free, keyless public apis where possible: google dns-over-https,
crt.sh, hackertarget, alienvault otx, ripestat, ip-api, the wayback machine cdx api,
and the github public api.

---

## legal & ethics

this tool is for **authorized security testing, research, and educational use only.**

use it only against systems you own or have **explicit written permission** to
test. all data it touches is already public — but how you use that data is your
responsibility. do not use rust cohle for harassment, stalking, unauthorized
access, or anything illegal in your jurisdiction. the author accepts no liability
for misuse.

if you don't have permission, you don't have a target.

---

## contributing

issues and pull requests welcome — especially:

- new sites for `sites.json` (include a `category` field)
- new email services for `emails.json`
- new subdomain-takeover fingerprints
- bug reports with the exact command and output

---

## license

MIT — see [LICENSE](LICENSE).

---

<div align="center">
<sub>built by <a href="https://github.com/anonyrecidivism-ux">@anonyrecidivism-ux</a> · osint never sleeps, neither does the cat</sub>
</div>