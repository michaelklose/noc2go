<p align="center">
  <!-- Feel free to replace this with a real banner later on -->
  <img src="https://raw.githubusercontent.com/michaelklose/noc2go/main/.github/banner.png" alt="noc2go banner" width="500"/>
</p>

<h1 align="center">NOC2GO</h1>
<p align="center"><em>Your friendly Swiss‑Army NOC toolkit—everything you need for quick diagnostics in one tiny, cross‑platform Go binary.</em></p>

<p align="center">
  <a href="https://github.com/michaelklose/noc2go/actions">
    <img alt="Build" src="https://img.shields.io/github/actions/workflow/status/michaelklose/noc2go/ci.yml?label=build&logo=github">
  </a>
  <a href="https://github.com/michaelklose/noc2go/releases">
    <img alt="Latest release" src="https://img.shields.io/github/v/release/michaelklose/noc2go?logo=semantic-release">
  </a>
  <a href="https://pkg.go.dev/github.com/michaelklose/noc2go">
    <img alt="Go Reference" src="https://pkg.go.dev/badge/github.com/michaelklose/noc2go.svg">
  </a>
  <a href="LICENSE">
    <img alt="License" src="https://img.shields.io/github/license/michaelklose/noc2go?color=blue">
  </a>
</p>

---

## ✨ Why NOC2GO?

Need to **ping a service, dig a DNS record, or peek at system details**—but don’t want to juggle half‑a‑dozen tools that behave differently on every OS?  
NOC2GO wraps the basics in a gorgeous little web UI and ships as **one self‑contained executable** for Windows, macOS, and Linux. Drop it onto a server, your home NAS, or a USB stick and you’re good to go. No installers, no baggage, just the essentials with a smile. 😊

---

## 🚀 Feature Highlights

| Web UI Tile | What it does |
|-------------|--------------|
| **Ping** | IPv4/IPv6 ICMP with live graphs, custom packet size/TTL, DF‑bit toggle, and summary stats. |
| **DNS Lookup** | A, AAAA, MX, NS, TXT, SRV, PTR—including reverse‑lookup helper, custom resolver support & caching. |
| **System Info** | Hostname, OS/arch, kernel, uptime, interfaces, routes, DNS servers, proxy vars—handy for “what box is this again?” moments. |
| **Settings** | Manage saved DNS servers & ping targets, change password, tweak privileged mode. |
| **TLS out‑of‑the‑box** | Generates a self‑signed cert on first run and serves everything over HTTPS. |

Under the hood you’ll also find:

* Single YAML config (`noc2go.yaml`) that gets auto‑created on first launch.  
* Session cookies (secure & http‑only) with bcrypt password hashing.  
* Cross‑platform raw‑socket ping when running with elevated privileges (fallback to system `ping` otherwise).  
* **No external dependencies**—just Go’s standard library plus a handful of battle‑tested packages.

---

## 🏃 Quick Start

```bash
# 1. Grab a binary from the latest release page
#    (choose noc2go‑<version>‑windows_amd64.exe, noc2go‑darwin_arm64, etc.)
curl -L -o noc2go https://github.com/michaelklose/noc2go/releases/latest/download/noc2go-linux_amd64
chmod +x noc2go

# 2. Fire it up (first run creates config, cert & key in cwd)
./noc2go --port 8443
#  => Prints a one‑time admin password & HTTPS URL

# 3. Visit https://<host>:8443 in your browser
#    (accept the self‑signed cert if your browser asks)
```

### First‑run tips

* **Admin credentials** are shown in the terminal the very first time. Change the password under **Settings → Account** afterwards.  
* Re‑run with `--config /path/to/noc2go.yaml` if you’d like to keep the config elsewhere.  
* Add `--privileged` to enable raw‑socket goodies (requires root/Administrator).

---

## 🛠 Building from Source

> Requires Go **1.24+**.

```bash
git clone https://github.com/michaelklose/noc2go.git
cd noc2go
go build -o noc2go ./...
```

The output binary is fully static on Linux (`CGO_ENABLED=0` by default) and contains embedded HTML templates, CSS & JS.

---

## 🔧 Command‑line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `noc2go.yaml` | Path to YAML config file. |
| `--port` | _auto‑select_ | HTTPS port. `0` = pick default (8443) or next free. |
| `--password` | _(random on first run)_ | Admin password seed when generating a fresh config. |
| `--privileged` | `false` | Enable raw‑socket features (needs root/Administrator). |
| `--dns-server` | _none_ | Additional upstream resolver(s). Can be specified multiple times. |

---

## 🤝 Contributing

Got an idea—or spotted a bug 🐞? PRs and issues are warmly welcomed!

1. Fork → hack → commit (use conventional commits if you can)  
2. `go test ./...` (tests coming soon)  
3. Open a pull request—CI will run `go vet`, `go test`, and linting.

Please read our brief [Code of Conduct](CODE_OF_CONDUCT.md) before diving in.

---

## 📜 License

NOC2GO is released under the **GNU GPL v3**.  
See the [LICENSE](LICENSE) file for the full text.

---

<p align="center">
  Made with ❤️ and <code>go run .</code> by <a href="https://github.com/michaelklose">Michael</a>
</p>
```