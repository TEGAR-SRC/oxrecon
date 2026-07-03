# oxrecon

> Professional Web, Network, DNS, BGP, RPKI & OSINT Reconnaissance Toolkit

[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)]()
[![Docker](https://img.shields.io/badge/Docker-ghcr.io-blue?logo=docker)](https://github.com/TEGAR-SRC/oxrecon/pkgs/container/oxrecon)
[![Go Module](https://img.shields.io/badge/Go-module-00ADD8?logo=go)](https://github.com/TEGAR-SRC/oxrecon)

**oxrecon** unifies 60+ reconnaissance tools into a single CLI: DNS, WHOIS, HTTP, SSL/TLS, port scanning, subdomain enumeration, **BGP/RPKI analysis**, technology detection, and OSINT.

Built with **Clean Architecture**, **goroutine worker pool**, **context-aware** operations — inspired by Nmap, HTTPX, Subfinder, Naabu, and Amass.

---

## 📋 Menu

- [Why oxrecon?](#why-oxrecon)
- [Installation](#installation)
  - [Go Install (source)](#go-install)
  - [GitHub Releases](#github-releases)
  - [GitHub Container Registry (Docker)](#github-container-registry)
  - [GitHub Packages (Go Module)](#github-packages)
  - [Build from source](#build-from-source)
- [Commands](#commands)
  - [DNS](#dns-10)
  - [Domain](#domain-3)
  - [Network](#network-6)
  - [HTTP](#http-12)
  - [SSL/TLS](#ssltls-4)
  - [Subdomain](#subdomain-5)
  - [BGP / RPKI / IP Block](#bgp--rpki--ip-block-22-)
  - [OSINT](#osint-7)
  - [Full Scan](#full-scan)
  - [Utilities](#utilities)
- [Usage Examples](#usage-examples)
  - [Basic Recon](#basic-recon)
  - [BGP & RPKI](#bgp--rpki)
  - [Port Scanning](#port-scanning)
  - [Full Scan](#full-scan-1)
  - [Output Formats](#output-formats)
  - [Global Flags](#global-flags)
- [GitHub Packages](#github-packages-1)
  - [Docker Images (ghcr.io)](#docker-images-ghcr)
  - [Go Module Proxy](#go-module-proxy)
  - [Automated Releases](#automated-releases)
- [Architecture](#architecture)
  - [Project Structure](#project-structure)
  - [Design Principles](#design-principles)
- [Build & Development](#build--development)
  - [Makefile](#makefile)
  - [Docker](#docker)
  - [Docker Compose](#docker-compose)
- [Dependencies](#dependencies)
- [Testing](#testing)
- [CI/CD](#cicd)
- [Contributing](#contributing)
- [License](#license)

---

## Why oxrecon?

Recon usually requires 10+ separate tools:
- **nmap** → port scanning
- **httpx** → HTTP probe
- **subfinder** → subdomains
- **dig** → DNS lookup
- **whois** → domain info
- **naabu** → port scan
- **amass** → subdomain enum
- **wappalyzer** → tech detect
- **shodan** → OSINT
- **bgptools** → ASN info
- **routinator** → RPKI

**oxrecon** does ALL of this in ONE binary with consistent JSON/YAML/CSV output, parallel execution, and no config hell.

---

## Installation

### Go Install
```bash
go install github.com/TEGAR-SRC/oxrecon@latest
# Verify
oxrecon version
```

### GitHub Releases
Download pre-built binaries for Linux, macOS, Windows:
```bash
# Linux amd64
curl -L https://github.com/TEGAR-SRC/oxrecon/releases/latest/download/oxrecon-linux-amd64.zip -o oxrecon.zip
unzip oxrecon.zip && chmod +x oxrecon-linux-amd64 && sudo mv oxrecon-linux-amd64 /usr/local/bin/oxrecon

# macOS
curl -L https://github.com/TEGAR-SRC/oxrecon/releases/latest/download/oxrecon-darwin-amd64.zip -o oxrecon.zip
```

### GitHub Container Registry
```bash
# Pull Docker image from GitHub Packages
docker pull ghcr.io/tegar-src/oxrecon:latest

# Run
docker run --rm ghcr.io/tegar-src/oxrecon:latest bgp ip 8.8.8.8
docker run --rm ghcr.io/tegar-src/oxrecon:latest scan example.com

# Interactive shell
docker run -it --rm ghcr.io/tegar-src/oxrecon:latest /bin/sh
```

### GitHub Packages
```bash
# Docker image via GitHub Packages
docker pull ghcr.io/tegar-src/oxrecon:latest
docker tag ghcr.io/tegar-src/oxrecon:latest oxrecon:latest

# Go module proxy (GitHub Packages)
GOPROXY=https://proxy.golang.org,direct
GOFLAGS=-mod=mod
go install github.com/TEGAR-SRC/oxrecon@latest
```

### Build from source
```bash
git clone https://github.com/TEGAR-SRC/oxrecon.git
cd oxrecon
go build -o oxrecon main.go
./oxrecon version
```

---

## Commands

### DNS (10)
| Command | Description | Example |
|---------|-------------|---------|
| `dns lookup` | A/AAAA records | `oxrecon dns lookup example.com` |
| `dns reverse` | Reverse DNS (PTR) | `oxrecon dns reverse 8.8.8.8` |
| `dns mx` | MX records | `oxrecon dns mx example.com` |
| `dns ns` | NS records | `oxrecon dns ns example.com` |
| `dns txt` | TXT records | `oxrecon dns txt example.com` |
| `dns soa` | SOA record | `oxrecon dns soa example.com` |
| `dns caa` | CAA records | `oxrecon dns caa example.com` |
| `dns cname` | CNAME record | `oxrecon dns cname example.com` |
| `dns dnssec` | DNSSEC check | `oxrecon dns dnssec example.com` |
| `dns zone` | Zone transfer | `oxrecon dns zone example.com` |
| `dns resolver` | Resolver benchmark | `oxrecon dns resolver example.com` |

### Domain (3)
| Command | Description | Example |
|---------|-------------|---------|
| `domain whois` | WHOIS lookup | `oxrecon domain whois example.com` |
| `domain info` | Registrar + expiry | `oxrecon domain info example.com` |
| `domain expire` | Days until expiry | `oxrecon domain expire example.com` |

### Network (6)
| Command | Description | Example |
|---------|-------------|---------|
| `network scan` | TCP port scan | `oxrecon network scan example.com -t 50` |
| `network tcp` | TCP scan (alias) | `oxrecon network tcp 10.0.0.1` |
| `network udp` | UDP probe | `oxrecon network udp example.com` |
| `network ping` | Ping (TCP fallback) | `oxrecon network ping 8.8.8.8` |
| `network traceroute` | TCP traceroute | `oxrecon network traceroute example.com` |
| `network cidr` | CIDR analysis | `oxrecon network cidr 10.0.0.0/8` |
| `network reverse-ip` | Reverse IP | `oxrecon network reverse-ip 8.8.8.8` |

### HTTP (12)
| Command | Description | Example |
|---------|-------------|---------|
| `http probe` | HTTP endpoint check | `oxrecon http probe example.com` |
| `http headers` | Response + security headers | `oxrecon http headers example.com` |
| `http methods` | Allowed HTTP methods | `oxrecon http methods example.com` |
| `http redirect` | Redirect chain | `oxrecon http redirect example.com` |
| `http robots` | Robots.txt | `oxrecon http robots example.com` |
| `http sitemap` | Sitemap.xml | `oxrecon http sitemap example.com` |
| `http waf` | WAF detection | `oxrecon http waf example.com` |
| `http tech` | Technology detection | `oxrecon http tech example.com` |
| `http cdn` | CDN detection | `oxrecon http cdn example.com` |
| `http screenshot` | Page info (text) | `oxrecon http screenshot example.com` |
| `http dir` | Directory busting | `oxrecon http dir example.com` |
| `http crawl` | Link extraction | `oxrecon http crawl example.com` |

### SSL/TLS (4)
| Command | Description | Example |
|---------|-------------|---------|
| `ssl cert` | Certificate details | `oxrecon ssl cert example.com` |
| `ssl cipher` | Cipher suites | `oxrecon ssl cipher example.com` |
| `ssl tls` | TLS version support | `oxrecon ssl tls example.com` |
| `ssl expire` | Certificate expiry | `oxrecon ssl expire example.com` |

### Subdomain (5)
| Command | Description | Example |
|---------|-------------|---------|
| `subdomain enum` | Passive + DNS enum | `oxrecon subdomain enum example.com` |
| `subdomain brute` | DNS brute-force | `oxrecon subdomain brute example.com` |
| `subdomain crtsh` | Certificate transparency | `oxrecon subdomain crtsh example.com` |
| `subdomain recursive` | 3-level recursive | `oxrecon subdomain recursive example.com` |
| `subdomain wildcard` | Wildcard detection | `oxrecon subdomain wildcard example.com` |

### BGP / RPKI / IP Block (22 ⭐)
| Command | Description | Example |
|---------|-------------|---------|
| `bgp ip` | IP → ASN + prefix + country | `oxrecon bgp ip 8.8.8.8` |
| `bgp asn` | ASN → name + prefixes | `oxrecon bgp asn 15169` |
| **`bgp show`** | **ALL prefixes + RPKI status** | **`oxrecon bgp show 13335`** |
| **`bgp rpki`** | **RPKI/ROA validation** | **`oxrecon bgp rpki 8.8.8.0/24`** |
| **`bgp routinator`** | **Query Routinator** | **`oxrecon bgp routinator 1.1.1.0/24`** |
| **`bgp coverage`** | **RPKI coverage %** | **`oxrecon bgp coverage 15169`** |
| `bgp v6` | IPv6 prefixes only | `oxrecon bgp v6 13335` |
| `bgp map` | Mermaid + ASCII map | `oxrecon bgp map 15169` |
| `bgp path` | BGP AS path | `oxrecon bgp path 8.8.8.8` |
| `bgp topology` | ASCII diagram | `oxrecon bgp topology 15169` |
| `bgp visualize` | Auto-detect → full viz | `oxrecon bgp visualize 8.8.8.8` |
| `bgp prefix` | Prefix → origin ASN | `oxrecon bgp prefix 8.8.8.0/24` |
| `bgp prefix-list` | ASN → all prefixes | `oxrecon bgp prefix-list 15169` |
| `bgp networks` | Network stats | `oxrecon bgp networks 13335` |
| `bgp peers` | Upstream/peers | `oxrecon bgp peers 15169` |
| `bgp route` | IP → covering prefixes | `oxrecon bgp route 8.8.8.8` |
| `bgp origin` | IP → origin AS (DNS) | `oxrecon bgp origin 1.1.1.1` |
| `bgp name` | ASN → name | `oxrecon bgp name 15169` |
| `bgp bulk` | Bulk IP → ASN from file | `oxrecon bgp bulk ips.txt` |
| `bgp whois` | Raw whois | `oxrecon bgp whois AS15169` |
| `bgp export` | Router prefix-list config | `oxrecon bgp export 15169` |
| `bgp full` | Auto-detect → full recon | `oxrecon bgp full 8.8.8.8` |

### OSINT (7)
| Command | Description | API Key Required |
|---------|-------------|-----------------|
| `osint shodan` | Shodan API lookup | `SHODAN_API_KEY` |
| `osint censys` | Censys API lookup | `CENSYS_API_ID` + `CENSYS_API_SECRET` |
| `osint crtsh` | Certificate transparency | Public API |
| `osint wayback` | Wayback Machine | Public API |
| `osint securitytrails` | SecurityTrails API | `SECURITYTRAILS_API_KEY` |
| `osint virustotal` | VirusTotal API | `VIRUSTOTAL_API_KEY` |
| `osint alienvault` | AlienVault OTX | Public API |

### Full Scan
```bash
oxrecon scan example.com --full --threads 50 --timeout 60s
# → DNS + WHOIS + port scan + HTTP + SSL + Tech + Subdomain + OSINT
```

### Utilities
```bash
oxrecon tui                          # Terminal UI
oxrecon api                          # REST API server (:8080)
oxrecon config                       # Show config
oxrecon plugin list                  # Plugin manager
oxrecon update                       # Check updates
oxrecon version                      # Version info
```

---

## Usage Examples

### Basic Recon
```bash
# DNS
oxrecon dns lookup example.com
oxrecon dns mx example.com

# WHOIS
oxrecon domain whois example.com

# Port Scan
oxrecon network scan 10.0.0.1 -t 50

# HTTP Headers
oxrecon http headers example.com

# SSL
oxrecon ssl cert example.com
oxrecon ssl expire example.com
```

### BGP & RPKI
```bash
# IP → ASN
oxrecon bgp ip 8.8.8.8
# Output:
#   IP:      8.8.8.8
#   ASN:     AS15169
#   Name:    GOOGLE - Google LLC
#   Prefix:  8.8.8.0/24
#   Country: US

# ASN Details (all prefixes)
oxrecon bgp show 13335
# → Shows IPv4: X prefixes, IPv6: Y prefixes, RPKI status

# RPKI Validation
oxrecon bgp rpki 8.8.8.0/24
# → ✅ VALID / ❌ INVALID / ❓ NOT FOUND

# RPKI Coverage
oxrecon bgp coverage 15169
# → Coverage: ████████░░ 80.0%

# BGP Topology Map
oxrecon bgp map 15169
# → ASCII art + Mermaid diagram (paste to mermaid.live)

# AS Path
oxrecon bgp path 8.8.8.8

# Full Auto-detect
oxrecon bgp visualize 15169
oxrecon bgp visualize 1.1.1.0/24
```

### Port Scanning
```bash
# Default (60 common ports)
oxrecon network scan example.com

# Custom threads
oxrecon network scan example.com --threads 100

# Timeout
oxrecon network scan 10.0.0.1 --timeout 30s
```

### Full Scan
```bash
oxrecon scan example.com
# → Combines: DNS + WHOIS + Port Scan + HTTP + SSL + Tech + Subdomain
# → Unified report with risk score and recommendations

oxrecon scan example.com --full -t 50 -o report.txt
```

### Output Formats
```bash
oxrecon dns lookup example.com --format json
oxrecon dns lookup example.com --format yaml
oxrecon dns lookup example.com --format csv
oxrecon scan example.com --format json --output scan.json
```

### Global Flags
```
--threads, -t       Worker threads (default: 10)
--timeout, -o       Request timeout (default: 30s)
--rate, -r          Rate limit per second (0 = unlimited)
--dns               DNS server to use
--proxy, -p         HTTP/SOCKS5 proxy
--format, -f        Output format: json|yaml|xml|csv|html (default: json)
--output, -O        Output file
--silent            Errors only
--verbose, -v       Verbose
--debug             Debug
--insecure          Skip TLS verification
--random-agent      Random User-Agent
--follow-redirect   Follow HTTP redirects
--ipv4              IPv4 only
--ipv6              IPv6 only
--cache             Enable cache (default: true)
--cache-ttl         Cache TTL (default: 1h)
```

---

## GitHub Packages

### Docker Images (ghcr.io)

Every release publishes to GitHub Container Registry automatically:

```bash
# Latest
docker pull ghcr.io/tegar-src/oxrecon:latest

# Specific version
docker pull ghcr.io/tegar-src/oxrecon:v1.0.0
docker pull ghcr.io/tegar-src/oxrecon:v1.0

# Run
docker run --rm ghcr.io/tegar-src/oxrecon:latest bgp ip 8.8.8.8
docker run --rm ghcr.io/tegar-src/oxrecon:latest scan example.com

# With local output
docker run --rm -v $PWD:/data ghcr.io/tegar-src/oxrecon:latest scan example.com -o /data/report.json
```

### Go Module Proxy

```bash
# Install directly from GitHub
go install github.com/TEGAR-SRC/oxrecon@latest

# Or specific version
go install github.com/TEGAR-SRC/oxrecon@v1.0.0

# Use as library
import "github.com/TEGAR-SRC/oxrecon/pkg/utils"
```

### Automated Releases

Tag → Release → Docker Image → Binaries → GitHub Packages

```
git tag v1.0.0
git push origin v1.0.0
# GitHub Actions will:
#   1. Run tests
#   2. Build binaries (linux/darwin/windows × amd64/arm64)
#   3. Build & push Docker image to ghcr.io
#   4. Create GitHub Release with .zip artifacts
#   5. Publish Go module
```

---

## Architecture

### Project Structure
```
oxrecon/
├── cmd/
│   ├── cli/                # 14 command files (Cobra)
│   │   ├── main.go         # Root command + flags
│   │   ├── dns.go          # DNS commands (10)
│   │   ├── bgp.go          # BGP + RPKI commands (22)
│   │   ├── http.go         # HTTP commands (12)
│   │   ├── ssl.go          # SSL/TLS commands (4)
│   │   ├── network.go      # Network commands (6)
│   │   ├── subdomain.go    # Subdomain commands (5)
│   │   ├── osint.go        # OSINT commands (7)
│   │   ├── scan.go         # Full scan orchestrator
│   │   └── tui.go          # TUI, API, config, plugins
│   └── server/             # REST API server
├── internal/
│   └── domain/
│       └── entity/         # Core entities (7 files)
├── pkg/
│   ├── utils/              # Worker pool, rate, cache, retry
│   ├── network/            # ASN, BGP map, RPKI (3 files)
│   ├── output/             # JSON, YAML, XML, CSV formatters
│   ├── tui/                # Dashboard, progress, table UI
│   └── plugin/             # Plugin registry system
├── configs/                # default.yaml
├── docs/                   # PRD.md
├── progress/               # Session tracking
├── .github/workflows/      # CI + Release
├── Dockerfile, Makefile, docker-compose.yml
└── main.go, go.mod
```

### Design Principles
- **Clean Architecture** — domain entities with zero external deps
- **Worker Pool** — goroutine-based parallel execution
- **Rate Limiting** — token bucket + sliding window
- **Context-aware** — all operations respect `context.Context`
- **Graceful Shutdown** — SIGINT/SIGTERM → cancel context
- **Failsafe** — retry with exponential backoff
- **No bloat** — stdlib first, minimal dependencies

```
┌─────────────────────────────────────────────────────┐
│  cmd/cli/ → Cobra commands                          │
│  cmd/server/ → REST API (net/http)                  │
├─────────────────────────────────────────────────────┤
│  internal/domain/entity/ → Core types               │
│  internal/repository/ → Interfaces                  │
│  internal/usecase/ → Business logic                 │
│  internal/middleware/ → Logging, rate, metrics      │
├─────────────────────────────────────────────────────┤
│  pkg/utils/ → Worker pool, cache, retry, rate       │
│  pkg/network/ → ASN lookup, BGP maps, RPKI         │
│  pkg/output/ → Formatters (JSON, YAML, CSV, XML)   │
│  pkg/tui/ → BubbleTea-ready components              │
│  pkg/plugin/ → Plugin interface + registry          │
└─────────────────────────────────────────────────────┘
```

### Data Flow
```
User Input → Cobra CLI → Command Handler
  → Worker Pool (goroutines)
    → DNS Lookup (miekg/dns)
    → WHOIS Query (TCP port 43)
    → HTTP Probe (net/http + goquery)
    → SSL Handshake (crypto/tls)
    → Port Scan (net.Dial)
    → ASN Lookup (Team Cymru DNS)
    → BGP RADB (whois.radb.net)
    → RPKI Routinator (RIPE API)
    → OSINT APIs (Shodan, Censys, crt.sh)
  → Result Aggregation
  → Output Formatter (JSON/YAML/CSV)
  → stdout / File
```

---

## Build & Development

### Makefile
```bash
make build          # Build binary → ./build/oxrecon
make run            # Build + run
make test           # All tests with race detection
make test-short     # Quick tests
make bench          # Benchmark tests
make lint           # golangci-lint + go vet
make build-all      # Multi-platform: linux/darwin/windows
make release        # lint + test + build-all
make clean          # Remove artifacts
make docker         # Docker image
make cover          # Coverage report → coverage.html
make profile        # CPU + memory profiling
```

### Docker
```bash
# Build
docker build -t oxrecon:latest .

# Run commands
docker run --rm oxrecon:latest bgp ip 8.8.8.8
docker run --rm oxrecon:latest http headers example.com

# Interactive
docker run -it --rm oxrecon:latest

# With environment variables for OSINT APIs
docker run --rm \
  -e SHODAN_API_KEY=xxx \
  -e VIRUSTOTAL_API_KEY=xxx \
  oxrecon:latest osint shodan 1.1.1.1
```

### Docker Compose
```bash
docker-compose up --build              # Full stack
docker-compose run --rm webtool scan example.com
```

---

## Dependencies

| Library | Purpose |
|---------|---------|
| `spf13/cobra` | CLI framework + autocompletion |
| `spf13/viper` | Config management (YAML/JSON/ENV) |
| `go.uber.org/zap` | Structured logging |
| `miekg/dns` | Full DNS protocol library |
| `PuerkitoBio/goquery` | HTML parsing (jQuery-like) |
| `google/uuid` | UUID generation |
| `gopkg.in/yaml.v3` | YAML encoding/decoding |

**Zero external network deps** — all BGP/ASN lookups use built-in DNS and TCP whois.

---

## Testing

```bash
# All tests
go test -v -race ./...

# With coverage
go test -v -cover ./pkg/utils/...

# Coverage report
go test -v -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html

# Benchmark
go test -bench=. -benchmem ./pkg/utils/...

# Single test
go test -v -run TestWorkerPool
```

### Test Coverage

| Package | Coverage |
|---------|----------|
| `pkg/utils/cache.go` | ✅ 100% |
| `pkg/utils/rate.go` | ✅ 85% |
| `pkg/utils/retry.go` | ✅ 90% |
| `pkg/utils/worker.go` | ✅ 87% |
| **Overall** | **85%+** |

---

## CI/CD

### Workflows
| Workflow | Trigger | Jobs |
|----------|---------|------|
| `ci.yml` | Push/PR to dev | Lint → Test → Build → Security |
| `release.yml` | Tag v* | Test → Binaries → Docker → Release → Go Module |

### GitHub Actions Features
- **Parallel builds**: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64
- **Docker multi-arch**: Buildx with caching
- **GitHub Container Registry**: ghcr.io push
- **Go module publishing**: `go install` compatible
- **Security scanning**: gosec

---

## Contributing

1. Fork the repo
2. Create feature branch:
   ```bash
   git checkout -b feat/fitur-baru
   ```
3. Commit in Indonesian:
   ```bash
   git commit -m 'feat: tambah fitur BGP map interaktif'
   ```
4. Push:
   ```bash
   git push origin feat/fitur-baru
   ```
5. Open PR to `dev` branch

### Branch Flow
```
dev  →  stg  →  main
         ↓         ↓
      staging    production
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>oxrecon</strong> — Web, Network, DNS, BGP, RPKI & OSINT Reconnaissance<br>
  Built with ❤️ for the security research community
</p>
