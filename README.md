# oxrecon

> Professional Web, Network, DNS, BGP, RPKI & OSINT Reconnaissance Toolkit

[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)]()

**oxrecon** is a comprehensive CLI tool that combines DNS, WHOIS, HTTP, SSL/TLS, port scanning, subdomain enumeration, BGP/RPKI analysis, technology detection, and OSINT into a single binary.

Built with **Clean Architecture**, **worker pool concurrency**, and **context-aware operations**.

---

## Why oxrecon?

Recon usually means 10+ separate tools (nmap, httpx, subfinder, dig, whois, naabu, amass...). **oxrecon** unifies them into one CLI with consistent output and parallel execution.

---

## Features

### DNS (10 subcommands)
| Command | Description |
|---------|-------------|
| `dns lookup` | A/AAAA record lookup |
| `dns reverse` | Reverse DNS (PTR) |
| `dns mx` | MX records |
| `dns ns` | NS records |
| `dns txt` | TXT records |
| `dns soa` | SOA record |
| `dns caa` | CAA records |
| `dns cname` | CNAME record |
| `dns dnssec` | DNSSEC validation |
| `dns zone` | Zone transfer attempt |
| `dns resolver` | Test multiple resolvers |

### Domain
| Command | Description |
|---------|-------------|
| `domain whois` | WHOIS lookup |
| `domain info` | Registrar + expiry |
| `domain expire` | Days until expiry |

### Network (6 subcommands)
| Command | Description |
|---------|-------------|
| `network scan` | TCP port scan (worker pool) |
| `network tcp` | TCP scan (alias) |
| `network udp` | UDP probe |
| `network ping` | TCP ping fallback |
| `network traceroute` | TCP traceroute |
| `network cidr` | CIDR analysis |
| `network reverse-ip` | Reverse IP lookup |

### HTTP (12 subcommands)
| Command | Description |
|---------|-------------|
| `http probe` | HTTP/HTTPS endpoint check |
| `http headers` | Response headers + security headers |
| `http methods` | Allowed HTTP methods |
| `http redirect` | Redirect chain |
| `http robots` | Robots.txt |
| `http sitemap` | Sitemap.xml |
| `http waf` | WAF detection |
| `http tech` | Technology detection (CMS, framework, JS, CDN) |
| `http cdn` | CDN detection |
| `http screenshot` | Text-based page info |
| `http dir` | Directory busting |
| `http crawl` | Link extraction |

### SSL/TLS
| Command | Description |
|---------|-------------|
| `ssl cert` | Certificate details |
| `ssl cipher` | Cipher suites |
| `ssl tls` | TLS version support |
| `ssl expire` | Certificate expiry |

### Subdomain
| Command | Description |
|---------|-------------|
| `subdomain enum` | Passive + DNS enumeration |
| `subdomain brute` | DNS brute-force |
| `subdomain crtsh` | Certificate transparency |
| `subdomain recursive` | 3-level recursive |
| `subdomain wildcard` | Wildcard detection |

### BGP / RPKI / IP Block (22 subcommands) ⭐
| Command | Description |
|---------|-------------|
| `bgp ip` | IP → ASN + prefix + country |
| `bgp asn` | ASN → name + details + prefixes |
| **`bgp show`** | **ALL IPv4+IPv6 prefixes with RPKI status** |
| **`bgp rpki`** | **RPKI/ROA validity check** |
| **`bgp routinator`** | **Query Routinator RPKI validator** |
| `bgp v6` | IPv6 prefixes only |
| **`bgp coverage`** | **RPKI coverage analysis (valid/invalid/unknown %)** |
| `bgp map` | Mermaid + ASCII topology diagram |
| `bgp path` | BGP AS path trace |
| `bgp topology` | ASCII topology diagram |
| `bgp visualize` | Auto-detect → full visualization |
| `bgp prefix` | Prefix → origin ASN |
| `bgp prefix-list` | ASN → all prefixes |
| `bgp networks` | Network stats |
| `bgp peers` | Upstream/peer relationships |
| `bgp route` | IP → covering prefixes |
| `bgp origin` | IP → origin ASN (DNS) |
| `bgp name` | ASN → name |
| `bgp bulk` | Bulk IP → ASN from file |
| `bgp whois` | Raw whois |
| `bgp export` | Router prefix-list config |
| `bgp full` | Auto-detect → full recon |

### OSINT
| Command | Description |
|---------|-------------|
| `osint shodan` | Shodan API lookup |
| `osint censys` | Censys API lookup |
| `osint crtsh` | Certificate transparency |
| `osint wayback` | Wayback Machine |
| `osint securitytrails` | SecurityTrails API |
| `osint virustotal` | VirusTotal |
| `osint alienvault` | AlienVault OTX |

### Full Scan
| Command | Description |
|---------|-------------|
| `scan <target>` | All modules in parallel → unified report |

### Utilities
| Command | Description |
|---------|-------------|
| `tui` | Terminal UI (BubbleTea) |
| `api` | REST API server |
| `config` | Config management |
| `plugin` | Plugin system |
| `update` | Check for updates |
| `version` | Version info |

---

## Install

```bash
# Build from source
git clone https://github.com/user/oxrecon.git
cd oxrecon
go build -o oxrecon main.go

# Or install
go install .

# Verify
oxrecon version
```

### Binary downloads
Download pre-built binaries from [Releases](https://github.com/user/oxrecon/releases).

---

## Usage Examples

### Basic recon
```bash
oxrecon dns lookup example.com
oxrecon domain whois example.com
oxrecon ssl cert example.com
oxrecon http headers example.com
```

### BGP / IP Block / RPKI
```bash
# IP → ASN lookup
oxrecon bgp ip 8.8.8.8
# Output:
#   ASN:    AS15169
#   Name:   GOOGLE - Google LLC
#   Prefix: 8.8.8.0/24
#   Country:US

# Show ALL prefixes + RPKI status
oxrecon bgp show 13335

# RPKI validation
oxrecon bgp rpki 8.8.8.0/24

# RPKI coverage analysis
oxrecon bgp coverage 15169

# BGP topology map (Mermaid + ASCII)
oxrecon bgp map 15169

# Full visualization (auto-detects IP/ASN/prefix)
oxrecon bgp visualize 8.8.8.8
```

### Full scan
```bash
oxrecon scan example.com --threads 20 --timeout 60s
```

### Output formats
```bash
oxrecon dns lookup example.com --format json
oxrecon dns lookup example.com --format yaml
oxrecon dns lookup example.com --format csv
oxrecon scan example.com --output report.json
```

### Global flags
```
--threads, -t    Worker threads (default: 10)
--timeout, -o    Request timeout (default: 30s)
--rate, -r       Rate limit per second
--format, -f     Output format: json, yaml, csv, xml
--output, -O     Output file
--silent         Silent mode (errors only)
--verbose, -v    Verbose output
--debug          Debug output
--insecure       Skip TLS verification
--random-agent   Random User-Agent
```

---

## Architecture

```
oxrecon/
├── cmd/
│   ├── cli/                # CLI commands (Cobra)
│   │   ├── main.go         # Root command
│   │   ├── dns.go          # DNS commands
│   │   ├── bgp.go          # BGP + RPKI commands
│   │   ├── http.go         # HTTP commands
│   │   ├── ssl.go          # SSL/TLS commands
│   │   ├── network.go      # Network commands
│   │   ├── subdomain.go    # Subdomain commands
│   │   ├── osint.go        # OSINT commands
│   │   ├── scan.go         # Full scan orchestrator
│   │   └── tui.go          # TUI, API, config, plugins
│   └── server/
│       └── main.go         # REST API server
├── internal/
│   └── domain/
│       └── entity/         # Core entities
│           ├── host.go     # Host, Port, GeoIP, ASN
│           ├── dns.go      # DNS records
│           ├── http.go     # HTTP, SSL, Tech
│           ├── bgp.go      # BGP entities
│           ├── rpki.go     # RPKI entities
│           └── scan.go     # Scan results
├── pkg/
│   ├── utils/              # Infrastructure
│   │   ├── worker.go       # Goroutine worker pool
│   │   ├── rate.go         # Token bucket rate limiter
│   │   ├── cache.go        # TTL cache
│   │   └── retry.go        # Exponential backoff
│   ├── network/
│   │   ├── asn.go          # ASN/BGP lookup engine
│   │   ├── bgpmap.go       # Mermaid + ASCII topology
│   │   └── rpki.go         # RPKI validation (Routinator)
│   ├── output/             # Output formatters
│   ├── tui/                # TUI components
│   └── plugin/             # Plugin system
├── configs/
├── docs/
├── tests/
├── Dockerfile
├── docker-compose.yml
├── Makefile
├── .github/workflows/ci.yml
├── go.mod
└── main.go
```

### Design Principles
- **Clean Architecture** — domain entities, no framework coupling
- **Worker Pool** — concurrent port scan, DNS, HTTP with goroutines
- **Rate Limiting** — token bucket + sliding window
- **Context-aware** — all ops respect `context.Context` + signal cancellation
- **Graceful Shutdown** — Ctrl+C triggers context cancellation
- **No bloat** — stdlib + only essential deps

---

## Build

```bash
make build          # Build binary
make test           # Run tests
make lint           # Run linters
make docker         # Build Docker image
make release        # Multi-platform build
```

### Docker
```bash
docker run --rm oxrecon:latest bgp ip 8.8.8.8
docker run --rm oxrecon:latest scan example.com
```

---

## Dependencies

| Library | Purpose |
|---------|---------|
| `spf13/cobra` | CLI framework |
| `spf13/viper` | Config management |
| `go.uber.org/zap` | Structured logging |
| `miekg/dns` | DNS protocol |
| `PuerkitoBio/goquery` | HTML parsing |
| `google/uuid` | UUID generation |
| `gopkg.in/yaml.v3` | YAML support |

---

## Testing

```bash
go test -v ./...                          # All tests
go test -v -cover ./pkg/utils/...         # With coverage
go test -bench=. ./pkg/utils/...          # Benchmark tests
go test -v -run TestWorkerPool            # Single test
```

### Test structure
```
pkg/utils/*_test.go    — Unit tests for core packages (85%+ coverage)
```

---

## Contributing

1. Fork the repo
2. Create feature branch (`git checkout -b feat/xxx`)
3. Commit (`git commit -m 'feat: tambah xxx'`)
4. Push (`git push origin feat/xxx`)
5. Open PR

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Author

Created with ❤️ for the security research community.
