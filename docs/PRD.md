# PRD — WebTool: Professional Reconnaissance & Security Toolkit

## 1. Overview

**WebTool** adalah CLI profesional untuk Web, Network, DNS, OSINT, dan Infrastructure reconnaissance — terinspirasi dari Nmap, HTTPX, Subfinder, Dig, Whois, Wappalyzer, Naabu, dan Amass.

**Masalah utama:** Security researcher dan pentester perlu menggunakan banyak tools terpisah untuk reconnaissance, membuat workflow tidak efisien dan sulit di-automate.

**Solusi:** Satu tool terintegrasi dengan arsitektur modular, worker pool, dan output terstandar.

**Tujuan:** Production-ready toolkit yang bisa digunakan untuk:
- Bug bounty hunting
- Penetration testing
- Security auditing
- OSINT investigation

---

## 2. Requirements

### 2.1 Core Requirements

- [x] **Bahasa:** Go latest (stable), Go Modules
- [x] **Arsitektur:** Clean Architecture (hexagonal/ports-and-adapters)
- [x] **Modular:** Setiap modul independently testable
- [x] **Dependency Injection:** Manual DI, no framework magic
- [x] **Context-aware:** Semua operations respect context.Context
- [x] **Concurrency:** Goroutine + Worker Pool pattern
- [x] **Graceful Shutdown:** Signal handling (SIGINT/SIGTERM)
- [x] **Retry Mechanism:** Exponential backoff untuk network operations
- [x] **Rate Limiter:** Token bucket atau sliding window
- [x] **Progress Bar:** Untuk long-running operations
- [x] **Logging:** Structured logging (Zap)
- [x] **Config Loader:** YAML/JSON via Viper
- [x] **Middleware:** Reusable untuk HTTP, network ops
- [x] **Plugin System:** Hot-reload plugins tanpa recompile main binary
- [x] **Cache:** In-memory cache dengan TTL
- [x] **Unit Test:** Per package dengan mockery
- [x] **Benchmark Test:** 성능 critical paths
- [x] **Integration Test:** Full workflow tests
- [x] **CI/CD:** GitHub Actions
- [x] **Docker:** Multi-stage build
- [x] **Docker Compose:** Local development
- [x] **Makefile:** Common tasks automation
- [x] **Dokumentasi:** Komprehensif

---

## 3. Tech Stack Decisions

| Layer | Options | Selected |
|-------|---------|----------|
| CLI Framework | Cobra, kingpin, cli | **Cobra** — de facto standard, bash completion, generate |
| Config | Viper, envconfig | **Viper** — YAML/JSON/ENV, hot reload |
| Logging | Zap, Logrus, zerolog, slog | **Zap** — structured, production-grade performance |
| TUI | BubbleTea, tview, gocui | **BubbleTea** (Charm) — functional, testable |
| DNS | miekg/dns, dnsproxy | **miekg/dns** — flexible, low-level |
| HTTP Client | stdlib net/http, fasthttp, retryablehttp | **net/http + retryablehttp** — stdlib compat |
| Web Scraping | goquery, colly | **goquery** — jQuery-like, lightweight |
| Browser Automation | chromedp, playwright | **chromedp** — headless Chrome |
| WHOIS | relyt/whois, WHOIS parsing libraries | **go-whois** + custom parsing |
| SSL/TLS | crypto/tls, projectdiscovery libraries | **crypto/tls + x/crypto** |
| ASN/OSINT | TeamCymru, Shodan, Censys APIs | **HTTP clients + API wrappers** |
| Rate Limiting | tollbooth, ratelimit | **Custom token bucket** |
| Database | SQLite, BoltDB, PostgreSQL | **SQLite** — embedded, no setup |
| Output | JSON, YAML, XML, CSV, HTML, PDF | Multiple formatters |
| UUID | google/uuid | **google/uuid** |

---

## 4. Clean Architecture Structure

```
webtool/
├── cmd/                          # CLI entry points
│   ├── cli/                      # Main CLI app
│   │   ├── main.go               # Root command
│   │   ├── dns.go                # DNS commands
│   │   ├── domain.go             # WHOIS commands
│   │   ├── subnet.go             # Network commands
│   │   ├── http.go               # HTTP commands
│   │   ├── ssl.go                # SSL/TLS commands
│   │   ├── osint.go              # OSINT commands
│   │   ├── scan.go               # Full scan command
│   │   ├── tui.go                # TUI mode
│   │   └── api.go                # REST API mode
│   └── server/                   # REST API server
│       └── main.go
├── internal/                     # Private application code
│   ├── domain/                   # Enterprise business rules
│   │   ├── entity/               # Core entities
│   │   │   ├── dns.go
│   │   │   ├── domain.go
│   │   │   ├── host.go
│   │   │   ├── http.go
│   │   │   ├── ssl.go
│   │   │   ├── network.go
│   │   │   └── osint.go
│   │   ├── repository/           # Repository interfaces
│   │   │   ├── dns_repository.go
│   │   │   ├── domain_repository.go
│   │   │   ├── host_repository.go
│   │   │   └── osint_repository.go
│   │   └── service/              # Service interfaces
│   │       ├── dns_service.go
│   │       ├── domain_service.go
│   │       ├── http_service.go
│   │       ├── ssl_service.go
│   │       ├── network_service.go
│   │       └── osint_service.go
│   ├── usecase/                  # Application business rules
│   │   ├── dns/
│   │   │   ├── lookup.go
│   │   │   ├── reverse.go
│   │   │   └── zone.go
│   │   ├── domain/
│   │   │   ├── whois.go
│   │   │   └── registrar.go
│   │   ├── subnet/
│   │   │   ├── port_scan.go
│   │   │   ├── ping_sweep.go
│   │   │   └── cidr.go
│   │   ├── http/
│   │   │   ├── probe.go
│   │   │   ├── headers.go
│   │   │   ├── screenshot.go
│   │   │   └── tech_detect.go
│   │   ├── ssl/
│   │   │   ├── certificate.go
│   │   │   └── cipher.go
│   │   ├── osint/
│   │   │   ├── shodan.go
│   │   │   ├── crtsh.go
│   │   │   └── wayback.go
│   │   └── scan/
│   │       └── full_scan.go
│   ├── handler/                  # Interface adapters (HTTP/gRPC)
│   │   ├── dns_handler.go
│   │   ├── domain_handler.go
│   │   ├── http_handler.go
│   │   ├── ssl_handler.go
│   │   ├── network_handler.go
│   │   ├── osint_handler.go
│   │   ├── scan_handler.go
│   │   └── api_handler.go        # REST API handlers
│   ├── repository/               # Infrastructure implementations
│   │   ├── dns_repo.go
│   │   ├── whois_repo.go
│   │   ├── http_repo.go
│   │   ├── ssl_repo.go
│   │   ├── network_repo.go
│   │   ├── osint_repo.go
│   │   └── cache_repo.go
│   ├── middleware/              # Cross-cutting concerns
│   │   ├── logging.go
│   │   ├── ratelimit.go
│   │   ├── retry.go
│   │   ├── timeout.go
│   │   └── metrics.go
│   └── infrastructure/          # External services
│       ├── dns/
│       ├── http/
│       ├── whois/
│       ├── shodan/
│       ├── censys/
│       └── storage/
├── pkg/                          # Public packages (reusable)
│   ├── dns/                      # DNS utilities
│   │   ├── lookup.go
│   │   ├── types.go
│   │   └── resolver.go
│   ├── http/                    # HTTP utilities
│   │   ├── client.go
│   │   ├── headers.go
│   │   └── redirect.go
│   ├── network/                 # Network utilities
│   │   ├── port.go
│   │   ├── scanner.go
│   │   └── banner.go
│   ├── ssl/                     # SSL/TLS utilities
│   │   ├── cert.go
│   │   └── cipher.go
│   ├── output/                  # Output formatters
│   │   ├── json.go
│   │   ├── yaml.go
│   │   ├── xml.go
│   │   ├── csv.go
│   │   ├── html.go
│   │   └── pdf.go
│   ├── tui/                     # TUI components
│   │   ├── dashboard.go
│   │   ├── progress.go
│   │   └── charts.go
│   └── utils/                   # General utilities
│       ├── rate.go
│       ├── retry.go
│       ├── cache.go
│       └── worker.go
├── configs/                     # Configuration files
│   ├── default.yaml             # Default config
│   ├── config.schema.json        # Config schema
│   └── wordlists/               # Wordlists for bruteforce
│       ├── subdomains.txt
│       └── directories.txt
├── plugins/                     # Plugin system
│   ├── loader.go                # Plugin loader
│   ├── registry.go             # Plugin registry
│   └── examples/               # Example plugins
│       ├── example.go
│       └── README.md
├── docs/                        # Documentation
│   ├── README.md
│   ├── INSTALLATION.md
│   ├── USAGE.md
│   ├── ARCHITECTURE.md
│   ├── CONTRIBUTING.md
│   └── CHANGELOG.md
├── examples/                    # Usage examples
│   ├── basic.go
│   ├── dns_lookup.go
│   ├── full_scan.go
│   └── custom_plugin.go
├── scripts/                     # Build and CI scripts
│   ├── build.sh
│   ├── test.sh
│   ├── docker-build.sh
│   └── release.sh
├── assets/                      # Static assets
│   ├── wordlists/
│   └── templates/
├── tests/                       # Integration tests
│   ├── dns_test.go
│   ├── http_test.go
│   ├── scan_test.go
│   └── fixtures/
├── main.go                      # Main entry point (redirects to cmd/cli)
├── go.mod
├── go.sum
├── Makefile
├── Dockerfile
├── docker-compose.yml
├── .github/
│   └── workflows/
│       ├── ci.yml
│       └── release.yml
├── README.md
├── CHANGELOG.md
└── LICENSE
```

---

## 5. Database Schema (SQLite)

```sql
-- scan_results table
CREATE TABLE scan_results (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    status TEXT DEFAULT 'pending'
);

-- hosts table
CREATE TABLE hosts (
    id TEXT PRIMARY KEY,
    ip TEXT UNIQUE NOT NULL,
    hostname TEXT,
    os TEXT,
    asn INTEGER,
    org TEXT,
    country TEXT,
    city TEXT,
    lat REAL,
    lon REAL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ports table
CREATE TABLE ports (
    id TEXT PRIMARY KEY,
    host_id TEXT REFERENCES hosts(id),
    port INTEGER NOT NULL,
    protocol TEXT DEFAULT 'tcp',
    service TEXT,
    version TEXT,
    banner TEXT,
    state TEXT DEFAULT 'open'
);

-- http_results table
CREATE TABLE http_results (
    id TEXT PRIMARY KEY,
    host_id TEXT REFERENCES hosts(id),
    url TEXT NOT NULL,
    status_code INTEGER,
    headers TEXT,
    technologies TEXT,
    server TEXT,
    content_type TEXT,
    body_hash TEXT,
    screenshot_path TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- domains table
CREATE TABLE domains (
    id TEXT PRIMARY KEY,
    domain TEXT UNIQUE NOT NULL,
    registrar TEXT,
    created_date DATETIME,
    expiry_date DATETIME,
    updated_date DATETIME,
    nameservers TEXT,
    whois_json TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- subdomains table
CREATE TABLE subdomains (
    id TEXT PRIMARY KEY,
    domain_id TEXT REFERENCES domains(id),
    subdomain TEXT NOT NULL,
    source TEXT,
    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- api_keys table (for OSINT services)
CREATE TABLE api_keys (
    id TEXT PRIMARY KEY,
    service TEXT UNIQUE NOT NULL,
    key TEXT NOT NULL,
    rate_limit INTEGER DEFAULT 1000,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

---

## 6. API Endpoints (REST API Mode)

| Method | Path | Description |
|--------|------|-------------|
| GET | /api/v1/health | Health check |
| GET | /api/v1/dns/lookup?domain=X | DNS lookup |
| GET | /api/v1/dns/reverse?ip=X | Reverse DNS |
| GET | /api/v1/whois?domain=X | WHOIS lookup |
| POST | /api/v1/scan | Start a new scan |
| GET | /api/v1/scan/:id | Get scan result |
| GET | /api/v1/scan/:id/status | Get scan progress |
| GET | /api/v1/host/:ip | Host reconnaissance |
| GET | /api/v1/port/:ip/:port | Port scan single |
| POST | /api/v1/port/batch | Batch port scan |
| GET | /api/v1/http/probe?url=X | HTTP probe |
| GET | /api/v1/ssl/cert?host=X | SSL certificate |
| GET | /api/v1/subdomain?domain=X | Subdomain enum |
| GET | /api/v1/osint/shodan?ip=X | Shodan OSINT |
| GET | /api/v1/osint/wayback?domain=X | Wayback data |
| GET | /api/v1/report/:id?format=X | Export report |

---

## 7. CLI Commands

### DNS
- `webtool dns lookup <domain>` - DNS A/AAAA records
- `webtool dns reverse <ip>` - Reverse DNS lookup
- `webtool dns mx <domain>` - MX records
- `webtool dns txt <domain>` - TXT records
- `webtool dns ns <domain>` - NS records
- `webtool dns soa <domain>` - SOA record
- `webtool dns cname <domain>` - CNAME record
- `webtool dns caa <domain>` - CAA record
- `webtool dns srv <domain>` - SRV record
- `webtool dns dnssec <domain>` - DNSSEC info
- `webtool dns zone <domain>` - Zone transfer attempt
- `webtool dns resolver <domain>` - Test resolver

### Domain
- `webtool whois <domain>` - WHOIS lookup
- `webtool domain info <domain>` - Domain details
- `webtool domain expire <domain>` - Expiry check

### Subdomain
- `webtool subdomain enum <domain>` - Passive enum
- `webtool subdomain brute <domain>` - Bruteforce
- `webtool subdomain crtsh <domain>` - Certificate transparency
- `webtool subdomain recursive <domain>` - Recursive enum
- `webtool subdomain wildcard <domain>` - Wildcard detection

### Network
- `webtool port scan <ip/cidr>` - Port scan
- `webtool port udp <ip>` - UDP scan
- `webtool network ping <ip>` - Ping
- `webtool network traceroute <ip>` - Traceroute
- `webtool network cidr <cidr>` - CIDR analysis
- `webtool network reverse-ip <ip>` - Reverse IP lookup

### HTTP
- `webtool http probe <url>` - HTTP probe
- `webtool http headers <url>` - Headers analysis
- `webtool http methods <url>` - Allowed methods
- `webtool http robots <url>` - Robots.txt
- `webtool http sitemap <url>` - Sitemap.xml
- `webtool http redirect <url>` - Redirect chain
- `webtool http waf <url>` - WAF detection
- `webtool http tech <url>` - Technology detection
- `webtool http cdn <url>` - CDN detection
- `webtool http screenshot <url>` - Screenshot
- `webtool http dir <url>` - Directory busting
- `webtool http crawl <url>` - Web crawler

### SSL/TLS
- `webtool ssl cert <host:port>` - Certificate info
- `webtool ssl cipher <host:port>` - Cipher suites
- `webtool ssl tls <host:port>` - TLS version
- `webtool ssl expire <host:port>` - Expiry check

### OSINT
- `webtool osint shodan <ip>` - Shodan lookup
- `webtool osint censys <ip>` - Censys lookup
- `webtool osint crtsh <domain>` - crt.sh lookup
- `webtool osint wayback <domain>` - Wayback Machine
- `webtool osint securitytrails <domain>` - SecurityTrails
- `webtool osint virustotal <domain>` - VirusTotal
- `webtool osint alienvault <domain>` - AlienVault OTX

### GeoIP/ASN
- `webtool geoip <ip>` - GeoIP lookup
- `webtool asn <asn>` - ASN info
- `webtool ipinfo <ip>` - IP info

### Security
- `webtool security headers <url>` - Security headers
- `webtool security cors <url>` - CORS policy
- `webtool security takeovers <domain>` - Subdomain takeover
- `webtool security exposed <domain>` - Exposed panels

### Full Scan
- `webtool scan <target> --full` - Full reconnaissance scan

### Output
- `webtool report <scan_id> --format json|yaml|html|csv|pdf` - Export

### Utilities
- `webtool tui` - Terminal UI mode
- `webtool api` - Start REST API server
- `webtool config` - Config management
- `webtool plugin` - Plugin management
- `webtool update` - Update tool
- `webtool version` - Version info

---

## 8. Flags Global

```
--threads, -t          Worker threads (default: 10)
--timeout, -to         Request timeout (default: 30s)
--rate, -r             Rate limit per second
--proxy, -p            HTTP/SOCKS proxy
--proxy-file           Load proxies from file
--dns                 DNS server to use
--resolver            Custom resolver file
--output, -o          Output file
--format, -f          Output format (json|yaml|xml|csv|html|pdf)
--silent              Silent mode
--verbose, -v         Verbose output
--debug               Debug output
--color               Color output (default: auto)
--no-color            Disable color
--random-agent        Random User-Agent
--follow-redirect     Follow redirects
--insecure            Skip TLS verification
--ipv4                IPv4 only
--ipv6                IPv6 only
--full                Full scan mode
--resume              Resume interrupted scan
--cache               Enable cache
--cache-ttl           Cache TTL (default: 1h)
```

---

## 9. Full Scan Output Schema

```json
{
  "scan_id": "uuid",
  "target": "example.com",
  "started_at": "2024-01-01T00:00:00Z",
  "completed_at": "2024-01-01T00:05:00Z",
  "duration_seconds": 300,
  "risk_score": 85,
  "security_grade": "B",
  "summary": {
    "open_ports": [80, 443, 22, 8080],
    "dns_records": {...},
    "whois": {...},
    "ssl": {...},
    "technologies": ["WordPress", "CloudFlare"],
    "subdomains": ["www", "api", "admin"],
    "vulnerabilities": ["Missing security headers", "Outdated SSL"]
  },
  "details": {
    "dns": {...},
    "whois": {...},
    "ssl": {...},
    "ports": [...],
    "http": {...},
    "technologies": {...},
    "subdomains": [...],
    "security_headers": {...},
    "wayback": {...}
  },
  "recommendations": [
    "Enable HSTS header",
    "Update SSL certificate",
    "Remove exposed admin panel"
  ]
}
```

---

## 10. TUI Design (BubbleTea)

### Screens

1. **Dashboard** - Overview stats, recent scans
2. **Scan** - Active scan with progress, live results
3. **Log** - Real-time log viewer
4. **Results** - Scan history and exports
5. **Settings** - Configuration

### Layout Components

```
┌─────────────────────────────────────────────────────────┐
│  WebTool v1.0.0                          [Settings] [?] │
├─────────────┬───────────────────────────────────────────┤
│ Navigation │                                           │
│             │  Main Content Area                        │
│ [1] Dashboard                                           │
│ [2] Scan   │  ┌─────────────────────────────────────┐   │
│ [3] Results│  │  Dynamic content based on          │   │
│ [4] Log    │  │  selected menu                      │   │
│ [5] Help   │  │                                     │   │
│             │  │                                     │   │
│             │  │                                     │   │
│             │  └─────────────────────────────────────┘   │
│             │                                           │
│             │  Status Bar                              │
├─────────────┴───────────────────────────────────────────┤
│  Workers: 10/10 | Queue: 5 | Rate: 100/s | CPU: 45%    │
└─────────────────────────────────────────────────────────┘
```

---

## 11. Plugin System

### Interface

```go
type Plugin interface {
    Name() string
    Version() string
    Execute(ctx context.Context, target string, opts map[string]any) (Result, error)
    Validate(target string) bool
}
```

### Plugin Loading

- Load from `./plugins/` directory
- Hot-reload on file change
- Sandboxed execution

### Built-in Plugin Types

- `dns` - Custom DNS checks
- `http` - Custom HTTP checks
- `osint` - Custom OSINT sources
- `output` - Custom output formatters
- `scan` - Custom scan modules

---

## 12. Worker Pool Implementation

```go
type WorkerPool struct {
    workers    int
    jobQueue   chan Job
    resultQueue chan Result
    wg         sync.WaitGroup
    ctx        context.Context
    cancel     context.CancelFunc
}

func (wp *WorkerPool) Start() { ... }
func (wp *WorkerPool) Submit(job Job) { ... }
func (wp *WorkerPool) SubmitWithRetry(job Job, maxRetries int) { ... }
func (wp *WorkerPool) Shutdown() { ... }
func (wp *WorkerPool) ShutdownWait() { ... }
```

### Configuration

- Default workers: 10
- Max workers: 100
- Queue size: 1000
- Retry attempts: 3
- Retry backoff: exponential (1s, 2s, 4s)

---

## 13. Rate Limiter

```go
type RateLimiter struct {
    rate     int           // requests per second
    burst    int           // max burst
    tokenCh  chan struct{}
    lastTick time.Time
}
```

---

## 14. CI/CD Pipeline

### GitHub Actions Workflow

1. **Lint** - golangci-lint, go vet
2. **Test** - `go test -race -cover`
3. **Build** - Multi-platform builds (linux/amd64, linux/arm64, windows/amd64)
4. **Security** - go-audit, trivy
5. **Docker** - Build and push to registry
6. **Release** - Create GitHub release with binaries

---

## 15. Docker Setup

### Multi-stage Build

```dockerfile
FROM golang:1.23-alpine AS builder
RUN apk add --no-cache git
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o webtool ./cmd/cli

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/webtool /usr/local/bin/
COPY --from=builder /app/configs/ /etc/webtool/
ENTRYPOINT ["webtool"]
```

---

## 16. Phased Implementation Plan

### Phase 1: Core Infrastructure (Week 1)
- [x] Project structure
- [x] Go module setup
- [ ] CLI framework (Cobra)
- [ ] Config system (Viper)
- [ ] Logging (Zap)
- [ ] Worker pool
- [ ] Rate limiter
- [ ] Base entities

### Phase 2: DNS Module (Week 2)
- [ ] DNS lookup (A, AAAA, MX, TXT, NS, SOA, CNAME, CAA, SRV)
- [ ] Reverse DNS
- [ ] DNSSEC validation
- [ ] Zone transfer

### Phase 3: Domain/WHOIS Module (Week 2)
- [ ] WHOIS lookup
- [ ] Registrar info
- [ ] Expiry check

### Phase 4: Network/Port Module (Week 3)
- [ ] TCP port scan
- [ ] UDP port scan
- [ ] Banner grabbing
- [ ] Service detection
- [ ] Ping sweep
- [ ] CIDR analysis

### Phase 5: HTTP Module (Week 3-4)
- [ ] HTTP probe
- [ ] Header analysis
- [ ] Technology detection (Wappalyzer)
- [ ] Screenshot (chromedp)
- [ ] WAF detection
- [ ] Directory busting

### Phase 6: SSL/TLS Module (Week 4)
- [ ] Certificate info
- [ ] Cipher suites
- [ ] TLS version
- [ ] Expiry check

### Phase 7: Subdomain Module (Week 5)
- [ ] Passive enumeration
- [ ] Bruteforce
- [ ] Certificate transparency (crt.sh)
- [ ] Recursive enumeration
- [ ] Wildcard detection

### Phase 8: OSINT Module (Week 5-6)
- [ ] Shodan integration
- [ ] Censys integration
- [ ] crt.sh
- [ ] Wayback Machine
- [ ] SecurityTrails

### Phase 9: Full Scan (Week 6)
- [ ] Orchestration
- [ ] Result aggregation
- [ ] Report generation

### Phase 10: TUI (Week 7)
- [ ] BubbleTea dashboard
- [ ] Live progress
- [ ] Interactive results

### Phase 11: REST API (Week 7-8)
- [ ] HTTP server
- [ ] All endpoints
- [ ] Auth (JWT)

### Phase 12: Plugin System (Week 8)
- [ ] Plugin interface
- [ ] Plugin loader
- [ ] Example plugins

### Phase 13: Polish (Week 9-10)
- [ ] Documentation
- [ ] Tests
- [ ] CI/CD
- [ ] Docker optimization

---

## 17. Timeline

| Phase | Duration | Milestone |
|-------|----------|-----------|
| Phase 1-4 | Week 1-3 | Basic reconnaissance (DNS, WHOIS, Port scan) |
| Phase 5-8 | Week 3-6 | Advanced modules (HTTP, SSL, Subdomain, OSINT) |
| Phase 9-11 | Week 6-8 | Full scan, TUI, REST API |
| Phase 12-13 | Week 8-10 | Plugin system, polish, release |

**Total: ~10 weeks for full feature parity**

---

## 18. Open Questions

1. **API Authentication** - JWT vs API key? (pending)
2. **Web Dashboard** - Next.js vs plain HTML? (deferred to Phase 2)
3. **Persistence** - SQLite sufficient for MVP? (yes)
4. ** Shodan/Censys API keys** - Required for OSINT features

---

## 19. Security Considerations

- No sensitive data logging
- Secure credential storage (encrypted at rest)
- Rate limiting enforcement
- Input validation on all user inputs
- TLS by default for all HTTP
- Plugin sandboxing
- No command injection