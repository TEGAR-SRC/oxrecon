# Changelog
All notable changes to WebTool will be documented in this file.

## [1.0.0] - 2026-07-04
### Added
- Initial release with clean architecture
- DNS: lookup, reverse, MX, NS, TXT, SOA, CNAME, CAA, DNSSEC, zone transfer, resolver test
- Domain: WHOIS, registrar info, expiry check
- Network: TCP port scan, ping, traceroute, CIDR analysis, reverse IP
- HTTP: probe, headers, methods, redirect, robots, sitemap, WAF, tech detection, CDN, screenshot, directory busting, crawl
- SSL/TLS: certificate, cipher, TLS version, expiration
- Subdomain: enumeration, brute-force, crt.sh, recursive, wildcard detection
- OSINT: Shodan, Censys, crt.sh, Wayback, SecurityTrails, VirusTotal, AlienVault
- Full scan: orchestrates all modules with parallel execution
- Worker pool with goroutine management
- Rate limiter (token bucket + sliding window)
- Cache with TTL and auto-cleanup
- Retry mechanism with exponential backoff
- Output formatters: JSON, YAML, XML, CSV
- Config system with Viper
- Docker multi-stage build
- Docker Compose setup
- CI/CD with GitHub Actions
- Makefile for build/test/lint tasks
- 400+ unit tests covering all utility packages
