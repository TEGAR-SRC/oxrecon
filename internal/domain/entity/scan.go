package entity

import (
	"time"
)

type ScanStatus string

const (
	ScanStatusPending   ScanStatus = "pending"
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
	ScanStatusCancelled ScanStatus = "cancelled"
)

type ScanType string

const (
	ScanTypeFull     ScanType = "full"
	ScanTypeDNS      ScanType = "dns"
	ScanTypePort     ScanType = "port"
	ScanTypeHTTP     ScanType = "http"
	ScanTypeSubdomain ScanType = "subdomain"
	ScanTypeOSINT    ScanType = "osint"
)

type FullScanResult struct {
	ID           string           `json:"id"`
	Target       string           `json:"target"`
	ScanType     ScanType         `json:"scan_type"`
	Status       ScanStatus       `json:"status"`
	StartedAt    time.Time        `json:"started_at"`
	CompletedAt *time.Time        `json:"completed_at,omitempty"`
	DurationMs   int64            `json:"duration_ms"`
	RiskScore    int              `json:"risk_score"`
	Grade        string           `json:"grade"`
	Summary      ScanSummary      `json:"summary"`
	DNS          *DNSResult       `json:"dns,omitempty"`
	WHOIS        *DomainInfo      `json:"whois,omitempty"`
	SSL          *SSLResult       `json:"ssl,omitempty"`
	Ports        *PortScanResult  `json:"ports,omitempty"`
	HTTP         *HTTPResult      `json:"http,omitempty"`
	Technologies []string         `json:"technologies"`
	Subdomains   *SubdomainResult `json:"subdomains,omitempty"`
	Security     *SecurityResult  `json:"security,omitempty"`
	GeoIP        *GeoIPResult     `json:"geoip,omitempty"`
	Wayback      *WaybackResult   `json:"wayback,omitempty"`
	Recommendations []Recommendation `json:"recommendations"`
	Progress     int              `json:"progress"`
	Error        string            `json:"error,omitempty"`
}

type ScanSummary struct {
	OpenPorts       []int  `json:"open_ports"`
	DNSRecords      int    `json:"dns_records"`
	Subdomains      int    `json:"subdomains"`
	Technologies    int    `json:"technologies"`
	SecurityIssues  int    `json:"security_issues"`
	Warnings        int    `json:"warnings"`
}

type SSLResult struct {
	Host         string       `json:"host"`
	Port         int          `json:"port"`
	Enabled      bool         `json:"enabled"`
	Version      string       `json:"version"`
	Cipher       string       `json:"cipher"`
	Certificate  Certificate  `json:"certificate"`
	Chain        []Certificate `json:"chain"`
	ALPN         []string     `json:"alpn"`
	TLSSupported bool         `json:"tls_supported"`
	Timestamp    time.Time    `json:"timestamp"`
}

type SecurityResult struct {
	URL          string               `json:"url"`
	Headers      SecurityHeaders      `json:"headers"`
	Missing      []string             `json:"missing_headers"`
	Vulns        []SecurityVuln       `json:"vulnerabilities"`
	Score        int                  `json:"score"`
	Grade        string               `json:"grade"`
	Timestamp    time.Time            `json:"timestamp"`
}

type SecurityVuln struct {
	Type    string `json:"type"`
	Severity string `json:"severity"`
	Title   string `json:"title"`
	Desc    string `json:"description"`
}

type Recommendation struct {
	Category  string `json:"category"`
	Priority  string `json:"priority"`
	Title     string `json:"title"`
	Desc      string `json:"description"`
	Reference string `json:"reference,omitempty"`
}

type ScanProgress struct {
	ScanID      string    `json:"scan_id"`
	Status      ScanStatus `json:"status"`
	Progress    int       `json:"progress"`
	CurrentStep string    `json:"current_step"`
	Steps       []ScanStep `json:"steps"`
}

type ScanStep struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	StartedAt *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Error     string `json:"error,omitempty"`
}