package entity

import (
	"time"
)

type SubdomainResult struct {
	Domain      string   `json:"domain"`
	Subdomains  []string `json:"subdomains"`
	Source      string   `json:"source,omitempty"`
	Count       int      `json:"count"`
	Wildcards   []string `json:"wildcards,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

type BruteforceResult struct {
	Domain     string   `json:"domain"`
	Found      []string `json:"found"`
	Tested     int      `json:"tested"`
	Source     string   `json:"source"`
	DurationMs int64    `json:"duration_ms"`
	Timestamp  time.Time `json:"timestamp"`
}

type crtshResult struct {
	Domain      string    `json:"domain"`
	CertID      uint64    `json:"cert_id"`
	Seen        time.Time `json:"seen"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	PublicKey   string    `json:"public_key"`
	CommonName  string    `json:"common_name"`
	Names       []string  `json:"names"`
}

type CertificateTransparencyResult struct {
	Domain     string       `json:"domain"`
	Entries    []ctEntry    `json:"entries"`
	Count      int          `json:"count"`
	Timestamp  time.Time    `json:"timestamp"`
}

type ctEntry struct {
	CommonName    string    `json:"common_name"`
	Names         []string  `json:"names"`
	CertID        uint64    `json:"cert_id"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	Source        string    `json:"source"`
}

type SubdomainTakeoverResult struct {
	Domain       string   `json:"domain"`
	Subdomain    string   `json:"subdomain"`
	Provider     string   `json:"provider"`
	Detected     bool     `json:"detected"`
	Vulnerable   bool     `json:"vulnerable"`
	Evidence     string   `json:"evidence,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
}

type RecursiveResult struct {
	Domain     string   `json:"domain"`
	Discovered []string `json:"discovered"`
	Depth      int      `json:"depth"`
	Sources    []string `json:"sources"`
	DurationMs int64    `json:"duration_ms"`
	Timestamp  time.Time `json:"timestamp"`
}