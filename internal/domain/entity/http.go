package entity

import (
	"time"
)

type HTTPResult struct {
	URL           string            `json:"url"`
	FinalURL      string            `json:"final_url,omitempty"`
	StatusCode    int               `json:"status_code"`
	Status        string            `json:"status"`
	Headers       map[string]string `json:"headers"`
	ContentType   string            `json:"content_type"`
	ContentLength int64             `json:"content_length"`
	Server        string            `json:"server"`
	WebServer     string            `json:"web_server"`
	ResponseTime  float64           `json:"response_time_ms"`
	SSL           SSLInfo           `json:"ssl,omitempty"`
	Technologies  []string          `json:"technologies"`
	RawHeader     string            `json:"raw_header,omitempty"`
	BodyHash      string            `json:"body_hash"`
	Timestamp     time.Time         `json:"timestamp"`
}

type SSLInfo struct {
	Enabled        bool         `json:"enabled"`
	Version        string       `json:"version"`
	Cipher         string       `json:"cipher"`
	Certificate    Certificate  `json:"certificate"`
	ALPN           []string     `json:"alpn"`
	TLSSupported   bool         `json:"tls_supported"`
	CertificateRaw string       `json:"certificate_raw,omitempty"`
}

type Certificate struct {
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	IssuerOrg     string    `json:"issuer_org"`
	Fingerprint   string    `json:"fingerprint"`
	SerialNumber  string    `json:"serial_number"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	DaysLeft      int       `json:"days_left"`
	Expired       bool      `json:"expired"`
	SANs          []string  `json:"sans"`
	IsCA          bool      `json:"is_ca"`
	KeyAlgorithm  string    `json:"key_algorithm"`
	KeySize       int       `json:"key_size"`
	SignatureAlgo string    `json:"signature_algorithm"`
}

type HTTPHeadersResult struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	SecurityHeaders SecurityHeaders `json:"security_headers"`
	Timestamp time.Time       `json:"timestamp"`
}

type SecurityHeaders struct {
	StrictTransportSecurity string `json:"hsts"`
	ContentSecurityPolicy string `json:"csp"`
	XFrameOptions          string `json:"x_frame_options"`
	XContentTypeOptions    string `json:"x_content_type_options"`
	XSSProtection          string `json:"x_xss_protection"`
	ReferrerPolicy         string `json:"referrer_policy"`
	PermissionsPolicy      string `json:"permissions_policy"`
}

type RedirectChain struct {
	URL       string `json:"url"`
	StatusCode int   `json:"status_code"`
	Location  string `json:"location,omitempty"`
}

type RedirectResult struct {
	InitialURL string         `json:"initial_url"`
	FinalURL   string         `json:"final_url"`
	Count      int            `json:"count"`
	Chain      []RedirectChain `json:"chain"`
	Timestamp  time.Time      `json:"timestamp"`
}

type TechResult struct {
	URL          string   `json:"url"`
	Technologies []Tech   `json:"technologies"`
	Categories   []string `json:"categories"`
	CMS          string   `json:"cms,omitempty"`
	Frameworks   []string `json:"frontend_frameworks"`
	Languages    []string `json:"languages"`
	Servers      []string `json:"servers"`
	CDNs         []string `json:"cdns"`
	Timestamp    time.Time `json:"timestamp"`
}

type Tech struct {
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	Confidence int    `json:"confidence"`
	Website    string `json:"website"`
	Categories []string `json:"categories"`
}

type WAFResult struct {
	URL       string   `json:"url"`
	Detected  bool     `json:"detected"`
	WAF       string   `json:"waf,omitempty"`
	Vendor    string   `json:"vendor,omitempty"`
	Level     string   `json:"level,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

type RobotsResult struct {
	URL        string   `json:"url"`
	Exists     bool     `json:"exists"`
	Disallowed []Rule   `json:"disallowed"`
	Allowed    []Rule   `json:"allowed"`
	Sitemaps   []string `json:"sitemaps"`
	Timestamp  time.Time `json:"timestamp"`
}

type Rule struct {
	Path    string `json:"path"`
	Delay   *int   `json:"delay,omitempty"`
	CrawlDelay *int `json:"crawl_delay,omitempty"`
}

type SitemapResult struct {
	URL     string   `json:"url"`
	Exists  bool     `json:"exists"`
	URLs    []string `json:"urls,omitempty"`
	Errors  []string `json:"errors,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

type DirBustResult struct {
	URL         string   `json:"url"`
	FoundDirs   []string `json:"found_dirs"`
	FoundFiles  []string `json:"found_files"`
	StatusCodes map[string]int `json:"status_codes"`
	Timestamp   time.Time `json:"timestamp"`
}

type ScreenshotResult struct {
	URL       string `json:"url"`
	Path      string `json:"path"`
	Width     int    `json:"width"`
	Height    int    `json:"height"`
	Timestamp time.Time `json:"timestamp"`
}

type CrawlResult struct {
	URL         string   `json:"url"`
	Links       []Link  `json:"links"`
	InternalCount int   `json:"internal_count"`
	ExternalCount int   `json:"external_count"`
	Depth       int     `json:"depth"`
	Timestamp   time.Time `json:"timestamp"`
}

type Link struct {
	URL    string `json:"url"`
	Text   string `json:"text,omitempty"`
	Follow bool   `json:"follow"`
}