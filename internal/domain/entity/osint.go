package entity

import (
	"time"
)

type ShodanResult struct {
	IP        string            `json:"ip"`
	Hostnames []string          `json:"hostnames"`
	Org       string            `json:"org"`
	ISP       string            `json:"isp"`
	ASN       string            `json:"asn"`
	Country   string            `json:"country"`
	Region    string            `json:"region"`
	City      string            `json:"city"`
	Latitude  float64           `json:"latitude"`
	Longitude float64           `json:"longitude"`
	Ports     []int             `json:"ports"`
	Tags      []string          `json:"tags"`
	Vulns     map[string][]Vuln `json:"vulnerabilities,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

type Vuln struct {
	CVE       string `json:"cve"`
	Summary   string `json:"summary"`
	Severity  string `json:"severity"`
	Score     float64 `json:"score"`
	Published time.Time `json:"published"`
	Modified  time.Time `json:"modified"`
}

type CensysResult struct {
	IP           string          `json:"ip"`
	Protocols    []Protocol      `json:"protocols"`
	Services     []Service       `json:"services"`
	Location     Location        `json:"location"`
	AutonomousSystem AS           `json:"autonomous_system"`
	Timestamp    time.Time       `json:"timestamp"`
}

type Protocol struct {
	Port  int    `json:"port"`
	Name  string `json:"name"`
	Title string `json:"title"`
}

type Service struct {
	Port           int               `json:"port"`
	ServiceName    string            `json:"service_name"`
	Transport      string            `json:"transport"`
	Banner         string            `json:"banner"`
	BannerHash     string            `json:"banner_hash"`
	ServiceProps   map[string]any    `json:"service_props"`
	Certificates   []ServiceCert     `json:"certificates,omitempty"`
	Body           string            `json:"body"`
	Headers        map[string]string `json:"headers"`
	HttpResponse   HTTPResult        `json:"http_response,omitempty"`
}

type ServiceCert struct {
	Subject    string   `json:"subject"`
	Issuer     string   `json:"issuer"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	Fingerprint string  `json:"fingerprint"`
}

type Location struct {
	Continent   string  `json:"continent"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	Timezone    string  `json:"timezone"`
}

type AS struct {
	ASNum   uint32 `json:"asn"`
	Name    string `json:"name"`
	Routing string `json:"routing"`
}

type WaybackResult struct {
	Domain    string          `json:"domain"`
	URLs      []WaybackURL    `json:"urls"`
	Count     int             `json:"count"`
	Timestamp time.Time       `json:"timestamp"`
}

type WaybackURL struct {
	URL       string    `json:"url"`
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
	Status    int       `json:"status"`
}

type SecurityTrailsResult struct {
	CurrentDNS []DNSRecord `json:"current_dns"`
	Subdomains []string    `json:"subdomains"`
	Registrar  string      `json:"registrar"`
	Contacts   []Contact   `json:"contacts"`
	Historical *Historical `json:"historical,omitempty"`
	Timestamp  time.Time   `json:"timestamp"`
}

type Contact struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Phone   string `json:"phone"`
	Country string `json:"country"`
}

type Historical struct {
	DNSRecords []DNSRecord `json:"dns_records"`
	Subdomains []string    `json:"subdomains"`
}

type VirusTotalResult struct {
	Domain      string           `json:"domain"`
	Detections  VTDetections     `json:"detections"`
	Relations   VTRelations      `json:"relations"`
	LastAnalysis time.Time       `json:"last_analysis"`
	Timestamp   time.Time        `json:"timestamp"`
}

type VTDetections struct {
	Malicious   int `json:"malicious"`
	Suspicious  int `json:"suspicious"`
	Harmless    int `json:"harmless"`
	Undetected  int `json:"undetected"`
}

type VTRelations struct {
	Resolutions []Resolution `json:"resolutions"`
	Communicated []string    `json:"communicated_files"`
	URLs        []string     `json:"urls"`
	Subdomains  []string     `json:"subdomains"`
}

type Resolution struct {
	IP        string    `json:"ip"`
	Hostname  string    `json:"hostname"`
	LastSeen  time.Time `json:"last_seen"`
}

type AlienVaultResult struct {
	Domain     string           `json:"domain"`
	Pulses     []Pulse          `json:"pulses"`
	Indicators []Indicator      `json:"indicators"`
	Reputation int              `json:"reputation"`
	Timestamp  time.Time        `json:"timestamp"`
}

type Pulse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Tags      []string  `json:"tags"`
	Created   time.Time `json:"created"`
	Modified  time.Time `json:"modified"`
	Indicators []Indicator `json:"indicators"`
}

type Indicator struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type URLScanResult struct {
	URL         string            `json:"url"`
	Status      int               `json:"status"`
	Title       string            `json:"title"`
	Summary     URLScanSummary    `json:"summary"`
	Screenshot  string            `json:"screenshot,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
}

type URLScanSummary struct {
	Server   string   `json:"server"`
	Title    string   `json:"title"`
	Technologies []string `json:"technologies"`
	IP       []string `json:"ips"`
	Country  []string `json:"countries"`
	Links    int      `json:"links"`
	Cookies  int      `json:"cookies"`
}