package entity

import (
	"time"
)

type Host struct {
	IP        string   `json:"ip"`
	Hostname  string   `json:"hostname,omitempty"`
	Hostnames []string `json:"hostnames,omitempty"`
	OS        string   `json:"os,omitempty"`
	ASN       uint32   `json:"asn,omitempty"`
	Org       string   `json:"org,omitempty"`
	ISP       string   `json:"isp,omitempty"`
	ASDescription string `json:"as_description,omitempty"`
	Country   string   `json:"country,omitempty"`
	Region    string   `json:"region,omitempty"`
	City      string   `json:"city,omitempty"`
	Latitude  float64  `json:"latitude,omitempty"`
	Longitude float64  `json:"longitude,omitempty"`
	Timezone  string   `json:"timezone,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

type Port struct {
	PortID     int        `json:"port"`
	Protocol   string     `json:"protocol"`
	State      string     `json:"state"`
	Service    string     `json:"service,omitempty"`
	Version    string     `json:"version,omitempty"`
	Banner     string     `json:"banner,omitempty"`
	TLS        bool       `json:"tls"`
	Timestamp  time.Time  `json:"timestamp"`
}

type PortScanResult struct {
	Host        string  `json:"host"`
	Ports       []Port  `json:"ports"`
	DurationMs  int64   `json:"duration_ms"`
	OpenCount   int     `json:"open_count"`
	ClosedCount int     `json:"closed_count"`
	FilteredCount int   `json:"filtered_count"`
	Timestamp   time.Time `json:"timestamp"`
}

type PingResult struct {
	IP        string        `json:"ip"`
	PacketsSent int          `json:"packets_sent"`
	PacketsRecv int          `json:"packets_recv"`
	PacketLoss float64       `json:"packet_loss"`
	MinLatency float64       `json:"min_latency_ms"`
	MaxLatency float64       `json:"max_latency_ms"`
	AvgLatency float64       `json:"avg_latency_ms"`
	Timestamp  time.Time    `json:"timestamp"`
}

type TracerouteHop struct {
	Hop       int      `json:"hop"`
	IP        string   `json:"ip"`
	Hostname  string   `json:"hostname,omitempty"`
	Latency   float64  `json:"latency_ms"`
	Locations []string `json:"locations,omitempty"`
}

type TracerouteResult struct {
	Target   string           `json:"target"`
	Hops     []TracerouteHop  `json:"hops"`
	Duration float64          `json:"duration_ms"`
	Timestamp time.Time       `json:"timestamp"`
}

type CIDRResult struct {
	CIDR       string   `json:"cidr"`
	Network    string   `json:"network"`
	Netmask    string   `json:"netmask"`
	Broadcast  string   `json:"broadcast"`
	HostMin    string   `json:"host_min"`
	HostMax    string   `json:"host_max"`
	HostCount  uint64   `json:"host_count"`
	Wildcard   string   `json:"wildcard"`
	Timestamp  time.Time `json:"timestamp"`
}

type ReverseIPResult struct {
	IP        string   `json:"ip"`
	Hostnames []string `json:"hostnames"`
	Count     int      `json:"count"`
	Timestamp time.Time `json:"timestamp"`
}

type GeoIPResult struct {
	IP        string  `json:"ip"`
	Country   string  `json:"country"`
	CountryCode string `json:"country_code"`
	Region    string  `json:"region"`
	City      string  `json:"city"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Timezone  string  `json:"timezone"`
	ISP       string  `json:"isp"`
	Org       string  `json:"org"`
	AS        string  `json:"as"`
	Timestamp time.Time `json:"timestamp"`
}

type ASNResult struct {
	ASN        uint32   `json:"asn"`
	Prefix     string   `json:"prefix"`
	Name       string   `json:"name"`
	Description string  `json:"description"`
	Country    string   `json:"country"`
	Registry   string   `json:"registry"`
	Allocated  string   `json:"allocated"`
	Type       string   `json:"type"`
	Contacts   []string `json:"contacts,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

type IPInfoResult struct {
	IP        string   `json:"ip"`
	GeoIP     GeoIPResult `json:"geoip"`
	ASN       ASNResult  `json:"asn"`
	Host      Host       `json:"host"`
	Timestamp time.Time  `json:"timestamp"`
}