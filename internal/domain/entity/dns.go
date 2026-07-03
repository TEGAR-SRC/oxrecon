package entity

import (
	"time"
)

type DNSRecordType string

const (
	DNS_A    DNSRecordType = "A"
	DNS_AAAA DNSRecordType = "AAAA"
	DNS_CNAME DNSRecordType = "CNAME"
	DNS_MX    DNSRecordType = "MX"
	DNS_NS    DNSRecordType = "NS"
	DNS_TXT   DNSRecordType = "TXT"
	DNS_SOA   DNSRecordType = "SOA"
	DNS_CAA   DNSRecordType = "CAA"
	DNS_SRV   DNSRecordType = "SRV"
	DNS_PTR   DNSRecordType = "PTR"
)

type DNSRecord struct {
	Type    DNSRecordType `json:"type"`
	Name    string        `json:"name"`
	Value   string        `json:"value"`
	TTL     uint32        `json:"ttl"`
	Class   string        `json:"class"`
	Priority int           `json:"priority,omitempty"`
}

type DNSResult struct {
	Domain     string      `json:"domain"`
	Records    []DNSRecord `json:"records"`
	Resolver   string      `json:"resolver"`
	DurationMs int64       `json:"duration_ms"`
	Timestamp  time.Time   `json:"timestamp"`
}

type ReverseDNSResult struct {
	IP       string   `json:"ip"`
	Hostnames []string `json:"hostnames"`
	Timestamp time.Time `json:"timestamp"`
}

type MXRecord struct {
	Priority int    `json:"priority"`
	Exchange string `json:"exchange"`
}

type TXTRecord struct {
	Text string `json:"text"`
}

type NSRecord struct {
	NS string `json:"ns"`
}

type SOARecord struct {
	NS      string `json:"ns"`
	Email   string `json:"email"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	MinTTL  uint32 `json:"min_ttl"`
}

type CAARecord struct {
	Flag    int    `json:"flag"`
	Tag     string `json:"tag"`
	Value   string `json:"value"`
}

type SRVRecord struct {
	Priority int    `json:"priority"`
	Weight   int    `json:"weight"`
	Port     int    `json:"port"`
	Target   string `json:"target"`
}

type DNSSECResult struct {
	Domain     string `json:"domain"`
	DSRecords  []DSRecord `json:"ds_records,omitempty"`
	DNSKEYRecords []DNSKEYRecord `json:"dnskey_records,omitempty"`
	Valid      bool   `json:"valid"`
	ValidationError string `json:"validation_error,omitempty"`
}

type DSRecord struct {
	KeyTag     uint16 `json:"key_tag"`
	Algorithm  uint8  `json:"algorithm"`
	DigestType uint8  `json:"digest_type"`
	Digest     string `json:"digest"`
}

type DNSKEYRecord struct {
	Flags     uint16 `json:"flags"`
	Protocol  uint8  `json:"protocol"`
	Algorithm uint8  `json:"algorithm"`
	PublicKey string `json:"public_key"`
}