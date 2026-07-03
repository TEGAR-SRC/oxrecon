package entity

import "time"

type RPKIValidation struct {
	Prefix         string `json:"prefix"`
	OriginAS       uint32 `json:"origin_as"`
	ASN            string `json:"asn"`
	Validity       string `json:"validity"` // valid, invalid, unknown, not_found
	Status         string `json:"status"`
	Description    string `json:"description,omitempty"`
	MaxLength      int    `json:"max_length,omitempty"`
	TA             string `json:"ta,omitempty"` // trust anchor
	Source         string `json:"source,omitempty"`
}

type RPKISummary struct {
	ASN            uint32 `json:"asn"`
	Name           string `json:"name"`
	TotalPrefixes  int    `json:"total_prefixes"`
	IPv4Count      int    `json:"ipv4_count"`
	IPv6Count      int    `json:"ipv6_count"`
	ValidCount     int    `json:"valid_count"`
	InvalidCount   int    `json:"invalid_count"`
	UnknownCount   int    `json:"unknown_count"`
	NotFoundCount  int    `json:"not_found_count"`
	CoveragePct    float64 `json:"coverage_pct"`
	OverlapCount   int    `json:"overlap_count"`
	Timestamp      time.Time `json:"timestamp"`
}

type BGPShowResult struct {
	ASN             uint32            `json:"asn"`
	Name            string            `json:"name"`
	Country         string            `json:"country"`
	Registry        string            `json:"registry"`
	IPv4Prefixes    []PrefixWithRPKI  `json:"ipv4_prefixes"`
	IPv6Prefixes    []PrefixWithRPKI  `json:"ipv6_prefixes"`
	TotalIPv4       int               `json:"total_ipv4"`
	TotalIPv6       int               `json:"total_ipv6"`
	RPKISummary     RPKISummary       `json:"rpki_summary"`
	Timestamp       time.Time         `json:"timestamp"`
}

type PrefixWithRPKI struct {
	Prefix     string `json:"prefix"`
	Mask       int    `json:"mask"`
	RPKIStatus string `json:"rpki_status"`
	RPKIDesc   string `json:"rpki_desc,omitempty"`
	OriginAS   string `json:"origin_as,omitempty"`
}

type RoutinatorResult struct {
	ROAs        []ROAEntry `json:"roas"`
	Total       int        `json:"total"`
	Valid       int        `json:"valid"`
	TotalUnique int        `json:"total_unique"`
	Source      string     `json:"source"`
	Timestamp   time.Time  `json:"timestamp"`
}

type ROAEntry struct {
	ASN          uint32 `json:"asn"`
	Prefix       string `json:"prefix"`
	MaxLength    int    `json:"max_length"`
	TA           string `json:"ta"`
	Validity     string `json:"validity"`
	Source       string `json:"source"`
}
