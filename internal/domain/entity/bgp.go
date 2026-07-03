package entity

import "time"

type BGPIPLookup struct {
	IP          string    `json:"ip"`
	ASN         uint32    `json:"asn"`
	Prefix      string    `json:"prefix"`
	Country     string    `json:"country"`
	Registry    string    `json:"registry"`
	AllocatedAt string    `json:"allocated_at"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Source      string    `json:"source"`
	Timestamp   time.Time `json:"timestamp"`
}

type BGPASNDetail struct {
	ASN             uint32       `json:"asn"`
	Name            string       `json:"name"`
	Description     string       `json:"description"`
	Country         string       `json:"country"`
	Org             string       `json:"org"`
	AdminContact    string       `json:"admin_contact,omitempty"`
	TechContact     string       `json:"tech_contact,omitempty"`
	AbuseContact    string       `json:"abuse_contact,omitempty"`
	Registry        string       `json:"registry"`
	AllocatedAt     string       `json:"allocated_at"`
	Type            string       `json:"type"`
	Prefixes        []BGPPrefix `json:"prefixes"`
	PrefixesV4      []string    `json:"prefixes_v4"`
	PrefixesV6      []string    `json:"prefixes_v6"`
	Peers           []BGPPeer   `json:"peers,omitempty"`
	Upstreams       []BGPPeer   `json:"upstreams,omitempty"`
	PrefixCount     int         `json:"prefix_count"`
	Timestamp       time.Time   `json:"timestamp"`
}

type BGPPrefix struct {
	Prefix      string `json:"prefix"`
	Description string `json:"description,omitempty"`
	Country     string `json:"country,omitempty"`
	OriginAS    uint32 `json:"origin_as,omitempty"`
	Length      int    `json:"length"`
	IsIPv6      bool   `json:"is_ipv6"`
}

type BGPPeer struct {
	ASN         uint32 `json:"asn"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Type        string `json:"type"` // upstream, peer, customer
}

type BGPPrefixDetail struct {
	Prefix      string `json:"prefix"`
	OriginAS    uint32 `json:"origin_as"`
	OriginName  string `json:"origin_name"`
	Route       string `json:"route"`
	Description string `json:"description"`
	Country     string `json:"country"`
	Source      string `json:"source"`
	Maintainer  string `json:"maintainer,omitempty"`
	Created     string `json:"created,omitempty"`
	Updated     string `json:"updated,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

type BGPWhoisResult struct {
	ASN          uint32   `json:"asn"`
	Prefix       string   `json:"prefix"`
	Description  string   `json:"description"`
	Country      string   `json:"country"`
	Source       string   `json:"source"`
	Maintainer   string   `json:"maintainer,omitempty"`
	AdminContact string   `json:"admin_contact,omitempty"`
	TechContact  string   `json:"tech_contact,omitempty"`
	Remarks      []string `json:"remarks,omitempty"`
	Members      []string `json:"members,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
}

type BGPBulkResult struct {
	Entries []BGPIPLookup `json:"entries"`
	Total   int           `json:"total"`
	Errors  []string      `json:"errors,omitempty"`
}
