package entity

import (
	"time"
)

type DomainInfo struct {
	Domain        string     `json:"domain"`
	Registrar    string     `json:"registrar,omitempty"`
	RegistrarURL string     `json:"registrar_url,omitempty"`
	CreationDate *time.Time `json:"creation_date,omitempty"`
	ExpiryDate   *time.Time `json:"expiry_date,omitempty"`
	UpdatedDate  *time.Time `json:"updated_date,omitempty"`
	NameServers  []string   `json:"nameservers,omitempty"`
	Status       []string   `json:"status,omitempty"`
	DNSSEC       string     `json:"dnssec,omitempty"`
	WhoisServer  string     `json:"whois_server,omitempty"`
	AbuseEmail   string     `json:"abuse_email,omitempty"`
	AbusePhone   string     `json:"abuse_phone,omitempty"`
	RawWhois     string     `json:"raw_whois,omitempty"`
	Timestamp    time.Time  `json:"timestamp"`
}

type RegistrarInfo struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	IANAID      string `json:"iana_id,omitempty"`
	Phone       string `json:"phone,omitempty"`
	Email       string `json:"email,omitempty"`
	ReferralURL string `json:"referral_url,omitempty"`
}

type DomainExpiration struct {
	Domain     string     `json:"domain"`
	ExpiryDate *time.Time `json:"expiry_date"`
	DaysLeft   int        `json:"days_left"`
	Expired    bool       `json:"expired"`
	Timestamp  time.Time  `json:"timestamp"`
}