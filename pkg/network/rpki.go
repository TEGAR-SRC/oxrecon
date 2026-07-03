package bgp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ─── RPKI types ─────────────────────────────────────────────

type RPKIValidity struct {
	Prefix   string
	OriginAS uint32
	Validity string // valid, invalid, unknown, not_found
	Status   string
	MaxLen   int
	TA       string
	Source   string
}

type PrefixFull struct {
	Prefix     string
	OriginAS   uint32
	OriginName string
	Mask       int
	IsIPv6     bool
	RPKI       RPKIValidity
	Timestamp  time.Time
}

type ROA struct {
	ASN       uint32
	Prefix    string
	MaxLength int
	TA        string
	Validity  string
}

type RPKIStats struct {
	Total       int
	Valid       int
	Invalid     int
	Unknown     int
	NotFound    int
	CoveragePct float64
}

// ─── API endpoints ─────────────────────────────────────────

const (
	rpkiValidatorRIPE = "https://rpki-validator.ripe.net/api/v1/validity"
	rpkiValidatorGIN  = "https://rpki.gin.ntt.net/api/v1/validity"
	rpkiRIPEStatus    = "https://rpki-validator.ripe.net/api/v1/status"
	rpkiRDAP          = "https://rdap.arin.net/registry/ip"
)

// FetchRPKIFromRIPE queries RIPE Routinator for RPKI validation of a prefix
func FetchRPKIFromRIPE(ctx context.Context, prefix string) (*RPKIValidity, error) {
	// Try multiple Routinator endpoints
	endpoints := []string{
		fmt.Sprintf("%s/%s", rpkiValidatorRIPE, prefix),
		fmt.Sprintf("%s/%s", rpkiValidatorGIN, prefix),
	}

	for _, url := range endpoints {
		body, err := httpGet(ctx, url, 15*time.Second)
		if err != nil {
			continue
		}

		// Try parsing as v1 response
		var v1 struct {
			Status  string `json:"status"`
			Valid   bool   `json:"valid"`
			Reason  string `json:"reason"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(body, &v1); err == nil && v1.Status != "" {
			validity := "unknown"
			if v1.Valid {
				validity = "valid"
			} else {
				validity = "invalid"
			}
			return &RPKIValidity{
				Prefix:   prefix,
				Validity: validity,
				Status:   strings.ToUpper(validity),
				Source:   url,
			}, nil
		}
	}

	return &RPKIValidity{
		Prefix:   prefix,
		Validity: "not_found",
		Status:   "NOT FOUND",
		Source:   "api-unavailable",
	}, nil
}

// FetchRPKIByASN gets all RPKI-validated prefixes for an ASN
func FetchRPKIByASN(ctx context.Context, asn uint32) ([]RPKIValidity, error) {
	// The RIPE Stat API is down — just try the Routinator endpoints
	endpoints := []string{
		fmt.Sprintf("%s/AS%d", rpkiValidatorRIPE, asn),
		fmt.Sprintf("%s/AS%d", rpkiValidatorGIN, asn),
	}

	for _, url := range endpoints {
		body, err := httpGet(ctx, url, 20*time.Second)
		if err != nil {
			continue
		}

		// Parse as ROA list
		var result []struct {
			Prefix   string `json:"prefix"`
			ASN      string `json:"asn"`
			Validity string `json:"validity"`
			MaxLen   int    `json:"maxLength"`
			TA       string `json:"ta"`
			Source   string `json:"source"`
		}

		if err := json.Unmarshal(body, &result); err == nil {
			var out []RPKIValidity
			for _, r := range result {
				out = append(out, RPKIValidity{
					Prefix:   r.Prefix,
					Validity: strings.ToLower(r.Validity),
					Status:   mapRPKIStatus(strings.ToLower(r.Validity)),
					MaxLen:   r.MaxLen,
					TA:       r.TA,
					Source:   r.Source,
				})
			}
			if len(out) > 0 {
				return out, nil
			}
		}

		// Try v1 format
		var v1 struct {
			Status string `json:"status"`
			Rows  []struct {
				Prefix string `json:"prefix"`
				State  string `json:"state"`
				MaxLen int    `json:"maxLength"`
			} `json:"rows"`
		}
		if err := json.Unmarshal(body, &v1); err == nil && len(v1.Rows) > 0 {
			var out []RPKIValidity
			for _, r := range v1.Rows {
				out = append(out, RPKIValidity{
					Prefix:   r.Prefix,
					Validity: strings.ToLower(r.State),
					Status:   mapRPKIStatus(strings.ToLower(r.State)),
					MaxLen:   r.MaxLen,
				})
			}
			return out, nil
		}
	}
	return nil, fmt.Errorf("RPKI validation unavailable for AS%d", asn)
}

// FetchFullPrefixList gets ALL prefixes (v4+v6) for an ASN from RADB whois
func FetchFullPrefixList(ctx context.Context, asn uint32) (v4, v6 []PrefixFull, err error) {
	conn, err := dialWhois(ctx, "whois.radb.net", fmt.Sprintf("!gAS%d", asn))
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	buf := make([]byte, 65536)
	n, _ := conn.Read(buf)
	if n == 0 {
		return nil, nil, fmt.Errorf("no prefixes for AS%d", asn)
	}

	text := string(buf[:n])
	lines := strings.Split(strings.TrimSpace(text), "\n")
	seen := make(map[string]bool)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true

		pf := PrefixFull{
			Prefix:    line,
			OriginAS:  asn,
			IsIPv6:    strings.Contains(line, ":"),
			Timestamp: time.Now(),
		}
		parts := strings.Split(line, "/")
		if len(parts) == 2 {
			pf.Mask, _ = strconv.Atoi(parts[1])
		}
		if pf.IsIPv6 {
			v6 = append(v6, pf)
		} else {
			v4 = append(v4, pf)
		}
	}

	sort.Slice(v4, func(i, j int) bool {
		if v4[i].Mask != v4[j].Mask {
			return v4[i].Mask < v4[j].Mask
		}
		return v4[i].Prefix < v4[j].Prefix
	})
	sort.Slice(v6, func(i, j int) bool {
		if v6[i].Mask != v6[j].Mask {
			return v6[i].Mask < v6[j].Mask
		}
		return v6[i].Prefix < v6[j].Prefix
	})

	return v4, v6, nil
}

// ComputeRPKIStats computes summary statistics for a set of prefixes
func ComputeRPKIStats(v4, v6 []PrefixFull) RPKIStats {
	all := append(v4, v6...)
	stats := RPKIStats{Total: len(all)}

	for _, p := range all {
		switch p.RPKI.Validity {
		case "valid", "validating":
			stats.Valid++
		case "invalid","invalid-maxlength","invalid-asn","invalid-length":
			stats.Invalid++
		case "unknown":
			stats.Unknown++
		default:
			stats.NotFound++
		}
	}
	if stats.Total > 0 {
		stats.CoveragePct = float64(stats.Valid) / float64(stats.Total) * 100
	}
	return stats
}

// RPKIStatusIcon returns emoji for status
func RPKIStatusIcon(v string) string {
	switch strings.ToLower(v) {
	case "valid","validating":
		return "✅"
	case "invalid","invalid-maxlength","invalid-asn","invalid-length":
		return "❌"
	case "unknown":
		return "⚠️"
	case "not_found","not-found":
		return "❓"
	default:
		return "⬜"
	}
}

func RPKIStatusLine(prefix string, v RPKIValidity) string {
	icon := RPKIStatusIcon(v.Validity)
	status := strings.ToUpper(v.Validity)
	if status == "" {
		status = "UNKNOWN"
	}
	return fmt.Sprintf("  %s %-24s %-10s %s", icon, prefix, status, v.TA)
}

func mapRPKIStatus(v string) string {
	switch v {
	case "valid","validating":
		return "VALID"
	case "invalid","invalid-maxlength","invalid-asn","invalid-length":
		return "INVALID"
	case "unknown":
		return "UNKNOWN"
	case "not_found","not-found":
		return "NOT FOUND"
	default:
		return "UNKNOWN"
	}
}

// ─── helpers ────────────────────────────────────────────────

func httpGet(ctx context.Context, url string, timeout time.Duration) ([]byte, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "WebTool/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func urlEncode(s string) string {
	return strings.ReplaceAll(s, "/", "%2F")
}

var _ = net.LookupAddr
