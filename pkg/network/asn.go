package bgp

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	cymruOriginTXT = "origin.asn.cymru.com"
	cymruASNTXT    = "asn.cymru.com"
	cymruWhoisHost = "whois.cymru.com"
	radbWhoisHost  = "whois.radb.net"
	ripeWhoisHost  = "whois.ripe.net"
)

type ASNInfo struct {
	ASN         uint32
	Prefix      string
	Country     string
	Registry    string
	AllocatedAt string
	Name        string
	Description string
	Source      string
	Timestamp   time.Time
}

type PrefixInfo struct {
	Prefix      string
	OriginAS    uint32
	Description string
	Country     string
	Source      string
	OriginName  string
	Timestamp   time.Time
}

type PeerInfo struct {
	ASN         uint32
	Name        string
	Description string
	Type        string
}

func LookupIP(ctx context.Context, ip string) (*ASNInfo, error) {
	res := &ASNInfo{Timestamp: time.Now()}

	// Metode 1: Team Cymru DNS (origin.asn.cymru.com TXT)
	if info, err := lookupOriginDNS(ctx, ip); err == nil {
		res = info
		res.Source = "Team Cymru DNS"
		res.Timestamp = time.Now()

		// Ambil nama AS dari whois
		if name, err := lookupASName(ctx, info.ASN); err == nil {
			res.Name = name
		}
		return res, nil
	}

	// Metode 2: Fallback whois ripe/radb
	if info, err := lookupWhoisASN(ctx, ip); err == nil {
		info.Source = "RADB Whois"
		info.Timestamp = time.Now()
		return info, nil
	}

	return nil, fmt.Errorf("ASN lookup failed for IP %s", ip)
}

func lookupOriginDNS(ctx context.Context, ip string) (*ASNInfo, error) {
	// Reverse IP: 1.2.3.4 â†’ 4.3.2.1.origin.asn.cymru.com
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, fmt.Errorf("invalid IP: %s", ip)
	}

	parts := strings.Split(parsed.String(), ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("not IPv4: %s", ip)
	}
	rev := fmt.Sprintf("%s.%s.%s.%s.%s",
		parts[3], parts[2], parts[1], parts[0], cymruOriginTXT)

	txts, err := net.DefaultResolver.LookupTXT(ctx, rev)
	if err != nil || len(txts) == 0 {
		return nil, fmt.Errorf("DNS lookup failed: %w", err)
	}

	return parseCymruTXT(txts[0]), nil
}

func parseCymruTXT(txt string) *ASNInfo {
	// Format: ASN | Prefix | Country | Registry | AllocatedAt
	info := &ASNInfo{}
	parts := strings.Split(txt, "|")
	if len(parts) < 5 {
		parts = strings.Split(txt, " | ")
	}

	trim := func(s string) string { return strings.TrimSpace(s) }

	if len(parts) >= 1 {
		asnStr := trim(parts[0])
		asnStr = strings.TrimPrefix(asnStr, "AS")
		asn, _ := strconv.ParseUint(asnStr, 10, 32)
		info.ASN = uint32(asn)
	}
	if len(parts) >= 2 {
		info.Prefix = trim(parts[1])
	}
	if len(parts) >= 3 {
		info.Country = trim(parts[2])
	}
	if len(parts) >= 4 {
		info.Registry = trim(parts[3])
	}
	if len(parts) >= 5 {
		info.AllocatedAt = trim(parts[4])
	}
	info.Source = "Team Cymru DNS"
	return info
}

func lookupASName(ctx context.Context, asn uint32) (string, error) {
	query := fmt.Sprintf("AS%d.asn.cymru.com", asn)
	txts, err := net.DefaultResolver.LookupTXT(ctx, query)
	if err != nil || len(txts) == 0 {
		// Fallback: whois query
		return lookupASNameWhois(ctx, asn), nil
	}

	return parseASNameTXT(txts[0]), nil
}

func parseASNameTXT(txt string) string {
	// Format: ASN | Country | Registry | AllocatedAt | Name
	parts := strings.Split(txt, "|")
	if len(parts) < 5 {
		parts = strings.Split(txt, " | ")
	}
	if len(parts) >= 5 {
		name := strings.TrimSpace(parts[4])
		// Ambil hanya nama (sebelum comma pertama)
		if idx := strings.Index(name, ","); idx > 0 {
			name = name[:idx]
		}
		return name
	}
	return ""
}

func lookupASNameWhois(ctx context.Context, asn uint32) string {
	conn, err := dialWhois(ctx, radbWhoisHost, fmt.Sprintf("!gAS%d\n", asn))
	if err != nil {
		return ""
	}
	defer conn.Close()

	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	if n == 0 {
		return ""
	}

	text := string(buf[:n])
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "as-name:") {
			return strings.TrimSpace(line[8:])
		}
	}
	return ""
}

func lookupWhoisASN(ctx context.Context, ip string) (*ASNInfo, error) {
	hosts := []string{"whois.ripe.net", "whois.radb.net", "whois.arin.net"}
	for _, host := range hosts {
		conn, err := dialWhois(ctx, host, ip)
		if err != nil {
			continue
		}
		defer conn.Close()

		buf := make([]byte, 16384)
		n, _ := conn.Read(buf)
		if n == 0 {
			continue
		}

		text := string(buf[:n])
		info := parseWhoisForASN(text)
		if info.ASN > 0 {
			return info, nil
		}
	}
	return nil, fmt.Errorf("whois ASN lookup failed")
}

func LookupASNM(ctx context.Context, asn uint32) (*ASNInfo, error) {
	info := &ASNInfo{ASN: asn, Timestamp: time.Now()}

	// Dapatkan nama AS
	if name := lookupASNameWhois(ctx, asn); name != "" {
		info.Name = name
	}
	if name, err := lookupASName(ctx, asn); err == nil && name != "" {
		info.Name = name
	}

	// Dapatkan detail dari whois
	conn, err := dialWhois(ctx, radbWhoisHost, fmt.Sprintf("!gAS%d\n", asn))
	if err != nil {
		return info, nil
	}
	defer conn.Close()

	buf := make([]byte, 16384)
	n, _ := conn.Read(buf)
	if n > 0 {
		text := string(buf[:n])
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(line, "as-name:"):
				info.Name = strings.TrimSpace(line[8:])
			case strings.HasPrefix(line, "descr:"):
				info.Description = strings.TrimSpace(line[6:])
			case strings.HasPrefix(line, "country:"):
				info.Country = strings.TrimSpace(line[8:])
			case strings.HasPrefix(line, "org:"):
				info.Registry = strings.TrimSpace(line[4:])
			}
		}
	}

	info.Source = "RADB Whois"
	return info, nil
}

func LookupPrefixes(ctx context.Context, asn uint32) ([]string, error) {
	var prefixes []string

	// RADB whois
	conn, err := dialWhois(ctx, radbWhoisHost, fmt.Sprintf("!gAS%d\n", asn))
	if err == nil {
		defer conn.Close()
		buf := make([]byte, 32768)
		n, _ := conn.Read(buf)
		if n > 0 {
			text := string(buf[:n])
			for _, line := range strings.Split(text, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "route:") || strings.HasPrefix(line, "route6:") {
					prefix := strings.TrimSpace(line[6:])
					prefixes = append(prefixes, prefix)
				}
			}
		}
	}

	// Team Cymru DNS fallback
	if len(prefixes) == 0 {
		txts, err := net.DefaultResolver.LookupTXT(ctx,
			fmt.Sprintf("AS%d.asn.cymru.com", asn))
		if err == nil && len(txts) > 0 {
			for _, txt := range txts {
				info := parseCymruPrefixTXT(txt)
				if info != "" {
					prefixes = append(prefixes, info)
				}
			}
		}
	}

	return prefixes, nil
}

func parseCymruPrefixTXT(txt string) string {
	// Format: ASN | Prefix | Country | Registry | AllocatedAt | Name
	parts := strings.Split(txt, "|")
	if len(parts) >= 2 {
		return strings.TrimSpace(parts[1])
	}
	parts = strings.Split(txt, " | ")
	if len(parts) >= 2 {
		return strings.TrimSpace(parts[1])
	}
	return ""
}

func LookupPrefixDetail(ctx context.Context, prefix string) (*PrefixInfo, error) {
	conn, err := dialWhois(ctx, radbWhoisHost, fmt.Sprintf("!g%s\n", prefix))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	buf := make([]byte, 16384)
	n, _ := conn.Read(buf)
	if n == 0 {
		return nil, fmt.Errorf("no data for prefix %s", prefix)
	}

	text := string(buf[:n])
	info := &PrefixInfo{Prefix: prefix, Timestamp: time.Now()}

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "origin:"):
			o := strings.TrimSpace(line[7:])
			o = strings.TrimPrefix(o, "AS")
			asn, _ := strconv.ParseUint(o, 10, 32)
			info.OriginAS = uint32(asn)
		case strings.HasPrefix(line, "descr:"):
			info.Description = strings.TrimSpace(line[6:])
		case strings.HasPrefix(line, "country:"):
			info.Country = strings.TrimSpace(line[8:])
		case strings.HasPrefix(line, "source:"):
			info.Source = strings.TrimSpace(line[7:])
		}
	}
	return info, nil
}

func LookupPeers(ctx context.Context, asn uint32) ([]PeerInfo, error) {
	conn, err := dialWhois(ctx, radbWhoisHost, fmt.Sprintf("!gAS%d\n", asn))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	buf := make([]byte, 32768)
	n, _ := conn.Read(buf)
	if n == 0 {
		return nil, fmt.Errorf("no peers for AS%d", asn)
	}

	text := string(buf[:n])
	var peers []PeerInfo
	seen := make(map[uint32]bool)

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "import:") || strings.HasPrefix(line, "export:") {
			parts := strings.Fields(line)
			isImport := strings.HasPrefix(line, "import:")
			for _, p := range parts {
				p = strings.TrimPrefix(p, "AS")
				asnP, err := strconv.ParseUint(p, 10, 32)
				if err == nil && asnP > 0 && !seen[uint32(asnP)] {
					seen[uint32(asnP)] = true
					typ := "peer"
					if isImport {
						typ = "upstream"
					}
					peers = append(peers, PeerInfo{
						ASN:  uint32(asnP),
						Type: typ,
					})
				}
			}
		}
	}
	return peers, nil
}

func LookupBulkIPs(ips []string) []ASNInfo {
	var results []ASNInfo
	for _, ip := range ips {
		if info, err := LookupIP(context.Background(), ip); err == nil {
			results = append(results, *info)
		}
	}
	return results
}

func dialWhois(ctx context.Context, host, query string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", host+":43")
	if err != nil {
		return nil, err
	}

	_, err = fmt.Fprintf(conn, "%s\r\n", query)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

func parseWhoisForASN(text string) *ASNInfo {
	info := &ASNInfo{}
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "origin:") || strings.HasPrefix(line, "Origin:"):
			o := strings.TrimPrefix(strings.TrimSpace(line[7:]), "AS")
			asn, err := strconv.ParseUint(o, 10, 32)
			if err == nil {
				info.ASN = uint32(asn)
			}
		case strings.HasPrefix(line, "descr:") || strings.HasPrefix(line, "Descr:"):
			if info.Name == "" {
				info.Name = strings.TrimSpace(line[6:])
			} else {
				info.Description = strings.TrimSpace(line[6:])
			}
		case strings.HasPrefix(line, "country:") || strings.HasPrefix(line, "Country:"):
			info.Country = strings.TrimSpace(line[8:])
		case strings.HasPrefix(line, "route:") || strings.HasPrefix(line, "Route:") || strings.HasPrefix(line, "route6:"):
			if info.Prefix == "" {
				info.Prefix = strings.TrimSpace(line[6:])
			}
		case strings.HasPrefix(line, "source:") || strings.HasPrefix(line, "Source:"):
			info.Source = strings.TrimSpace(line[7:])
		}
	}
	return info
}

type LookupResult struct {
	ASN   uint32 `json:"asn"`
	IP    string `json:"ip"`
	CIDR  string `json:"cidr"`
	ISP   string `json:"isp"`
	Org   string `json:"org"`
}

type BGPSummary struct {
	ASN         uint32   `json:"asn"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Country     string   `json:"country"`
	Prefixes    []string `json:"prefixes"`
	PrefixCount int      `json:"prefix_count"`
	Peers       int      `json:"peers"`
	Source      string   `json:"source"`
}

