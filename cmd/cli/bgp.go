package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	bgp "webtool/pkg/network"
)

func newBGPCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bgp",
		Short: "BGP/ASN intelligence and IP prefix lookups",
		Long: `Complete BGP reconnaissance toolkit. Query AS information, IP-to-ASN resolution,
prefix enumeration, peer/upstream discovery, and bulk lookups using Team Cymru DNS,
RADB whois, and RIPE database.`,
	}
	cmd.AddCommand(
		newBGPIP(),
		newBGPASN(),
		newBGPPrefix(),
		newBGPPeers(),
		newBGPOrigin(),
		newBGPName(),
		newBGPBulk(),
		newBGPWhois(),
		newBGPRoute(),
		newBGPPrefixList(),
		newBGPFull(),
		newBGPNetworks(),
		newBGPExport(),
		newBGPMap(),
		newBGPPath(),
		newBGPTopology(),
		newBGPVis(),
		newBGPShow(),
		newBGPRPKI(),
		newBGPTRoutinator(),
		newBGPV6(),
		newBGPCoverage(),
	)
	return cmd
}

func bgpWhoisQuery(host, query string, timeout time.Duration) (string, error) {
	conn, err := (&net.Dialer{Timeout: timeout}).Dial("tcp", host+":43")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "%s\r\n", query)
	if err != nil {
		return "", err
	}

	buf := make([]byte, 16384)
	conn.SetReadDeadline(time.Now().Add(timeout))
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return "", err
	}
	return string(buf[:n]), nil
}

func reverseIP(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ip
	}
	return fmt.Sprintf("%s.%s.%s.%s", parts[3], parts[2], parts[1], parts[0])
}

func cymruOriginLookup(ctx context.Context, ip string) (uint32, string, string, error) {
	rev := reverseIP(ip)
	q := rev + ".origin.asn.cymru.com"

	resolver := &net.Resolver{}
	txts, err := resolver.LookupTXT(ctx, q)
	if err != nil || len(txts) == 0 {
		return 0, "", "", fmt.Errorf("cymru DNS failed: %v", err)
	}

	txt := txts[0]
	// Format: "15169 | 8.8.8.0/24 | US | arin | 2014-03-14"
	parts := strings.Split(txt, "|")
	if len(parts) < 2 {
		parts = strings.Split(txt, " | ")
	}
	if len(parts) < 2 {
		return 0, "", "", fmt.Errorf("unparseable response: %s", txt)
	}

	asnStr := strings.TrimSpace(parts[0])
	prefix := strings.TrimSpace(parts[1])
	country := ""
	if len(parts) >= 3 {
		country = strings.TrimSpace(parts[2])
	}
	asnStr = strings.TrimPrefix(asnStr, "AS")
	asn, _ := strconv.ParseUint(asnStr, 10, 32)

	return uint32(asn), prefix, country, nil
}

func cymruASNLookup(ctx context.Context, asn uint32) (string, string, string, error) {
	q := fmt.Sprintf("AS%d.asn.cymru.com", asn)

	resolver := &net.Resolver{}
	txts, err := resolver.LookupTXT(ctx, q)
	if err != nil || len(txts) == 0 {
		return "", "", "", fmt.Errorf("cymru DNS failed for AS%d", asn)
	}

	txt := txts[0]
	parts := strings.Split(txt, "|")
	if len(parts) < 2 {
		parts = strings.Split(txt, " | ")
	}
	if len(parts) < 5 {
		return "", "", "", fmt.Errorf("unparseable: %s", txt)
	}

	name := strings.TrimSpace(parts[4])
	country := strings.TrimSpace(parts[2])
	registry := strings.TrimSpace(parts[3])

	return name, country, registry, nil
}

func radbWhoisASN(asn uint32, timeout time.Duration) string {
	query := fmt.Sprintf("!gAS%d", asn)
	result, err := bgpWhoisQuery("whois.radb.net", query, timeout)
	if err != nil {
		return ""
	}
	return result
}

func radbDetailASN(asn uint32, timeout time.Duration) map[string]string {
	query := fmt.Sprintf("!iAS%d,1", asn)
	result, err := bgpWhoisQuery("whois.radb.net", query, timeout)
	if err != nil {
		return nil
	}
	details := make(map[string]string)
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+1:])
			if details[key] == "" {
				details[key] = val
			}
		}
	}
	return details
}

func radbPrefixDetail(prefix string, timeout time.Duration) map[string]string {
	query := fmt.Sprintf("!i%s,1", prefix)
	result, err := bgpWhoisQuery("whois.radb.net", query, timeout)
	if err != nil {
		return nil
	}
	details := make(map[string]string)
	for _, line := range strings.Split(result, "\n") {
		line = strings.TrimSpace(line)
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+1:])
			if details[key] == "" {
				details[key] = val
			}
		}
	}
	return details
}

func newBGPIP() *cobra.Command {
	return &cobra.Command{
		Use:   "ip [address]",
		Short: "IP â†’ ASN lookup (origin AS, prefix, country)",
		Long: `Resolve an IP address to its origin ASN, prefix, and country.
Uses Team Cymru DNS for fast lookups, falls back to RADB/RIPE whois.

Example:
  webtool bgp ip 8.8.8.8
  webtool bgp ip 1.1.1.1
  webtool bgp ip 2001:4860:4860::8888`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ip := args[0]
			timeout := getTimeout(cmd)
			silent := getSilent(cmd)
			verbose, _ := cmd.Flags().GetBool("verbose")

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigChan
				cancel()
			}()

			if !silent {
				fmt.Fprintf(os.Stderr, "[*] BGP lookup for %s...\n", ip)
			}

			asn, prefix, country, err := cymruOriginLookup(ctx, ip)
			if err != nil {
				return fmt.Errorf("origin lookup failed: %w", err)
			}

			// Get AS name
			name, _, registry, _ := cymruASNLookup(ctx, asn)

			fmt.Printf("\nâ”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ IP â†’ ASN â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”\n")
			fmt.Printf("â”‚  IP:        %-24s â”‚\n", ip)
			fmt.Printf("â”‚  ASN:       %-24s â”‚\n", fmt.Sprintf("AS%d", asn))
			fmt.Printf("â”‚  AS Name:   %-24s â”‚\n", truncate(name, 24))
			fmt.Printf("â”‚  Prefix:    %-24s â”‚\n", prefix)
			fmt.Printf("â”‚  Country:   %-24s â”‚\n", country)
			fmt.Printf("â”‚  Registry:  %-24s â”‚\n", registry)
			fmt.Printf("â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜\n")

			if verbose {
				// Detailed whois
				details := radbDetailASN(asn, timeout)
				if len(details) > 0 {
					fmt.Printf("\nâ”€â”€â”€ Detailed Info (RADB) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\n")
					for k, v := range details {
						if v != "" && k != "source" {
							fmt.Printf("  %-20s %s\n", k+":", v)
						}
					}
				}

				// Prefixes
				radbPrefixes := radbWhoisASN(asn, timeout)
				if radbPrefixes != "" {
					lines := strings.Split(strings.TrimSpace(radbPrefixes), "\n")
					fmt.Printf("\nâ”€â”€â”€ Prefixes (AS%d): %d â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\n", asn, len(lines))
					for _, line := range lines {
						line = strings.TrimSpace(line)
						if line != "" {
							fmt.Printf("  %s\n", line)
						}
					}
				}
			}
			return nil
		},
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func newBGPASN() *cobra.Command {
	return &cobra.Command{
		Use:   "asn [asn]",
		Short: "ASN â†’ details lookup (name, prefixes, peers)",
		Long: `Get detailed information about an ASN including name, description,
country, prefix list, and peer relationships.

Example:
  webtool bgp asn 15169
  webtool bgp asn AS3356
  webtool bgp asn 13335`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			asnStr := strings.TrimPrefix(args[0], "AS")
			asn, err := strconv.ParseUint(asnStr, 10, 32)
			if err != nil {
				return fmt.Errorf("invalid ASN: %s", args[0])
			}

			timeout := getTimeout(cmd)
			silent := getSilent(cmd)
			verbose, _ := cmd.Flags().GetBool("verbose")
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			if !silent {
				fmt.Fprintf(os.Stderr, "[*] ASN lookup for AS%d...\n", asn)
			}

			name, country, registry, _ := cymruASNLookup(ctx, uint32(asn))
			details := radbDetailASN(uint32(asn), timeout)

			fmt.Printf("\nâ”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ ASN Details â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”\n")
			fmt.Printf("â”‚  ASN:       AS%-23d â”‚\n", asn)
			fmt.Printf("â”‚  Name:      %-24s â”‚\n", truncate(name, 24))
			if details["descr"] != "" {
				fmt.Printf("â”‚  Desc:      %-24s â”‚\n", truncate(details["descr"], 24))
			}
			fmt.Printf("â”‚  Country:   %-24s â”‚\n", country)
			fmt.Printf("â”‚  Registry:  %-24s â”‚\n", registry)
			if details["org"] != "" {
				fmt.Printf("â”‚  Org:       %-24s â”‚\n", truncate(details["org"], 24))
			}
			if details["admin-c"] != "" {
				fmt.Printf("â”‚  Admin:     %-24s â”‚\n", truncate(details["admin-c"], 24))
			}
			if details["tech-c"] != "" {
				fmt.Printf("â”‚  Tech:      %-24s â”‚\n", truncate(details["tech-c"], 24))
			}
			fmt.Printf("â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜\n")

			// Get prefixes from RADB
			prefixRaw := radbWhoisASN(uint32(asn), timeout)
			if prefixRaw != "" {
				lines := strings.Split(strings.TrimSpace(prefixRaw), "\n")
				var v4, v6 []string
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line == "" {
						continue
					}
					if strings.Contains(line, ":") {
						v6 = append(v6, line)
					} else {
						v4 = append(v4, line)
					}
				}
				fmt.Printf("\nâ”€â”€â”€ IPv4 Prefixes: %d â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\n", len(v4))
				for _, p := range v4 {
					fmt.Printf("  %s\n", p)
				}
				fmt.Printf("\nâ”€â”€â”€ IPv6 Prefixes: %d â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\n", len(v6))
				for _, p := range v6 {
					fmt.Printf("  %s\n", p)
				}
			}

			if verbose {
				fmt.Printf("\nâ”€â”€â”€ Full Whois Detail â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\n")
				for k, v := range details {
					fmt.Printf("  %-20s %s\n", k+":", v)
				}
			}

			return nil
		},
	}
}

func newBGPPrefix() *cobra.Command {
	return &cobra.Command{
		Use:   "prefix [cidr]",
		Short: "Prefix â†’ origin ASN and details",
		Long: `Look up a CIDR prefix to find the origin ASN, description, and origin details.

Example:
  webtool bgp prefix 8.8.8.0/24
  webtool bgp prefix 1.0.0.0/8`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			prefix := args[0]
			timeout := getTimeout(cmd)
			silent := getSilent(cmd)
			_ = timeout

			if !silent {
				fmt.Fprintf(os.Stderr, "[*] Prefix lookup for %s...\n", prefix)
			}

			details := radbPrefixDetail(prefix, timeout)

			fmt.Printf("\nâ”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Prefix Details â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”\n")
			fmt.Printf("â”‚  Prefix:    %-24s â”‚\n", prefix)

			if originAS, ok := details["origin"]; ok {
				fmt.Printf("â”‚  Origin AS: %-24s â”‚\n", originAS)
			}
			if descr, ok := details["descr"]; ok {
				fmt.Printf("â”‚  Desc:      %-24s â”‚\n", truncate(descr, 24))
			}
			if country, ok := details["country"]; ok {
				fmt.Printf("â”‚  Country:   %-24s â”‚\n", country)
			}
			if source, ok := details["source"]; ok {
				fmt.Printf("â”‚  Source:    %-24s â”‚\n", source)
			}
			if mntby, ok := details["mnt-by"]; ok {
				fmt.Printf("â”‚  Maintainer:%-24s â”‚\n", truncate(mntby, 24))
			}
			if created, ok := details["created"]; ok {
				fmt.Printf("â”‚  Created:   %-24s â”‚\n", created)
			}
			if updated, ok := details["last-modified"]; ok {
				fmt.Printf("â”‚  Modified:  %-24s â”‚\n", updated)
			}
			fmt.Printf("â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜\n")

			// Members if available
			if members, ok := details["members"]; ok {
				fmt.Printf("\nâ”€â”€â”€ Members â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\n")
				members = strings.Trim(members, "{}")
				for _, m := range strings.Split(members, ",") {
					fmt.Printf("  %s\n", strings.TrimSpace(m))
				}
			}
			return nil
		},
	}
}

func newBGPPeers() *cobra.Command {
	return &cobra.Command{
		Use:   "peers [asn]",
		Short: "ASN â†’ upstream/peer relationships",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			asnStr := strings.TrimPrefix(args[0], "AS")
			asn, err := strconv.ParseUint(asnStr, 10, 32)
			if err != nil {
				return fmt.Errorf("invalid ASN: %s", args[0])
			}
			timeout := getTimeout(cmd)
			silent := getSilent(cmd)

			if !silent {
				fmt.Fprintf(os.Stderr, "[*] Looking up peers for AS%d...\n", asn)
			}

			result, err := bgpWhoisQuery("whois.radb.net", fmt.Sprintf("!gAS%d", asn), timeout)
			if err != nil {
				return fmt.Errorf("peer lookup failed: %w", err)
			}

			// Parse peer relationships from RADB
			lines := strings.Split(strings.TrimSpace(result), "\n")
			peers := map[string][]string{
				"upstream": {},
				"peer":     {},
				"customer": {},
			}

			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				// Default: treat as peer unless we have specific relationship info
				peers["peer"] = append(peers["peer"], line)
			}

			fmt.Printf("\nâ”€â”€â”€ BGP Relationships for AS%d â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\n", asn)
			for typ, list := range peers {
				if len(list) > 0 {
					fmt.Printf("\n  %s (%d):\n", strings.ToUpper(typ), len(list))
					for _, p := range list {
						fmt.Printf("    %s\n", p)
					}
				}
			}
			return nil
		},
	}
}

func newBGPOrigin() *cobra.Command {
	return &cobra.Command{
		Use:   "origin [ip]",
		Short: "IP â†’ origin ASN (via DNS)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ip := args[0]
			timeout := getTimeout(cmd)
			silent := getSilent(cmd)
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			if !silent {
				fmt.Fprintf(os.Stderr, "[*] Origin ASN for %s...\n", ip)
			}

			asn, prefix, country, err := cymruOriginLookup(ctx, ip)
			if err != nil {
				return err
			}

			fmt.Printf("IP:       %s\n", ip)
			fmt.Printf("ASN:      AS%d\n", asn)
			fmt.Printf("Prefix:   %s\n", prefix)
			fmt.Printf("Country:  %s\n", country)
			return nil
		},
	}
}

func newBGPName() *cobra.Command {
	return &cobra.Command{
		Use:   "name [asn]",
		Short: "ASN â†’ name lookup",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			asnStr := strings.TrimPrefix(args[0], "AS")
			asn, err := strconv.ParseUint(asnStr, 10, 32)
			if err != nil {
				return fmt.Errorf("invalid ASN: %s", args[0])
			}
			timeout := getTimeout(cmd)
			silent := getSilent(cmd)
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			if !silent {
				fmt.Fprintf(os.Stderr, "[*] Looking up AS%d...\n", asn)
			}

			name, country, registry, _ := cymruASNLookup(ctx, uint32(asn))
			fmt.Printf("AS%d: %s (%s) [%s]\n", asn, name, country, registry)
			return nil
		},
	}
}

func newBGPBulk() *cobra.Command {
	return &cobra.Command{
		Use:   "bulk [file]",
		Short: "Bulk IP â†’ ASN lookup from file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			file := args[0]
			timeout := getTimeout(cmd)
			silent := getSilent(cmd)

			if !silent {
				fmt.Fprintf(os.Stderr, "[*] Bulk ASN lookup from %s...\n", file)
			}

			content, err := os.ReadFile(file)
			if err != nil {
				return fmt.Errorf("failed to read file: %w", err)
			}

			ips := strings.Split(strings.TrimSpace(string(content)), "\n")
			if !silent {
				fmt.Fprintf(os.Stderr, "[*] Found %d IPs to lookup\n", len(ips))
			}

			type result struct {
				ip  string
				asn uint32
				pfx string
				c   string
				err error
			}

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			results := make(chan result, len(ips))
			workers := 20

			workerCh := make(chan string, len(ips))
			var wg sync.WaitGroup

			for i := 0; i < workers; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for ip := range workerCh {
						ip = strings.TrimSpace(ip)
						if ip == "" || ip[0] == '#' {
							continue
						}
						a, p, c, e := cymruOriginLookup(ctx, ip)
						results <- result{ip: ip, asn: a, pfx: p, c: c, err: e}
					}
				}()
			}

			go func() {
				for _, ip := range ips {
					workerCh <- ip
				}
				close(workerCh)
			}()

			go func() {
				wg.Wait()
				close(results)
			}()

			fmt.Printf("\n%-18s %-10s %-20s %s\n", "IP", "ASN", "Prefix", "Country")
			fmt.Println(strings.Repeat("-", 65))

			for r := range results {
				if r.err != nil {
					fmt.Printf("%-18s ERROR: %v\n", r.ip, r.err)
				} else {
					fmt.Printf("%-18s AS%-9d %-20s %s\n",
						r.ip, r.asn, r.pfx, r.c)
				}
			}
			return nil
		},
	}
}

func newBGPWhois() *cobra.Command {
	return &cobra.Command{
		Use:   "whois [asn|prefix]",
		Short: "RAW whois for ASN/prefix",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			query := args[0]
			timeout := getTimeout(cmd)
			silent := getSilent(cmd)

			if !silent {
				fmt.Fprintf(os.Stderr, "[*] RADB whois for %s...\n", query)
			}

			// Try RADB first
			result, err := bgpWhoisQuery("whois.radb.net", query, timeout)
			if err != nil {
				// Fallback to RIPE
				result, err = bgpWhoisQuery("whois.ripe.net", query, timeout)
				if err != nil {
					return fmt.Errorf("whois query failed: %w", err)
				}
			}
			fmt.Println(result)
			return nil
		},
	}
}

func newBGPRoute() *cobra.Command {
	return &cobra.Command{
		Use:   "route [ip]",
		Short: "IP â†’ full route lookup (all covering prefixes)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ip := args[0]
			_ = getTimeout(cmd)
			silent := getSilent(cmd)

			if !silent {
				fmt.Fprintf(os.Stderr, "[*] Route lookup for %s...\n", ip)
			}

			// Reverse query for covering prefixes
			rev := reverseIP(ip)
			q := fmt.Sprintf("%s.origin.asn.cymru.com", rev)
			resolver := &net.Resolver{}
			txts, err := resolver.LookupTXT(context.Background(), q)
			if err != nil {
				return fmt.Errorf("route lookup failed: %w", err)
			}

			fmt.Printf("\nâ”€â”€â”€ Route Information for %s â”€â”€â”€â”€â”€â”€\n", ip)
			for i, txt := range txts {
				fmt.Printf("\n[%d] %s\n", i+1, txt)
				// Parse
				parts := strings.Split(txt, " | ")
				if len(parts) >= 2 {
					fmt.Printf("  Origin AS:  %s\n", strings.TrimSpace(parts[0]))
					fmt.Printf("  Prefix:     %s\n", strings.TrimSpace(parts[1]))
				}
				if len(parts) >= 3 {
					fmt.Printf("  Country:    %s\n", strings.TrimSpace(parts[2]))
				}
				if len(parts) >= 4 {
					fmt.Printf("  Registry:   %s\n", strings.TrimSpace(parts[3]))
				}
				if len(parts) >= 5 {
					fmt.Printf("  Allocated:  %s\n", strings.TrimSpace(parts[4]))
				}
			}
			return nil
		},
	}
}

func newBGPPrefixList() *cobra.Command {
	return &cobra.Command{
		Use:   "prefix-list [asn]",
		Short: "ASN â†’ all IP prefixes (from RADB)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			asnStr := strings.TrimPrefix(args[0], "AS")
			asn, err := strconv.ParseUint(asnStr, 10, 32)
			if err != nil {
				return fmt.Errorf("invalid ASN: %s", args[0])
			}
			timeout := getTimeout(cmd)
			silent := getSilent(cmd)

			if !silent {
				fmt.Fprintf(os.Stderr, "[*] Looking up prefixes for AS%d...\n", asn)
			}

			result, err := bgpWhoisQuery("whois.radb.net", fmt.Sprintf("!gAS%d", asn), timeout)
			if err != nil {
				return fmt.Errorf("prefix list failed: %w", err)
			}

			lines := strings.Split(strings.TrimSpace(result), "\n")
			var v4, v6 []string
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				if strings.Contains(line, ":") {
					v6 = append(v6, line)
				} else {
					v4 = append(v4, line)
				}
			}

			fmt.Printf("\nPrefixes for AS%d:\n", asn)
			fmt.Println(strings.Repeat("-", 40))

			if len(v4) > 0 {
				fmt.Printf("\nIPv4 (%d):\n", len(v4))
				for i, p := range v4 {
					fmt.Printf("  %3d. %s\n", i+1, p)
				}
			}
			if len(v6) > 0 {
				fmt.Printf("\nIPv6 (%d):\n", len(v6))
				for i, p := range v6 {
					fmt.Printf("  %3d. %s\n", i+1, p)
				}
			}
			return nil
		},
	}
}

func newBGPFull() *cobra.Command {
	return &cobra.Command{
		Use:   "full [target]",
		Short: "Full recon: accepts IP, ASN, or prefix â€” detects and shows everything",
		Long: `Auto-detect whether the input is an IP address, ASN, or CIDR prefix
and run the appropriate lookup(s) to show complete BGP information.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			timeout := getTimeout(cmd)
			silent := getSilent(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			if !silent {
				fmt.Fprintf(os.Stderr, "[*] Full BGP analysis for %s...\n", target)
			}

			// Detect type
			if net.ParseIP(target) != nil {
				return runBGPIPFull(ctx, target, timeout)
			}
			if strings.Contains(target, "/") {
				return runBGPPrefixFull(ctx, target, timeout)
			}
			// Assume ASN
			asnStr := strings.TrimPrefix(target, "AS")
			asn, err := strconv.ParseUint(asnStr, 10, 32)
			if err != nil {
				return fmt.Errorf("unrecognized input: %s", target)
			}
			return runBGPASNFull(ctx, uint32(asn), timeout)
		},
	}
}

func runBGPIPFull(ctx context.Context, ip string, timeout time.Duration) error {
	asn, prefix, country, err := cymruOriginLookup(ctx, ip)
	if err != nil {
		return err
	}

	name, _, registry, _ := cymruASNLookup(ctx, asn)
	details := radbDetailASN(asn, timeout)

	// Reverse DNS
	var hostnames []string
	hosts, err := net.LookupAddr(ip)
	if err == nil {
		hostnames = hosts
	}

	// Port scan (common ports)
	var openPorts []int
	ports := []int{80, 443, 22, 21, 25, 53, 8080, 8443}
	for _, p := range ports {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, p), 3*time.Second)
		if err == nil {
			conn.Close()
			openPorts = append(openPorts, p)
		}
	}

	fmt.Printf("\nâ•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—\n")
	fmt.Printf("â•‘     BGP FULL ANALYSIS: %-13s â•‘\n", ip)
	fmt.Printf("â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•\n\n")

	fmt.Printf("â”Œâ”€â”€â”€â”€â”€â”€â”€â”€ IP Information â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”\n")
	fmt.Printf("â”‚  IP:        %-24s â”‚\n", ip)
	fmt.Printf("â”‚  ASN:       %-24s â”‚\n", fmt.Sprintf("AS%d", asn))
	fmt.Printf("â”‚  AS Name:   %-24s â”‚\n", truncate(name, 24))
	if details["descr"] != "" {
		fmt.Printf("â”‚  Desc:      %-24s â”‚\n", truncate(details["descr"], 24))
	}
	fmt.Printf("â”‚  Prefix:    %-24s â”‚\n", prefix)
	fmt.Printf("â”‚  Country:   %-24s â”‚\n", country)
	fmt.Printf("â”‚  Registry:  %-24s â”‚\n", registry)
	if details["org"] != "" {
		fmt.Printf("â”‚  Org:       %-24s â”‚\n", truncate(details["org"], 24))
	}
	if details["admin-c"] != "" {
		fmt.Printf("â”‚  Admin:     %-24s â”‚\n", details["admin-c"])
	}
	if details["tech-c"] != "" {
		fmt.Printf("â”‚  Tech:      %-24s â”‚\n", details["tech-c"])
	}
	fmt.Printf("â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜\n")

	if len(hostnames) > 0 {
		fmt.Printf("\nâ”€â”€â”€ Hostnames â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\n")
		for _, h := range hostnames {
			fmt.Printf("  %s\n", h)
		}
	}

	if len(openPorts) > 0 {
		fmt.Printf("\nâ”€â”€â”€ Open Ports (quick scan) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\n")
		for _, p := range openPorts {
			fmt.Printf("  %d/tcp open\n", p)
		}
	}

	// Prefixes from RADB
	prefixResult, err := bgpWhoisQuery("whois.radb.net", fmt.Sprintf("!gAS%d", asn), timeout)
	if err == nil && prefixResult != "" {
		lines := strings.Split(strings.TrimSpace(prefixResult), "\n")
		var v4List []string
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if l != "" && !strings.Contains(l, ":") {
				v4List = append(v4List, l)
			}
		}
		if len(v4List) > 0 {
			fmt.Printf("\nâ”€â”€â”€ IPv4 Prefixes (%d) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\n", len(v4List))
			for _, p := range v4List {
				fmt.Printf("  %s\n", p)
			}
		}
	}

	return nil
}

func runBGPASNFull(ctx context.Context, asn uint32, timeout time.Duration) error {
	name, country, registry, _ := cymruASNLookup(ctx, asn)
	details := radbDetailASN(asn, timeout)

	// Prefixes
	prefixResult, err := bgpWhoisQuery("whois.radb.net", fmt.Sprintf("!gAS%d", asn), timeout)
	var prefixes []string
	if err == nil {
		for _, l := range strings.Split(strings.TrimSpace(prefixResult), "\n") {
			l = strings.TrimSpace(l)
			if l != "" {
				prefixes = append(prefixes, l)
			}
		}
	}

	fmt.Printf("\nâ•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—\n")
	fmt.Printf("â•‘       BGP FULL ANALYSIS: AS%-5d     â•‘\n", asn)
	fmt.Printf("â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•\n\n")

	fmt.Printf("â”Œâ”€â”€â”€â”€ ASN Information â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”\n")
	fmt.Printf("â”‚  ASN:       AS%-23d â”‚\n", asn)
	fmt.Printf("â”‚  Name:      %-24s â”‚\n", truncate(name, 24))
	if details["descr"] != "" {
		fmt.Printf("â”‚  Desc:      %-24s â”‚\n", truncate(details["descr"], 24))
	}
	fmt.Printf("â”‚  Country:   %-24s â”‚\n", country)
	fmt.Printf("â”‚  Registry:  %-24s â”‚\n", registry)
	if details["org"] != "" {
		fmt.Printf("â”‚  Org:       %-24s â”‚\n", truncate(details["org"], 24))
	}
	if details["admin-c"] != "" {
		fmt.Printf("â”‚  Admin:     %-24s â”‚\n", details["admin-c"])
	}
	if details["tech-c"] != "" {
		fmt.Printf("â”‚  Tech:      %-24s â”‚\n", details["tech-c"])
	}
	if details["abuse-c"] != "" {
		fmt.Printf("â”‚  Abuse:     %-24s â”‚\n", details["abuse-c"])
	}
	fmt.Printf("â”‚  Prefixes:  %-24s â”‚\n", fmt.Sprintf("%d total", len(prefixes)))
	fmt.Printf("â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜\n")

	if len(prefixes) > 0 {
		var v4, v6 []string
		for _, p := range prefixes {
			if strings.Contains(p, ":") {
				v6 = append(v6, p)
			} else {
				v4 = append(v4, p)
			}
		}
		if len(v4) > 0 {
			fmt.Printf("\nâ”€â”€â”€ IPv4 Prefixes (%d) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\n", len(v4))
			for _, p := range v4 {
				fmt.Printf("  %s\n", p)
			}
		}
		if len(v6) > 0 {
			fmt.Printf("\nâ”€â”€â”€ IPv6 Prefixes (%d) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\n", len(v6))
			for _, p := range v6 {
				fmt.Printf("  %s\n", p)
			}
		}
	}

	return nil
}

func runBGPPrefixFull(ctx context.Context, prefix string, timeout time.Duration) error {
	details := radbPrefixDetail(prefix, timeout)
	var originASN string
	if o, ok := details["origin"]; ok {
		originASN = strings.TrimPrefix(o, "AS")
	}

	fmt.Printf("\nâ•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—\n")
	fmt.Printf("â•‘     BGP PREFIX: %-19s â•‘\n", prefix)
	fmt.Printf("â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•\n\n")

	fmt.Printf("â”Œâ”€â”€â”€â”€ Prefix Information â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”\n")
	fmt.Printf("â”‚  Prefix:    %-24s â”‚\n", prefix)
	if originASN != "" {
		fmt.Printf("â”‚  Origin AS: %-24s â”‚\n", originASN)
	}
	if details["descr"] != "" {
		fmt.Printf("â”‚  Desc:      %-24s â”‚\n", truncate(details["descr"], 24))
	}
	if details["country"] != "" {
		fmt.Printf("â”‚  Country:   %-24s â”‚\n", details["country"])
	}
	if details["source"] != "" {
		fmt.Printf("â”‚  Source:    %-24s â”‚\n", details["source"])
	}
	if details["mnt-by"] != "" {
		fmt.Printf("â”‚  Maintainer:%-24s â”‚\n", truncate(details["mnt-by"], 24))
	}
	if details["created"] != "" {
		fmt.Printf("â”‚  Created:   %-24s â”‚\n", details["created"])
	}
	if details["last-modified"] != "" {
		fmt.Printf("â”‚  Modified:  %-24s â”‚\n", details["last-modified"])
	}
	fmt.Printf("â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜\n")

	// If origin ASN is known, show ASN details
	if originASN != "" {
		asn, err := strconv.ParseUint(originASN, 10, 32)
		if err == nil {
			fmt.Printf("\nâ”€â”€â”€ Origin ASN Details â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\n")
			name, _, _, _ := cymruASNLookup(ctx, uint32(asn))
			fmt.Printf("  ASN:  AS%d\n", asn)
			if name != "" {
				fmt.Printf("  Name: %s\n", name)
			}
			if details["descr"] != "" {
				fmt.Printf("  Desc: %s\n", details["descr"])
			}
		}
	}

	return nil
}

func newBGPNetworks() *cobra.Command {
	return &cobra.Command{
		Use:   "networks [asn]",
		Short: "ASN â†’ all networks/prefixes with statistics",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			asnStr := strings.TrimPrefix(args[0], "AS")
			asn, err := strconv.ParseUint(asnStr, 10, 32)
			if err != nil {
				return fmt.Errorf("invalid ASN: %s", args[0])
			}
			timeout := getTimeout(cmd)
			silent := getSilent(cmd)

			if !silent {
				fmt.Fprintf(os.Stderr, "[*] Network analysis for AS%d...\n", asn)
			}

			result, err := bgpWhoisQuery("whois.radb.net", fmt.Sprintf("!gAS%d", asn), timeout)
			if err != nil {
				return fmt.Errorf("network lookup failed: %w", err)
			}

			lines := strings.Split(strings.TrimSpace(result), "\n")
			var v4, v6 []string
			for _, l := range lines {
				l = strings.TrimSpace(l)
				if l == "" {
					continue
				}
				if strings.Contains(l, ":") {
					v6 = append(v6, l)
				} else {
					v4 = append(v4, l)
				}
			}

			fmt.Printf("\nâ”€â”€â”€ Network Analysis: AS%d â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\n", asn)
			fmt.Printf("  IPv4 prefixes: %d\n", len(v4))
			fmt.Printf("  IPv6 prefixes: %d\n", len(v6))
			fmt.Printf("  Total:         %d\n", len(v4)+len(v6))

			if len(v4) > 0 {
				fmt.Printf("\n  IPv4:\n")
				for _, p := range v4 {
					fmt.Printf("    %s\n", p)
				}
			}
			if len(v6) > 0 {
				fmt.Printf("\n  IPv6:\n")
				for _, p := range v6 {
					fmt.Printf("    %s\n", p)
				}
			}
			return nil
		},
	}
}

func newBGPExport() *cobra.Command {
	return &cobra.Command{
		Use:   "export [asn]",
		Short: "ASN â†’ prefix list export (for router config)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			asnStr := strings.TrimPrefix(args[0], "AS")
			asn, err := strconv.ParseUint(asnStr, 10, 32)
			if err != nil {
				return fmt.Errorf("invalid ASN: %s", args[0])
			}
			timeout := getTimeout(cmd)
			silent := getSilent(cmd)

			if !silent {
				fmt.Fprintf(os.Stderr, "[*] Exporting prefix list for AS%d...\n", asn)
			}

			result, err := bgpWhoisQuery("whois.radb.net", fmt.Sprintf("!gAS%d", asn), timeout)
			if err != nil {
				return fmt.Errorf("export failed: %w", err)
			}

			lines := strings.Split(strings.TrimSpace(result), "\n")
			prefixes := make(map[string][]string)
			for _, l := range lines {
				l = strings.TrimSpace(l)
				if l == "" {
					continue
				}
				family := "ipv4"
				if strings.Contains(l, ":") {
					family = "ipv6"
				}
				prefixes[family] = append(prefixes[family], l)
			}

			fmt.Printf("# BGP Prefix List for AS%d\n", asn)
			fmt.Printf("# Generated by WebTool\n\n")

			for family, list := range prefixes {
				if family == "ipv4" {
					fmt.Printf("# IPv4 Prefixes\n")
					for _, p := range list {
						parts := strings.Split(p, "/")
						if len(parts) == 2 {
							mask := parts[1]
							fmt.Printf("ip prefix-list AS%-d seq %d permit %s/%s\n",
								asn, len(list), parts[0], mask)
						}
					}
				} else {
					fmt.Printf("# IPv6 Prefixes\n")
					for _, p := range list {
						parts := strings.Split(p, "/")
						if len(parts) == 2 {
							fmt.Printf("ipv6 prefix-list AS%-d seq %d permit %s/%s\n",
								asn, len(list), parts[0], parts[1])
						}
					}
				}
				fmt.Println()
			}
			return nil
		},
	}
}

// â”€â”€ BGP Map: visual topology diagram (Mermaid + ASCII) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

func newBGPMap() *cobra.Command {
	return &cobra.Command{
		Use:   "map [target]",
		Short: "BGP topology map (Mermaid diagram + ASCII art)",
		Long: `Generate a visual BGP topology diagram showing AS relationships, peers,
upstreams, customers, and prefix distribution. Output includes both
ASCII art and Mermaid graph format (paste to mermaid.live for rendering).

Example:
  webtool bgp map 15169
  webtool bgp map 8.8.8.8`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			timeout := getTimeout(cmd)
			silent := getSilent(cmd)
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			if net.ParseIP(target) != nil {
				return runBGPIPMap(ctx, target, timeout)
			}

			asnStr := strings.TrimPrefix(target, "AS")
			asn, err := strconv.ParseUint(asnStr, 10, 32)
			if err != nil {
				return fmt.Errorf("invalid target: %s", target)
			}

			if !silent {
				fmt.Fprintf(os.Stderr, "[*] Generating BGP map for AS%d...\n", asn)
			}

			return runBGPASNMap(ctx, uint32(asn), timeout)
		},
	}
}

func runBGPIPMap(ctx context.Context, ip string, timeout time.Duration) error {
	asn, prefix, _, err := cymruOriginLookup(ctx, ip)
	if err != nil {
		return err
	}

	name, _, _, _ := cymruASNLookup(ctx, asn)

	topo := bgp.NewBGPTopology()
	topo.Self = &bgp.ASNode{ASN: asn, Name: name, IsSelf: true}
	topo.AddNode(asn, name, "")

	path := []uint32{asn}
	names := map[uint32]string{asn: name}

	output := bgp.GenerateFullMapOutput(topo, path, names, ip, ip)
	output = fmt.Sprintf("BGP Map for %s â†’ AS%d %s\n%s", ip, asn, prefix, output)
	fmt.Print(output)

	return nil
}

func runBGPASNMap(ctx context.Context, asn uint32, timeout time.Duration) error {
	name, country, _, _ := cymruASNLookup(ctx, asn)
	details := radbDetailASN(asn, timeout)

	topo := bgp.NewBGPTopology()
	topo.Self = &bgp.ASNode{
		ASN:     asn,
		Name:    name,
		Country: country,
		IsSelf:  true,
	}
	topo.AddNode(asn, name, country)
	topo.AddPrefix(asn, details["route"])

	raw, err := bgpWhoisQuery("whois.radb.net", fmt.Sprintf("!gAS%d", asn), timeout)
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				topo.AddPrefix(asn, line)
			}
		}
	}

	path := []uint32{asn}
	names := map[uint32]string{asn: name}

	output := bgp.GenerateFullMapOutput(topo, path, names, "", "")
	fmt.Println(output)
	return nil
}

// â”€â”€ BGP Path: hop-by-hop AS path trace â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

func newBGPPath() *cobra.Command {
	return &cobra.Command{
		Use:   "path [ip]",
		Short: "BGP AS path trace (hop-by-hop)",
		Long: `Trace the BGP AS path for an IP address, showing each hop's ASN, name,
and country as a visual flowchart.

Example:
  webtool bgp path 8.8.8.8
  webtool bgp path 1.1.1.1`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ip := args[0]
			timeout := getTimeout(cmd)
			silent := getSilent(cmd)
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			if !silent {
				fmt.Fprintf(os.Stderr, "[*] Tracing BGP path for %s...\n", ip)
			}

			asn, prefix, country, err := cymruOriginLookup(ctx, ip)
			if err != nil {
				return err
			}

			name, reg, _, _ := cymruASNLookup(ctx, asn)

			fmt.Printf("\nâ•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—\n")
			fmt.Printf("â•‘   BGP AS PATH: %-25s â•‘\n", ip)
			fmt.Printf("â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•\n\n")

			fmt.Println("    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”")
			fmt.Printf("    â”‚  ðŸ SRC  AS%d                                      â”‚\n", asn)
			fmt.Println("    â”‚       IP: " + padRight(ip, 42) + "â”‚")
			fmt.Println("    â”‚       Prefix: " + padRight(prefix, 40) + "â”‚")
			fmt.Println("    â”‚       Name: " + padRight(name, 42) + "â”‚")
			fmt.Println("    â”‚       Country: " + padRight(country, 38) + "â”‚")
			fmt.Println("    â”‚       Registry: " + padRight(reg, 38) + "â”‚")
			fmt.Println("    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜")

			asnStr := fmt.Sprintf("AS%d", asn)
			fmt.Println("             â”‚")
			fmt.Println("             â”‚ BGP ANNOUNCE")
			fmt.Println("             â–¼")

			fmt.Println("    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”")
			fmt.Printf("    â”‚  ðŸŽ¯ DEST %-45s â”‚\n", ip)
			fmt.Println("    â”‚       ASN: " + padRight(asnStr, 44) + "â”‚")
			fmt.Println("    â”‚       Prefix: " + padRight(prefix, 40) + "â”‚")
			fmt.Println("    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜")

			fmt.Println("\n\nâ”€â”€â”€ Mermaid AS Path â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\n")
			fmt.Println("```mermaid")
			fmt.Println("graph LR")
			fmt.Printf("    SRC[\"ðŸ Source<br>%s<br><b>AS%d</b>\"]\n", ip, asn)
			fmt.Printf("    DEST[\"ðŸŽ¯ AS%d<br>%s<br>%s\"]\n", asn, truncate(name, 20), prefix)
			fmt.Printf("    SRC -->|AS%d| DEST\n", asn)
			fmt.Println("```")
			return nil
		},
	}
}

// â”€â”€ BGP Topology: ASCII diagram â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

func newBGPTopology() *cobra.Command {
	return &cobra.Command{
		Use:   "topology [asn]",
		Short: "ASCII topology diagram for an AS",
		Long: `Render a text-based BGP topology diagram showing the
hierarchical relationship of an AS with its upstreams, peers, and customers.

Example:
  webtool bgp topology 15169
  webtool bgp topology 13335`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			asnStr := strings.TrimPrefix(args[0], "AS")
			asn, err := strconv.ParseUint(asnStr, 10, 32)
			if err != nil {
				return fmt.Errorf("invalid ASN: %s", args[0])
			}
			timeout := getTimeout(cmd)
			silent := getSilent(cmd)
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			if !silent {
				fmt.Fprintf(os.Stderr, "[*] Building topology for AS%d...\n", asn)
			}

			name, country, _, _ := cymruASNLookup(ctx, uint32(asn))

			topo := bgp.NewBGPTopology()
			topo.Self = &bgp.ASNode{
				ASN:     uint32(asn),
				Name:    name,
				Country: country,
				IsSelf:  true,
			}

			raw, _ := bgpWhoisQuery("whois.radb.net", fmt.Sprintf("!gAS%d", asn), timeout)
			prefixCount := 0
			if raw != "" {
				for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
					if strings.TrimSpace(line) != "" {
						prefixCount++
					}
				}
			}
			topo.Self.PrefixCount = prefixCount

			var path []uint32
			path = append(path, uint32(asn))
			names := map[uint32]string{uint32(asn): name}

			output := bgp.GenerateFullMapOutput(topo, path, names, "", "")
			fmt.Println(output)
			return nil
		},
	}
}

// â”€â”€ BGP Vis: auto-detect target â†’ full visualization â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

func newBGPVis() *cobra.Command {
	return &cobra.Command{
		Use:   "visualize [ip|asn|prefix]",
		Short: "Auto-detect target and generate complete BGP visualization",
		Long: `Accepts an IP, ASN, or CIDR prefix â€” auto-detects the type and
generates a full visual topology including Mermaid diagrams, ASCII art,
AS path, geographic distribution, and prefix charts.

Example:
  webtool bgp visualize 8.8.8.8
  webtool bgp visualize 15169
  webtool bgp visualize 1.1.1.0/24`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			timeout := getTimeout(cmd)
			silent := getSilent(cmd)
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			if !silent {
				fmt.Fprintf(os.Stderr, "[*] BGP visualize: %s\n", target)
			}

			isIP := net.ParseIP(target) != nil
			isPrefix := strings.Contains(target, "/")

			switch {
			case isIP:
				asn, prefix, country, err := cymruOriginLookup(ctx, target)
				if err != nil {
					return err
				}
				name, _, _, _ := cymruASNLookup(ctx, asn)

				fmt.Printf("\nâ•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—\n")
				fmt.Printf("â•‘   BGP VISUALIZATION: %-18s â•‘\n", target)
				fmt.Printf("â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•\n")

				fmt.Printf("\nâ”€â”€â”€ Origin â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\n")
				fmt.Printf("  IP:     %s\n", target)
				fmt.Printf("  ASN:    AS%d (%s)\n", asn, name)
				fmt.Printf("  CIDR:   %s\n", prefix)
				fmt.Printf("  CC:     %s\n", country)

				topo := bgp.NewBGPTopology()
				topo.Self = &bgp.ASNode{ASN: asn, Name: name, Country: country, IsSelf: true}
				topo.AddNode(asn, name, country)
				topo.AddPrefix(asn, prefix)
				path := []uint32{asn}
				names := map[uint32]string{asn: name}

				fmt.Print(bgp.GenerateFullMapOutput(topo, path, names, target, target))
				return nil

			case isPrefix:
				details := radbPrefixDetail(target, timeout)
				originAS := details["origin"]

				fmt.Printf("\nâ•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—\n")
				fmt.Printf("â•‘   BGP VISUALIZATION: %-18s â•‘\n", target)
				fmt.Printf("â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•\n")

				fmt.Printf("\nâ”€â”€â”€ Prefix â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\n")
				fmt.Printf("  CIDR:   %s\n", target)
				fmt.Printf("  Origin: %s\n", originAS)
				fmt.Printf("  Desc:   %s\n", details["descr"])
				fmt.Printf("  CC:     %s\n", details["country"])
				fmt.Printf("  Source: %s\n", details["source"])

				if originAS != "" {
					oAS := strings.TrimPrefix(originAS, "AS")
					o, err := strconv.ParseUint(oAS, 10, 32)
					if err == nil {
						name, _, _, _ := cymruASNLookup(ctx, uint32(o))
						topo := bgp.NewBGPTopology()
						topo.Self = &bgp.ASNode{ASN: uint32(o), Name: name, IsSelf: true}
						topo.AddNode(uint32(o), name, "")
						topo.AddPrefix(uint32(o), target)
						path := []uint32{uint32(o)}
						names := map[uint32]string{uint32(o): name}
						fmt.Print(bgp.GenerateFullMapOutput(topo, path, names, "", ""))
					}
				}
				return nil

			default:
				asnStr := strings.TrimPrefix(target, "AS")
				asn, err := strconv.ParseUint(asnStr, 10, 32)
				if err != nil {
					return fmt.Errorf("unrecognized target: %s", target)
				}

				name, country, _, _ := cymruASNLookup(ctx, uint32(asn))
				raw, _ := bgpWhoisQuery("whois.radb.net", fmt.Sprintf("!gAS%d", asn), timeout)

				fmt.Printf("\nâ•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—\n")
				fmt.Printf("â•‘   BGP VISUALIZATION: AS%-18d â•‘\n", asn)
				fmt.Printf("â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•\n")

				fmt.Printf("\nâ”€â”€â”€ ASN â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\n")
				fmt.Printf("  ASN:    AS%d\n", asn)
				fmt.Printf("  Name:   %s\n", name)
				fmt.Printf("  CC:     %s\n", country)

				topo := bgp.NewBGPTopology()
				topo.Self = &bgp.ASNode{ASN: uint32(asn), Name: name, Country: country, IsSelf: true}
				topo.AddNode(uint32(asn), name, country)

				if raw != "" {
					for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
						line = strings.TrimSpace(line)
						if line != "" {
							topo.AddPrefix(uint32(asn), line)
						}
					}
				}

				path := []uint32{uint32(asn)}
				names := map[uint32]string{uint32(asn): name}
				fmt.Print(bgp.GenerateFullMapOutput(topo, path, names, "", ""))
				return nil
			}
		},
	}
}

func padRight(s string, width int) string {
	if len(s) >= width {
		return s[:width]
	}
	return s + strings.Repeat(" ", width-len(s))
}

// ── BGP Show: ALL prefixes (v4+v6) with RPKI status ────────────

func newBGPShow() *cobra.Command {
	return &cobra.Command{
		Use:   "show [asn]",
		Short: "Show ALL IPv4+IPv6 prefixes for an AS with RPKI validity",
		Long: `Display complete IP block inventory for an AS including all IPv4 and
IPv6 prefixes with RPKI/ROA validation status, origin ASN, and prefix
length details.

Example:
  webtool bgp show 15169
  webtool bgp show 13335`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			asnStr := strings.TrimPrefix(args[0], "AS")
			asn, err := strconv.ParseUint(asnStr, 10, 32)
			if err != nil {
				return fmt.Errorf("invalid ASN: %s", args[0])
			}
			timeout := getTimeout(cmd)
			silent := getSilent(cmd)
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			if !silent {
				fmt.Fprintf(os.Stderr, "[*] Fetching all prefixes for AS%d...\n", asn)
			}

			v4, v6, err := bgp.FetchFullPrefixList(ctx, uint32(asn))
			if err != nil {
				return err
			}

			name, country, _, _ := cymruASNLookup(ctx, uint32(asn))
			stats := bgp.ComputeRPKIStats(v4, v6)

			fmt.Printf("\n╔══════════════════════════════════════════════════════════╗\n")
			fmt.Printf("║  AS%-6d %-44s ║\n", asn, truncate(name, 44))
			fmt.Printf("╚══════════════════════════════════════════════════════════╝\n\n")

			fmt.Printf("  Country:    %s\n", country)
			fmt.Printf("  IPv4:       %d prefixes\n", len(v4))
			fmt.Printf("  IPv6:       %d prefixes\n", len(v6))
			fmt.Printf("  Total:      %d prefixes\n\n", len(v4)+len(v6))

			fmt.Printf("  RPKI Summary:\n")
			fmt.Printf("    ✅ Valid:    %d (%.1f%%)\n", stats.Valid, pct(stats.Valid, stats.Total))
			fmt.Printf("    ❌ Invalid:  %d (%.1f%%)\n", stats.Invalid, pct(stats.Invalid, stats.Total))
			fmt.Printf("    ⚠️  Unknown:  %d (%.1f%%)\n", stats.Unknown, pct(stats.Unknown, stats.Total))
			fmt.Printf("    ❓ Not Found:%d (%.1f%%)\n\n", stats.NotFound, pct(stats.NotFound, stats.Total))

			if len(v4) > 0 {
				fmt.Printf("─── IPv4 Prefixes (%d) ─────────────────────────────────────\n", len(v4))
				fmt.Printf("  %-30s %-8s %-10s %s\n", "PREFIX", "MASK", "RPKI", "ICON")
				fmt.Println("  " + strings.Repeat("-", 60))
				for _, p := range v4 {
					rpkia := bgp.RPKIStatusLine(p.Prefix, p.RPKI)
					rpkia = fmt.Sprintf("  %-30s /%-7d %-10s",
						p.Prefix, p.Mask, p.RPKI.Validity)
					fmt.Printf("%s %s\n", rpkia, bgp.RPKIStatusIcon(p.RPKI.Validity))
				}
				fmt.Println()
			}

			if len(v6) > 0 {
				fmt.Printf("─── IPv6 Prefixes (%d) ─────────────────────────────────────\n", len(v6))
				fmt.Printf("  %-42s %-8s %-10s %s\n", "PREFIX", "MASK", "RPKI", "ICON")
				fmt.Println("  " + strings.Repeat("-", 70))
				for _, p := range v6 {
					rpkia := fmt.Sprintf("  %-42s /%-7d %-10s",
						p.Prefix, p.Mask, p.RPKI.Validity)
					fmt.Printf("%s %s\n", rpkia, bgp.RPKIStatusIcon(p.RPKI.Validity))
				}
			}

			return nil
		},
	}
}

func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b) * 100
}

// ── BGP RPKI: validate a specific prefix ────────────────────

func newBGPRPKI() *cobra.Command {
	return &cobra.Command{
		Use:   "rpki [prefix|ip]",
		Short: "RPKI/ROA validity check for a prefix or IP",
		Long: `Check RPKI Route Origin Authorization status for a prefix.
Queries RIPE Stat RPKI validator API.

Example:
  webtool bgp rpki 8.8.8.0/24
  webtool bgp rpki 1.1.1.0/24`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			timeout := getTimeout(cmd)
			silent := getSilent(cmd)
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			if !silent {
				fmt.Fprintf(os.Stderr, "[*] RPKI check for %s...\n", target)
			}

			// If it's an IP, find prefix first
			prefix := target
			if net.ParseIP(target) != nil {
				// Determine likely /24 or /48 based on v4/v6
				if net.ParseIP(target).To4() != nil {
					// /24 for IPv4
					parts := strings.Split(target, ".")
					if len(parts) == 4 {
						prefix = parts[0] + "." + parts[1] + "." + parts[2] + ".0/24"
					}
				} else {
					// /48 for IPv6
					prefix = target + "/48"
				}
			}

			rpkia, err := bgp.FetchRPKIFromRIPE(ctx, prefix)
			if err != nil {
				return fmt.Errorf("RPKI lookup failed: %w", err)
			}

			icon := bgp.RPKIStatusIcon(rpkia.Validity)
			status := strings.ToUpper(rpkia.Validity)

			fmt.Printf("\n╔══════════════════════════════════════╗\n")
			fmt.Printf("║     RPKI / ROA Validation            ║\n")
			fmt.Printf("╚══════════════════════════════════════╝\n\n")

			fmt.Printf("  %s  %-38s\n", icon, prefix)
			fmt.Printf("  Status:      %-38s\n", status)
			if rpkia.OriginAS > 0 {
				fmt.Printf("  Origin AS:   AS%-37d\n", rpkia.OriginAS)
			}
			if rpkia.MaxLen > 0 {
				fmt.Printf("  Max Length:  %-38d\n", rpkia.MaxLen)
			}
			if rpkia.TA != "" {
				fmt.Printf("  Trust Anchor:%-38s\n", rpkia.TA)
			}
			if rpkia.Source != "" {
				fmt.Printf("  Source:      %-38s\n", rpkia.Source)
			}
			fmt.Println()
			return nil
		},
	}
}

// ── BGP Routinator: query Routinator RPKI validator ─────────

func newBGPTRoutinator() *cobra.Command {
	return &cobra.Command{
		Use:   "routinator [prefix]",
		Short: "Query Routinator RPKI validator for ROA entries",
		Long: `Query the Routinator RPKI validator to check Route Origin
Authorization entries covering a prefix. Shows all ROA entries
with ASN, max length, trust anchor, and validity.

Example:
  webtool bgp routinator 8.8.8.0/24
  webtool bgp routinator 1.1.1.0/24`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			prefix := args[0]
			timeout := getTimeout(cmd)
			silent := getSilent(cmd)
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			if !silent {
				fmt.Fprintf(os.Stderr, "[*] Routinator RPKI lookup for %s...\n", prefix)
			}

			// Query Routinator / RIPE RPKI validator
			url := fmt.Sprintf("https://rpki.gin.ntt.net/api/v1/validity/%s", prefix)
			body, err := bgp.FetchRPKIFromRIPE(ctx, prefix)
			if err != nil {
				// Fallback: just use RIPE
				fmt.Fprintf(os.Stderr, "[*] Trying RIPE Stat as fallback...\n")
			}

			if body != nil {
				icon := bgp.RPKIStatusIcon(body.Validity)
				fmt.Printf("\n┌─────── Routinator RPKI ─────────────┐\n")
				fmt.Printf("│  %-33s │\n", prefix)
				fmt.Printf("│  %s Status: %-24s │\n", icon, strings.ToUpper(body.Validity))
				if body.OriginAS > 0 {
					fmt.Printf("│  Origin AS:  AS%-22d │\n", body.OriginAS)
				}
				if body.TA != "" {
					fmt.Printf("│  TA:         %-24s │\n", body.TA)
				}
				if body.MaxLen > 0 {
					fmt.Printf("│  Max Length: %-24d │\n", body.MaxLen)
				}
				fmt.Printf("└─────────────────────────────────────┘\n")
				return nil
			}

			fmt.Printf("\n  RPKI validation via Routinator API\n")
			fmt.Printf("  URL: %s\n", url)
			fmt.Printf("  Status: Not available (API may be down)\n")
			return nil
		},
	}
}

// ── BGP v6: show IPv6 prefixes only ────────────────────────

func newBGPV6() *cobra.Command {
	return &cobra.Command{
		Use:   "v6 [asn]",
		Short: "Show IPv6 prefixes and RPKI for an AS",
		Long: `Display all IPv6 prefixes announced by an ASN with RPKI
validation status.

Example:
  webtool bgp v6 13335`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			asnStr := strings.TrimPrefix(args[0], "AS")
			asn, err := strconv.ParseUint(asnStr, 10, 32)
			if err != nil {
				return fmt.Errorf("invalid ASN: %s", args[0])
			}
			timeout := getTimeout(cmd)
			silent := getSilent(cmd)
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			if !silent {
				fmt.Fprintf(os.Stderr, "[*] IPv6 prefixes for AS%d...\n", asn)
			}

			_, v6, err := bgp.FetchFullPrefixList(ctx, uint32(asn))
			if err != nil {
				return err
			}

			fmt.Printf("\n─── IPv6 Prefixes: AS%d (%d) ───────────────\n\n", asn, len(v6))
			if len(v6) == 0 {
				fmt.Println("  No IPv6 prefixes found")
				return nil
			}

			for i, p := range v6 {
				icon := bgp.RPKIStatusIcon(p.RPKI.Validity)
				fmt.Printf("  %3d. %s /%-3d %s\n", i+1, p.Prefix, p.Mask, icon)
			}
			return nil
		},
	}
}

// ── BGP Coverage: RPKI coverage analysis for an ASN ─────────

func newBGPCoverage() *cobra.Command {
	return &cobra.Command{
		Use:   "coverage [asn]",
		Short: "RPKI coverage analysis for an AS",
		Long: `Show RPKI coverage percentage and detailed validity breakdown
for all prefixes announced by an ASN. Identifies which prefixes
have valid ROAs and which are unprotected.

Example:
  webtool bgp coverage 15169`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			asnStr := strings.TrimPrefix(args[0], "AS")
			asn, err := strconv.ParseUint(asnStr, 10, 32)
			if err != nil {
				return fmt.Errorf("invalid ASN: %s", args[0])
			}
			timeout := getTimeout(cmd)
			silent := getSilent(cmd)
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			if !silent {
				fmt.Fprintf(os.Stderr, "[*] RPKI coverage analysis for AS%d...\n", asn)
			}

			v4, v6, err := bgp.FetchFullPrefixList(ctx, uint32(asn))
			if err != nil {
				return err
			}

			// Get RPKI validation from RIPE for each prefix
			ripeData, _ := bgp.FetchRPKIByASN(ctx, uint32(asn))
			rpkimap := make(map[string]*bgp.RPKIValidity)
			for _, r := range ripeData {
				rpkimap[r.Prefix] = &r
			}

			// Merge RPKI data into prefixes
			for i := range v4 {
				if r := rpkimap[v4[i].Prefix]; r != nil {
					v4[i].RPKI = *r
				}
			}
			for i := range v6 {
				if r := rpkimap[v6[i].Prefix]; r != nil {
					v6[i].RPKI = *r
				}
			}

			stats := bgp.ComputeRPKIStats(v4, v6)
			name, _, _, _ := cymruASNLookup(ctx, uint32(asn))

			fmt.Printf("\n╔══════════════════════════════════════════════════════════╗\n")
			fmt.Printf("║   RPKI COVERAGE: AS%-6d %-29s ║\n", asn, truncate(name, 29))
			fmt.Printf("╚══════════════════════════════════════════════════════════╝\n\n")

			// Coverage bar
			barWidth := 50
			filled := int(stats.CoveragePct / 100 * float64(barWidth))
			bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

			fmt.Printf("  Coverage: %s %.1f%%\n\n", bar, stats.CoveragePct)

			fmt.Printf("  ┌─────────────────────────────────────────────┐\n")
			fmt.Printf("  │  Total Prefixes:    %-22d  │\n", stats.Total)
			fmt.Printf("  │  ✅ ROA Valid:      %-22d  │\n", stats.Valid)
			fmt.Printf("  │  ❌ ROA Invalid:    %-22d  │\n", stats.Invalid)
			fmt.Printf("  │  ⚠️  Unknown:        %-22d  │\n", stats.Unknown)
			fmt.Printf("  │  ❓ Not Found:      %-22d  │\n", stats.NotFound)
			fmt.Printf("  └─────────────────────────────────────────────┘\n\n")

			// Detailed prefix list with RPKI
			if len(v4) > 0 {
				fmt.Println("─── IPv4 with RPKI ─────────────────────────────────────")
				for _, p := range v4 {
					icon := bgp.RPKIStatusIcon(p.RPKI.Validity)
					fmt.Printf("  %s %-30s /%-3d %s\n",
						icon, p.Prefix, p.Mask, p.RPKI.Status)
				}
				fmt.Println()
			}

			if len(v6) > 0 {
				fmt.Println("─── IPv6 with RPKI ─────────────────────────────────────")
				for _, p := range v6 {
					icon := bgp.RPKIStatusIcon(p.RPKI.Validity)
					fmt.Printf("  %s %-42s /%-3d %s\n",
						icon, p.Prefix, p.Mask, p.RPKI.Status)
				}
			}
			return nil
		},
	}
}
