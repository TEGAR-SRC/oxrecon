package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

// ── DNS Security: SPF, DMARC, DKIM ──────────────────────────

func newDNSSecurityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "security",
		Short: "DNS security analysis (SPF, DMARC, DKIM)",
	}
	cmd.AddCommand(
		newDNSSPFCmd(),
		newDNSDMARCCmd(),
		newDNSDKIMCmd(),
		newDNSALookupCmd(),
		newDNSAAAA(),
	)
	return cmd
}

func newDNSSPFCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "spf [domain]",
		Short: "Parse and analyze SPF record",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return parseTXTRecord(cmd, args[0], "spf")
		},
	}
}

func newDNSDMARCCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "dmarc [domain]",
		Short: "Parse and analyze DMARC record",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return parseTXTRecord(cmd, args[0], "dmarc")
		},
	}
}

func newDNSDKIMCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "dkim [domain]",
		Short: "Look up DKIM records for common selectors",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)
			silent := getSilent(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			if !silent {
				fmt.Fprintf(os.Stderr, "[*] DKIM lookup for %s...\n", domain)
			}

			selectors := []string{
				"default", "google", "selector1", "selector2",
				"k1", "k2", "mandrill", "dkim", "s1", "s2",
				"protonmail", "mxvault", "everlytickey1", "everlytickey2",
				"zoho", "mail", "smtp", "outlook", "exchange",
			}

			var found []string
			for _, sel := range selectors {
				if ctx.Err() != nil {
					break
				}
				qname := fmt.Sprintf("%s._domainkey.%s", sel, domain)
				ips, err := net.DefaultResolver.LookupTXT(ctx, qname)
				if err == nil && len(ips) > 0 {
					found = append(found, fmt.Sprintf("  selector: %-20s %s", sel, truncate(ips[0], 60)))
				}
			}

			if len(found) == 0 {
				fmt.Printf("No DKIM records found for %s\n", domain)
			} else {
				fmt.Printf("\nDKIM records for %s (%d found):\n", domain, len(found))
				for _, f := range found {
					fmt.Println(f)
				}
			}
			return nil
		},
	}
}

func newDNSALookupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "a [domain]",
		Short: "DNS A record lookup",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			ips, err := net.DefaultResolver.LookupHost(ctx, domain)
			if err != nil {
				return err
			}
			for _, ip := range ips {
				fmt.Println(ip)
			}
			return nil
		},
	}
}

func newDNSAAAA() *cobra.Command {
	return &cobra.Command{
		Use:   "aaaa [domain]",
		Short: "DNS AAAA (IPv6) lookup",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)

			r := &dns.Msg{}
			r.SetQuestion(dns.Fqdn(domain), dns.TypeAAAA)
			r.RecursionDesired = true

			c := &dns.Client{Timeout: timeout}
			resp, _, err := c.Exchange(r, "8.8.8.8:53")
			if err != nil {
				return err
			}

			for _, ans := range resp.Answer {
				if a, ok := ans.(*dns.AAAA); ok {
					fmt.Println(a.AAAA.String())
				}
			}
			return nil
		},
	}
}

func parseTXTRecord(cmd *cobra.Command, domain string, lookupType string) error {
	timeout := getTimeout(cmd)
	silent := getSilent(cmd)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_ = ctx

	if !silent {
		fmt.Fprintf(os.Stderr, "[*] %s lookup for %s...\n", strings.ToUpper(lookupType), domain)
	}

	servers := []string{"8.8.8.8:53", "1.1.1.1:53"}
	qtype := dns.TypeTXT
	qname := domain

	if lookupType == "dmarc" {
		qname = "_dmarc." + domain
	} else if lookupType == "dkim" {
		qname = "default._domainkey." + domain
	}

	var records []string
	for _, server := range servers {
		r := new(dns.Msg)
		r.SetQuestion(dns.Fqdn(qname), qtype)
		r.RecursionDesired = true

		c := new(dns.Client)
		c.Timeout = timeout
		resp, _, err := c.Exchange(r, server)
		if err != nil {
			continue
		}

		for _, ans := range resp.Answer {
			if txt, ok := ans.(*dns.TXT); ok {
				records = append(records, strings.Join(txt.Txt, " "))
			}
		}
		if len(records) > 0 {
			break
		}
	}

	if len(records) == 0 {
		fmt.Printf("No %s records found for %s\n", strings.ToUpper(lookupType), domain)
		return nil
	}

	fmt.Printf("\n%s Record for %s:\n", strings.ToUpper(lookupType), domain)
	fmt.Println(strings.Repeat("-", 60))

	for i, rec := range records {
		fmt.Printf("[%d] %s\n\n", i+1, rec)

		// Parse and analyze
		switch lookupType {
		case "spf":
			analyzeSPF(rec)
		case "dmarc":
			analyzeDMARC(rec)
		}
	}
	return nil
}

func analyzeSPF(spf string) {
	fmt.Println("  Analysis:")
	spf = strings.TrimPrefix(spf, "v=spf1 ")
	parts := strings.Fields(spf)

	mechanisms := map[string]int{
		"include": 0, "a": 0, "mx": 0, "ip4": 0, "ip6": 0,
		"all": 0, "exists": 0, "redirect": 0,
	}
	includes := []string{}

	for _, p := range parts {
		if strings.HasPrefix(p, "include:") {
			mechanisms["include"]++
			includes = append(includes, strings.TrimPrefix(p, "include:"))
		} else if strings.HasPrefix(p, "ip4:") {
			mechanisms["ip4"]++
		} else if strings.HasPrefix(p, "ip6:") {
			mechanisms["ip6"]++
		} else if strings.HasPrefix(p, "a") {
			mechanisms["a"]++
		} else if strings.HasPrefix(p, "mx") {
			mechanisms["mx"]++
		} else if strings.HasPrefix(p, "exists:") {
			mechanisms["exists"]++
		} else if strings.HasPrefix(p, "~all") || strings.HasPrefix(p, "-all") || strings.HasPrefix(p, "+all") || p == "all" {
			mechanisms["all"]++
		}
	}

	for k, v := range mechanisms {
		if v > 0 {
			fmt.Printf("    %-10s %d\n", k+":", v)
		}
	}
	if len(includes) > 0 {
		fmt.Printf("    Includes: %s\n", strings.Join(includes, ", "))
	}
}

func analyzeDMARC(dmarc string) {
	fmt.Println("  Analysis:")
	dmarc = strings.TrimPrefix(dmarc, "v=DMARC1;")
	parts := strings.Split(dmarc, ";")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "p=") {
			fmt.Printf("    Policy:   %s\n", strings.TrimPrefix(part, "p="))
		} else if strings.HasPrefix(part, "rua=") {
			fmt.Printf("    Aggregate: %s\n", strings.TrimPrefix(part, "rua="))
		} else if strings.HasPrefix(part, "ruf=") {
			fmt.Printf("    Forensic:  %s\n", strings.TrimPrefix(part, "ruf="))
		} else if strings.HasPrefix(part, "adkim=") {
			fmt.Printf("    DKIM Mode: %s\n", strings.TrimPrefix(part, "adkim="))
		} else if strings.HasPrefix(part, "aspf=") {
			fmt.Printf("    SPF Mode:  %s\n", strings.TrimPrefix(part, "aspf="))
		} else if strings.HasPrefix(part, "pct=") {
			fmt.Printf("    Percent:   %s\n", strings.TrimPrefix(part, "pct="))
		} else if strings.HasPrefix(part, "sp=") {
			fmt.Printf("    Subdomain Policy: %s\n", strings.TrimPrefix(part, "sp="))
		} else if strings.HasPrefix(part, "fo=") {
			fmt.Printf("    Failure Options: %s\n", strings.TrimPrefix(part, "fo="))
		}
	}
}
