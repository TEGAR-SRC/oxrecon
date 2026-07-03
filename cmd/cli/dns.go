package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

func newDNSCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dns",
		Short: "DNS reconnaissance and analysis",
		Long:  `Perform DNS lookups, reverse DNS, zone transfers, and DNS analysis.`,
	}

	cmd.AddCommand(
		newDNSLookupCmd(),
		newDNSReverseCmd(),
		newDNSMXCmd(),
		newDNSNSCmd(),
		newDNSTXTCmd(),
		newDNSSOACmd(),
		newDNSCAACmd(),
		newDNSCNAMECmd(),
		newDNSDNSSecCmd(),
		newDNSZoneCmd(),
		newDNSResolverCmd(),
		newDNSSecurityCmd(),
		newDNSALookupCmd(),
		newDNSAAAA(),
	)

	return cmd
}

func getTimeout(cmd *cobra.Command) time.Duration {
	d, _ := cmd.Flags().GetDuration("timeout")
	return d
}

func getSilent(cmd *cobra.Command) bool {
	s, _ := cmd.Flags().GetBool("silent")
	return s
}

func getOutputFile(cmd *cobra.Command) string {
	o, _ := cmd.Flags().GetString("output")
	return o
}

func getFormat(cmd *cobra.Command) string {
	f, _ := cmd.Flags().GetString("format")
	return f
}

func resolveServers(cmd *cobra.Command) []string {
	servers := []string{"8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"}
	dnsServer, _ := cmd.Flags().GetString("dns")
	if dnsServer != "" {
		if !strings.Contains(dnsServer, ":") {
			dnsServer += ":53"
		}
		servers = []string{dnsServer}
	}
	return servers
}

func newDNSLookupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lookup [domain]",
		Short: "Perform DNS A record lookup",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)
			servers := resolveServers(cmd)
			silent := getSilent(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigChan
				cancel()
			}()

			var results []string
			for _, server := range servers {
				if ctx.Err() != nil {
					break
				}
				r := new(dns.Msg)
				r.SetQuestion(dns.Fqdn(domain), dns.TypeA)
				r.RecursionDesired = true

				c := new(dns.Client)
				c.Timeout = timeout
				resp, _, err := c.Exchange(r, server)
				if err != nil {
					if !silent {
						fmt.Fprintf(os.Stderr, "error querying %s: %v\n", server, err)
					}
					continue
				}

				for _, ans := range resp.Answer {
					if a, ok := ans.(*dns.A); ok {
						results = append(results, a.A.String())
					}
				}
			}

			if len(results) == 0 {
				return fmt.Errorf("no A records found for %s", domain)
			}

			for _, ip := range results {
				fmt.Println(ip)
			}
			return nil
		},
	}
}

func newDNSReverseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reverse [ip]",
		Short: "Perform reverse DNS lookup",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ip := args[0]
			timeout := getTimeout(cmd)
			silent := getSilent(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			hostnames, err := net.LookupAddr(ip)
			if err != nil {
				return fmt.Errorf("reverse lookup failed: %w", err)
			}

			if len(hostnames) == 0 {
				return fmt.Errorf("no PTR records found for %s", ip)
			}

			for _, h := range hostnames {
				fmt.Println(h)
			}

			_ = ctx
			_ = silent
			return nil
		},
	}
}

func newDNSMXCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mx [domain]",
		Short: "Query MX records",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)
			servers := resolveServers(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			var records []dns.MX
			for _, server := range servers {
				if ctx.Err() != nil {
					break
				}
				r := new(dns.Msg)
				r.SetQuestion(dns.Fqdn(domain), dns.TypeMX)
				r.RecursionDesired = true

				c := new(dns.Client)
				c.Timeout = timeout
				resp, _, err := c.Exchange(r, server)
				if err != nil {
					continue
				}

				for _, ans := range resp.Answer {
					if mx, ok := ans.(*dns.MX); ok {
						records = append(records, *mx)
					}
				}
			}

			if len(records) == 0 {
				return fmt.Errorf("no MX records found for %s", domain)
			}

			for _, mx := range records {
				fmt.Printf("%d %s\n", mx.Preference, mx.Mx)
			}
			return nil
		},
	}
}

func newDNSNSCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ns [domain]",
		Short: "Query NS records",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)
			servers := resolveServers(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			var records []string
			for _, server := range servers {
				if ctx.Err() != nil {
					break
				}
				r := new(dns.Msg)
				r.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
				r.RecursionDesired = true

				c := new(dns.Client)
				c.Timeout = timeout
				resp, _, err := c.Exchange(r, server)
				if err != nil {
					continue
				}

				for _, ans := range resp.Answer {
					if ns, ok := ans.(*dns.NS); ok {
						records = append(records, ns.Ns)
					}
				}
			}

			if len(records) == 0 {
				return fmt.Errorf("no NS records found for %s", domain)
			}

			for _, ns := range records {
				fmt.Println(ns)
			}
			return nil
		},
	}
}

func newDNSTXTCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "txt [domain]",
		Short: "Query TXT records",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)
			servers := resolveServers(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			var records []string
			for _, server := range servers {
				if ctx.Err() != nil {
					break
				}
				r := new(dns.Msg)
				r.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)
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
			}

			if len(records) == 0 {
				return fmt.Errorf("no TXT records found for %s", domain)
			}

			for _, txt := range records {
				fmt.Println(txt)
			}
			return nil
		},
	}
}

func newDNSSOACmd() *cobra.Command {
	return &cobra.Command{
		Use:   "soa [domain]",
		Short: "Query SOA record",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)
			servers := resolveServers(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			for _, server := range servers {
				if ctx.Err() != nil {
					break
				}
				r := new(dns.Msg)
				r.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)
				r.RecursionDesired = true

				c := new(dns.Client)
				c.Timeout = timeout
				resp, _, err := c.Exchange(r, server)
				if err != nil {
					continue
				}

				for _, ans := range resp.Answer {
					if soa, ok := ans.(*dns.SOA); ok {
						fmt.Printf("primary: %s\n", soa.Ns)
						fmt.Printf("admin: %s\n", soa.Mbox)
						fmt.Printf("serial: %d\n", soa.Serial)
						fmt.Printf("refresh: %d\n", soa.Refresh)
						fmt.Printf("retry: %d\n", soa.Retry)
						fmt.Printf("expire: %d\n", soa.Expire)
						fmt.Printf("minimum: %d\n", soa.Minttl)
						return nil
					}
				}
			}
			return fmt.Errorf("no SOA record found for %s", domain)
		},
	}
}

func newDNSCAACmd() *cobra.Command {
	return &cobra.Command{
		Use:   "caa [domain]",
		Short: "Query CAA records",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)
			servers := resolveServers(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			var records []string
			for _, server := range servers {
				if ctx.Err() != nil {
					break
				}
				r := new(dns.Msg)
				r.SetQuestion(dns.Fqdn(domain), dns.TypeCAA)
				r.RecursionDesired = true

				c := new(dns.Client)
				c.Timeout = timeout
				resp, _, err := c.Exchange(r, server)
				if err != nil {
					continue
				}

				for _, ans := range resp.Answer {
					if caa, ok := ans.(*dns.CAA); ok {
						records = append(records, fmt.Sprintf("%d %s \"%s\"",
							caa.Flag, caa.Tag, caa.Value))
					}
				}
			}

			if len(records) == 0 {
				return fmt.Errorf("no CAA records found for %s", domain)
			}

			for _, r := range records {
				fmt.Println(r)
			}
			return nil
		},
	}
}

func newDNSCNAMECmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cname [domain]",
		Short: "Query CNAME record",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)
			servers := resolveServers(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			for _, server := range servers {
				if ctx.Err() != nil {
					break
				}
				r := new(dns.Msg)
				r.SetQuestion(dns.Fqdn(domain), dns.TypeCNAME)
				r.RecursionDesired = true

				c := new(dns.Client)
				c.Timeout = timeout
				resp, _, err := c.Exchange(r, server)
				if err != nil {
					continue
				}

				for _, ans := range resp.Answer {
					if cname, ok := ans.(*dns.CNAME); ok {
						fmt.Println(cname.Target)
						return nil
					}
				}
			}
			return fmt.Errorf("no CNAME record found for %s", domain)
		},
	}
}

func newDNSDNSSecCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "dnssec [domain]",
		Short: "Check DNSSEC status",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)
			servers := resolveServers(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			for _, server := range servers {
				if ctx.Err() != nil {
					break
				}
				r := new(dns.Msg)
				r.SetQuestion(dns.Fqdn(domain), dns.TypeDNSKEY)
				r.RecursionDesired = true
				r.CheckingDisabled = false

				c := new(dns.Client)
				c.Timeout = timeout
				resp, _, err := c.Exchange(r, server)
				if err != nil {
					continue
				}

				fmt.Printf("Domain: %s\n", domain)
				fmt.Printf("Authenticated: %v\n", resp.AuthenticatedData)

				if len(resp.Answer) == 0 {
					fmt.Println("DNSSEC: not enabled or no keys found")
					return nil
				}

				fmt.Println("\nDNSKEY records:")
				for _, ans := range resp.Answer {
					if key, ok := ans.(*dns.DNSKEY); ok {
						fmt.Printf("  Flags: %d, Protocol: %d, Algorithm: %d\n",
							key.Flags, key.Protocol, key.Algorithm)
					}
				}
				return nil
			}
			return fmt.Errorf("DNSSEC check failed for %s", domain)
		},
	}
}

func newDNSZoneCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "zone [domain]",
		Short: "Attempt zone transfer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)
			silent := getSilent(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			nsRecords, err := net.LookupNS(domain)
			if err != nil {
				return fmt.Errorf("failed to get NS records: %w", err)
			}

			success := false
			for _, ns := range nsRecords {
				if ctx.Err() != nil {
					break
				}
				if !silent {
					fmt.Fprintf(os.Stderr, "Trying zone transfer on %s...\n", ns.Host)
				}

				r := new(dns.Msg)
				r.SetAxfr(dns.Fqdn(domain))

				t := new(dns.Transfer)

				m, err := t.In(r, ns.Host+":53")
				if err != nil {
					if !silent {
						fmt.Fprintf(os.Stderr, "  Transfer failed on %s: %v\n", ns.Host, err)
					}
					continue
				}

				success = true
				for env := range m {
					for _, rr := range env.RR {
						fmt.Println(rr)
					}
				}
				break
			}

			if !success {
				return fmt.Errorf("zone transfer failed for %s", domain)
			}
			return nil
		},
	}
}

func newDNSResolverCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "resolver [domain]",
		Short: "Test multiple resolvers against a domain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			resolvers := []string{
				"8.8.8.8:53",
				"8.8.4.4:53",
				"1.1.1.1:53",
				"1.0.0.1:53",
				"9.9.9.9:53",
				"208.67.222.222:53",
			}

			type result struct {
				server string
				ip     string
				latency time.Duration
				err    error
			}

			results := make(chan result, len(resolvers))
			for _, res := range resolvers {
				go func(server string) {
					start := time.Now()
					r := new(dns.Msg)
					r.SetQuestion(dns.Fqdn(domain), dns.TypeA)
					r.RecursionDesired = true

					c := new(dns.Client)
					c.Timeout = timeout
					resp, rtt, err := c.Exchange(r, server)
					_ = rtt
					latency := time.Since(start)

					if err != nil {
						results <- result{server: server, err: err}
						return
					}

					for _, ans := range resp.Answer {
						if a, ok := ans.(*dns.A); ok {
							results <- result{server: server, ip: a.A.String(), latency: latency}
							return
						}
					}
					results <- result{server: server, err: fmt.Errorf("no A record")}
				}(res)
			}

			fmt.Printf("Testing resolvers for %s:\n\n", domain)
			fmt.Printf("%-20s %-16s %s\n", "Resolver", "IP", "Latency")
			fmt.Println(strings.Repeat("-", 50))

			for i := 0; i < len(resolvers); i++ {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case r := <-results:
					if r.err != nil {
						fmt.Printf("%-20s %-16s %s\n", r.server, "error", r.err)
					} else {
						fmt.Printf("%-20s %-16s %v\n", r.server, r.ip, r.latency)
					}
				}
			}
			return nil
		},
	}
}
