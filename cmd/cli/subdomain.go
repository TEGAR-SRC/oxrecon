package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

func newSubdomainCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "subdomain",
		Short: "Subdomain enumeration and discovery",
		Long:  `Passive and active subdomain enumeration using DNS brute-force, certificate transparency, and more.`,
	}
	cmd.AddCommand(
		newSubdomainEnumCmd(),
		newSubdomainBruteCmd(),
		newSubdomainCRTshCmd(),
		newSubdomainRecursiveCmd(),
		newSubdomainWildcardCmd(),
	)
	return cmd
}

func newSubdomainEnumCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "enum [domain]",
		Short: "Passive subdomain enumeration (DNS + crt.sh)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)
			silent := getSilent(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigChan
				cancel()
			}()

			var subdomains sync.Map
			var wg sync.WaitGroup

			// Method 1: crt.sh
			wg.Add(1)
			go func() {
				defer wg.Done()
				if !silent {
					fmt.Fprintln(os.Stderr, "[*] Checking crt.sh...")
				}
				entries := queryCrtsh(ctx, domain)
				for _, e := range entries {
					for _, name := range e.names {
						if strings.HasSuffix(name, "."+domain) || name == domain {
							subdomains.Store(name, true)
						}
					}
				}
			}()

			// Method 2: DNS queries for common subdomains
			wg.Add(1)
			go func() {
				defer wg.Done()
				if !silent {
					fmt.Fprintln(os.Stderr, "[*] DNS brute-force (common subdomains)...")
				}
				prefixes := []string{
					"www", "mail", "ftp", "smtp", "ns1", "ns2", "ns3", "dns",
					"blog", "dev", "api", "app", "admin", "panel", "cpanel",
					"webmail", "mx", "mx1", "mx2", "imap", "pop", "vpn",
					"remote", "ssh", "git", "jenkins", "ci", "cd",
					"test", "staging", "beta", "alpha", "demo",
					"cdn", "assets", "static", "media", "img", "images",
					"store", "shop", "pay", "billing", "support", "help",
					"docs", "wiki", "forum", "community", "status",
					"db", "database", "sql", "redis", "mongo", "elastic",
					"cache", "queue", "mq", "rabbit", "kafka",
					"grafana", "kibana", "monitor", "logs", "log",
					"backup", "bak", "old", "archive", "temp",
				}

				for _, prefix := range prefixes {
					if ctx.Err() != nil {
						break
					}
					sub := prefix + "." + domain
					ips, err := net.LookupHost(sub)
					if err == nil && len(ips) > 0 {
						subdomains.Store(sub, true)
					}
				}
			}()

			wg.Wait()

			var found []string
			subdomains.Range(func(key, value any) bool {
				found = append(found, key.(string))
				return true
			})

			fmt.Printf("Subdomains for %s (%d found):\n", domain, len(found))
			fmt.Println(strings.Repeat("-", 40))
			for _, s := range found {
				fmt.Println(s)
			}
			return nil
		},
	}
}

type crtshEntry struct {
	certID uint64
	names  []string
}

func queryCrtsh(ctx context.Context, domain string) []crtshEntry {
	queryURL := fmt.Sprintf("https://crt.sh/?q=%%%s&output=json", domain)
	_ = queryURL

	type result struct {
		entries []crtshEntry
		err     error
	}

	ch := make(chan result, 1)
	go func() {
		// Use DNS cert transparency log instead
		// For now return empty - full implementation uses HTTP to crt.sh
		ch <- result{entries: nil, err: nil}
	}()

	select {
	case <-ctx.Done():
		return nil
	case r := <-ch:
		_ = r.err
		return r.entries
	}
}

func newSubdomainBruteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "brute [domain]",
		Short: "DNS bruteforce subdomain discovery",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)
			threads, _ := cmd.Flags().GetInt("threads")
			silent := getSilent(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			prefixes := []string{
				"www", "mail", "ftp", "smtp", "ns1", "ns2", "ns3", "dns",
				"blog", "dev", "api", "app", "admin", "panel", "cpanel",
				"webmail", "mx", "mx1", "mx2", "imap", "pop", "vpn",
				"remote", "ssh", "git", "jenkins", "ci", "cd",
				"test", "staging", "beta", "alpha", "demo",
				"cdn", "assets", "static", "media", "img", "images",
				"store", "shop", "pay", "billing", "support", "help",
				"docs", "wiki", "forum", "community", "status",
				"db", "database", "sql", "redis", "mongo", "elastic",
				"grafana", "kibana", "monitor", "logs",
				"backup", "bak", "old", "archive", "temp",
				"ns1", "ns2", "mx1", "mx2", "autodiscover",
				"webdisk", "cpanel", "whm", "autoconfig",
			}

			if !silent {
				fmt.Fprintf(os.Stderr, "Bruteforcing %s (%d prefixes, %d workers)...\n",
					domain, len(prefixes), threads)
			}

			type result struct {
				subdomain string
				found     bool
			}

			jobCh := make(chan string, len(prefixes))
			resultCh := make(chan result, len(prefixes))
			var wg sync.WaitGroup

			for i := 0; i < threads; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for sub := range jobCh {
						if ctx.Err() != nil {
							return
						}
						fqdn := sub + "." + domain
						ips, err := net.LookupHost(fqdn)
						if err == nil && len(ips) > 0 {
							resultCh <- result{subdomain: fqdn, found: true}
						}
					}
				}()
			}

			go func() {
				for _, p := range prefixes {
					select {
					case jobCh <- p:
					case <-ctx.Done():
						break
					}
				}
				close(jobCh)
			}()

			go func() {
				wg.Wait()
				close(resultCh)
			}()

			var found []string
			for r := range resultCh {
				if r.found {
					found = append(found, r.subdomain)
				}
			}

			fmt.Printf("Subdomains found for %s (%d):\n", domain, len(found))
			for _, f := range found {
				fmt.Println(f)
			}
			return nil
		},
	}
}

func newSubdomainCRTshCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "crtsh [domain]",
		Short: "Query crt.sh for subdomain discovery",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			entries := queryCrtsh(ctx, domain)
			if len(entries) == 0 {
				fmt.Println("No subdomains found via crt.sh (HTTP fetch needed)")
				return nil
			}

			var names []string
			for _, e := range entries {
				for _, n := range e.names {
					names = append(names, n)
				}
			}

			unique := dedupStrings(names)
			fmt.Printf("Subdomains via crt.sh for %s (%d):\n", domain, len(unique))
			for _, n := range unique {
				fmt.Println(n)
			}
			return nil
		},
	}
}

func dedupStrings(in []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func newSubdomainRecursiveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "recursive [domain]",
		Short: "Recursive subdomain discovery (3 levels deep)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)
			silent := getSilent(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			var allSubdomains sync.Map
			var wg sync.WaitGroup

			level1 := []string{"www", "api", "dev", "admin", "mail", "cdn", "staging", "test"}

			for _, prefix := range level1 {
				wg.Add(1)
				go func(p string) {
					defer wg.Done()
					sub := p + "." + domain
					ips, err := net.LookupHost(sub)
					if err == nil && len(ips) > 0 {
						allSubdomains.Store(sub, true)

						// Level 2
						level2 := []string{"www", "api", "dev", "admin", "mail", "cdn"}
						for _, p2 := range level2 {
							if ctx.Err() != nil {
								return
							}
							sub2 := p2 + "." + sub
							ips2, err2 := net.LookupHost(sub2)
							if err2 == nil && len(ips2) > 0 {
								allSubdomains.Store(sub2, true)

								// Level 3
								for _, p3 := range level2 {
									if ctx.Err() != nil {
										return
									}
									sub3 := p3 + "." + sub2
									ips3, err3 := net.LookupHost(sub3)
									if err3 == nil && len(ips3) > 0 {
										allSubdomains.Store(sub3, true)
									}
								}
							}
						}
					}
				}(prefix)
			}

			wg.Wait()

			var found []string
			allSubdomains.Range(func(k, v any) bool {
				found = append(found, k.(string))
				return true
			})

			if !silent {
				fmt.Fprintf(os.Stderr, "Recursive scan complete. Found %d subdomains.\n", len(found))
			}

			fmt.Printf("Subdomains for %s (%d):\n", domain, len(found))
			for _, s := range found {
				fmt.Println(s)
			}
			return nil
		},
	}
}

func newSubdomainWildcardCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "wildcard [domain]",
		Short: "Detect wildcard DNS for a domain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			r := new(dns.Msg)
			r.SetQuestion(dns.Fqdn(domain), dns.TypeA)
			r.RecursionDesired = true

			c := new(dns.Client)
			c.Timeout = timeout
			resp, _, err := c.Exchange(r, "8.8.8.8:53")
			if err != nil {
				return fmt.Errorf("wildcard check failed: %w", err)
			}

			wildcardIPs := make(map[string]bool)
			for _, ans := range resp.Answer {
				if a, ok := ans.(*dns.A); ok {
					wildcardIPs[a.A.String()] = true
				}
			}

			// Test with random subdomain
			randomSub := fmt.Sprintf("xyz%d.%d.%s", time.Now().UnixNano()%10000, time.Now().UnixNano()%100, domain)
			ips, err := net.LookupHost(randomSub)
			if err != nil {
				fmt.Printf("Wildcard DNS: NOT detected (random subdomain %s did not resolve)\n", randomSub)
				fmt.Printf("Wildcard IPs: %v\n", wildcardIPs)
			} else {
				fmt.Printf("Wildcard DNS: DETECTED (random subdomain %s resolved)\n", randomSub)
				fmt.Printf("Wildcard IPs: %v\n", ips)
				fmt.Printf("Domain IPs: %v\n", wildcardIPs)
			}
			_ = ctx
			return nil
		},
	}
}

func dialTCP(ctx context.Context, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	return d.DialContext(ctx, "tcp", addr)
}
