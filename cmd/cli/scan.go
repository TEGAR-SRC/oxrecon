package cli

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

type scanTarget struct {
	host    string
	port    int
	service string
}

func newScanCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "scan [target]",
		Short: "Full reconnaissance scan on a target",
		Long: `Perform a comprehensive scan combining DNS, WHOIS, port scan, HTTP analysis,
SSL/TLS checks, technology detection, and more — producing a unified report.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			timeout := getTimeout(cmd)
			threads, _ := cmd.Flags().GetInt("threads")
			silent := getSilent(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout*5)
			defer cancel()

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigChan
				cancel()
			}()

			startTime := time.Now()

			type scanStep struct {
				name string
				fn   func() (string, error)
			}

			var mu sync.Mutex
			var wg sync.WaitGroup
			var results []string

			report := strings.Builder{}
			report.WriteString(fmt.Sprintf("╔══════════════════════════════════════════════╗\n"))
			report.WriteString(fmt.Sprintf("║  FULL SCAN REPORT: %-25s ║\n", target))
			report.WriteString(fmt.Sprintf("╚══════════════════════════════════════════════╝\n\n"))

			addResult := func(name, result string) {
				mu.Lock()
				defer mu.Unlock()
				results = append(results, fmt.Sprintf("━━━ %s ━━━\n%s\n", name, result))
			}

			printProgress := func(step string) {
				if !silent {
					fmt.Fprintf(os.Stderr, "  [*] %s\n", step)
				}
			}

			// Determine if target is IP or domain
			isIP := net.ParseIP(target) != nil

			// DNS
			wg.Add(1)
			go func() {
				defer wg.Done()
				printProgress("DNS Lookup")
				domain := target
				if isIP {
					hostnames, err := net.LookupAddr(target)
					if err == nil && len(hostnames) > 0 {
						domain = hostnames[0]
						domain = strings.TrimSuffix(domain, ".")
					}
				}

				ips, _ := net.LookupHost(domain)
				mx, _ := net.LookupMX(domain)
				ns, _ := net.LookupNS(domain)
				txt, _ := net.LookupTXT(domain)

				var b strings.Builder
				b.WriteString(fmt.Sprintf("Domain: %s\n", domain))
				b.WriteString(fmt.Sprintf("IPs: %s\n", strings.Join(ips, ", ")))
				b.WriteString(fmt.Sprintf("MX Records: %d\n", len(mx)))
				for _, m := range mx {
					b.WriteString(fmt.Sprintf("  %d %s\n", m.Pref, m.Host))
				}
				b.WriteString(fmt.Sprintf("NS Records: %d\n", len(ns)))
				for _, n := range ns {
					b.WriteString(fmt.Sprintf("  %s\n", n.Host))
				}
				b.WriteString(fmt.Sprintf("TXT Records: %d\n", len(txt)))
				for _, t := range txt {
					b.WriteString(fmt.Sprintf("  %s\n", t))
				}
				addResult("DNS", b.String())
			}()

			// Port Scan
			wg.Add(1)
			go func() {
				defer wg.Done()
				printProgress("Port Scan")

				scanTarget := target
				if !isIP {
					ips, _ := net.LookupHost(target)
					if len(ips) > 0 {
						scanTarget = ips[0]
					}
				}

				ports := []int{21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143,
					443, 445, 465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432,
					5900, 6379, 8080, 8443, 8888, 9090, 9200, 27017}

				var openPorts []int
				var mu sync.Mutex
				var wg2 sync.WaitGroup

				portCh := make(chan int, threads)
				for i := 0; i < threads; i++ {
					wg2.Add(1)
					go func() {
						defer wg2.Done()
						for p := range portCh {
							if ctx.Err() != nil {
								return
							}
							addr := fmt.Sprintf("%s:%d", scanTarget, p)
							conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
							if err == nil {
								conn.Close()
								mu.Lock()
								openPorts = append(openPorts, p)
								mu.Unlock()
							}
						}
					}()
				}
				for _, p := range ports {
					portCh <- p
				}
				close(portCh)
				wg2.Wait()

				sort.Ints(openPorts)
				var b strings.Builder
				b.WriteString(fmt.Sprintf("Open Ports: %d\n", len(openPorts)))
				for _, p := range openPorts {
					svc := serviceName(p)
					b.WriteString(fmt.Sprintf("  %d/tcp  %s\n", p, svc))
				}
				addResult("PORT SCAN", b.String())
			}()

			// HTTP Headers
			wg.Add(1)
			go func() {
				defer wg.Done()
				printProgress("HTTP Headers")

				url := fmt.Sprintf("https://%s", target)
				client := &http.Client{
					Timeout: 15 * time.Second,
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
					},
					CheckRedirect: func(req *http.Request, via []*http.Request) error {
						return http.ErrUseLastResponse
					},
				}

				resp, err := client.Get(url)
				if err != nil {
					addResult("HTTP HEADERS", fmt.Sprintf("Error: %v\n", err))
					return
				}
				defer resp.Body.Close()
				io.Copy(io.Discard, resp.Body)

				var b strings.Builder
				b.WriteString(fmt.Sprintf("URL: %s\n", resp.Request.URL.String()))
				b.WriteString(fmt.Sprintf("Status: %d\n", resp.StatusCode))
				b.WriteString(fmt.Sprintf("Server: %s\n", resp.Header.Get("Server")))

				// Security headers check
				secHeaders := map[string]string{
					"Strict-Transport-Security": "",
					"Content-Security-Policy":   "",
					"X-Frame-Options":           "",
					"X-Content-Type-Options":    "",
					"X-XSS-Protection":          "",
					"Referrer-Policy":            "",
				}
				missing := 0
				b.WriteString("\nSecurity Headers:\n")
				for h := range secHeaders {
					val := resp.Header.Get(h)
					status := "✓"
					if val == "" {
						status = "✗ MISSING"
						missing++
					}
					b.WriteString(fmt.Sprintf("  %-35s %s\n", h+":", status))
				}
				b.WriteString(fmt.Sprintf("\nMissing: %d/%d headers\n", missing, len(secHeaders)))

				addResult("HTTP HEADERS", b.String())
			}()

			// SSL/TLS
			wg.Add(1)
			go func() {
				defer wg.Done()
				printProgress("SSL/TLS Certificate")

				host := target
				if isIP {
					hostnames, err := net.LookupAddr(target)
					if err == nil && len(hostnames) > 0 {
						host = strings.TrimSuffix(hostnames[0], ".")
					}
				}

				conf := &tls.Config{
					InsecureSkipVerify: true,
				}

				addr := fmt.Sprintf("%s:443", host)
				conn, err := tls.DialWithDialer(
					&net.Dialer{Timeout: 10 * time.Second},
					"tcp", addr, conf,
				)
				if err != nil {
					addResult("SSL/TLS", fmt.Sprintf("Error: %v\n", err))
					return
				}
				defer conn.Close()

				certs := conn.ConnectionState().PeerCertificates
				if len(certs) == 0 {
					addResult("SSL/TLS", "No certificates returned\n")
					return
				}

				leaf := certs[0]
				daysLeft := int(time.Until(leaf.NotAfter).Hours() / 24)

				var b strings.Builder
				b.WriteString(fmt.Sprintf("Host: %s\n", host))
				b.WriteString(fmt.Sprintf("TLS Version: %s\n", tlsVer(conn.ConnectionState().Version)))
				b.WriteString(fmt.Sprintf("Cipher: %s\n", tls.CipherSuiteName(conn.ConnectionState().CipherSuite)))
				b.WriteString(fmt.Sprintf("Subject: %s\n", leaf.Subject.CommonName))
				b.WriteString(fmt.Sprintf("Issuer: %s (%s)\n", leaf.Issuer.CommonName, leaf.Issuer.Organization))
				b.WriteString(fmt.Sprintf("Expires: %s (%d days)\n", leaf.NotAfter.Format("2006-01-02"), daysLeft))
				if daysLeft < 0 {
					b.WriteString("⚠ EXPIRED!\n")
				} else if daysLeft < 30 {
					b.WriteString("⚠ EXPIRING SOON!\n")
				}
				if len(leaf.DNSNames) > 0 {
					b.WriteString(fmt.Sprintf("SANs: %s\n", strings.Join(leaf.DNSNames, ", ")))
				}

				addResult("SSL/TLS", b.String())
			}()

			// Technology Detection
			wg.Add(1)
			go func() {
				defer wg.Done()
				printProgress("Technology Detection")

				url := fmt.Sprintf("https://%s", target)
				client := &http.Client{
					Timeout: 15 * time.Second,
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
					},
				}

				resp, err := client.Get(url)
				if err != nil {
					addResult("TECHNOLOGY", fmt.Sprintf("Error: %v\n", err))
					return
				}
				defer resp.Body.Close()

				body, _ := io.ReadAll(resp.Body)
				bodyStr := string(body)

				var techs []string
				server := resp.Header.Get("Server")
				if server != "" {
					techs = append(techs, fmt.Sprintf("Server: %s", server))
				}
				xpb := resp.Header.Get("X-Powered-By")
				if xpb != "" {
					techs = append(techs, fmt.Sprintf("Powered-by: %s", xpb))
				}
				if strings.Contains(bodyStr, "wp-content") {
					techs = append(techs, "CMS: WordPress")
				}
				if strings.Contains(bodyStr, "react") {
					techs = append(techs, "JS: React")
				}
				if strings.Contains(bodyStr, "vue") {
					techs = append(techs, "JS: Vue.js")
				}
				if strings.Contains(bodyStr, "angular") {
					techs = append(techs, "JS: Angular")
				}
				if strings.Contains(bodyStr, "bootstrap") {
					techs = append(techs, "CSS: Bootstrap")
				}
				if strings.Contains(bodyStr, "tailwind") {
					techs = append(techs, "CSS: Tailwind")
				}
				if resp.Header.Get("CF-Ray") != "" {
					techs = append(techs, "CDN: Cloudflare")
				}
				if strings.Contains(bodyStr, "jquery") {
					techs = append(techs, "JS: jQuery")
				}

				var b strings.Builder
				b.WriteString("Technologies:\n")
				for _, t := range techs {
					b.WriteString(fmt.Sprintf("  ✓ %s\n", t))
				}
				addResult("TECHNOLOGY", b.String())
			}()

			// Subdomain scan
			wg.Add(1)
			go func() {
				defer wg.Done()
				printProgress("Subdomain Enumeration")

				domain := target
				if isIP {
					return
				}

				prefixes := []string{"www", "mail", "api", "dev", "admin", "cdn", "test", "staging", "blog", "shop"}
				var found []string

				for _, p := range prefixes {
					if ctx.Err() != nil {
						break
					}
					sub := p + "." + domain
					ips, err := net.LookupHost(sub)
					if err == nil && len(ips) > 0 {
						found = append(found, fmt.Sprintf("%s → %s", sub, strings.Join(ips, ", ")))
					}
				}

				var b strings.Builder
				b.WriteString(fmt.Sprintf("Subdomains: %d\n", len(found)))
				for _, f := range found {
					b.WriteString(fmt.Sprintf("  %s\n", f))
				}
				addResult("SUBDOMAINS", b.String())
			}()

			wg.Wait()

			// Compile report
			for _, r := range results {
				report.WriteString(r)
			}

			duration := time.Since(startTime)

			// Summary
			report.WriteString("\n━━━ SUMMARY ━━━\n")
			report.WriteString(fmt.Sprintf("Target: %s\n", target))
			report.WriteString(fmt.Sprintf("Scan Duration: %.1f seconds\n", duration.Seconds()))
			report.WriteString(fmt.Sprintf("Steps Completed: %d\n", len(results)))
			report.WriteString(fmt.Sprintf("Completed: %s\n", time.Now().Format(time.RFC3339)))

			fmt.Println(report.String())

			// Save to file if output specified
			if outputFile := getOutputFile(cmd); outputFile != "" {
				if err := os.WriteFile(outputFile, []byte(report.String()), 0644); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to write report: %v\n", err)
				} else {
					fmt.Fprintf(os.Stderr, "Report saved to %s\n", outputFile)
				}
			}

			return nil
		},
	}
}

func tlsVer(v uint16) string {
	switch v {
	case 769:
		return "TLS 1.0"
	case 770:
		return "TLS 1.1"
	case 771:
		return "TLS 1.2"
	case 772:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}


