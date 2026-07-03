package cli

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// â”€â”€ Port Detail: Banner Grab, Service Detect â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

func newPortDetailCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "detail [target]",
		Short: "Advanced port scan with banner grabbing + service detection",
		Long: `Detailed port scan including banner grabbing, service detection,
version identification, and TLS detection per port.`,
	}
	cmd.AddCommand(
		newBannerCmd(),
		newPortVersionCmd(),
		newPortMultiCmd(),
	)
	return cmd
}

func newBannerCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "banner [ip:port]",
		Short: "Grab banner from a single port",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			addr := args[0]
			if !strings.Contains(addr, ":") {
				addr = addr + ":80"
			}
			timeout := getTimeout(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			fmt.Printf("Banner grabbing: %s\n", addr)
			fmt.Println(strings.Repeat("-", 50))

			banner, err := grabBannerTCP(ctx, addr, timeout)
			if err != nil {
				return err
			}

			// Sanitize banner output
			clean := strings.Map(func(r rune) rune {
				if r >= 32 && r <= 126 {
					return r
				}
				if r == '\n' || r == '\r' || r == '\t' {
					return r
				}
				return -1
			}, banner)

			fmt.Printf("[%s]\n", clean)
			return nil
		},
	}
}

func newPortVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version [ip]",
		Short: "Service version detection on open ports",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			timeout := getTimeout(cmd)
			_ = cmd

			// Common ports with known services
			services := map[int]string{
				21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
				80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
				445: "SMB", 993: "IMAPS", 995: "POP3S", 3306: "MySQL",
				3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
				8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
			}

			fmt.Printf("Service version detection: %s\n", target)
			fmt.Printf("%-8s %-15s %-30s %s\n", "PORT", "SERVICE", "BANNER", "TLS")
			fmt.Println(strings.Repeat("-", 75))

			var mu sync.Mutex
			var wg sync.WaitGroup
			ports := make([]int, 0, len(services))
			for p := range services {
				ports = append(ports, p)
			}

			for _, p := range ports {
				wg.Add(1)
				go func(port int) {
					defer wg.Done()
					addr := fmt.Sprintf("%s:%d", target, port)
					banner, err := grabBannerTCP(context.Background(), addr, timeout)
					if err != nil {
						return
					}
					clean := strings.TrimSpace(banner)
					if len(clean) > 28 {
						clean = clean[:28] + "..."
					}
					clean = strings.Map(func(r rune) rune {
						if r >= 32 && r <= 126 || r == ' ' || r == '-' || r == '/' {
							return r
						}
						return -1
					}, clean)

					tlsStatus := "no"
					if port == 443 || port == 993 || port == 995 || port == 8443 {
						tlsStatus = "yes"
					}

					mu.Lock()
					fmt.Printf("%-8d %-15s %-30s %s\n", port, services[port], clean, tlsStatus)
					mu.Unlock()
				}(p)
			}
			wg.Wait()

			return nil
		},
	}
}

func newPortMultiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "multi [target] [ports...]",
		Short: "Scan custom ports with banner grabbing",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			ports := []int{80, 443, 22, 21, 25, 8080}
			if len(args) > 1 {
				ports = nil
				for _, p := range args[1:] {
					port := 0
					fmt.Sscanf(p, "%d", &port)
					if port > 0 {
						ports = append(ports, port)
					}
				}
			}
			timeout := getTimeout(cmd)
			threads, _ := cmd.Flags().GetInt("threads")

			_, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			type result struct {
				port   int
				open   bool
				banner string
				latency time.Duration
			}

			var mu sync.Mutex
			var results []result
			var wg sync.WaitGroup
			portCh := make(chan int, len(ports))

			for i := 0; i < threads; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for port := range portCh {
						addr := fmt.Sprintf("%s:%d", target, port)
						start := time.Now()
						conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
						latency := time.Since(start)
						if err != nil {
							continue
						}
						defer conn.Close()

						// Try to grab a banner
						banner, _ := grabBannerTCP(context.Background(), addr, 3*time.Second)

						mu.Lock()
						results = append(results, result{
							port:    port,
							open:    true,
							banner:  banner,
							latency: latency,
						})
						mu.Unlock()
					}
				}()
			}

			for _, p := range ports {
				portCh <- p
			}
			close(portCh)
			wg.Wait()

			fmt.Printf("Port scan result for %s:\n", target)
			fmt.Println(strings.Repeat("-", 50))
			for _, r := range results {
				b := ""
				if r.banner != "" {
					b = truncate(strings.TrimSpace(r.banner), 30)
				}
				fmt.Printf("  OPEN %-5d %-10s %v  %s\n", r.port, serviceName(r.port), r.latency, b)
			}
			return nil
		},
	}
}

func grabBannerTCP(ctx context.Context, addr string, timeout time.Duration) (string, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	// Try common probes per port
	parts := strings.Split(addr, ":")
	port := parts[len(parts)-1]
	p := 0
	fmt.Sscanf(port, "%d", &p)

	switch p {
	case 80, 8080, 8000:
		conn.Write([]byte("GET / HTTP/1.0\r\nHost: " + parts[0] + "\r\n\r\n"))
	case 21:
		// FTP server will send banner immediately
	case 22:
		// SSH will send banner immediately
	case 25:
		conn.Write([]byte("EHLO scan\r\n"))
	case 110:
		conn.Write([]byte("USER anonymous\r\n"))
	case 143:
		conn.Write([]byte("a001 LOGOUT\r\n"))
	case 443, 8443:
		return "TLS (use ssl cert)", nil
	default:
		// Just read what the server sends
	}

	reader := bufio.NewReader(conn)
	banner := ""
	for i := 0; i < 5; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		banner += line
	}

	return strings.TrimSpace(banner), nil
}

// â”€â”€ Discovery Providers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

func newDiscoveryProvidersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "discovery [domain]",
		Short: "Subdomain discovery via multiple providers",
		Long: `Enumerate subdomains using multiple sources:
certspotter, rapiddns, hacker-target, bufferover, anubis, alienvault`,
	}
	cmd.AddCommand(
		newDiscCertSpotter(),
		newDiscRapidDNS(),
		newDiscHackerTarget(),
		newDiscBufferOver(),
		newDiscAnubis(),
		newDiscAll(),
	)
	return cmd
}

func newDiscCertSpotter() *cobra.Command {
	return &cobra.Command{
		Use:   "certspotter [domain]",
		Short: "CertSpotter subdomain lookup",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)
			silent := getSilent(cmd)

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			cancel := func() {}
			defer cancel()

			if !silent {
				fmt.Fprintf(os.Stderr, "[*] CertSpotter: %s\n", domain)
			}

			url := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain)
			data, err := osintHTTPGet(url, timeout)
			if err != nil {
				return fmt.Errorf("certspotter failed: %w", err)
			}

			fmt.Printf("CertSpotter results for %s:\n", domain)
			fmt.Println(data)
			return nil
		},
	}
}

func newDiscRapidDNS() *cobra.Command {
	return &cobra.Command{
		Use:   "rapiddns [domain]",
		Short: "RapidDNS subdomain lookup",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)
			silent := getSilent(cmd)

			_, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			go func() { <-sigChan; cancel() }()

			if !silent {
				fmt.Fprintf(os.Stderr, "[*] RapidDNS: %s\n", domain)
			}

			url := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", domain)
			data, err := osintHTTPGet(url, timeout)
			if err != nil {
				return fmt.Errorf("rapiddns failed: %w", err)
			}

			fmt.Printf("RapidDNS results for %s:\n", domain)
			fmt.Println(data)
			return nil
		},
	}
}

func newDiscHackerTarget() *cobra.Command {
	return &cobra.Command{
		Use:   "hackertarget [domain]",
		Short: "HackerTarget subdomain lookup",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)
			silent := getSilent(cmd)

			_, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			go func() { <-sigChan; cancel() }()
			

			if !silent {
				fmt.Fprintf(os.Stderr, "[*] HackerTarget: %s\n", domain)
			}

			url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
			data, err := osintHTTPGet(url, timeout)
			if err != nil {
				return fmt.Errorf("hackertarget failed: %w", err)
			}

			fmt.Printf("HackerTarget results for %s:\n", domain)
			fmt.Println(data)
			return nil
		},
	}
}

func newDiscBufferOver() *cobra.Command {
	return &cobra.Command{
		Use:   "bufferover [domain]",
		Short: "BufferOver subdomain lookup",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)
			silent := getSilent(cmd)

			_, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			go func() { <-sigChan; cancel() }()
			

			if !silent {
				fmt.Fprintf(os.Stderr, "[*] BufferOver: %s\n", domain)
			}

			url := fmt.Sprintf("https://dns.bufferover.run/dns?q=.%s", domain)
			data, err := osintHTTPGet(url, timeout)
			if err != nil {
				return fmt.Errorf("bufferover failed: %w", err)
			}

			fmt.Printf("BufferOver results for %s:\n", domain)
			fmt.Println(data)
			return nil
		},
	}
}

func newDiscAnubis() *cobra.Command {
	return &cobra.Command{
		Use:   "anubis [domain]",
		Short: "Anubis subdomain lookup",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)
			silent := getSilent(cmd)

			_, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			go func() { <-sigChan; cancel() }()
			

			if !silent {
				fmt.Fprintf(os.Stderr, "[*] Anubis: %s\n", domain)
			}

			url := fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", domain)
			data, err := osintHTTPGet(url, timeout)
			if err != nil {
				return fmt.Errorf("anubis failed: %w", err)
			}

			fmt.Printf("Anubis results for %s:\n", domain)
			fmt.Println(data)
			return nil
		},
	}
}

func newDiscAll() *cobra.Command {
	return &cobra.Command{
		Use:   "all [domain]",
		Short: "All discovery providers combined",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)

			fmt.Printf("ðŸ”„ Running all discovery providers for: %s\n\n", domain)

			type result struct {
				name string
				data string
				err  error
			}

			providers := []struct {
				name string
				fn   func(string, time.Duration) (string, error)
			}{
				{"CertSpotter", func(d string, t time.Duration) (string, error) {
					return osintHTTPGet(fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", d), t)
				}},
				{"HackerTarget", func(d string, t time.Duration) (string, error) {
					return osintHTTPGet(fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", d), t)
				}},
				{"RapidDNS", func(d string, t time.Duration) (string, error) {
					return osintHTTPGet(fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", d), t)
				}},
				{"BufferOver", func(d string, t time.Duration) (string, error) {
					return osintHTTPGet(fmt.Sprintf("https://dns.bufferover.run/dns?q=.%s", d), t)
				}},
				{"Anubis", func(d string, t time.Duration) (string, error) {
					return osintHTTPGet(fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", d), t)
				}},
				{"AlienVault", func(d string, t time.Duration) (string, error) {
					return osintHTTPGet(fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/url_list?limit=100", d), t)
				}},
			}

			results := make(chan result, len(providers))
			var wg sync.WaitGroup
			for _, p := range providers {
				wg.Add(1)
				go func(name string, fn func(string, time.Duration) (string, error)) {
					defer wg.Done()
					data, err := fn(domain, timeout)
					results <- result{name: name, data: data, err: err}
				}(p.name, p.fn)
			}
			go func() { wg.Wait(); close(results) }()

			for r := range results {
				fmt.Printf("\nâ”€â”€â”€ %s â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\n", r.name)
				if r.err != nil {
					fmt.Printf("  Error: %v\n", r.err)
				} else {
					fmt.Printf("  %s\n", truncate(r.data, 200))
				}
			}
			return nil
		},
	}
}
