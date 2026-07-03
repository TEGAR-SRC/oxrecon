package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

func newOSINTCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "osint",
		Short: "Open Source Intelligence (OSINT) gathering",
		Long:  `Query Shodan, Censys, crt.sh, Wayback Machine, and other OSINT sources.`,
	}
	cmd.AddCommand(
		newOSINTShodanCmd(),
		newOSINTCensysCmd(),
		newOSINTCrtshCmd(),
		newOSINTWaybackCmd(),
		newOSINTSecurityTrailsCmd(),
		newOSINTVirusTotalCmd(),
		newOSINTAlienVaultCmd(),
	)
	return cmd
}

func osintHTTPGet(url string, timeout time.Duration) (string, error) {
	client := &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{TLSClientConfig: nil},
	}

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "WebTool/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return string(body), nil
}

func newOSINTShodanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "shodan [ip]",
		Short: "Look up IP on Shodan",
		Long:  `Query Shodan.io API for information about an IP address.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ip := args[0]
			timeout := getTimeout(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigChan
				cancel()
			}()

			apiKey := os.Getenv("SHODAN_API_KEY")
			url := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", ip, apiKey)

			fmt.Fprintf(os.Stderr, "Querying Shodan for %s...\n", ip)

			data, err := osintHTTPGet(url, timeout)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Shodan query failed: %v\n", err)
				fmt.Println("\nNote: SHODAN_API_KEY environment variable required.")
				fmt.Println("Get a free API key at https://account.shodan.io/register")
				return nil
			}

			fmt.Printf("Shodan Results for %s:\n", ip)
			fmt.Println(strings.Repeat("-", 50))
			fmt.Println(data)
			_ = ctx
			return nil
		},
	}
}

func newOSINTCensysCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "censys [ip]",
		Short: "Look up IP on Censys",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ip := args[0]
			timeout := getTimeout(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigChan
				cancel()
			}()

			apiID := os.Getenv("CENSYS_API_ID")
			apiSecret := os.Getenv("CENSYS_API_SECRET")

			if apiID == "" || apiSecret == "" {
				fmt.Println("Censys API credentials required:")
				fmt.Println("  CENSYS_API_ID     - your Censys API ID")
				fmt.Println("  CENSYS_API_SECRET - your Censys API Secret")
				fmt.Println("Register at https://search.censys.io/register")
				return nil
			}

			url := fmt.Sprintf("https://search.censys.io/api/v2/hosts/%s", ip)

			fmt.Fprintf(os.Stderr, "Querying Censys for %s...\n", ip)

			data, err := osintHTTPGet(url, timeout)
			if err != nil {
				return fmt.Errorf("Censys query failed: %w", err)
			}

			fmt.Printf("Censys Results for %s:\n", ip)
			fmt.Println(strings.Repeat("-", 50))
			fmt.Println(data)
			_ = ctx
			return nil
		},
	}
}

func newOSINTCrtshCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "crtsh [domain]",
		Short: "Query crt.sh for certificate transparency logs",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			url := fmt.Sprintf("https://crt.sh/?q=%%%s&output=json", domain)

			fmt.Fprintf(os.Stderr, "Querying crt.sh for %s...\n", domain)

			data, err := osintHTTPGet(url, timeout)
			if err != nil {
				return fmt.Errorf("crt.sh query failed: %w", err)
			}

			fmt.Printf("crt.sh Results for %s:\n", domain)
			fmt.Println(strings.Repeat("-", 50))
			fmt.Println(data)
			_ = ctx
			return nil
		},
	}
}

func newOSINTWaybackCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "wayback [domain]",
		Short: "Query Wayback Machine for historical snapshots",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)

			url := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=%s/*&output=json&limit=100", domain)

			fmt.Fprintf(os.Stderr, "Querying Wayback Machine for %s...\n", domain)

			data, err := osintHTTPGet(url, timeout)
			if err != nil {
				return fmt.Errorf("Wayback Machine query failed: %w", err)
			}

			fmt.Printf("\nWayback Machine Results for %s:\n", domain)
			fmt.Println(strings.Repeat("-", 70))

			var rows [][]string
			raw := strings.TrimSpace(data)
			if strings.HasPrefix(raw, "[") {
				var parsed [][]string
				if err := json.Unmarshal([]byte(raw), &parsed); err == nil {
					for i, row := range parsed {
						if i == 0 {
							continue // skip header
						}
						if len(row) >= 6 {
							ts := row[1]
							origURL := row[2]
							status := row[4]
							archURL := fmt.Sprintf("https://web.archive.org/web/%s/%s", ts, origURL)

							year := "????"
							if len(ts) >= 4 {
								year = ts[:4]
							}
							rows = append(rows, []string{
								year,
								status,
								origURL[:min(len(origURL), 40)],
								archURL,
							})
						}
					}
				}
			}

			if len(rows) == 0 {
				fmt.Println("No historical snapshots found.")
				return nil
			}

			fmt.Printf("Found %d snapshots:\n\n", len(rows))
			fmt.Printf("%-6s %-8s %-42s %s\n", "YEAR", "STATUS", "URL", "ARCHIVE LINK")
			fmt.Println(strings.Repeat("-", 110))
			for _, r := range rows {
				fmt.Printf("%-6s %-8s %-42s %s\n", r[0], r[1], r[2], r[3])
			}

			return nil
		},
	}
}

func newOSINTSecurityTrailsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "securitytrails [domain]",
		Short: "Query SecurityTrails API",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			apiKey := os.Getenv("SECURITYTRAILS_API_KEY")

			fmt.Fprintf(os.Stderr, "Querying SecurityTrails for %s...\n", domain)

			url := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains?apikey=%s", domain, apiKey)
			data, err := osintHTTPGet(url, timeout)
			if err != nil {
				return fmt.Errorf("SecurityTrails query failed: %w", err)
			}

			fmt.Printf("SecurityTrails Results for %s:\n", domain)
			fmt.Println(strings.Repeat("-", 50))
			fmt.Println(data)
			_ = ctx
			return nil
		},
	}
}

func newOSINTVirusTotalCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "virustotal [domain]",
		Short: "Query VirusTotal for domain reputation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			apiKey := os.Getenv("VIRUSTOTAL_API_KEY")

			fmt.Fprintf(os.Stderr, "Querying VirusTotal for %s...\n", domain)

			url := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s?x-apikey=%s", domain, apiKey)
			data, err := osintHTTPGet(url, timeout)
			if err != nil {
				return fmt.Errorf("VirusTotal query failed: %w", err)
			}

			fmt.Printf("VirusTotal Results for %s:\n", domain)
			fmt.Println(strings.Repeat("-", 50))
			fmt.Println(data)
			_ = ctx
			return nil
		},
	}
}

func newOSINTAlienVaultCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "alienvault [domain]",
		Short: "Query AlienVault OTX for threat intelligence",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			fmt.Fprintf(os.Stderr, "Querying AlienVault OTX for %s...\n", domain)

			url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/general", domain)
			data, err := osintHTTPGet(url, timeout)
			if err != nil {
				return fmt.Errorf("AlienVault query failed: %w", err)
			}

			fmt.Printf("AlienVault OTX Results for %s:\n", domain)
			fmt.Println(strings.Repeat("-", 50))
			fmt.Println(data)
			_ = ctx
			return nil
		},
	}
}
