package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

func newDomainCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "domain",
		Short: "Domain and WHOIS reconnaissance",
		Long:  `Look up WHOIS information, registrar details, and domain expiration.`,
	}
	cmd.AddCommand(
		newWhoisCmd(),
		newDomainInfoCmd(),
		newDomainExpireCmd(),
	)
	return cmd
}

func newWhoisCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "whois [domain]",
		Short: "WHOIS lookup for a domain",
		Long:  `Perform WHOIS lookup to get registration details, registrar info, and domain status.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigChan
				cancel()
			}()

			res, err := performWhoisLookup(ctx, domain)
			if err != nil {
				return fmt.Errorf("WHOIS lookup failed: %w", err)
			}

			fmt.Println(res)
			return nil
		},
	}
}

func performWhoisLookup(ctx context.Context, domain string) (string, error) {
	// Attempt TCP WHOIS (port 43) to IANA/Verisign servers
	servers := []string{
		"whois.verisign-grs.com:43",
		"whois.iana.org:43",
	}

	type whoisResp struct {
		data string
		err  error
	}

	respCh := make(chan whoisResp, len(servers))

	for _, srv := range servers {
		go func(server string) {
			conn, err := dialTCP(ctx, server)
			if err != nil {
				respCh <- whoisResp{data: "", err: err}
				return
			}
			defer conn.Close()

			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			_, err = fmt.Fprintf(conn, "%s\r\n", domain)
			if err != nil {
				respCh <- whoisResp{data: "", err: err}
				return
			}

			_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			buf := make([]byte, 65536)
			n, err := conn.Read(buf)
			if err != nil {
				respCh <- whoisResp{err: err}
				return
			}

			if n > 0 {
				respCh <- whoisResp{data: string(buf[:n])}
			}
		}(srv)
	}

	var raw string
	for i := 0; i < len(servers); i++ {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case r := <-respCh:
			if r.err == nil && len(r.data) > 100 {
				raw = r.data
				break
			}
		}
	}

	if raw == "" {
		return "", fmt.Errorf("WHOIS returned empty result")
	}
	return raw, nil
}

func newDomainInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info [domain]",
		Short: "Get domain registration info",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			res, err := performWhoisLookup(ctx, domain)
			if err != nil {
				return fmt.Errorf("domain lookup failed: %w", err)
			}

			fmt.Printf("Domain: %s\n", domain)
			fmt.Println(stringsRepeat("-", 40))
			extractWhoisFields(res)
			return nil
		},
	}
}

func stringsRepeat(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}

func extractWhoisFields(data string) {
	lines := []string{}
	curr := ""
	for _, ch := range data {
		if ch == '\n' {
			lines = append(lines, curr)
			curr = ""
		} else {
			curr += string(ch)
		}
	}
	if curr != "" {
		lines = append(lines, curr)
	}

	fields := []string{
		"Registrar:", "Domain Name:", "Creation Date:", "Registry Expiry Date:",
		"Updated Date:", "Name Server:", "DNSSEC:", "Registrar Abuse Contact Email:",
		"Registrar Abuse Contact Phone:", "Status:",
	}

	for _, line := range lines {
		for _, field := range fields {
			if len(line) >= len(field) && line[:len(field)] == field {
				fmt.Println(line)
				break
			}
		}
	}
}

func newDomainExpireCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "expire [domain]",
		Short: "Check domain expiration date",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			timeout := getTimeout(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			res, err := performWhoisLookup(ctx, domain)
			if err != nil {
				return fmt.Errorf("expiry check failed: %w", err)
			}

			fmt.Printf("Domain: %s\n", domain)
			for _, line := range strings.Split(res, "\n") {
				if len(line) >= 24 && line[:24] == "Registry Expiry Date:" {
					dateStr := line[24:]
					dateStr = trimSpace(dateStr)
					fmt.Printf("Expiry: %s\n", dateStr)
					if t, err := time.Parse("2006-01-02T15:04:05Z", dateStr); err == nil {
						daysLeft := int(time.Until(t).Hours() / 24)
						if daysLeft > 0 {
							fmt.Printf("Days left: %d\n", daysLeft)
						} else {
							fmt.Println("Expired!")
						}
					}
					return nil
				}
			}
			return fmt.Errorf("could not find expiry date for %s", domain)
		},
	}
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}
