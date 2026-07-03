package cli

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

func newSSLCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ssl",
		Short: "SSL/TLS certificate and cipher analysis",
		Long:  `Inspect SSL/TLS certificates, cipher suites, protocol versions, and chain validation.`,
	}
	cmd.AddCommand(
		newSSLCertCmd(),
		newSSLCipherCmd(),
		newSSLTLSCmd(),
		newSSLExpireCmd(),
	)
	return cmd
}

func newSSLCertCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cert [host]",
		Short: "Show SSL/TLS certificate details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			host := args[0]
			timeout := getTimeout(cmd)
			insecure, _ := cmd.Flags().GetBool("insecure")

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigChan
				os.Exit(0)
			}()
			_ = sigChan

			port := 443
			if strings.Contains(host, ":") {
				p := host[strings.Index(host, ":")+1:]
				host = host[:strings.Index(host, ":")]
				fmt.Sscanf(p, "%d", &port)
			}

			addr := fmt.Sprintf("%s:%d", host, port)
			conf := &tls.Config{
				InsecureSkipVerify: insecure,
			}

			dialer := &net.Dialer{Timeout: timeout}
			conn, err := tls.DialWithDialer(dialer, "tcp", addr, conf)
			if err != nil {
				return fmt.Errorf("TLS connection failed: %w", err)
			}
			defer conn.Close()

			certs := conn.ConnectionState().PeerCertificates
			if len(certs) == 0 {
				return fmt.Errorf("no certificates returned")
			}

			leaf := certs[0]

			fmt.Printf("Certificate for %s:%d\n", host, port)
			fmt.Println(strings.Repeat("-", 50))
			fmt.Printf("Subject: %s\n", leaf.Subject.CommonName)
			fmt.Printf("Issuer: %s (%s)\n", leaf.Issuer.CommonName, leaf.Issuer.Organization)
			fmt.Printf("Serial Number: %s\n", leaf.SerialNumber)
			fmt.Printf("Not Before: %s\n", leaf.NotBefore.Format(time.RFC3339))
			fmt.Printf("Not After: %s\n", leaf.NotAfter.Format(time.RFC3339))

			daysLeft := int(time.Until(leaf.NotAfter).Hours() / 24)
			fmt.Printf("Days Left: %d\n", daysLeft)
			if daysLeft < 0 {
				fmt.Println("Status: EXPIRED!")
			} else if daysLeft < 30 {
				fmt.Println("Status: EXPIRING SOON!")
			} else {
				fmt.Println("Status: Valid")
			}

			fmt.Printf("Key Algorithm: %s\n", leaf.PublicKeyAlgorithm)
			fmt.Printf("Signature Algorithm: %s\n", leaf.SignatureAlgorithm)
			fmt.Printf("Is CA: %v\n", leaf.IsCA)

			if len(leaf.DNSNames) > 0 {
				fmt.Printf("\nSANs (%d):\n", len(leaf.DNSNames))
				for _, san := range leaf.DNSNames {
					fmt.Printf("  - %s\n", san)
				}
			}

			if len(certs) > 1 {
				fmt.Printf("\nChain (%d certificates):\n", len(certs))
				for i, c := range certs {
					fmt.Printf("  [%d] %s → %s\n", i, c.Subject.CommonName, c.Issuer.CommonName)
				}
			}

			fmt.Printf("\nTLS Version: %s\n", tlsVersionName(conn.ConnectionState().Version))
			fmt.Printf("Cipher Suite: %s\n", tls.CipherSuiteName(conn.ConnectionState().CipherSuite))

			return nil
		},
	}
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionSSL30:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

func newSSLCipherCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cipher [host]",
		Short: "List supported cipher suites",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			host := args[0]
			timeout := getTimeout(cmd)
			insecure, _ := cmd.Flags().GetBool("insecure")

			port := 443
			if strings.Contains(host, ":") {
				p := host[strings.Index(host, ":")+1:]
				host = host[:strings.Index(host, ":")]
				fmt.Sscanf(p, "%d", &port)
			}

			addr := fmt.Sprintf("%s:%d", host, port)
			conf := &tls.Config{
				InsecureSkipVerify: insecure,
				CipherSuites: []uint16{
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				},
			}

			dialer := &net.Dialer{Timeout: timeout}
			conn, err := tls.DialWithDialer(dialer, "tcp", addr, conf)
			if err != nil {
				return fmt.Errorf("TLS connection failed: %w", err)
			}
			defer conn.Close()

			state := conn.ConnectionState()
			fmt.Printf("TLS Cipher Suites for %s:%d\n", host, port)
			fmt.Println(strings.Repeat("-", 50))
			fmt.Printf("Negotiated Suite: %s\n", tls.CipherSuiteName(state.CipherSuite))
			fmt.Printf("TLS Version: %s\n", tlsVersionName(state.Version))
			fmt.Printf("ALPN: %s\n", state.NegotiatedProtocol)

			return nil
		},
	}
}

func newSSLTLSCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tls [host]",
		Short: "Check supported TLS protocol versions",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			host := args[0]
			timeout := getTimeout(cmd)
			insecure, _ := cmd.Flags().GetBool("insecure")

			port := 443
			if strings.Contains(host, ":") {
				p := host[strings.Index(host, ":")+1:]
				host = host[:strings.Index(host, ":")]
				fmt.Sscanf(p, "%d", &port)
			}

			addr := fmt.Sprintf("%s:%d", host, port)

			type protoTest struct {
				name    string
				version uint16
			}

			protos := []protoTest{
				{"TLS 1.3", tls.VersionTLS13},
				{"TLS 1.2", tls.VersionTLS12},
				{"TLS 1.1", tls.VersionTLS11},
				{"TLS 1.0", tls.VersionTLS10},
				{"SSL 3.0", tls.VersionSSL30},
			}

			fmt.Printf("TLS version support for %s:%d\n", host, port)
			fmt.Println(strings.Repeat("-", 50))

			for _, p := range protos {
				conf := &tls.Config{
					InsecureSkipVerify: insecure,
					MinVersion:         p.version,
					MaxVersion:         p.version,
				}

				dialer := &net.Dialer{Timeout: timeout}
				conn, err := tls.DialWithDialer(dialer, "tcp", addr, conf)

				status := "✗ NOT SUPPORTED"
				if err == nil {
					status = "✓ SUPPORTED"
					conn.Close()
				}

				fmt.Printf("  %-8s %s\n", p.name, status)
			}
			return nil
		},
	}
}

func newSSLExpireCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "expire [host]",
		Short: "Check SSL certificate expiration",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			host := args[0]
			timeout := getTimeout(cmd)
			insecure, _ := cmd.Flags().GetBool("insecure")

			port := 443
			if strings.Contains(host, ":") {
				p := host[strings.Index(host, ":")+1:]
				host = host[:strings.Index(host, ":")]
				fmt.Sscanf(p, "%d", &port)
			}

			addr := fmt.Sprintf("%s:%d", host, port)
			conf := &tls.Config{
				InsecureSkipVerify: insecure,
			}

			dialer := &net.Dialer{Timeout: timeout}
			conn, err := tls.DialWithDialer(dialer, "tcp", addr, conf)
			if err != nil {
				return fmt.Errorf("TLS connection failed: %w", err)
			}
			defer conn.Close()

			leaf := conn.ConnectionState().PeerCertificates[0]

			fmt.Printf("SSL Expiration for %s:%d\n", host, port)
			fmt.Println(strings.Repeat("-", 50))
			fmt.Printf("Subject: %s\n", leaf.Subject.CommonName)
			fmt.Printf("Issued: %s\n", leaf.NotBefore.Format(time.RFC3339))
			fmt.Printf("Expires: %s\n", leaf.NotAfter.Format(time.RFC3339))

			daysLeft := int(time.Until(leaf.NotAfter).Hours() / 24)
			if daysLeft < 0 {
				fmt.Printf("Status: ⚠ EXPIRED (%d days ago)\n", -daysLeft)
			} else if daysLeft < 30 {
				fmt.Printf("Status: ⚠ EXPIRING SOON (%d days)\n", daysLeft)
			} else if daysLeft < 90 {
				fmt.Printf("Status: ⚠ EXPIRING WITHIN 90 DAYS (%d days)\n", daysLeft)
			} else {
				fmt.Printf("Status: ✓ Valid (%d days remaining)\n", daysLeft)
			}
			return nil
		},
	}
}
