package cli

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// ── SSL Chain + OCSP ────────────────────────────────────────

func newSSLChainCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "chain [host]",
		Short: "Full certificate chain + OCSP + stapling",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			host := args[0]
			port := 443
			if strings.Contains(host, ":") {
				p := host[strings.Index(host, ":")+1:]
				host = host[:strings.Index(host, ":")]
				fmt.Sscanf(p, "%d", &port)
			}
			insecure, _ := cmd.Flags().GetBool("insecure")
			timeout := getTimeout(cmd)

			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", fmt.Sprintf("%s:%d", host, port), &tls.Config{
				InsecureSkipVerify: insecure,
			})
			if err != nil {
				return err
			}
			defer conn.Close()

			state := conn.ConnectionState()
			chain := state.PeerCertificates

			if len(chain) == 0 {
				return fmt.Errorf("no certificates returned")
			}

			fmt.Printf("\n═══════════════════════════════════════════════════════════════\n")
			fmt.Printf("  CERTIFICATE CHAIN — %s:%d\n", host, port)
			fmt.Printf("═══════════════════════════════════════════════════════════════\n\n")

			fmt.Printf("  TLS Version:    %s\n", tlsVersionName(state.Version))
			fmt.Printf("  Cipher Suite:   %s\n", tls.CipherSuiteName(state.CipherSuite))
			fmt.Printf("  ALPN:           %s\n", state.NegotiatedProtocol)
			fmt.Printf("  Chain Length:   %d\n\n", len(chain))

			for i, cert := range chain {
				role := "INTERMEDIATE"
				if i == 0 {
					role = "LEAF (Server)"
				} else if i == len(chain)-1 {
					role = "ROOT CA"
				}

				daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
				status := "VALID"
				if daysLeft < 0 {
					status = "EXPIRED"
				} else if daysLeft < 30 {
					status = "EXPIRING"
				}

				fingerprint := certFingerprint(cert)
				keyType, keySize := certKeyInfo(cert)

				fmt.Printf("  ┌─ [%d] %s (%s) ──────────────────────────┐\n", i, role, status)
				fmt.Printf("  │  Subject:    %s\n", cert.Subject.CommonName)
				fmt.Printf("  │  Issuer:     %s (%s)\n", cert.Issuer.CommonName, strings.Join(cert.Issuer.Organization, ", "))
				fmt.Printf("  │  Serial:     %s\n", cert.SerialNumber.String())
				fmt.Printf("  │  Valid:      %s → %s (%d days)\n", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"), daysLeft)
				fmt.Printf("  │  Key:        %s %d bits\n", keyType, keySize)
				fmt.Printf("  │  Fingerprint: %s\n", fingerprint)
				if len(cert.DNSNames) > 0 {
					fmt.Printf("  │  SANs:       %s\n", truncate(strings.Join(cert.DNSNames, ", "), 50))
				}
				if len(cert.EmailAddresses) > 0 {
					fmt.Printf("  │  Email:      %s\n", strings.Join(cert.EmailAddresses, ", "))
				}
				if len(cert.IPAddresses) > 0 {
					var ips []string
					for _, ip := range cert.IPAddresses {
						ips = append(ips, ip.String())
					}
					fmt.Printf("  │  IP SANs:    %s\n", strings.Join(ips, ", "))
				}
				fmt.Printf("  └────────────────────────────────────────────────┘\n\n")
			}

			// OCSP check
			fmt.Printf("  OCSP Stapling: checking...\n")
			if state.OCSPResponse != nil && len(state.OCSPResponse) > 0 {
				fmt.Printf("  OCSP Stapling: YES (%d bytes)\n", len(state.OCSPResponse))
			} else {
				fmt.Printf("  OCSP Stapling: NO (not supported)\n")
			}

			return nil
		},
	}
}

func certFingerprint(cert *x509.Certificate) string {
	sha := sha256.Sum256(cert.Raw)
	var parts []string
	for _, b := range sha {
		parts = append(parts, fmt.Sprintf("%02X", b))
	}
	return strings.Join(parts, ":")
}

func certKeyInfo(cert *x509.Certificate) (string, int) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	case crypto.Signer:
		return "Unknown", 0
	default:
		return fmt.Sprintf("%T", pub), 0
	}
}
