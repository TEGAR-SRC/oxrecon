package cli

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/spf13/cobra"
)

// ── HTTP Security: CSP, Cookie, Favicon, WebSocket ─────────

func newHTTPSecurityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "security",
		Short: "HTTP security analysis (CSP, cookie, favicon)",
	}
	cmd.AddCommand(
		newHTTPCSPCmd(),
		newHTTPCookieCmd(),
		newHTTPFaviconCmd(),
		newHTTPWebsocketCmd(),
		newHTTPHTTP2Cmd(),
	)
	return cmd
}

func newHTTPCSPCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "csp [url]",
		Short: "Parse and analyze Content-Security-Policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetURL := args[0]
			client := httpClient(cmd)

			if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
				targetURL = "https://" + targetURL
			}

			req, _ := http.NewRequest("GET", targetURL, nil)
			req.Header.Set("User-Agent", "WebTool/1.0")
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)

			csp := resp.Header.Get("Content-Security-Policy")
			if csp == "" {
				// Try report-only
				csp = resp.Header.Get("Content-Security-Policy-Report-Only")
				if csp != "" {
					fmt.Println("CSP (Report-Only mode):")
				} else {
					fmt.Println("⚠ No Content-Security-Policy header found")
					fmt.Println("This site has NO CSP protection against XSS/data injection.")
					return nil
				}
			} else {
				fmt.Println("Content-Security-Policy:")
			}

			fmt.Println(strings.Repeat("-", 60))
			directives := strings.Split(csp, ";")

			for _, dir := range directives {
				dir = strings.TrimSpace(dir)
				if dir == "" {
					continue
				}
				parts := strings.SplitN(dir, " ", 2)
				name := parts[0]
				vals := ""
				if len(parts) > 1 {
					vals = parts[1]
				}

				icon := "✓"
				if name == "default-src" && vals == "'none'" {
					icon = "✓"
				} else if strings.Contains(vals, "'unsafe-inline'") || strings.Contains(vals, "'unsafe-eval'") {
					icon = "⚠"
				}

				fmt.Printf("  %s %-25s %s\n", icon, name+":", vals)
			}

			return nil
		},
	}
}

func newHTTPCookieCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cookie [url]",
		Short: "Analyze HTTP cookies (secure, httponly, samesite)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetURL := args[0]
			client := httpClient(cmd)

			if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
				targetURL = "https://" + targetURL
			}

			req, _ := http.NewRequest("GET", targetURL, nil)
			req.Header.Set("User-Agent", "WebTool/1.0")
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)

			cookies := resp.Header["Set-Cookie"]
			if len(cookies) == 0 {
				fmt.Println("No cookies set by this site")
				return nil
			}

			fmt.Printf("Cookies (%d):\n", len(cookies))
			fmt.Println(strings.Repeat("-", 60))

			for i, c := range cookies {
				parts := strings.SplitN(c, ";", 2)
				name := parts[0]

				flags := ""
				secure := strings.Contains(c, "Secure")
				httponly := strings.Contains(c, "HttpOnly")
				samesite := ""
				if strings.Contains(c, "SameSite=None") {
					samesite = "None"
				} else if strings.Contains(c, "SameSite=Lax") {
					samesite = "Lax"
				} else if strings.Contains(c, "SameSite=Strict") {
					samesite = "Strict"
				}

				if secure {
					flags += " 🔒 Secure"
				} else {
					flags += " ⚠ Not-Secure"
				}
				if httponly {
					flags += " 🛡 HttpOnly"
				}
				if samesite != "" {
					flags += fmt.Sprintf(" SameSite=%s", samesite)
				}

				fmt.Printf("  [%d] %s\n", i+1, truncate(name, 55))
				if len(parts) > 1 {
					fmt.Printf("      Attributes:%s\n", flags)
					exp := extractAttr(parts[1], "Expires=")
					if exp != "" {
						fmt.Printf("      Expires: %s\n", exp)
					}
					maxAge := extractAttr(parts[1], "Max-Age=")
					if maxAge != "" {
						fmt.Printf("      Max-Age: %s\n", maxAge)
					}
					domain := extractAttr(parts[1], "Domain=")
					if domain != "" {
						fmt.Printf("      Domain:  %s\n", domain)
					}
					path := extractAttr(parts[1], "Path=")
					if path != "" {
						fmt.Printf("      Path:    %s\n", path)
					}
				}
			}
			return nil
		},
	}
}

func extractAttr(s, prefix string) string {
	parts := strings.Split(s, ";")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, prefix) {
			return strings.TrimPrefix(p, prefix)
		}
	}
	return ""
}

func newHTTPFaviconCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "favicon [url]",
		Short: "Fetch favicon and compute hashes (MMH3, MD5, SHA256)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetURL := args[0]
			client := httpClient(cmd)

			if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
				targetURL = "https://" + targetURL
			}

			// Try /favicon.ico first
			u, _ := url.Parse(targetURL)
			favURL := u.Scheme + "://" + u.Host + "/favicon.ico"

			// Also check HTML for alternate favicon paths
			req, _ := http.NewRequest("GET", targetURL, nil)
			req.Header.Set("User-Agent", "WebTool/1.0")
			resp, err := client.Do(req)
			if err == nil {
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)
				doc, _ := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
				doc.Find("link[rel*='icon']").Each(func(i int, s *goquery.Selection) {
					if href, exists := s.Attr("href"); exists {
						if strings.HasPrefix(href, "http") {
							favURL = href
						} else {
							favURL = u.Scheme + "://" + u.Host + href
						}
					}
				})
			}

			fmt.Printf("Favicon URL: %s\n", favURL)

			req, _ = http.NewRequest("GET", favURL, nil)
			req.Header.Set("User-Agent", "WebTool/1.0")
			resp, err = client.Do(req)
			if err != nil {
				return fmt.Errorf("favicon fetch failed: %w", err)
			}
			defer resp.Body.Close()

			data, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}

			fmt.Printf("Size: %d bytes\n", len(data))

			// MD5 hash
			md5h := md5.Sum(data)
			md5Str := hex.EncodeToString(md5h[:])
			fmt.Printf("MD5:    %s\n", md5Str)

			// SHA256 hash
			sha256h := sha256.Sum256(data)
			sha256Str := hex.EncodeToString(sha256h[:])
			fmt.Printf("SHA256: %s\n", sha256Str)

			// Favicon hash (base64 encoded SHA256 - used by Shodan)
			b64Hash := base64.StdEncoding.EncodeToString(sha256h[:])
			fmt.Printf("Base64: %s\n", truncate(b64Hash, 50))

			// Content type
			ct := resp.Header.Get("Content-Type")
			if ct != "" {
				fmt.Printf("Type:   %s\n", ct)
			}

			fmt.Println("\nUse these hashes to search on Shodan, ZoomEye, and FOFA")

			return nil
		},
	}
}

func newHTTPWebsocketCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ws [url]",
		Short: "Detect WebSocket endpoint support",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check for WebSocket via HTTP Upgrade header
			targetURL := args[0]
			client := httpClient(cmd)

			if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
				targetURL = "https://" + targetURL
			}

			req, _ := http.NewRequest("GET", targetURL, nil)
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("User-Agent", "WebTool/1.0")
			req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
			req.Header.Set("Sec-WebSocket-Version", "13")

			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)

			upgrade := resp.Header.Get("Upgrade")

			fmt.Printf("WebSocket Detection for %s:\n", targetURL)
			if strings.ToLower(upgrade) == "websocket" {
				fmt.Println("  ✅ WebSocket SUPPORTED (101 Switching Protocols)")
			} else {
				fmt.Printf("  ❌ WebSocket NOT supported (response: %d)\n", resp.StatusCode)
			}

			// Detect WS endpoints from page
			return nil
		},
	}
}

func newHTTPHTTP2Cmd() *cobra.Command {
	return &cobra.Command{
		Use:   "http2 [url]",
		Short: "Check HTTP/2 and HTTP/3 support",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetURL := args[0]
			if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
				targetURL = "https://" + targetURL
			}

			u, _ := url.Parse(targetURL)
			host := u.Host
			port := "443"
			if strings.Contains(host, ":") {
				port = host[strings.Index(host, ":")+1:]
				host = host[:strings.Index(host, ":")]
			}

			fmt.Printf("HTTP/2 & HTTP/3 for %s:\n", targetURL)

			// HTTP/2 via TLS ALPN
			conn, err := tls.DialWithDialer(
				&net.Dialer{Timeout: 10 * time.Second},
				"tcp", host+":"+port,
				&tls.Config{NextProtos: []string{"h2", "http/1.1"}},
			)
			if err == nil {
				defer conn.Close()
				proto := conn.ConnectionState().NegotiatedProtocol
				if proto == "h2" {
					fmt.Println("  ✅ HTTP/2 SUPPORTED")
				} else {
					fmt.Println("  ❌ HTTP/2 NOT supported (negotiated:", proto, ")")
				}
			} else {
				fmt.Println("  ❌ Cannot connect to check HTTP/2")
			}

			// HTTP/3 (QUIC) via DNS doh or alt-svc header
			client := httpClient(cmd)
			req, _ := http.NewRequest("GET", targetURL, nil)
			req.Header.Set("User-Agent", "WebTool/1.0")
			resp, err := client.Do(req)
			if err == nil {
				defer resp.Body.Close()
				altSvc := resp.Header.Get("Alt-Svc")
				if strings.Contains(altSvc, "h3") || strings.Contains(altSvc, "h3-29") {
					fmt.Printf("  ✅ HTTP/3 (QUIC) SUPPORTED via Alt-Svc: %s\n", truncate(altSvc, 40))
				} else {
					fmt.Println("  ❌ HTTP/3 NOT detected (no Alt-Svc header)")
				}
			}

			return nil
		},
	}
}
