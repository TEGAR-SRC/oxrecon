package cli

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/spf13/cobra"
)

func newHTTPCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "http",
		Short: "HTTP reconnaissance and analysis",
		Long:  `Probe HTTP endpoints, analyze headers, detect technologies, WAF, CDN, and more.`,
	}
	cmd.AddCommand(
		newHTTPProbeCmd(),
		newHTTPHeadersCmd(),
		newHTTPMethodsCmd(),
		newHTTPRedirectCmd(),
		newHTTPRobotsCmd(),
		newHTTPSitemapCmd(),
		newHTTPWAFCmd(),
		newHTTPTechCmd(),
		newHTTPCDNCmd(),
		newHTTPScreenshotCmd(),
		newHTTPDirCmd(),
		newHTTPCrawlCmd(),
	)
	return cmd
}

func httpClient(cmd *cobra.Command) *http.Client {
	frr, _ := cmd.Flags().GetBool("follow-redirect")
	ins, _ := cmd.Flags().GetBool("insecure")
	timeout := getTimeout(cmd)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: ins},
		MaxIdleConns:    100,
		IdleConnTimeout: 30 * time.Second,
		DisableKeepAlives: false,
	}

	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !frr {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
}

func buildReq(cmd *cobra.Command, targetURL string) (*http.Request, error) {
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, err
	}

	ra, _ := cmd.Flags().GetBool("random-agent")
	if ra {
		req.Header.Set("User-Agent", randomAgent())
	} else {
		req.Header.Set("User-Agent", "WebTool/1.0")
	}
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	return req, nil
}

func randomAgent() string {
	agents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
	}
	return agents[time.Now().UnixNano()%int64(len(agents))]
}

func newHTTPProbeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "probe [url]",
		Short: "HTTP probe to check endpoint availability and response info",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetURL := args[0]
			client := httpClient(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), getTimeout(cmd))
			defer cancel()

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigChan
				cancel()
			}()

			req, err := buildReq(cmd, targetURL)
			if err != nil {
				return err
			}
			req = req.WithContext(ctx)

			start := time.Now()
			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("request failed: %w", err)
			}
			defer resp.Body.Close()
			latency := time.Since(start)

			body, _ := io.ReadAll(resp.Body)

			fmt.Printf("URL: %s\n", resp.Request.URL.String())
			fmt.Printf("Status: %d %s\n", resp.StatusCode, resp.Status)
			fmt.Printf("Response Time: %.2f ms\n", float64(latency.Microseconds())/1000.0)
			fmt.Printf("Content-Type: %s\n", resp.Header.Get("Content-Type"))
			fmt.Printf("Content-Length: %d\n", resp.ContentLength)
			fmt.Printf("Server: %s\n", resp.Header.Get("Server"))
			fmt.Printf("Body Size: %d bytes\n", len(body))

			if len(body) > 0 {
				hash := simpleHash(string(body))
				fmt.Printf("Body Hash: %s\n", hash)
			}
			return nil
		},
	}
}

func simpleHash(s string) string {
	h := 0
	for _, c := range s {
		h = (h*31 + int(c)) & 0x7FFFFFFF
	}
	return fmt.Sprintf("%08x", h)
}

func newHTTPHeadersCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "headers [url]",
		Short: "Analyze HTTP response headers",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetURL := args[0]
			client := httpClient(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), getTimeout(cmd))
			defer cancel()

			req, err := buildReq(cmd, targetURL)
			if err != nil {
				return err
			}
			req = req.WithContext(ctx)

			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("request failed: %w", err)
			}
			defer resp.Body.Close()

			fmt.Printf("HTTP Headers for %s:\n", resp.Request.URL.String())
			fmt.Println(strings.Repeat("-", 60))

			for key, vals := range resp.Header {
				for _, v := range vals {
					fmt.Printf("%s: %s\n", key, v)
				}
			}

			fmt.Println()
			fmt.Println("Security Headers:")
			secHeaders := []string{
				"Strict-Transport-Security", "Content-Security-Policy",
				"X-Frame-Options", "X-Content-Type-Options",
				"X-XSS-Protection", "Referrer-Policy",
				"Permissions-Policy", "Access-Control-Allow-Origin",
			}
			for _, h := range secHeaders {
				v := resp.Header.Get(h)
				status := "❌ MISSING"
				if v != "" {
					status = fmt.Sprintf("✓ %s", v)
				}
				fmt.Printf("  %-35s %s\n", h+":", status)
			}
			return nil
		},
	}
}

func newHTTPMethodsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "methods [url]",
		Short: "Detect allowed HTTP methods",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetURL := args[0]
			timeout := getTimeout(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
				targetURL = "https://" + targetURL
			}

			methods := []string{"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT"}
			client := httpClient(cmd)

			fmt.Printf("Testing HTTP methods for %s:\n", targetURL)
			fmt.Println(strings.Repeat("-", 60))

			for _, method := range methods {
				req, err := http.NewRequest(method, targetURL, nil)
				if err != nil {
					continue
				}
				req = req.WithContext(ctx)
				req.Header.Set("User-Agent", "WebTool/1.0")

				resp, err := client.Do(req)
				if err != nil {
					fmt.Printf("  %-8s → ERROR: %v\n", method, err)
					continue
				}
				resp.Body.Close()

				status := "✓"
				if resp.StatusCode >= 400 {
					status = "✗"
				}
				fmt.Printf("  %-8s %s %d %s\n", method, status, resp.StatusCode, resp.Status)
			}
			return nil
		},
	}
}

func newHTTPRedirectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "redirect [url]",
		Short: "Trace HTTP redirect chain with no-follow redirects",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetURL := args[0]
			client := httpClient(cmd)
			_ = client

			if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
				targetURL = "https://" + targetURL
			}

			ctx, cancel := context.WithTimeout(context.Background(), getTimeout(cmd))
			defer cancel()

			fmt.Printf("Redirect chain for %s:\n", targetURL)
			fmt.Println(strings.Repeat("-", 60))

			currentURL := targetURL
			chainLen := 0

			for chainLen < 10 {
				req, err := http.NewRequest("GET", currentURL, nil)
				if err != nil {
					return err
				}
				req = req.WithContext(ctx)
				req.Header.Set("User-Agent", "WebTool/1.0")

				tr := &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				}
				noRedirectClient := &http.Client{
					Transport: tr,
					Timeout:   10 * time.Second,
					CheckRedirect: func(req *http.Request, via []*http.Request) error {
						return http.ErrUseLastResponse
					},
				}

				resp, err := noRedirectClient.Do(req)
				if err != nil {
					fmt.Printf("  → ERROR: %v\n", err)
					break
				}

				fmt.Printf("  %d %s → %s\n", resp.StatusCode, resp.Status, currentURL)

				loc := resp.Header.Get("Location")
				resp.Body.Close()

				loc = strings.TrimSpace(loc)
				if loc == "" || resp.StatusCode < 300 || resp.StatusCode >= 400 {
					fmt.Printf("\nFinal URL: %s\n", currentURL)
					break
				}

				if strings.HasPrefix(loc, "/") {
					u, _ := url.Parse(currentURL)
					loc = u.Scheme + "://" + u.Host + loc
				} else if !strings.HasPrefix(loc, "http://") && !strings.HasPrefix(loc, "https://") {
					u, _ := url.Parse(currentURL)
					base := u.Scheme + "://" + u.Host
					if !strings.HasPrefix(u.Path, "/") {
						base += "/"
					}
					loc = base + loc
				}

				currentURL = loc
				chainLen++
			}
			return nil
		},
	}
}

func newHTTPRobotsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "robots [url]",
		Short: "Fetch and parse robots.txt",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetURL := args[0]
			client := httpClient(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), getTimeout(cmd))
			defer cancel()

			if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
				targetURL = "https://" + targetURL
			}

			u, err := url.Parse(targetURL)
			if err != nil {
				return err
			}

			robotsURL := u.Scheme + "://" + u.Host + "/robots.txt"
			req, _ := http.NewRequest("GET", robotsURL, nil)
			req = req.WithContext(ctx)
			req.Header.Set("User-Agent", "WebTool/1.0")

			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("failed to fetch robots.txt: %w", err)
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)

			if resp.StatusCode == 404 {
				fmt.Printf("No robots.txt found at %s\n", robotsURL)
				return nil
			}

			fmt.Printf("robots.txt at %s:\n", robotsURL)
			fmt.Println(strings.Repeat("-", 60))
			fmt.Println(string(body))
			return nil
		},
	}
}

func newHTTPSitemapCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sitemap [url]",
		Short: "Fetch and parse sitemap.xml",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetURL := args[0]
			client := httpClient(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), getTimeout(cmd))
			defer cancel()

			if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
				targetURL = "https://" + targetURL
			}

			u, err := url.Parse(targetURL)
			if err != nil {
				return err
			}

			sitemapURL := u.Scheme + "://" + u.Host + "/sitemap.xml"
			req, _ := http.NewRequest("GET", sitemapURL, nil)
			req = req.WithContext(ctx)
			req.Header.Set("User-Agent", "WebTool/1.0")

			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("failed to fetch sitemap.xml: %w", err)
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)

			if resp.StatusCode == 404 {
				fmt.Printf("No sitemap.xml found at %s\n", sitemapURL)
				return nil
			}

			fmt.Printf("sitemap.xml at %s:\n", sitemapURL)
			fmt.Println(strings.Repeat("-", 60))
			fmt.Println(string(body))
			return nil
		},
	}
}

func newHTTPWAFCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "waf [url]",
		Short: "Detect Web Application Firewall (WAF)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetURL := args[0]
			client := httpClient(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), getTimeout(cmd))
			defer cancel()

			if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
				targetURL = "https://" + targetURL
			}

			req, _ := http.NewRequest("GET", targetURL, nil)
			req = req.WithContext(ctx)
			req.Header.Set("User-Agent", "WebTool/1.0")
			req.Header.Set("Accept", "*/*")

			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("request failed: %w", err)
			}
			defer resp.Body.Close()

			server := resp.Header.Get("Server")
			waf := "None Detected"
			detected := false

			for k, v := range resp.Header {
				hk := strings.ToLower(k)
				hv := strings.ToLower(strings.Join(v, " "))
				switch {
				case strings.Contains(hv, "cloudflare"), strings.Contains(hk, "cf-ray"), strings.Contains(hk, "cf-cache-status"):
					waf = "Cloudflare"
					detected = true
				case strings.Contains(hv, "akamai"), strings.Contains(hk, "akamai"), strings.Contains(hk, "x-akamai"):
					waf = "Akamai"
					detected = true
				case strings.Contains(hv, "incapsula"), strings.Contains(hk, "incapsula"):
					waf = "Incapsula"
					detected = true
				case strings.Contains(hv, "sucuri"), strings.Contains(hk, "x-sucuri-id"):
					waf = "Sucuri"
					detected = true
				case strings.Contains(hv, "mod_security"), strings.Contains(hk, "x-mod-security"):
					waf = "ModSecurity"
					detected = true
				case strings.Contains(hv, "aws"), strings.Contains(hk, "x-amz"):
					waf = "AWS WAF"
					detected = true
				case strings.Contains(hv, "f5"), strings.Contains(hk, "x-f5"):
					waf = "F5 BIG-IP"
					detected = true
				case strings.Contains(resp.Status, "406"):
					if strings.Contains(hv, "blocked") || strings.Contains(server, "cloudflare") {
						waf = "Cloudflare"
						detected = true
					}
				}
			}

			fmt.Printf("URL: %s\n", targetURL)
			fmt.Printf("Server: %s\n", server)
			fmt.Printf("WAF Detected: %v\n", detected)
			if detected {
				fmt.Printf("WAF Type: %s\n", waf)
			}
			return nil
		},
	}
}

func newHTTPTechCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tech [url]",
		Short: "Detect web technologies (CMS, frameworks, servers)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetURL := args[0]
			client := httpClient(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), getTimeout(cmd))
			defer cancel()

			if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
				targetURL = "https://" + targetURL
			}

			req, _ := http.NewRequest("GET", targetURL, nil)
			req = req.WithContext(ctx)
			req.Header.Set("User-Agent", randomAgent())
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("request failed: %w", err)
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			bodyStr := string(body)

			doc, _ := goquery.NewDocumentFromReader(strings.NewReader(bodyStr))

			var technologies []string

			// Server header
			server := resp.Header.Get("Server")
			if server != "" {
				technologies = append(technologies, fmt.Sprintf("Server: %s", server))
			}

			// X-Powered-By
			xpb := resp.Header.Get("X-Powered-By")
			if xpb != "" {
				technologies = append(technologies, fmt.Sprintf("Powered-by: %s", xpb))
			}

			// Check for CMS via meta generator
			doc.Find("meta[name=generator]").Each(func(i int, s *goquery.Selection) {
				if content, exists := s.Attr("content"); exists {
					technologies = append(technologies, fmt.Sprintf("CMS: %s", content))
				}
			})

			// WordPress
			if strings.Contains(bodyStr, "wp-content") || strings.Contains(bodyStr, "wp-includes") || strings.Contains(bodyStr, "/wp-json/") {
				technologies = append(technologies, "CMS: WordPress")
			}

			// Joomla
			if strings.Contains(bodyStr, "com_content") || strings.Contains(bodyStr, "/components/com_") {
				technologies = append(technologies, "CMS: Joomla")
			}

			// Drupal
			if strings.Contains(bodyStr, "Drupal.settings") || strings.Contains(bodyStr, "/sites/default/files") {
				technologies = append(technologies, "CMS: Drupal")
			}

			// Laravel
			if strings.Contains(bodyStr, "laravel_session") || strings.Contains(bodyStr, "XSRF-TOKEN") {
				technologies = append(technologies, "Framework: Laravel")
			}

			// React
			if strings.Contains(bodyStr, "react.development") || strings.Contains(bodyStr, "react.production") || strings.Contains(bodyStr, "_reactRootContainer") || strings.Contains(bodyStr, "__NEXT_DATA__") {
				technologies = append(technologies, "JS Framework: React")
			}

			// Vue.js
			if strings.Contains(bodyStr, "vue.js") || strings.Contains(bodyStr, "vue.min.js") || strings.Contains(bodyStr, "__vue__") {
				technologies = append(technologies, "JS Framework: Vue.js")
			}

			// Angular
			if strings.Contains(bodyStr, "angular.js") || strings.Contains(bodyStr, "ng-app") || strings.Contains(bodyStr, "ng-version") {
				technologies = append(technologies, "JS Framework: Angular")
			}

			// jQuery
			if strings.Contains(bodyStr, "jquery") {
				technologies = append(technologies, "JS Library: jQuery")
			}

			// Bootstrap
			if strings.Contains(bodyStr, "bootstrap") {
				technologies = append(technologies, "CSS Framework: Bootstrap")
			}

			// Tailwind
			if strings.Contains(bodyStr, "tailwind") {
				technologies = append(technologies, "CSS Framework: Tailwind CSS")
			}

			// Cloudflare
			cfRay := resp.Header.Get("CF-Ray")
			if cfRay != "" {
				technologies = append(technologies, "CDN/WAF: Cloudflare")
			}

			// Google Analytics
			if strings.Contains(bodyStr, "google-analytics.com") || strings.Contains(bodyStr, "googletagmanager.com") {
				technologies = append(technologies, "Analytics: Google Analytics")
			}

			// Font Awesome
			if strings.Contains(bodyStr, "font-awesome") || strings.Contains(bodyStr, "fontawesome") {
				technologies = append(technologies, "Icons: Font Awesome")
			}

			fmt.Printf("Technologies for %s:\n", targetURL)
			fmt.Println(strings.Repeat("-", 60))
			for _, t := range technologies {
				fmt.Printf("  ✓ %s\n", t)
			}
			return nil
		},
	}
}

func newHTTPCDNCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cdn [url]",
		Short: "Detect CDN provider",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetURL := args[0]
			client := httpClient(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), getTimeout(cmd))
			defer cancel()

			if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
				targetURL = "https://" + targetURL
			}

			u, err := url.Parse(targetURL)
			if err != nil {
				return err
			}

			// Check via IP whois
			ips, err := net.LookupHost(u.Host)
			if err != nil {
				return fmt.Errorf("DNS lookup failed: %w", err)
			}

			fmt.Printf("CDN detection for %s:\n", targetURL)
			fmt.Println(strings.Repeat("-", 60))

			for _, ip := range ips {
				cdn := detectCDN(ip)
				fmt.Printf("  %-16s → %s\n", ip, cdn)
			}

			// Check HTTP headers
			req, _ := http.NewRequest("GET", targetURL, nil)
			req = req.WithContext(ctx)
			req.Header.Set("User-Agent", "WebTool/1.0")

			resp, err := client.Do(req)
			if err == nil {
				defer resp.Body.Close()
				server := resp.Header.Get("Server")
				via := resp.Header.Get("Via")
				cfRay := resp.Header.Get("CF-Ray")
				akamai := resp.Header.Get("X-Akamai-Transformed")

				if cfRay != "" {
					fmt.Printf("  CDN: Cloudflare (CF-Ray: %s)\n", cfRay)
				}
				if strings.Contains(via, "cloudflare") {
					fmt.Println("  CDN: Cloudflare (Via header)")
				}
				if akamai != "" {
					fmt.Printf("  CDN: Akamai (X-Akamai-Transformed: %s)\n", akamai)
				}
				if server != "" {
					fmt.Printf("  Server: %s\n", server)
				}
			}
			return nil
		},
	}
}

func detectCDN(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) < 2 {
		return "Unknown"
	}

	// Check common CDN IP ranges (simplified)
	ipPrefix := parts[0] + "." + parts[1]

	switch ipPrefix {
	case "104.16", "104.17", "104.18", "104.19", "104.20", "104.21",
		"104.22", "104.23", "104.24", "104.25", "104.26", "104.27", "104.28":
		return "Cloudflare"
	case "151.101", "151.202":
		return "Fastly"
	case "23.1", "23.2", "23.3", "23.4", "23.5", "23.6", "23.7", "23.8":
		return "Akamai"
	case "13.32", "13.33", "13.34", "13.35", "13.224", "13.225", "13.226":
		return "AWS CloudFront"
	case "199.232":
		return "Fastly"
	}

	return "Unknown / Direct"
}

func newHTTPScreenshotCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "screenshot [url]",
		Short: "Take a screenshot of a webpage",
		Long:  `Screenshot a webpage using HTTP rendering (text-based fallback if no headless browser).`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetURL := args[0]
			client := httpClient(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), getTimeout(cmd))
			defer cancel()

			if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
				targetURL = "https://" + targetURL
			}

			req, _ := http.NewRequest("GET", targetURL, nil)
			req = req.WithContext(ctx)
			req.Header.Set("User-Agent", "WebTool/1.0")

			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("failed to fetch page: %w", err)
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			doc, _ := goquery.NewDocumentFromReader(strings.NewReader(string(body)))

			fmt.Printf("Screenshot (text-based) for %s:\n", targetURL)
			fmt.Println(strings.Repeat("-", 60))

			title := doc.Find("title").Text()
			fmt.Printf("Title: %s\n", title)

			fmt.Printf("Body: %d bytes\n", len(body))
			fmt.Printf("Status: %d\n", resp.StatusCode)

			h1 := doc.Find("h1").First().Text()
			if h1 != "" {
				fmt.Printf("H1: %s\n", h1)
			}

			metaDesc, _ := doc.Find("meta[name=description]").Attr("content")
			if metaDesc != "" {
				fmt.Printf("Description: %s\n", metaDesc)
			}

			linkCount := doc.Find("a").Length()
			imgCount := doc.Find("img").Length()
			scriptCount := doc.Find("script").Length()
			linkTags := doc.Find("link").Length()

			fmt.Printf("Links: %d, Images: %d, Scripts: %d, Link Tags: %d\n",
				linkCount, imgCount, scriptCount, linkTags)
			return nil
		},
	}
}

func newHTTPDirCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "dir [url]",
		Short: "Directory busting (common paths)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetURL := args[0]
			client := httpClient(cmd)
			threads, _ := cmd.Flags().GetInt("threads")
			silent := getSilent(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), getTimeout(cmd))
			defer cancel()

			if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
				targetURL = "https://" + targetURL
			}

			u, err := url.Parse(targetURL)
			if err != nil {
				return err
			}
			base := u.Scheme + "://" + u.Host

			paths := []string{
				"/admin", "/wp-admin", "/administrator", "/login", "/wp-login",
				"/backup", "/.git", "/.env", "/config", "/api", "/v1",
				"/.htaccess", "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
				"/phpinfo.php", "/test", "/dev", "/uploads", "/downloads",
				"/images", "/css", "/js", "/assets", "/static", "/public",
				"/server-status", "/.well-known", "/vendor", "/node_modules",
				"/swagger", "/docs", "/api/v1", "/api/v2", "/graphql",
				"/.aws", "/.ssh", "/id_rsa", "/docker-compose.yml",
				"/Dockerfile", "/.dockerignore", "/Makefile", "/package.json",
				"/composer.json", "/Gemfile", "/requirements.txt",
				"/config.php", "/config.json", "/config.yaml", "/config.yml",
				"/database.yml", "/database.php", "/db.php",
				"/wp-config.php", "/wp-config.bak",
				"/install", "/setup", "/panel", "/cpanel", "/webadmin",
				"/manager", "/console", "/shell", "/cmd", "/command",
				"/logs", "/log", "/error_log", "/access_log",
				"/cgi-bin", "/cgi-bin/test.cgi",
				"/server-info", "/server-health", "/status",
				"/actuator", "/actuator/health",
				"/.env.production", "/.env.development",
				"/index.php", "/index.html", "/index.htm",
				"/default.aspx", "/default.html",
				"/index.php/login", "/administrator/index.php",
			}

			if !silent {
				fmt.Fprintf(os.Stderr, "Directory busting %s (%d paths, %d workers)...\n",
					targetURL, len(paths), threads)
			}

			type pathResult struct {
				path   string
				status int
				size   int
			}

			var mu sync.Mutex
			var wg sync.WaitGroup
			results := make(chan pathResult, threads)
			pathCh := make(chan string, len(paths))

			for i := 0; i < threads; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for path := range pathCh {
						if ctx.Err() != nil {
							return
						}

						fullURL := base + path
						req, _ := http.NewRequest("GET", fullURL, nil)
						req = req.WithContext(ctx)
						req.Header.Set("User-Agent", "WebTool/1.0")
						req.Header.Set("Accept", "*/*")

						resp, err := client.Do(req)
						if err != nil {
							continue
						}

						status := resp.StatusCode
						size := int(resp.ContentLength)
						resp.Body.Close()

						mu.Lock()
						results <- pathResult{path, status, size}
						mu.Unlock()
					}
				}()
			}

			for _, p := range paths {
				select {
				case pathCh <- p:
				case <-ctx.Done():
					goto done
				}
			}
			close(pathCh)

			wg.Wait()
			close(results)

		done:
			fmt.Printf("\nDirectory busting results for %s:\n", base)
			fmt.Printf("%-35s %s\n", "Path", "Status")
			fmt.Println(strings.Repeat("-", 45))
			found := 0
			for r := range results {
				if r.status < 400 || r.status == 401 || r.status == 403 {
					found++
					statusStr := fmt.Sprintf("%d (%d bytes)", r.status, r.size)
					fmt.Printf("%-35s %s\n", r.path, statusStr)
				}
			}
			if found == 0 {
				fmt.Println("  No interesting paths discovered.")
			}
			return nil
		},
	}
}

func newHTTPCrawlCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "crawl [url]",
		Short: "Crawl a webpage and extract links",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetURL := args[0]
			client := httpClient(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), getTimeout(cmd))
			defer cancel()

			if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
				targetURL = "https://" + targetURL
			}

			u, err := url.Parse(targetURL)
			if err != nil {
				return err
			}
			baseHost := u.Host

			req, _ := http.NewRequest("GET", targetURL, nil)
			req = req.WithContext(ctx)
			req.Header.Set("User-Agent", randomAgent())

			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("crawl failed: %w", err)
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			doc, _ := goquery.NewDocumentFromReader(strings.NewReader(string(body)))

			var internal, external []string

			doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
				href, _ := s.Attr("href")
				if href == "" || href == "#" || strings.HasPrefix(href, "javascript:") {
					return
				}

				hrefStr := href
				if strings.HasPrefix(href, "/") {
					hrefStr = u.Scheme + "://" + u.Host + href
				} else if !strings.HasPrefix(href, "http://") && !strings.HasPrefix(href, "https://") {
					return
				}

				hrefURL, err := url.Parse(hrefStr)
				if err != nil {
					return
				}

				if hrefURL.Host == baseHost || strings.HasSuffix(hrefURL.Host, "."+baseHost) {
					internal = append(internal, hrefStr)
				} else {
					external = append(external, hrefStr)
				}
			})

			fmt.Printf("Crawl results for %s:\n", targetURL)
			fmt.Println(strings.Repeat("-", 60))
			fmt.Printf("\nInternal links (%d):\n", len(internal))
			for _, l := range dedupAndSort(internal) {
				fmt.Printf("  %s\n", l)
			}
			fmt.Printf("\nExternal links (%d):\n", len(external))
			for _, l := range dedupAndSort(external) {
				fmt.Printf("  %s\n", l)
			}
			return nil
		},
	}
}

func dedupAndSort(items []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}
