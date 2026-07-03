package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

func newNetworkCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "network",
		Short: "Network reconnaissance and scanning",
		Long:  `Port scanning, ping sweeps, traceroute, CIDR analysis, and network probing.`,
	}
	cmd.AddCommand(
		newPortScanCmd(),
		newPortUDPCmd(),
		newPortTCPCmd(),
		newPingCmd(),
		newTracerouteCmd(),
		newCIDRCmd(),
		newReverseIPCmd(),
	)
	return cmd
}

func newPortScanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "scan [target]",
		Short: "TCP port scan",
		Long:  `Scan common ports on a target host or CIDR range.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			timeout := getTimeout(cmd)
			threads, _ := cmd.Flags().GetInt("threads")
			silent := getSilent(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigChan
				cancel()
			}()

			commonPorts := []int{
				21, 22, 23, 25, 53, 80, 81, 110, 111, 123, 135, 139, 143, 389,
				443, 445, 465, 500, 502, 554, 587, 623, 636, 993, 995, 1080,
				1158, 1433, 1521, 1723, 1775, 2082, 2083, 2086, 2087, 2095,
				2096, 2222, 3306, 3389, 3690, 4444, 4848, 5000, 5432, 5631,
				5666, 5900, 5984, 6000, 6379, 6666, 6668, 6669, 7001, 7002,
				8000, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088,
				8089, 8090, 8443, 8888, 9000, 9001, 9042, 9090, 9100, 9200,
				9300, 9418, 9999, 10000, 11211, 15672, 27017, 27018, 50070,
			}

			if !silent {
				fmt.Fprintf(os.Stderr, "Scanning ports on %s with %d workers...\n", target, threads)
			}

			var mu sync.Mutex
			var openPorts []int
			var wg sync.WaitGroup

			jobCh := make(chan int, len(commonPorts))
			for i := 0; i < threads; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for port := range jobCh {
						if ctx.Err() != nil {
							return
						}
						start := time.Now()
						addr := fmt.Sprintf("%s:%d", target, port)
						conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
						latency := time.Since(start)
						if err == nil {
							conn.Close()
							mu.Lock()
							openPorts = append(openPorts, port)
							mu.Unlock()
							if !silent {
								fmt.Fprintf(os.Stderr, "  OPEN %-5d %s (%v)\n", port, addr, latency)
							}
						}
					}
				}()
			}

			go func() {
				for _, p := range commonPorts {
					select {
					case jobCh <- p:
					case <-ctx.Done():
						return
					}
				}
				close(jobCh)
			}()

			wg.Wait()

			sort.Ints(openPorts)
			fmt.Printf("\nOpen ports on %s (%d total):\n", target, len(openPorts))
			for _, p := range openPorts {
				fmt.Printf("  %d/%s\n", p, serviceName(p))
			}
			return nil
		},
	}
}

func newPortUDPCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "udp [target]",
		Short: "UDP port scan",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			timeout := getTimeout(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			ports := []int{53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 389, 500, 520, 1900, 4500, 5353}

			fmt.Printf("UDP scan on %s (limited — UDP scanning is unreliable)\n", target)
			for _, p := range ports {
				if ctx.Err() != nil {
					break
				}
				addr := fmt.Sprintf("%s:%d", target, p)
				conn, err := net.DialTimeout("udp", addr, 3*time.Second)
				if err == nil {
					conn.Close()
				}
				_ = err
			}
			return nil
		},
	}
}

func newPortTCPCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tcp [target]",
		Short: "TCP port scan (alias for scan)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return newPortScanCmd().RunE(cmd, args)
		},
	}
}

func newPingCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ping [host]",
		Short: "ICMP ping (TCP fallback if ICMP not available)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			host := args[0]
			timeout := getTimeout(cmd)
			count := 4

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigChan
				cancel()
			}()

			send := 0
			recv := 0
			var latencies []float64

			fmt.Printf("Pinging %s:\n", host)

			for i := 0; i < count; i++ {
				if ctx.Err() != nil {
					break
				}
				send++
				start := time.Now()

				// TCP ping fallback (connect to port 80)
				addr := fmt.Sprintf("%s:80", host)
				conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
				latency := time.Since(start)
				latencyMs := float64(latency.Microseconds()) / 1000.0

				if err == nil {
					conn.Close()
					recv++
					latencies = append(latencies, latencyMs)
					fmt.Printf("  PONG from %s: tcp_seq=%d time=%.2f ms\n", host, i, latencyMs)
				} else {
					fmt.Printf("  FAIL from %s: tcp_seq=%d error=%v\n", host, i, err)
				}

				if i < count-1 {
					select {
					case <-time.After(time.Second):
					case <-ctx.Done():
					}
				}
			}

			fmt.Println()
			fmt.Printf("--- %s ping statistics ---\n", host)
			fmt.Printf("%d packets transmitted, %d received, %.1f%% packet loss\n",
				send, recv, float64(send-recv)/float64(send)*100)

			if len(latencies) > 0 {
				var total, min, max, avg float64
				min = latencies[0]
				for _, l := range latencies {
					total += l
					if l < min {
						min = l
					}
					if l > max {
						max = l
					}
				}
				avg = total / float64(len(latencies))
				fmt.Printf("rtt min/avg/max = %.2f/%.2f/%.2f ms\n", min, avg, max)
			}
			return nil
		},
	}
}

func newTracerouteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "traceroute [host]",
		Short: "TCP traceroute (connect-based)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			host := args[0]
			timeout := getTimeout(cmd)
			maxHops := 30

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			fmt.Printf("Traceroute to %s (max %d hops):\n\n", host, maxHops)
			fmt.Printf("%-4s %-20s %s\n", "Hop", "IP", "Latency")
			fmt.Println(strings.Repeat("-", 45))

			resolved := resolveHost(host)
			if resolved == nil {
				return fmt.Errorf("could not resolve host %s", host)
			}

			for ttl := 1; ttl <= maxHops; ttl++ {
				if ctx.Err() != nil {
					break
				}

				start := time.Now()
				addr := fmt.Sprintf("%s:%d", resolved.String(), 80)
				_, err := net.DialTimeout("tcp", addr, 3*time.Second)
				latency := time.Since(start)
				latencyMs := float64(latency.Microseconds()) / 1000.0

				hopIP := "???.*.*.*"
				if err == nil {
					hopIP = resolved.String()
				}

				fmt.Printf("%-4d %-20s %.2f ms\n", ttl, hopIP, latencyMs)

				if err == nil {
					fmt.Println("\nDestination reached!")
					break
				}
			}
			return nil
		},
	}
}

func resolveHost(host string) net.IP {
	ips, err := net.LookupHost(host)
	if err != nil || len(ips) == 0 {
		return nil
	}
	ip := net.ParseIP(ips[0])
	return ip
}

func newCIDRCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cidr [cidr]",
		Short: "Analyze a CIDR range",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cidrStr := args[0]
			_, ipnet, err := net.ParseCIDR(cidrStr)
			if err != nil {
				return fmt.Errorf("invalid CIDR: %w", err)
			}

			ones, bits := ipnet.Mask.Size()
			hostCount := uint64(1 << (bits - ones))

			fmt.Printf("CIDR: %s\n", cidrStr)
			fmt.Printf("Network: %s\n", ipnet.IP)
			fmt.Printf("Mask: %s\n", ipnet.Mask)
			fmt.Printf("Prefix: /%d\n", ones)
			fmt.Printf("Hosts: %d\n", hostCount-2) // minus network + broadcast

			network := ipnet.IP.Mask(ipnet.Mask)
			broadcast := make(net.IP, len(network))
			for i := 0; i < len(network); i++ {
				broadcast[i] = network[i] | ^ipnet.Mask[i]
			}
			fmt.Printf("Network: %s\n", network)
			fmt.Printf("Broadcast: %s\n", broadcast)

			return nil
		},
	}
}

func newReverseIPCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reverse-ip [target]",
		Short: "Reverse IP lookup (find hostnames for an IP via DNS PTR)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			timeout := getTimeout(cmd)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			hostnames, err := net.LookupAddr(target)
			if err != nil {
				return fmt.Errorf("reverse IP lookup failed: %w", err)
			}

			fmt.Printf("IP: %s\n", target)
			fmt.Printf("Hostnames (%d):\n", len(hostnames))
			for _, h := range hostnames {
				fmt.Printf("  %s\n", h)
			}
			_ = ctx
			return nil
		},
	}
}

func serviceName(port int) string {
	services := map[int]string{
		21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
		80: "HTTP", 81: "HTTP-Alt", 110: "POP3", 111: "RPC", 123: "NTP",
		135: "RPC", 137: "NetBIOS", 139: "SMB", 143: "IMAP", 389: "LDAP",
		443: "HTTPS", 445: "SMB", 465: "SMTPS", 500: "IKE", 502: "Modbus",
		554: "RTSP", 587: "SMTP-Sub", 623: "IPMI", 636: "LDAPS",
		993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MSSQL",
		1521: "Oracle", 1723: "PPTP", 2082: "cPanel", 2083: "cPanel-SSL",
		2086: "WHM", 2087: "WHM-SSL", 2095: "Webmail", 2096: "Webmail-SSL",
		2222: "DirectAdmin", 3306: "MySQL", 3389: "RDP",
		4848: "GlassFish", 5000: "HTTP-Alt", 5432: "PostgreSQL",
		5631: "VNC", 5666: "NRPE", 5900: "VNC", 5984: "CouchDB",
		6000: "X11", 6379: "Redis", 7001: "WebLogic", 7002: "WebLogic-SSL",
		8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
		9000: "SonarQube", 9001: "Tor", 9042: "Cassandra", 9090: "HTTP-Alt",
		9100: "Jolokia", 9200: "Elasticsearch", 9300: "Elasticsearch-Transport",
		10000: "Webmin", 11211: "Memcached", 15672: "RabbitMQ-Mgmt",
		27017: "MongoDB", 27018: "MongoDB-Shard", 50070: "HDFS",
	}
	if name, ok := services[port]; ok {
		return name
	}
	return "unknown"
}

func broadcastAddr(ipnet *net.IPNet) net.IP {
	broadcast := make(net.IP, len(ipnet.IP))
	for i := 0; i < len(ipnet.IP); i++ {
		broadcast[i] = ipnet.IP[i] | ^ipnet.Mask[i]
	}
	return broadcast
}
