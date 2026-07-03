package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	cfgFile    string
	rootCmd    = &cobra.Command{
		Use:   "oxrecon",
		Short: "oxrecon — Web, Network, DNS, BGP & OSINT Recon Toolkit",
		Long: `oxrecon is a comprehensive reconnaissance and security toolkit
combining DNS, WHOIS, HTTP, SSL/TLS, port scanning, subdomain enumeration,
BGP/RPKI analysis, technology detection, and OSINT capabilities into a single CLI.

Inspired by Nmap, HTTPX, Subfinder, Dig, Whois, Wappalyzer, Naabu, and Amass.
Source: https://github.com/TEGAR-SRC/oxrecon`,
		Version: "1.0.0",
		SilenceUsage: true,
		SilenceErrors: true,
	}
)

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default: ~/.oxrecon/config.yaml)")
	rootCmd.PersistentFlags().IntP("threads", "t", 10, "worker threads")
	rootCmd.PersistentFlags().DurationP("timeout", "o", 30_000_000_000, "request timeout (e.g. 30s)")
	rootCmd.PersistentFlags().IntP("rate", "r", 0, "rate limit per second (0 = unlimited)")
	rootCmd.PersistentFlags().String("proxy", "", "HTTP/SOCKS5 proxy")
	rootCmd.PersistentFlags().String("proxy-file", "", "load proxies from file")
	rootCmd.PersistentFlags().String("dns", "", "DNS server to use")
	rootCmd.PersistentFlags().String("resolver", "", "resolver file")
	rootCmd.PersistentFlags().StringP("output", "O", "", "output file")
	rootCmd.PersistentFlags().StringP("format", "f", "json", "output format (json|yaml|xml|csv|html)")
	rootCmd.PersistentFlags().Bool("silent", false, "silent mode")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().Bool("debug", false, "debug output")
	rootCmd.PersistentFlags().Bool("color", true, "enable color output")
	rootCmd.PersistentFlags().Bool("no-color", false, "disable color output")
	rootCmd.PersistentFlags().Bool("random-agent", false, "use random User-Agent")
	rootCmd.PersistentFlags().Bool("follow-redirect", false, "follow HTTP redirects")
	rootCmd.PersistentFlags().Bool("insecure", false, "skip TLS verification")
	rootCmd.PersistentFlags().Bool("ipv4", false, "IPv4 only")
	rootCmd.PersistentFlags().Bool("ipv6", false, "IPv6 only")
	rootCmd.PersistentFlags().Bool("full", false, "full scan mode")
	rootCmd.PersistentFlags().Bool("cache", true, "enable cache")
	rootCmd.PersistentFlags().Duration("cache-ttl", 3_600_000_000_000, "cache TTL (default: 1h)")

	rootCmd.AddCommand(
		newDNSCommand(),
		newDomainCommand(),
		newNetworkCommand(),
		newPortDetailCmd(),
		newHTTPCommand(),
		newSSLCommand(),
		newSSLChainCmd(),
		newSubdomainCommand(),
		newDiscoveryProvidersCmd(),
		newBGPCommand(),
		newOSINTCommand(),
		newScanCommand(),
		newTUICommand(),
		newAPICommand(),
		newConfigCommand(),
		newPluginCommand(),
		newUpdateCommand(),
		newVersionCommand(),
	)
}
