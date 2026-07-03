package tui

import (
	"fmt"
	"strings"
	"time"
)

type Dashboard struct {
	Version      string
	StartTime    time.Time
	TotalScans   int
	ActiveScans  int
	Workers      int
	QueueLen     int
	HostsScanned int

	// BGP fields
	ASNLookups    int
	RPKIChecks    int
	PrefixChecks  int
	LastASN       string
	LastPrefix    string
}

type BGPStats struct {
	ASN         uint32
	Name        string
	TotalPrefix int
	IPv4Prefix  int
	IPv6Prefix  int
	RPKIValid   int
	RPKIInvalid int
	RPKICover   float64
	PeersCount  int
}

func NewDashboard() *Dashboard {
	return &Dashboard{
		Version:   "1.0.0",
		StartTime: time.Now(),
		Workers:   10,
	}
}

func (d *Dashboard) Render() string {
	var b strings.Builder
	b.WriteString(d.header())
	b.WriteString(d.stats())
	b.WriteString(d.menu())
	return b.String()
}

func (d *Dashboard) header() string {
	return fmt.Sprintf(`
╔══════════════════════════════════════════════════════════╗
║                   WebTool v%s                        ║
║        Reconnaissance & Security Toolkit                 ║
║     DNS · HTTP · SSL · BGP · RPKI · OSINT · SCAN        ║
╚══════════════════════════════════════════════════════════╝
`, d.Version)
}

func (d *Dashboard) stats() string {
	uptime := time.Since(d.StartTime).Round(time.Second).String()
	var bgpLine string
	if d.ASNLookups > 0 || d.RPKIChecks > 0 {
		bgpLine = fmt.Sprintf(`
├────────── BGP / RPKI ───────────┤
│  ASN Lookups:  %-16d │
│  RPKI Checks:  %-16d │
│  Prefix Checks:%-16d │
│  Last ASN:     %-16s │
│  Last Prefix:  %-16s │
├─────────────────────────────────┤`, d.ASNLookups, d.RPKIChecks, d.PrefixChecks,
			d.LastASN, d.LastPrefix)
	}

	return fmt.Sprintf(`
┌─────────── STATISTICS ───────────┬────────── SYSTEM ───────────┐
│  Total Scans:  %-16d │  Uptime:     %-16s │
│  Active Scans: %-16d │  Workers:    %-16d │
│  Queue Length: %-16d │  Version:    %-16s │
│  Hosts Scanned:%-16d │  Mode:       CLI/API/TUI      │%s
└──────────────────────────────────┴─────────────────────────────┘
`, d.TotalScans, uptime, d.ActiveScans, d.Workers, d.QueueLen, d.Version, d.HostsScanned, bgpLine)
}

func (d *Dashboard) RenderBGP(stats *BGPStats) string {
	if stats == nil {
		return ""
	}

	barWidth := 30
	filled := int(stats.RPKICover / 100 * float64(barWidth))
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

	return fmt.Sprintf(`
┌────────── BGP / RPKI ──────────────────────────────────┐
│  %-52s │
│  IPv4: %-5d          IPv6: %-5d          Total: %-5d  │
│  ✅ RPKI Valid: %-3d     ❌ Invalid: %-3d              │
│  Coverage: %s %.0f%%            │
│  Peers: %-3d                                             │
└─────────────────────────────────────────────────────────┘
`, truncateDash(stats.Name, 52), stats.IPv4Prefix, stats.IPv6Prefix, stats.TotalPrefix,
		stats.RPKIValid, stats.RPKIInvalid, bar, stats.RPKICover, stats.PeersCount)
}

func (d *Dashboard) RenderRPKI(prefix string, status string, icon string) string {
	return fmt.Sprintf("  %s %-32s %s", icon, prefix, status)
}

func (d *Dashboard) menu() string {
	return `
┌────────── COMMANDS ──────────┐
│                                │
│ ─── Recon ──────────────────  │
│  [1] DNS Lookup               │
│  [2] Port Scan                │
│  [3] HTTP Probe               │
│  [4] SSL Certificate          │
│  [5] WHOIS                    │
│  [6] Subdomain Enumeration    │
│                                │
│ ─── BGP / RPKI ────────────  │
│  [7] BGP IP Lookup            │
│  [8] BGP ASN Details          │
│  [9] BGP Show (prefix+RPKI)   │
│  [10] RPKI/ROA Validation     │
│  [11] BGP Map/Topology        │
│                                │
│ ─── OSINT ──────────────────  │
│  [12] Full Scan               │
│  [13] OSINT Lookup            │
│                                │
│  [0] Settings                 │
│  [q] Quit                     │
└───────────────────────────────┘
`
}

func truncateDash(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

type ProgressBar struct {
	Total     int
	Current   int
	Width     int
	Label     string
	StartTime time.Time
}

func NewProgressBar(total int, label string) *ProgressBar {
	return &ProgressBar{
		Total:     total,
		Width:     40,
		Label:     label,
		StartTime: time.Now(),
	}
}

func (pb *ProgressBar) Update(current int) {
	pb.Current = current
}

func (pb *ProgressBar) Render() string {
	if pb.Total == 0 {
		return ""
	}

	pct := float64(pb.Current) / float64(pb.Total)
	filled := int(pct * float64(pb.Width))
	elapsed := time.Since(pb.StartTime).Round(time.Millisecond).String()

	bar := strings.Repeat("█", filled) + strings.Repeat("░", pb.Width-filled)
	return fmt.Sprintf("\r  %s [%s] %3.0f%% (%d/%d) %s",
		pb.Label, bar, pct*100, pb.Current, pb.Total, elapsed)
}

type Spinner struct {
	frames []string
	pos    int
}

func NewSpinner() *Spinner {
	return &Spinner{
		frames: []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
	}
}

func (s *Spinner) Next() string {
	frame := s.frames[s.pos]
	s.pos = (s.pos + 1) % len(s.frames)
	return frame
}

type Table struct {
	Headers []string
	Rows    [][]string
}

func NewTable(headers []string) *Table {
	return &Table{Headers: headers}
}

func (t *Table) AddRow(row []string) {
	t.Rows = append(t.Rows, row)
}

func (t *Table) Render() string {
	if len(t.Headers) == 0 {
		return ""
	}

	widths := make([]int, len(t.Headers))
	for i, h := range t.Headers {
		widths[i] = len(h)
	}
	for _, row := range t.Rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	var b strings.Builder
	sep := "+"
	for _, w := range widths {
		sep += strings.Repeat("-", w+2) + "+"
	}

	b.WriteString(sep + "\n")
	b.WriteString("|")
	for i, h := range t.Headers {
		b.WriteString(fmt.Sprintf(" %-*s |", widths[i], h))
	}
	b.WriteString("\n" + sep + "\n")

	for _, row := range t.Rows {
		b.WriteString("|")
		for i, cell := range row {
			if i < len(widths) {
				b.WriteString(fmt.Sprintf(" %-*s |", widths[i], cell))
			}
		}
		b.WriteString("\n")
	}
	b.WriteString(sep + "\n")

	return b.String()
}

type LogViewer struct {
	entries []string
	max     int
}

func NewLogViewer(max int) *LogViewer {
	return &LogViewer{max: max}
}

func (lv *LogViewer) Add(entry string) {
	lv.entries = append(lv.entries, entry)
	if len(lv.entries) > lv.max {
		lv.entries = lv.entries[len(lv.entries)-lv.max:]
	}
}

func (lv *LogViewer) Render() string {
	return strings.Join(lv.entries, "\n")
}

