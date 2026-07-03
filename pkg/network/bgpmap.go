package bgp

import (
	"fmt"
	"strings"
)

// ─────────────────────────────────────────────────────────────
// BGP Map — Mermaid + ASCII topology for AS/prefix relations
// ─────────────────────────────────────────────────────────────

type ASNode struct {
	ASN         uint32
	Name        string
	Country     string
	IPs         []string
	PrefixCount int
	IsOrigin    bool
	IsSelf      bool
}

type ASLink struct {
	FromASN     uint32
	ToASN       uint32
	LinkType    string // upstream, peer, customer, transit
	Label       string
	Prefixes    []string
	Country     string
}

type BGPTopology struct {
	Self   *ASNode
	Nodes  map[uint32]*ASNode
	Links  []ASLink
	Prefix map[string]*ASNode // prefix → origin AS
}

type BGPMermaid struct {
	Directed bool
	Title    string
	RootASN  uint32
	RootName string
	Nodes    map[uint32]string
	Links    []MermaidLink
	Subgraph map[string][]uint32
}

type MermaidLink struct {
	From  uint32
	To    uint32
	Label string
	Style string // solid, dashed, thick
}

func NewBGPTopology() *BGPTopology {
	return &BGPTopology{
		Nodes:  make(map[uint32]*ASNode),
		Prefix: make(map[string]*ASNode),
	}
}

func (bt *BGPTopology) AddNode(asn uint32, name string, country string) {
	if _, exists := bt.Nodes[asn]; !exists {
		bt.Nodes[asn] = &ASNode{
			ASN:     asn,
			Name:    name,
			Country: country,
		}
	}
}

func (bt *BGPTopology) AddPrefix(asn uint32, prefix string) {
	node := bt.Nodes[asn]
	if node == nil {
		node = &ASNode{ASN: asn}
		bt.Nodes[asn] = node
	}
	node.PrefixCount++
	node.IPs = append(node.IPs, prefix)
	bt.Prefix[prefix] = node
}

func (bt *BGPTopology) AddLink(from, to uint32, linkType string) {
	bt.Links = append(bt.Links, ASLink{
		FromASN:  from,
		ToASN:    to,
		LinkType: linkType,
	})
}

// ─── Mermaid diagram generator ──────────────────────────────

func GenerateMermaidDiagram(topo *BGPTopology, title string) string {
	var b strings.Builder

	b.WriteString("```mermaid\n")
	b.WriteString("graph TD\n")
	b.WriteString(fmt.Sprintf("    title[\"%s\"]\n", title))
	b.WriteString("    style title fill:#1a1a2e,stroke:none,color:#eee\n\n")

	// Country subgraphs
	countries := make(map[string][]uint32)
	for _, node := range topo.Nodes {
		if node.Country != "" {
			countries[node.Country] = append(countries[node.Country], node.ASN)
		}
	}
	for country, asns := range countries {
		b.WriteString(fmt.Sprintf("    subgraph %s[\"%s\"]\n", country, country))
		for _, asn := range asns {
			_ = topo.Nodes[asn]
			b.WriteString(fmt.Sprintf("        AS%d\n", asn))
		}
		b.WriteString("    end\n\n")
	}

	// Nodes
	for _, node := range topo.Nodes {
		style := getASStyle(node, topo)
		label := getASLabel(node)
		b.WriteString(fmt.Sprintf("    AS%d[\"%s\"] %s\n",
			node.ASN, label, style))
	}

	b.WriteString("\n")

	// Links
	for _, link := range topo.Links {
		arrow := getArrow(link.LinkType)
		label := link.Label
		if label == "" {
			label = link.LinkType
		}
		cls := getLinkClass(link.LinkType)
		b.WriteString(fmt.Sprintf("    AS%d %s AS%d \"%s\" %s\n",
			link.FromASN, arrow, link.ToASN, label, cls))
	}

	b.WriteString("\n")

	// Legend
	b.WriteString("    subgraph Legend\n")
	b.WriteString("        upstream[\"⬆ Upstream\"]\n")
	b.WriteString("        peer[\"↔ Peer\"]\n")
	b.WriteString("        customer[\"⬇ Customer\"]\n")
	b.WriteString("        transit[\"→ Transit\"]\n")
	b.WriteString("    end\n")

	b.WriteString("```\n")
	return b.String()
}

func getASStyle(node *ASNode, topo *BGPTopology) string {
	if node.IsOrigin {
		return ":::origin"
	}
	if node.ASN == topo.Self.ASN {
		return ":::self"
	}
	switch node.Country {
	case "US":
		return ":::us"
	case "DE":
		return ":::de"
	case "NL":
		return ":::nl"
	case "GB":
		return ":::gb"
	case "FR":
		return ":::fr"
	case "JP":
		return ":::jp"
	case "SG":
		return ":::sg"
	case "AU":
		return ":::au"
	case "BR":
		return ":::br"
	case "IN":
		return ":::in"
	default:
		return ""
	}
}

func getASLabel(node *ASNode) string {
	name := node.Name
	if len(name) > 25 {
		name = name[:22] + "..."
	}
	return fmt.Sprintf("<b>AS%d</b><br>%s<br>%d prefixes",
		node.ASN, name, node.PrefixCount)
}

func getArrow(linkType string) string {
	switch linkType {
	case "upstream":
		return "-->"
	case "peer":
		return "---"
	case "customer":
		return "==>"
	case "transit":
		return "-.->"
	default:
		return "-->"
	}
}

func getLinkClass(linkType string) string {
	switch linkType {
	case "upstream":
		return ":::upstream"
	case "peer":
		return ":::peer"
	case "customer":
		return ":::customer"
	case "transit":
		return ":::transit"
	default:
		return ""
	}
}

// ─── ASCII topology map ─────────────────────────────────────

func GenerateASCTITopology(topo *BGPTopology) string {
	var b strings.Builder
	self := topo.Self
	if self == nil {
		return ""
	}

	b.WriteString(fmt.Sprintf("                    ┌─────── AS%d ───────┐\n", self.ASN))
	b.WriteString(fmt.Sprintf("                    │ %-18s │\n", truncateStr(self.Name, 18)))
	b.WriteString(fmt.Sprintf("                    │ %-18s │\n", self.Country))
	b.WriteString(fmt.Sprintf("                    └────────┬───────────┘\n"))

	// Group links by type
	upstreams := make(map[uint32]*ASLink)
	peers := make(map[uint32]*ASLink)
	customers := make(map[uint32]*ASLink)

	for i := range topo.Links {
		link := &topo.Links[i]
		switch link.LinkType {
		case "upstream":
			upstreams[link.ToASN] = link
		case "peer":
			peers[link.ToASN] = link
		case "customer":
			customers[link.ToASN] = link
		}
	}

	// Upstreams (above)
	if len(upstreams) > 0 {
		b.WriteString("                    │\n")
		b.WriteString(fmt.Sprintf("         ┌─────────┴─────────┐\n"))
		b.WriteString(fmt.Sprintf("         │    UPSTREAMS (%d)   │\n", len(upstreams)))
		b.WriteString(fmt.Sprintf("         └─────────┬─────────┘\n"))
		for asn := range upstreams {
			node := topo.Nodes[asn]
			if node != nil {
				b.WriteString(fmt.Sprintf("              ┌────┴────┐\n"))
				b.WriteString(fmt.Sprintf("         ┌────┤ AS%-5d  ├────┐\n", asn))
				b.WriteString(fmt.Sprintf("         │    │%-12s│    │\n", truncateStr(node.Name, 12)))
				b.WriteString(fmt.Sprintf("         │    └─────────┘    │\n"))
			}
		}
	}

	// Peers (left-right)
	if len(peers) > 0 {
		b.WriteString("                    │\n")
		b.WriteString("     ┌───────────────┴───────────────┐\n")
		b.WriteString(fmt.Sprintf("     │           PEERS (%d)           │\n", len(peers)))
		b.WriteString("     └───────────────┬───────────────┘\n")
		for asn := range peers {
			node := topo.Nodes[asn]
			if node != nil {
				b.WriteString(fmt.Sprintf("  ┌─────────┐                  ┌─────────┐\n"))
				b.WriteString(fmt.Sprintf("  │ AS%-5d  │──────────────────│ AS%-5d  │\n", asn))
				b.WriteString(fmt.Sprintf("  │%-14s│                  │%-14s│\n",
					truncateStr(node.Name, 14), ""))
				b.WriteString(fmt.Sprintf("  └─────────┘                  └─────────┘\n"))
			}
		}
	}

	// Customers (below)
	if len(customers) > 0 {
		b.WriteString("                    │\n")
		b.WriteString(fmt.Sprintf("         ┌─────────┴─────────┐\n"))
		b.WriteString(fmt.Sprintf("         │   CUSTOMERS (%d)   │\n", len(customers)))
		b.WriteString(fmt.Sprintf("         └─────────┬─────────┘\n"))
		for asn := range customers {
			node := topo.Nodes[asn]
			if node != nil {
				b.WriteString(fmt.Sprintf("              ┌────┴────┐\n"))
				b.WriteString(fmt.Sprintf("         ┌────┤ AS%-5d  ├────┐\n", asn))
				b.WriteString(fmt.Sprintf("         │    │%-12s│    │\n", truncateStr(node.Name, 12)))
				b.WriteString(fmt.Sprintf("         │    └─────────┘    │\n"))
			}
		}
	}

	// Prefix summary
	b.WriteString("                    │\n")
	b.WriteString(fmt.Sprintf("            [Prefixes: %d]\n", self.PrefixCount))

	return b.String()
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// ─── BGP AS Path diagram ────────────────────────────────────

func GenerateASPathDiagram(path []uint32, names map[uint32]string) string {
	if len(path) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("BGP AS Path:\n\n")

	for i, asn := range path {
		name := names[asn]
		if name == "" {
			name = "Unknown"
		}
		if len(name) > 30 {
			name = name[:27] + "..."
		}

		prefix := "    "

		if i > 0 {
			prefix = "    │\n    │ BGP UPDATE\n    │\n    ▼\n    "
		}

		b.WriteString(fmt.Sprintf("%s┌─── AS%d ───┐\n", prefix, asn))
		b.WriteString(fmt.Sprintf("    │ %-20s │\n", truncateStr(name, 20)))
		b.WriteString(fmt.Sprintf("    └─────────────┘\n"))

	}

	return b.String()
}

// ─── Full Mermaid path diagram ──────────────────────────────

func GenerateMermaidPathDiagram(path []uint32, names map[uint32]string, sourceIP, destIP string) string {
	var b strings.Builder
	b.WriteString("```mermaid\n")
	b.WriteString("graph LR\n")

	for i, asn := range path {
		name := names[asn]
		if len(name) > 20 {
			name = name[:17] + "..."
		}
		nodeID := fmt.Sprintf("AS%d", asn)
		b.WriteString(fmt.Sprintf("    %s[\"%s<br>AS%d<br>_%s_\"]\n", nodeID, name, asn, name))

		if i > 0 {
			prevID := fmt.Sprintf("AS%d", path[i-1])
			b.WriteString(fmt.Sprintf("    %s -->|%s| %s\n", prevID, getHopLabel(i), nodeID))
		}
	}

	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("    source[\"🌐 Source<br>%s\"] -->|\"Entry\"| AS%d\n", sourceIP, path[0]))
	if len(path) > 1 {
		b.WriteString(fmt.Sprintf("    AS%d -->|\"Exit\"| dest[\"🎯 Destination<br>%s\"]\n", path[len(path)-1], destIP))
	}

	b.WriteString("```\n")
	return b.String()
}

func getHopLabel(i int) string {
	if i == 1 {
		return "IGP"
	}
	return fmt.Sprintf("eBGP-%d", i)
}

// ─── GeoIP BGP world map (Mermaid) ─────────────────────────

func GenerateMermaidWorldMap(topo *BGPTopology) string {
	var b strings.Builder
	b.WriteString("```mermaid\n")
	b.WriteString("graph LR\n\n")

	// Group by country
	countries := make(map[string][]*ASNode)
	for _, node := range topo.Nodes {
		c := node.Country
		if c == "" {
			c = "Unknown"
		}
		countries[c] = append(countries[c], node)
	}

	for country, nodes := range countries {
		subgraphID := strings.ReplaceAll(country, " ", "_")
		b.WriteString(fmt.Sprintf("    subgraph %s[\"%s\"]\n", subgraphID, country))
		for _, node := range nodes {
			prefixInfo := fmt.Sprintf("%d prefixes", node.PrefixCount)
			b.WriteString(fmt.Sprintf("        AS%d[\"AS%d<br>%s<br>%s\"]\n",
				node.ASN, node.ASN, truncateStr(node.Name, 15), prefixInfo))
		}
		b.WriteString("    end\n\n")
	}

	// Links between countries
	linkSeen := make(map[string]bool)
	for _, link := range topo.Links {
		fromNode := topo.Nodes[link.FromASN]
		toNode := topo.Nodes[link.ToASN]
		if fromNode == nil || toNode == nil {
			continue
		}
		key := fmt.Sprintf("%s-%s", fromNode.Country, toNode.Country)
		if linkSeen[key] {
			continue
		}
		linkSeen[key] = true

		b.WriteString(fmt.Sprintf("    %s --> %s\n",
			strings.ReplaceAll(fromNode.Country, " ", "_"),
			strings.ReplaceAll(toNode.Country, " ", "_")))
	}

	b.WriteString("```\n")
	return b.String()
}

// ─── Prefix distribution chart (Mermaid pie) ────────────────

func GenerateMermaidPrefixPie(topo *BGPTopology) string {
	var b strings.Builder
	b.WriteString("```mermaid\n")
	b.WriteString("pie title Prefix Distribution by AS\n")

	for _, node := range topo.Nodes {
		if node.PrefixCount > 0 {
			b.WriteString(fmt.Sprintf("    \"AS%d %s\" : %d\n",
				node.ASN, truncateStr(node.Name, 15), node.PrefixCount))
		}
	}

	b.WriteString("```\n")
	return b.String()
}

// ─── Full comprehensive output ─────────────────────────────

func GenerateFullMapOutput(topo *BGPTopology, path []uint32, names map[uint32]string, sourceIP, destIP string) string {
	var b strings.Builder

	b.WriteString("╔══════════════════════════════════════════════════════════════╗\n")
	b.WriteString("║                  BGP MAP — VISUALIZATION                   ║\n")
	b.WriteString("╚══════════════════════════════════════════════════════════════╝\n\n")

	// ASCII Topology
	b.WriteString(GenerateASCTITopology(topo))

	// Mermaid diagram
	b.WriteString("\n\n─── Mermaid Diagram (paste to mermaid.live) ──────────────────\n\n")
	b.WriteString(GenerateMermaidDiagram(topo, fmt.Sprintf("AS%d BGP Topology", topo.Self.ASN)))

	// AS Path
	if len(path) > 0 {
		b.WriteString("\n─── AS Path ──────────────────────────────────────────────────\n\n")
		b.WriteString(GenerateASPathDiagram(path, names))
	}

	// Mermaid Path
	if len(path) > 1 {
		b.WriteString("\n─── Mermaid AS Path ──────────────────────────────────────────\n\n")
		b.WriteString(GenerateMermaidPathDiagram(path, names, sourceIP, destIP))
	}

	// World Map
	b.WriteString("\n─── Geographic Distribution ──────────────────────────────────\n\n")
	b.WriteString(GenerateMermaidWorldMap(topo))

	// Prefix Pie
	if len(topo.Nodes) > 1 {
		b.WriteString("\n─── Prefix Distribution ──────────────────────────────────────\n\n")
		b.WriteString(GenerateMermaidPrefixPie(topo))
	}

	return b.String()
}
