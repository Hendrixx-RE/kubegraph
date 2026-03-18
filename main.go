package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// App state
type state int

const (
	stateLanding state = iota
	stateScanning
	stateResults
)

// Model
type model struct {
	state          state
	sidebarChoice  int
	spinner        spinner.Model
	width          int
	height         int
	remediationMsg bool
	scanProgress   float64
}

// Sidebar items
var sidebarItems = []string{"󱂬", "󱖫", "󱔎", "󱇱", "󰒓"}
var sidebarLabels = []string{"Dashboard", "Graph Explorer", "Vulnerabilities", "Kill Chain", "Settings"}

// Styles
var (
	crimson = lipgloss.Color("#FF0000")
	muted   = lipgloss.Color("#444444")
	white   = lipgloss.Color("#EEEEEE")
	bg      = lipgloss.Color("#0A0A0A")

	logoStyle = lipgloss.NewStyle().
			Foreground(crimson).
			Bold(true).
			Padding(0, 1)

	topBarStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder(), false, false, true, false).
			BorderForeground(muted).
			Padding(0, 1)

	sidebarStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder(), false, true, false, false).
			BorderForeground(muted).
			Padding(1, 1).
			Width(6)

	mainCanvasStyle = lipgloss.NewStyle().
			Padding(1, 2)

	rightPanelStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder(), false, false, false, true).
			BorderForeground(muted).
			Padding(1, 2).
			Width(35)

	nodeStyle = lipgloss.NewStyle().
			Foreground(muted).
			Bold(true)

	criticalNodeStyle = lipgloss.NewStyle().
				Foreground(crimson).
				Bold(true)

	metricCardStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(muted).
			Padding(0, 1).
			MarginRight(1)

	scanButtonStyle = lipgloss.NewStyle().
			Foreground(bg).
			Background(crimson).
			Padding(0, 1).
			Bold(true)
)

func initialModel() model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(crimson)

	return model{
		state:         stateLanding,
		sidebarChoice: 0,
		spinner:       s,
	}
}

func (m model) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "s":
			if m.state == stateLanding {
				m.state = stateScanning
				return m, tea.Tick(time.Second*2, func(t time.Time) tea.Msg {
					return "scan_complete"
				})
			}
		case "up":
			if m.sidebarChoice > 0 {
				m.sidebarChoice--
			}
		case "down":
			if m.sidebarChoice < len(sidebarItems)-1 {
				m.sidebarChoice++
			}
		case "enter":
			if m.state == stateResults {
				m.remediationMsg = true
				_ = os.WriteFile("remediation.yaml", []byte("apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata:\n  name: role-x-binding\n  namespace: default\nsubjects:\n- kind: ServiceAccount\n  name: service-account-b\nroleRef:\n  kind: Role\n  name: role-x\n  apiGroup: rbac.authorization.k8s.io\n# REMEDIATION: This binding is overly permissive and part of a critical attack path.\n# REMOVE or RESTRICT to minimize blast radius.\n"), 0644)
			}
		}

	case string:
		if msg == "scan_complete" {
			m.state = stateResults
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m model) View() string {
	if m.width == 0 || m.height == 0 {
		return "Initializing..."
	}

	// Components
	topBar := m.renderTopBar()
	sidebar := m.renderSidebar()

	var content string
	switch m.state {
	case stateLanding:
		content = m.renderLanding()
	case stateScanning:
		content = m.renderScanning()
	case stateResults:
		content = m.renderResults()
	}

	mainLayout := lipgloss.JoinHorizontal(lipgloss.Top, sidebar, content)
	return lipgloss.JoinVertical(lipgloss.Left, topBar, mainLayout)
}

func (m model) renderTopBar() string {
	logo := logoStyle.Render("KubeGraph")
	cluster := lipgloss.NewStyle().Foreground(muted).Render("Cluster: prod-us-east-1")
	
	btnText := "Initiate Cluster Scan"
	if m.state == stateScanning {
		btnText = "Scanning..."
	}
	scanBtn := scanButtonStyle.Render(btnText)
	
	avatar := lipgloss.NewStyle().Foreground(white).Render("👤 ATUL")

	middle := lipgloss.PlaceHorizontal(m.width-40, lipgloss.Center, cluster)
	right := lipgloss.JoinHorizontal(lipgloss.Center, scanBtn, "  ", avatar)

	return topBarStyle.Width(m.width).Render(
		lipgloss.JoinHorizontal(lipgloss.Center, logo, middle, right),
	)
}

func (m model) renderSidebar() string {
	var items []string
	for i, item := range sidebarItems {
		style := lipgloss.NewStyle().Padding(1, 0)
		if i == m.sidebarChoice {
			style = style.Foreground(crimson).Bold(true)
		} else {
			style = style.Foreground(muted)
		}
		items = append(items, style.Render(item))
	}
	return sidebarStyle.Height(m.height - 4).Render(lipgloss.JoinVertical(lipgloss.Center, items...))
}

func (m model) renderLanding() string {
	title := lipgloss.NewStyle().Foreground(white).Bold(true).Render("Welcome to KubeGraph")
	sub := lipgloss.NewStyle().Foreground(muted).Render("Press 's' to initiate a security scan of the production cluster.")
	
	return lipgloss.Place(m.width-10, m.height-6, lipgloss.Center, lipgloss.Center, 
		lipgloss.JoinVertical(lipgloss.Center, title, "\n", sub),
	)
}

func (m model) renderScanning() string {
	text := lipgloss.NewStyle().Foreground(white).Render("Ingesting RBAC configurations...")
	sub := lipgloss.NewStyle().Foreground(muted).Render("Building mathematical topology graph...")
	
	return lipgloss.Place(m.width-10, m.height-6, lipgloss.Center, lipgloss.Center, 
		lipgloss.JoinVertical(lipgloss.Center, m.spinner.View(), "\n", text, sub),
	)
}

func (m model) renderResults() string {
	// Main Content Area: Graph (Left) + Intelligence (Right)
	graphArea := m.renderGraph()
	rightPanel := m.renderRightPanel()

	mainWidth := m.width - 10 - 35
	canvas := mainCanvasStyle.Width(mainWidth).Height(m.height - 6).Render(graphArea)

	return lipgloss.JoinHorizontal(lipgloss.Top, canvas, rightPanel)
}

func (m model) renderGraph() string {
	// Nodes and connections simulation for the critical path
	criticalPath := []string{
		"  󱉭 Pod-A  ",
		"      ↓      ",
		" 󰟵 ServiceAccount-B ",
		"      ↓      ",
		"  󱇱 [ Role-X ]  ",
		"      ↓      ",
		"󱘖 production-db",
	}

	var graph strings.Builder
	graph.WriteString("\n")

	// Center the critical path
	for i, n := range criticalPath {
		style := criticalNodeStyle
		if i%2 != 0 {
			style = style.Foreground(crimson)
		}
		graph.WriteString(lipgloss.PlaceHorizontal(m.width-50, lipgloss.Center, style.Render(n)) + "\n")
	}

	// Peripheral nodes to fill the graph (8-10 total nodes)
	bgNodesRow1 := []string{"󰟵 Pod-C", "󰟵 Pod-D", "󱇱 Role-Y"}
	bgNodesRow2 := []string{"󱉭 ConfigMap-Z", "󱘖 Secrets-1", "󰟵 Namespace-Q"}

	graph.WriteString("\n\n")
	
	// Helper to render background nodes with muted colors
	renderRow := func(nodes []string) string {
		var styledNodes []string
		for _, n := range nodes {
			styledNodes = append(styledNodes, nodeStyle.Render("○ "+n))
		}
		return lipgloss.PlaceHorizontal(m.width-50, lipgloss.Center, strings.Join(styledNodes, "     "))
	}

	graph.WriteString(renderRow(bgNodesRow1) + "\n\n")
	graph.WriteString(renderRow(bgNodesRow2) + "\n")

	// Decorative edges for background nodes
	graph.WriteString(lipgloss.PlaceHorizontal(m.width-50, lipgloss.Center, nodeStyle.Render("      ↘        ↙        ↘")) + "\n")
	graph.WriteString(lipgloss.PlaceHorizontal(m.width-50, lipgloss.Center, nodeStyle.Render("       ( Muted Nodes Area )")))

	return graph.String()
}

func (m model) renderRightPanel() string {
	header := lipgloss.NewStyle().Foreground(crimson).Bold(true).Render("Critical Attack Path Detected")
	
	metrics := lipgloss.JoinHorizontal(lipgloss.Top,
		metricCardStyle.Render("Hops\n4"),
		metricCardStyle.Render("Risk\n24.7"),
		metricCardStyle.Render("Blast\n7"),
	)

	alertBox := lipgloss.NewStyle().
		Border(lipgloss.ThickBorder()).
		BorderForeground(crimson).
		Padding(1).
		Width(30).
		Render(fmt.Sprintf("CRITICAL NODE IDENTIFIED:\n%s\n\nRemoving this binding eliminates 80%% of attack paths.", criticalNodeStyle.Render("Role-X")))

	btn := lipgloss.NewStyle().
		Background(white).
		Foreground(bg).
		Padding(0, 1).
		Bold(true).
		Render("Generate Remediation YAML")
	
	if m.remediationMsg {
		btn = lipgloss.NewStyle().Foreground(crimson).Render("✓ YAML Generated to 'remediation.yaml'")
	}

	return rightPanelStyle.Height(m.height - 6).Render(
		lipgloss.JoinVertical(lipgloss.Left, 
			header, "\n", 
			metrics, "\n\n",
			alertBox, "\n\n\n",
			btn,
		),
	)
}

func main() {
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running program: %v", err)
	}
}
