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

	mut = lipgloss.NewStyle().Foreground(muted) // Shorthand for muted text style

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
		case "up", "k":
			if m.sidebarChoice > 0 {
				m.sidebarChoice--
			}
		case "down", "j":
			if m.sidebarChoice < len(sidebarItems)-1 {
				m.sidebarChoice++
			}
		case "1", "2", "3", "4", "5":
			m.sidebarChoice = int(msg.String()[0] - '1')
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

func (m model) renderFooter() string {
	label := sidebarLabels[m.sidebarChoice]
	status := lipgloss.NewStyle().
		Foreground(white).
		Background(muted).
		Padding(0, 1).
		Render(fmt.Sprintf(" MODE: %s ", strings.ToUpper(label)))
	
	hints := mut.Render(" [↑/↓] Navigate • [1-5] Quick Jump • [Q] Quit")
	if m.state == stateResults && m.sidebarChoice == 1 {
		hints = mut.Render(" [↑/↓] Navigate • [1-5] Quick Jump • [Enter] Generate YAML • [Q] Quit")
	}

	return lipgloss.JoinHorizontal(lipgloss.Center, status, " ", hints)
}

func (m model) View() string {
	if m.width == 0 || m.height == 0 {
		return "Initializing..."
	}

	// Components
	topBar := m.renderTopBar()
	sidebar := m.renderSidebar()
	footer := m.renderFooter()

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
	fullLayout := lipgloss.JoinVertical(lipgloss.Left, topBar, mainLayout, footer)
	
	return fullLayout
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
		iconStyle := lipgloss.NewStyle().Padding(1, 0)
		indicator := mut.Render(" ")
		
		if i == m.sidebarChoice {
			iconStyle = iconStyle.Foreground(crimson).Bold(true)
			indicator = lipgloss.NewStyle().Foreground(crimson).Bold(true).Render("┃")
		} else {
			iconStyle = iconStyle.Foreground(muted)
		}
		
		// Join indicator and icon
		styledItem := lipgloss.JoinHorizontal(lipgloss.Center, indicator, iconStyle.Render(item))
		items = append(items, styledItem)
	}
	return sidebarStyle.Height(m.height - 8).Render(lipgloss.JoinVertical(lipgloss.Left, items...))
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
	// Main Content Area: Content (Left) + Intelligence (Right)
	var contentArea string
	
	switch m.sidebarChoice {
	case 1: // Graph Explorer
		contentArea = m.renderGraph()
	case 2: // Vulnerability List
		contentArea = m.renderVulnerabilities()
	case 3: // Kill Chain Reports
		contentArea = m.renderKillChain()
	case 4: // Settings
		contentArea = m.renderSettings()
	default: // Dashboard (Home)
		contentArea = m.renderDashboardSummary()
	}

	mainWidth := m.width - 10 - 35
	canvas := mainCanvasStyle.Width(mainWidth).Height(m.height - 6).Render(contentArea)

	return lipgloss.JoinHorizontal(lipgloss.Top, canvas, m.renderRightPanel())
}

func (m model) renderDashboardSummary() string {
	title := lipgloss.NewStyle().Foreground(white).Bold(true).Render("Cluster Security Overview")
	stats := lipgloss.JoinVertical(lipgloss.Left,
		"\n",
		lipgloss.NewStyle().Foreground(crimson).Render("● 1 Critical Attack Path"),
		lipgloss.NewStyle().Foreground(lipgloss.Color("#FFA500")).Render("● 12 High Vulnerabilities"),
		lipgloss.NewStyle().Foreground(muted).Render("● 142 Benign Entities"),
	)
	
	desc := "\n\nSelect 'Graph Explorer' (2nd icon) to visualize the active kill chain."
	return lipgloss.JoinVertical(lipgloss.Left, title, stats, desc)
}

func (m model) renderVulnerabilities() string {
	title := lipgloss.NewStyle().Foreground(white).Bold(true).Render("Active Vulnerability Feed")
	list := []string{
		"CVE-2024-1234  [Critical]  Privilege Escalation in Role-X",
		"CVE-2023-5678  [High]      Container Escape in Pod-A",
		"CVE-2024-9012  [Medium]    Unauthorized ConfigMap Access",
	}
	
	var content strings.Builder
	content.WriteString(title + "\n\n")
	for _, item := range list {
		content.WriteString(mut.Render("󱔎 ") + item + "\n")
	}
	return content.String()
}

func (m model) renderKillChain() string {
	title := lipgloss.NewStyle().Foreground(white).Bold(true).Render("Kill Chain Analysis Report")
	report := "\nStep 1: Initial Access via Exposed Pod-A\nStep 2: ServiceAccount Token Extraction\nStep 3: RBAC Pivoting via Role-X\nStep 4: Exfiltration of 'production-db'"
	return title + "\n" + mut.Render(report)
}

func (m model) renderSettings() string {
	return lipgloss.NewStyle().Foreground(white).Bold(true).Render("System Settings") + "\n\n" + mut.Render("󰒓 Cluster Integration: Connected\n󰒓 Scan Frequency: Real-time\n󰒓 Notification Webhook: Active")
}


func (m model) renderGraph() string {
	// Define color styles for semantic meaning
	crit := criticalNodeStyle
	mut := nodeStyle
	arr := lipgloss.NewStyle().Foreground(crimson)
	mutArr := lipgloss.NewStyle().Foreground(muted)

	// Build the graph row by row for precise alignment
	// We'll create a 7-row layout with multiple nodes per row to show complexity
	
	row1 := lipgloss.JoinHorizontal(lipgloss.Center,
		mut.Render("󰟵 Pod-C"), "       ", mut.Render("󰟵 Pod-D"),
	)

	row2 := lipgloss.JoinHorizontal(lipgloss.Center,
		mutArr.Render("   │           │   "),
	)

	row3 := lipgloss.JoinHorizontal(lipgloss.Center,
		mut.Render("󱇱 Role-Y"), " ─── ", crit.Render("󱉭 Pod-A"), " ─── ", mut.Render("󱉭 ConfigMap-Z"),
	)

	row4 := lipgloss.JoinHorizontal(lipgloss.Center,
		mutArr.Render("   │   "), "       ", arr.Render("┃"), "       ", mutArr.Render("   │   "),
	)

	row5 := lipgloss.JoinHorizontal(lipgloss.Center,
		mut.Render("󱘖 Secrets-1"), " ─── ", crit.Render("󰟵 SA-B"), " ─── ", mut.Render("󰟵 Namespace-Q"),
	)

	row6 := lipgloss.JoinHorizontal(lipgloss.Center,
		"               ", arr.Render("┃"), "               ",
	)

	row7 := lipgloss.JoinHorizontal(lipgloss.Center,
		"             ", crit.Render("󱇱 [ Role-X ]"), "            ",
	)

	row8 := lipgloss.JoinHorizontal(lipgloss.Center,
		"               ", arr.Render("┃"), "               ",
	)

	row9 := lipgloss.JoinHorizontal(lipgloss.Center,
		"           ", crit.Render("󱘖 production-db"), "          ",
	)

	// Combine rows
	var g strings.Builder
	rows := []string{row1, row2, row3, row4, row5, row6, row7, row8, row9}
	
	maxWidth := 0
	for _, r := range rows {
		w := lipgloss.Width(r)
		if w > maxWidth {
			maxWidth = w
		}
	}

	g.WriteString("\n")
	for _, r := range rows {
		// Center each row within the maxWidth to ensure vertical alignment
		centeredRow := lipgloss.PlaceHorizontal(m.width-45, lipgloss.Center, r)
		g.WriteString(centeredRow + "\n")
	}

	return g.String()
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
