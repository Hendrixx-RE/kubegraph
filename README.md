# KubeGraph: Kubernetes Attack Path Visualizer

KubeGraph is an enterprise-grade Command Line Interface (CLI) prototype designed for cybersecurity analysts to visualize and remediate complex attack paths within Kubernetes clusters. By transforming isolated security alerts into a unified mathematical topology, KubeGraph provides the context necessary to identify and sever critical kill chains.


https://github.com/user-attachments/assets/0c5f79c8-1fae-466e-8ff0-fdfcb7454254


## Overview

Traditional security tools often overwhelm analysts with thousands of disconnected vulnerabilities. KubeGraph solves this by utilizing graph theory to map relationships between Pods, ServiceAccounts, Roles, and sensitive infrastructure. It highlights multi-hop paths that an attacker might take to escalate privileges or access "Crown Jewel" assets like production databases.

## Key Features

- **Interactive Attack Path Visualization**: A terminal-based Directed Acyclic Graph (DAG) that highlights critical 4-hop attack sequences in high-contrast crimson.
- **Kill Chain Intelligence**: Automated calculation of Path Risk Scores, Blast Radius metrics, and hop counts.
- **Algorithmic Chokepoint Identification**: Identifies the specific RBAC binding or configuration that, if removed, eliminates the majority of active attack paths.
- **One-Click Remediation**: Generates localized Kubernetes YAML patches to instantly harden the cluster posture.
- **High-Performance TUI**: Built with Go and the Bubble Tea framework for a smooth, responsive, and aesthetically professional experience in the terminal.

## Navigation and Controls

The interface is divided into a sidebar navigation system and a main intelligence canvas.

- **[S]**: Initiate a simulated cluster scan.
- **[1-5]**: Quick jump between Dashboard, Graph Explorer, Vulnerabilities, Kill Chain Reports, and Settings.
- **[Up/Down] or [J/K]**: Navigate the sidebar menu.
- **[Enter]**: Generate the Remediation YAML (when in Graph Explorer).
- **[Q]**: Exit the application.

## Technical Architecture

- **Language**: Go 1.26+
- **Frameworks**: 
    - Bubble Tea (The Elm Architecture for TUI)
    - Lipgloss (Style and Layout Engine)
- **Design System**: Strict Dark Mode with a high data-ink ratio and neon crimson highlights for critical security threats.

## Installation and Usage

To build and run the prototype locally:

1. Ensure you have Go installed on your system.
2. Clone this repository.
3. Build the binary:
   ```bash
   go build -o kubegraph main.go
   ```
4. Run the application:
   ```bash
   ./kubegraph
   ```

## Presentation Demo Flow

1. **The Hook**: Launch the dashboard to show the Cluster Security Overview.
2. **The Catalyst**: Press [S] to simulate the RBAC ingestion and graph generation.
3. **The Problem**: Navigate to the Graph Explorer [2] to show the crimson multi-hop path from a public Pod to the database.
4. **The Value**: Point to the "Path Risk Score" and "Blast Radius" metrics in the right-hand panel.
5. **The Handoff**: Press [Enter] to generate the `remediation.yaml` file, demonstrating actionable security outcomes.

## License

This project is part of the KubeGraph security suite prototype. All rights reserved.
