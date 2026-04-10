# SOC Hunt Orchestrator

A Bash-based SOC automation project for collecting telemetry, parsing suspicious activity, correlating IOCs, and generating analyst-ready reports across Apache, Docker, and Kubernetes environments.

## Overview

SOC Hunt Orchestrator is a portfolio-grade Bash project designed to simulate practical blue-team and detection engineering workflows. It combines host-based web telemetry, container inspection, Kubernetes workload review, IOC matching, and structured reporting into one end-to-end script.

The project was built to demonstrate how Bash can be used beyond basic scripting to support security automation, log analysis, detection logic, and investigation workflows.

## Core Capabilities

- Analyze Apache access and error logs
- Inspect Docker containers and collect container telemetry
- Review Kubernetes pod posture and collect workload logs
- Parse suspicious request patterns and scanner user-agents
- Correlate IPs, domains, and user-agents against local IOC feeds
- Assign risk scores to findings
- Generate reports in JSON, CSV, and Markdown

## Project Goals

- Demonstrate practical SOC analyst workflow design
- Combine Bash scripting with real security use cases
- Simulate detection and triage across web and cloud-native environments
- Build a project suitable for GitHub, LinkedIn, resume, and interview discussion

## Technologies Used

- Bash
- Apache
- Docker
- Kubernetes
- kubectl
- kind
- jq
- curl
- awk
- sed
- grep

## Project Structure

```text
soc-hunt-orchestrator/
├── soc_hunt_orchestrator.sh
├── apache-k8s.yaml
├── feeds/
│   ├── iocs.txt
│   ├── domains.txt
│   └── user_agents.txt
├── output/
│   └── run-<timestamp>-<random>/
│       ├── raw/
│       ├── processed/
│       └── reports/
└── README.md
