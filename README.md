# Ryha Security Flow

Enterprise Penetration Testing Platform with AI-Powered Agent Orchestration.

## Features

- 🤖 **Multi-Agent Orchestration**: Deploy up to 60 parallel agents
- 🔓 **GitHub Copilot Integration**: Use Claude Opus 4.6 and other models
- 📋 **Authorization Framework**: Mandatory scope documents for legal compliance
- 🔍 **Automated Vulnerability Detection**: Network, Web, Infrastructure, Code scanning
- 🎯 **Zero-Day Detection**: AI-powered anomaly detection
- 📊 **Enterprise Reporting**: Detailed findings with remediation advice
- 🐧 **Kali Linux Native**: Root-level access, full tool integration
- 24/7 **Continuous Monitoring**: Scheduled automated testing

## Installation (Kali Linux)

```bash
# Clone and setup
git clone <repo> && cd ryha-security-flow
bash scripts/install-kali.sh

# Install dependencies
npm install

# Authenticate with Copilot
ryha auth

# Create authorization document
ryha scope --create
```

## Quick Start

```bash
# Start pentest on authorized domain
ryha pentest --domain target.com --type full --auth <auth-id>

# View agents
ryha agents --status

# Generate report
ryha report --job <job-id> --export pdf
```

## Architecture

- **Orchestrator**: Validates authorization, coordinates agents
- **Scanners**: Network, Web, Infrastructure, Code analysis
- **Analyzers**: Vulnerability assessment, risk scoring, zero-day detection
- **Executors**: Tool runners with root permissions
- **Reporters**: Evidence collection, compliance reporting
