# Ryha Security Flow

**Enterprise Penetration Testing Platform with AI-Powered Multi-Agent Orchestration**

Fully autonomous, AI-driven pentesting platform for Kali Linux that orchestrates up to 10 parallel agents across 5 phases to perform comprehensive security assessments. Uses GitHub Copilot (Claude Opus, Sonnet, GPT-4o) for intelligent tool selection, vulnerability analysis, and professional report generation.

---

## 🎯 Key Features

- **Fully Autonomous Pentesting** — AI orchestrates entire assessment without human intervention
- **300+ Security Tools** — Integrated across 18 categories (recon, scanning, exploitation, forensics, etc.)
- **5-Phase Framework** — Recon → Scanning → Deep Analysis → Exploitation → Post-Exploitation
- **Multi-Agent Architecture** — Up to 10 concurrent agents with parallel execution
- **Web Dashboard** — Real-time terminal, live agent monitoring, vulnerability feed (http://localhost:3000)
- **GitHub Copilot Integration** — 5 AI models: Claude Opus 4.6, Sonnet, GPT-4o, GPT-4, o1-preview
- **One-Time Authentication** — GitHub device flow OAuth, auto-detection of authorization documents
- **Authorization & Compliance** — Scope validation, wildcard/CIDR support, audit logging
- **Professional Reports** — HTML/PDF/Markdown with executive summaries and remediation advice
- **Custom Tool Creation** — AI generates security tools on-the-fly (Python, Bash, Ruby, Perl, Go)
- **GitHub Tool Installer** — Auto-detects build system, clone/build/install any security tool
- **Auto-Install Cascade** — Missing tools auto-installed via apt → pip → go → GitHub → AI-generated

---

## 📊 Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│     Web Dashboard (http://localhost:3000)              │
│  - Live Terminal (color-coded output)                  │
│  - 5 Tabs: Dashboard, New Pentest, Terminal,           │
│    Agents, Vulnerabilities                             │
│  - Real-time Socket.IO updates                         │
└──────────────────────┬──────────────────────────────────┘
                       │ Socket.IO + REST API
┌──────────────────────▼──────────────────────────────────┐
│        Express.js API Server                           │
│  - 13 REST endpoints                                   │
│  - 11 Socket.IO event types                            │
│  - Terminal streaming                                  │
│  - Job management                                      │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│     Pentest Orchestrator                               │
│  - Job lifecycle management                            │
│  - Phase coordination                                  │
│  - Agent pooling (max 10 concurrent)                   │
│  - Vulnerability aggregation                           │
└──────────────────────┬──────────────────────────────────┘
                       │
    ┌──────────────┬───┴────┬──────────────┐
    │              │        │              │
┌───▼────┐  ┌─────▼──┐  ┌──▼────┐  ┌─────▼──┐
│ Recon  │  │ Scan   │  │Analyze│  │Exploit │
│ Agents │  │ Agents │  │Agents │  │ Agents │
└────┬───┘  └────┬───┘  └───┬───┘  └────┬───┘
     │           │          │           │
     └───────────┬──────────┬───────────┘
                 │          │
         ┌───────▼──────────▼────────┐
         │  AI Tool Selector        │
         │  (Claude Opus 4.6)       │
         └───────┬──────────────────┘
                 │
    ┌────────────┼────────────┐
    │            │            │
┌───▼──┐  ┌──────▼──┐  ┌──────▼───┐
│ Kali │  │ GitHub  │  │ AI-Gen   │
│Tools │  │ Repos   │  │ Tools    │
└───┬──┘  └────┬────┘  └────┬─────┘
    │          │            │
    └──────────┬────────────┘
               │
        ┌──────▼─────────┐
        │  Scanner Agent │
        │  (Execute any  │
        │   CLI tool)    │
        └──────┬─────────┘
               │
        ┌──────▼────────────────────┐
        │ Copilot AI Analysis       │
        │ (Extract vulnerabilities) │
        │ (CVSS scoring)            │
        └──────┬─────────────────────┘
               │
        ┌──────▼────────────┐
        │ Professional      │
        │ Report Generator  │
        │ (HTML/PDF/MD)     │
        └───────────────────┘
```

---

## 🚀 Installation & Setup

### Prerequisites
- **Kali Linux** (primary platform) or any Linux with security tools
- **Node.js 18+** and **npm 9+**
- **GitHub account** with Copilot access (Free, Pro, or Enterprise)
- **Root/sudo access** (for tools like nmap SYN scan, masscan, etc.)

### Install

```bash
# Clone the repository
git clone https://github.com/ryhatechnologies/Ryha-Security-Flow.git
cd Ryha-Security-Flow

# Install dependencies
npm install

# Build TypeScript
npm run build

# Link CLI globally (optional)
npm link
```

### One-Time Setup (< 5 minutes)

```bash
# Method 1: Setup wizard (recommended)
ryha setup
# ✅ Step 1: GitHub device flow authentication
# ✅ Step 2: Create authorization document

# Method 2: Step by step
ryha auth login                # Authenticate with Copilot
ryha scope create              # Create authorization document
```

---

## 🎮 Web Dashboard (Primary Interface)

### Starting the Dashboard

```bash
# Start server on port 3000
ryha server

# Or custom port
ryha server -p 8080
```

Then open **http://localhost:3000** in your browser.

### Dashboard - 5 Tabs

#### 1️⃣ **Dashboard (Home)**
- **Stats Bar**: Total vulnerabilities, active agents, progress percentage
- **Live Terminal**: Real-time command output (color-coded by type)
  - 🔵 Blue = commands being executed
  - ⚫ Gray = tool stdout
  - 🟠 Orange = stderr/warnings
  - 🟢 Green = success messages
  - 🔴 Red = errors
  - 🟣 Purple = agent activities
- **Right Sidebar**:
  - Current job status (running/completed/failed)
  - Phase timeline with status indicators
  - Latest vulnerabilities with severity badges

**Real-Time Updates**: All data updates via Socket.IO as pentest progresses

#### 2️⃣ **New Pentest**
Launch a pentest directly from browser:

```
Target Domain / IP:     example.com or 192.168.1.0/24
Scan Type:              Full / Web / Network / Quick / Compliance
Client / Company Name:  Acme Corp
Authorized By:          John Doe
In-Scope Targets:       *.example.com, 10.0.0.0/24
Out-of-Scope:           mail.example.com (optional)
```

Click **Launch Pentest** → Auto-creates authorization doc → Auto-switches to Dashboard

#### 3️⃣ **Live Terminal**
Full-screen terminal view with all command output:
- Color-coded by message type
- Timestamps on each entry
- Auto-scrolls to bottom
- Monospace font (Cascadia Code / JetBrains Mono)

#### 4️⃣ **Agents**
Grid view of all active agents:
- ⚫ Gray dot = idle
- 🟡 Yellow dot (pulsing) = working
- 🟢 Green dot = completed
- 🔴 Red dot = failed

Shows: Agent name, current status, task description

#### 5️⃣ **Vulnerabilities**
Scrollable list of all discovered vulnerabilities:
- **Severity Badges**: Critical (red), High (orange), Medium (yellow), Low (cyan), Info (gray)
- **Vuln Title**: Brief description
- **Discovering Agent**: Which agent found it
- **Count Summary**: Total found so far

---

## 💻 CLI Commands (9 Commands)

### Setup & Authentication

```bash
# One-time setup wizard
ryha setup

# Manual authentication
ryha auth login                    # GitHub device flow
ryha auth status                   # Check auth status
ryha auth logout                   # Clear tokens
```

### Authorization Documents

```bash
# Create authorization document (scope)
ryha scope create

# List all authorization documents
ryha scope list

# View specific document
ryha scope view <id>
```

### Running Pentests

```bash
# Start a pentest (auth auto-detected)
ryha pentest -d target.com -t full

# Specify scan type options
ryha pentest -d target.com -t web        # Web app testing
ryha pentest -d target.com -t network    # Infrastructure testing
ryha pentest -d target.com -t quick      # Fast reconnaissance

# Explicitly provide auth doc (optional)
ryha pentest -d target.com -t full -a <auth-doc-id>
```

**Scan Type Options:**
- `full` — All 5 phases (default, ~2-4 hours)
- `quick` — Recon + Scanning only (15-30 minutes)
- `web` — Web application focused (30-60 minutes)
- `network` — Infrastructure focused (1-2 hours)
- `compliance` — No exploitation (recon + scanning only)

### Server & Dashboard

```bash
# Start web dashboard
ryha server                         # Port 3000 (default)
ryha server -p 8080                # Custom port
```

### Tool Management

```bash
# List all 300+ tools
ryha tools list

# Show only installed tools
ryha tools list -i

# Filter by category
ryha tools list -c recon

# Tool info
ryha tools info nmap

# Install from apt
ryha tools install nikto

# Install from GitHub
ryha tools github projectdiscovery/nuclei

# Auto-install with fallback
ryha tools ensure feroxbuster

# Create custom AI tool
ryha tools create
```

### Agent Management

```bash
# List active agents
ryha agents list

# Agent pool status
ryha agents status
```

### Reporting

```bash
# Generate report (after pentest completes)
ryha report <jobId>                # HTML format
ryha report <jobId> -f markdown    # Markdown format
ryha report <jobId> -f pdf         # PDF format
```

### Configuration

```bash
# Set configuration
ryha config set logLevel debug
ryha config set copilot.defaultModel claude-opus-4-6

# Get configuration
ryha config get logLevel

# List all config
ryha config list
```

---

## 🔄 Workflow Example - Full Penetration Test

### Step 1: Start Dashboard

```bash
ryha server
# Opens on http://localhost:3000
```

### Step 2: Click "New Pentest" Tab

Fill in the form:
```
Target Domain:      target.example.com
Scan Type:          Full (All Phases)
Client Name:        Acme Corporation
Authorized By:      Sarah Johnson
In-Scope:           *.example.com, 10.20.0.0/16
Out-of-Scope:       vpn.example.com, staging.example.com
```

### Step 3: Click "Launch Pentest"

The system automatically:
1. ✅ Creates authorization document
2. ✅ Validates scope and authorization
3. ✅ Switches to Dashboard tab
4. ✅ Starts the pentest job

### Step 4: Watch Live Progress

The Dashboard shows real-time:
- 📺 Live terminal with all tool output
- 🔍 Active agents and their tasks
- 📊 Vulnerabilities as they're discovered
- ⏱️ Phase timeline (Recon → Scan → Analysis → Exploit → Post-Exploit)

### Step 5: Get Interactive Updates

```
Via Socket.IO events:
- terminal:entry → New command/output line
- agent:started → Agent spawned
- agent:completed → Agent finished
- vulnerability:found → New vuln discovered
- phase:complete → Phase finished
```

### Step 6: Generate Report

After pentest completes, click "Generate Report" or use CLI:

```bash
ryha report <job-id> -f html
# Generates: ~/.ryha/reports/<job-id>.html

# Or other formats
ryha report <job-id> -f pdf       # PDF
ryha report <job-id> -f markdown  # Markdown
```

---

## 🎯 AI Model Selection

### 5 Available Models

| Model | Speed | Cost | Best For |
|-------|-------|------|----------|
| `claude-opus-4-6` | Slow | $$ | Complex reasoning, tool selection, attack planning |
| `claude-3-5-sonnet-20241022` | Medium | $ | Tool output analysis, report generation (default) |
| `gpt-4o` | Fast | $ | Quick searches, fast analysis |
| `gpt-4` | Slow | $$ | Alternative to Opus |
| `o1-preview` | Very Slow | $$$ | Advanced reasoning, complex problems |

### How to Select Default Model

**Method 1: CLI Command**
```bash
ryha config set copilot.defaultModel claude-opus-4-6
```

**Method 2: Environment Variable**
```bash
export RYHA_COPILOT_DEFAULT_MODEL=claude-opus-4-6
ryha server
```

**Method 3: Configuration File**
Edit `~/.ryha/config.yaml`:
```yaml
copilot:
  defaultModel: claude-opus-4-6
  models:
    - claude-opus-4-6
    - claude-3-5-sonnet-20241022
    - gpt-4o
```

---

## 🔐 5-Phase Penetration Testing Workflow

### Phase 1: Reconnaissance
**Agents**: DNS Enumeration, WHOIS/OSINT, Service Discovery, Tech Fingerprinting
**Tools**: nmap, masscan, amass, subfinder, theHarvester, whois
**Output**: Discovered services, domains, IP ranges, technology stack

```bash
# Example tools discovered:
- nmap -Pn --min-rate 1000 target.com
- amass enum -d target.com
- subfinder -d target.com
```

### Phase 2: Scanning
**Agents**: Vulnerability Scanning, Web App Testing, Directory/File Discovery, SSL/TLS Analysis
**Tools**: nuclei, nikto, OpenVAS, wpscan, dirb, gobuster, nessus
**Output**: CVEs, misconfigurations, exposed files, weak credentials

```bash
# Example tools discovered:
- nuclei -t /path/to/templates -u target.com
- nikto -h target.com
- gobuster dir -u http://target.com -w wordlist.txt
```

### Phase 3: Deep Analysis
**Agents**: AI Vulnerability Analysis, Auth Testing, API Security, Zero-Day Detection
**Tools**: Manual AI analysis, burp scanner, zaproxy, custom scripts
**Output**: CVSS scores, attack chains, exploitability assessment

### Phase 4: Exploitation
**Agents**: Exploit Verification, Privilege Escalation, Lateral Movement
**Tools**: metasploit, sqlmap, searchsploit, custom exploits
**Output**: Proof-of-concept results, access level verification

### Phase 5: Post-Exploitation
**Agents**: Data Exposure Assessment, Lateral Movement Analysis
**Tools**: Custom data scanners, network analysis
**Output**: Sensitive data found, additional targets identified

---

## 📝 Example CLI Usage

### Example 1: Quick Web App Test

```bash
# One-time setup (if not already done)
ryha setup

# Run quick web app scan
ryha pentest -d webapp.example.com -t web

# Watch progress on dashboard
ryha server
# Open http://localhost:3000
```

### Example 2: Network Infrastructure Scan

```bash
# Full network assessment on authorized subnet
ryha pentest -d 192.168.1.0/24 -t network

# Generate report in PDF
ryha report <job-id> -f pdf
```

### Example 3: Full Compliance Assessment

```bash
# Compliance-focused (no exploitation)
ryha pentest -d target.com -t compliance

# Get HTML report with all details
ryha report <job-id> -f html
```

### Example 4: Install Tools from GitHub

```bash
# Install nuclei scanner
ryha tools github projectdiscovery/nuclei

# Search for tools
ryha tools github-search "http fuzzer golang"

# Auto-install with fallback methods
ryha tools ensure feroxbuster
```

### Example 5: Create Custom Tool

```bash
# Interactive tool creation
ryha tools create

# Prompts:
# Purpose: Scan for exposed API keys in public repos
# Target type: web
# Language: python
# Template: custom

# Tool generated and registered automatically
```

---

## 📊 Authorization & Compliance

Every pentest requires a valid authorization document with:
- **Target Domain**: Primary domain under test
- **In-Scope**: Allowed targets (supports wildcards: `*.example.com`, CIDR: `10.0.0.0/24`)
- **Out-of-Scope**: Explicitly excluded targets
- **Start Date**: When authorization is valid
- **End Date**: When authorization expires
- **Testing Types**: Approved testing methods (network, web, full, etc.)
- **Authorized By**: Name of authorizing person

### Auto-Detection

When you run `ryha pentest`, the system:
1. Searches all saved auth docs for matching domain
2. Falls back to any valid non-expired doc
3. Creates new doc from web form if needed

```bash
# Auto-detection in action
ryha pentest -d target.com -t full
# ✅ Auto-detected: "Acme Corp Q1 2024" auth doc
```

---

## 🛠️ Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Language** | TypeScript 5+ | Type-safe backend |
| **API Server** | Express.js | REST API endpoints |
| **Real-Time** | Socket.IO | Live dashboard updates |
| **Frontend** | Vanilla JS (zero deps) | No framework bloat |
| **Authentication** | GitHub Copilot OAuth | Secure device flow |
| **Encryption** | AES-256-CBC | Token encryption |
| **Database** | JSON + YAML | Config/docs storage |
| **UI Framework** | Flexbox CSS | Responsive design |

---

## 📋 File Structure

```
ryha-security-flow/
├── src/
│   ├── cli.ts                      # CLI entry point (9 commands)
│   ├── index.ts                    # Module exports
│   ├── api/
│   │   └── server.ts               # Express + Socket.IO server
│   ├── ui/
│   │   └── index.html              # Web dashboard (5 tabs)
│   ├── orchestrator/
│   │   └── orchestrator.ts         # Job + phase orchestration
│   ├── auth/
│   │   └── copilot-auth.ts         # GitHub Copilot auth
│   ├── compliance/
│   │   └── auth-*.ts               # Authorization validation
│   ├── tools/
│   │   ├── ai-tool-selector.ts     # Autonomous tool selection
│   │   ├── tool-manager.ts         # 300+ tool database
│   │   └── github-installer.ts     # GitHub installer
│   ├── scanners/
│   │   └── scanner-agent.ts        # Tool execution
│   ├── agents/
│   │   └── system-instructions.ts  # AI agent prompts
│   └── [other modules]
├── dist/                           # Compiled JavaScript
├── docs/
│   ├── README.md                   # Full documentation
│   ├── AI-MODEL-CONFIGURATION.md   # Model selection guide
│   └── DEPLOYMENT-READY.md         # Deployment checklist
├── package.json
└── tsconfig.json
```

---

## ✅ Deployment Ready

**Production Status**: ✅ **READY FOR DEPLOYMENT**

- ✅ TypeScript: 0 compilation errors
- ✅ Web Dashboard: All 5 tabs verified
- ✅ API: 13 endpoints working
- ✅ Documentation: Comprehensive (1200+ lines)
- ✅ GitHub: Published at https://github.com/ryhatechnologies/Ryha-Security-Flow

---

## 📖 Full Documentation

For comprehensive details, see:
- **`docs/README.md`** — Complete user guide (1200+ lines)
- **`docs/AI-MODEL-CONFIGURATION.md`** — AI model selection guide
- **`docs/DEPLOYMENT-READY.md`** — Deployment checklist

---

## 🤝 Support & Troubleshooting

### "Not authenticated"
```bash
ryha auth login
```

### "No valid auth documents found"
```bash
ryha scope create
```

### "Target is not in authorized scope"
Create new auth document that includes target in in-scope list.

### "Tool not found"
```bash
# Auto-install with fallback methods
ryha tools ensure <tool-name>
```

### Web dashboard not loading
```bash
# Verify server is running
ryha server
# Check port 3000 is available
netstat -tlnp | grep 3000
```

---

## 📜 License

MIT License. See [LICENSE](LICENSE) for details.

**Important**: This tool is designed for authorized security testing only. Always ensure you have proper written authorization before conducting any penetration testing. Unauthorized access to computer systems is illegal.
