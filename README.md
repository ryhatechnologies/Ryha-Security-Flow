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

## 🤖 Agent System - How Agents Spawn & Work in Parallel

### What Are Agents?

Agents are autonomous AI-powered workers that execute specific penetration testing tasks:
- Each agent is **specialized** in one role (recon, scanning, analysis, etc.)
- Each agent **runs concurrently** (parallel) with other agents in the same phase
- Each agent **communicates** results back to the orchestrator in real-time
- Each agent **adapts** based on findings and AI analysis

### Agent Types (9 Total)

| Agent Type | Count | Role | Task |
|------------|-------|------|------|
| **DNS Enumeration** | 1 | Recon | DNS records, zone transfers, subdomain discovery |
| **WHOIS/OSINT** | 1 | Recon | WHOIS data, email harvesting, social media footprinting |
| **Service Discovery** | 1 | Recon | Port scanning, service detection, OS fingerprinting |
| **Tech Fingerprinting** | 1 | Recon | CMS detection, framework ID, WAF detection |
| **Vulnerability Scanner** | 2 | Scanning | CVE detection (nuclei, nikto, OpenVAS) |
| **Web App Tester** | 2 | Scanning | OWASP Top 10 testing (XSS, SQLi, CSRF, etc.) |
| **Analyzer** | 1 | Analysis | CVSS scoring, risk prioritization, attack chains |
| **Exploit Tester** | 1 | Exploitation | Safe PoC exploitation, privilege escalation |
| **Data Exposure** | 1 | Post-Exploitation | Sensitive data assessment, lateral movement |

**Total Agents Per Phase**: 4-6 agents spawned (varies by phase)
**Maximum Concurrent**: 10 agents running simultaneously

### How Parallel Execution Works

#### Timeline: Agent Spawning & Execution

```
┌─────────────────────────────────────────────────────────────────────┐
│                    PENTEST JOB STARTS                              │
│                     (T = 0 seconds)                                 │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
   PHASE 1:           PHASE 2:           PHASE 3:           PHASE 4:
   RECON              SCANNING           ANALYSIS           EXPLOIT
   (0-15 min)         (15-45 min)        (45-60 min)        (60-90 min)
        │                  │                  │                  │
        │                  │                  │                  │
   ┌────▼─────┐       ┌────▼─────┐      ┌────▼─────┐       ┌────▼─────┐
   │ Agent 1  │       │ Agent 5  │      │ Agent 10 │       │ Agent 14 │
   │ Agent 2  │       │ Agent 6  │      │ (AI)     │       │ Agent 15 │
   │ Agent 3  │       │ Agent 7  │      │ Agent 11 │       │          │
   │ Agent 4  │       │ Agent 8  │      │ Agent 12 │       │          │
   │          │       │ Agent 9  │      │ Agent 13 │       │          │
   │ (Running │       │          │      │          │       │ (Running │
   │ in       │       │ (Running │      │ (Running │       │ in       │
   │ parallel)│       │ in       │      │ in       │       │ parallel)│
   │          │       │ parallel)│      │ parallel)│       │          │
   └────┬─────┘       └────┬─────┘      └────┬─────┘       └────┬─────┘
        │                  │                  │                  │
        └──────────────────┼──────────────────┼──────────────────┘
                           │
                ┌──────────▼──────────┐
                │  PHASE 5:           │
                │  POST-EXPLOITATION  │
                │  (90-120 min)       │
                │  AgentX (Running)   │
                └──────────┬──────────┘
                           │
                ┌──────────▼──────────┐
                │  REPORTING & EXPORT │
                │  (120-135 min)      │
                └────────────────────┘
```

### How Agents Spawn - Step by Step

#### Step 1: Job Started
```
ryha pentest -d target.com -t full
           ↓
   Orchestrator creates job UUID
           ↓
   Loads all 5 phases from config
           ↓
   Validates authorization document
           ↓
   Starts PHASE 1: Reconnaissance
```

#### Step 2: Phase 1 - Recon (Agents spawn CONCURRENTLY)

```
T = 0:00  Agent 1 spawns: DNS Enumeration
          ├─ Query DNS records for target.com
          ├─ Enumerate subdomains (amass, subfinder)
          └─ Detect DNS zone transfers

T = 0:00  Agent 2 spawns: WHOIS/OSINT (SAME TIME as Agent 1)
          ├─ WHOIS lookup
          ├─ Email harvesting (theHarvester)
          ├─ Social media footprinting
          └─ Company association mapping

T = 0:00  Agent 3 spawns: Service Discovery (SAME TIME)
          ├─ Port scan full range (masscan, nmap)
          ├─ Service version detection
          ├─ OS fingerprinting
          └─ Firewall/WAF detection

T = 0:00  Agent 4 spawns: Tech Fingerprinting (SAME TIME)
          ├─ CMS detection (WordPress, Drupal, Joomla)
          ├─ Web framework identification
          ├─ Web server detection (Apache, Nginx, IIS)
          └─ Programming language detection

T = 5:00   Agent 1 completes → Submits findings
           └─ 247 subdomains discovered

T = 8:00   Agent 2 completes → Submits findings
           └─ 3 leaked emails, company info gathered

T = 12:00  Agent 3 completes → Submits findings
           └─ 28 open ports, services mapped

T = 15:00  Agent 4 completes → Submits findings
           └─ WordPress 5.8.1 detected, Apache 2.4.41

         ▼▼▼ ALL PHASE 1 AGENTS COMPLETE ▼▼▼

T = 15:01  PHASE 1 COMPLETE - Aggregate findings
           → 247 targets identified
           → 28 services cataloged
           → Technology stack mapped
```

#### Step 3: Phase 2 - Scanning (New agents spawn when Phase 1 ends)

```
T = 15:01  Agent 5 spawns: Vulnerability Scanner (nuclei)
          ├─ Run CVE templates against all 247 targets
          ├─ Check for known vulnerable versions
          └─ Generate risk scores for each CVE

T = 15:01  Agent 6 spawns: Web App Tester (burp, zaproxy)
          ├─ Test OWASP Top 10 vulnerabilities:
          │  - XSS (Cross-Site Scripting)
          │  - SQLi (SQL Injection)
          │  - CSRF (Cross-Site Request Forgery)
          │  - SSRF (Server-Side Request Forgery)
          │  - LFI/RFI (Local/Remote File Inclusion)
          │  - Auth bypass
          │  - Session management issues
          │  - Insecure deserialization
          └─ Generate findings for each endpoint

T = 15:01  Agent 7 spawns: Directory/File Discovery
          ├─ Brute-force common directories (gobuster)
          ├─ Find backup files (.bak, .zip, .old)
          ├─ Discover hidden API endpoints
          └─ Enumerate git repositories exposed

T = 15:01  Agent 8 spawns: SSL/TLS Analyzer
          ├─ Certificate chain validation
          ├─ Cipher strength analysis
          ├─ Deprecated protocol detection (SSLv3, TLS 1.0)
          └─ Check for SSL/TLS misconfigurations

T = 15:01  Agent 9 spawns: Additional Scanner (nikto)
          ├─ Alternative CVE scanning engine
          ├─ Backup from Agent 5 (redundancy)
          └─ Cross-validate findings

T = 20:00   Agent 5 completes → 14 CVEs found
            └─ 3 Critical, 5 High, 6 Medium

T = 25:00   Agent 6 completes → 12 Web vulns found
            └─ 2 SQLi, 3 XSS, 4 CSRF, 3 Auth issues

T = 22:00   Agent 7 completes → 8 files/dirs exposed
            └─ web.config.bak, .git, admin_backup.zip

T = 28:00   Agent 8 completes → 6 SSL issues found
            └─ TLS 1.0 enabled, weak ciphers

T = 32:00   Agent 9 completes → 5 additional vulns
            └─ Cross-validates Agent 5 findings

T = 32:01  PHASE 2 COMPLETE - Aggregate findings
           → 39 vulnerabilities discovered
           → Severity breakdown: 3 Critical, 8 High, 12 Medium, 16 Low
```

#### Step 4: Phase 3 - Deep Analysis (1 agent, AI-powered)

```
T = 32:01  Agent 10 spawns: AI Vulnerability Analyzer
          ├─ Read all 39 vulnerabilities from Phases 1-2
          ├─ For each vulnerability:
          │  ├─ Calculate CVSS score (0-10)
          │  ├─ Assess exploitability (easy/moderate/hard)
          │  ├─ Identify attack chains
          │  ├─ Check for combinations (e.g., SQLi + Auth Bypass)
          │  └─ Generate remediation advice
          ├─ Identify zero-days or unusual patterns
          ├─ Prioritize by real-world impact
          └─ Output: Structured JSON with all details

T = 45:00  Agent 10 completes → Analysis done
           └─ 39 vulns analyzed and prioritized
           └─ 2 critical attack chains identified

T = 45:01  PHASE 3 COMPLETE
           → Attack chains identified
           → Remediation advice generated
           → Risk scoring complete
```

#### Step 5: Phase 4 - Exploitation (2 agents in parallel)

```
T = 45:01  Agent 14 spawns: Exploit Tester
          ├─ For each Critical/High vuln:
          │  ├─ Create safe PoC (no data deletion)
          │  ├─ Verify exploitability
          │  └─ Document attack path
          ├─ Privilege escalation testing
          ├─ Lateral movement assessment
          └─ Document real-world impact

T = 45:01  Agent 15 spawns: Metasploit Integration
          ├─ Run applicable MSF modules
          ├─ Verify RCE/code execution
          ├─ Test credential harvesting
          └─ Assess system compromise level

T = 75:00  Agent 14 completes → 4 vulns exploited
           └─ Created proofs-of-concept

T = 80:00  Agent 15 completes → 2 additional exploits
           └─ RCE confirmed on 2 targets

T = 80:01  PHASE 4 COMPLETE
           → 6 vulnerabilities confirmed via PoC
           → System compromise level assessed
```

#### Step 6: Phase 5 - Post-Exploitation (1 agent)

```
T = 80:01  Agent 16 spawns: Data Exposure Assessment
          ├─ Search for sensitive files:
          │  ├─ Database backups
          │  ├─ API keys/credentials
          │  ├─ Customer PII
          │  ├─ Source code
          │  └─ Configuration files
          ├─ Assess data exfiltration risk
          ├─ Check for lateral movement paths
          └─ Document impact

T = 105:00 Agent 16 completes → Exposure assessment done
            └─ 47GB of accessible data
            └─ 1,200 customer records at risk

T = 105:01 PHASE 5 COMPLETE
           → Full post-exploitation landscape mapped
```

#### Step 7: Report Generation

```
T = 105:01 Orchestrator aggregates all findings
           ├─ 40 vulnerabilities total
           ├─ 6 confirmed via PoC
           ├─ 2 critical attack chains
           ├─ 47GB sensitive data exposed
           └─ Executive summary generated

T = 120:00 Report generation complete
           └─ HTML/PDF/Markdown generated

Dashboard updates with completion status:
✅ Recon Phase: 4 agents, 15 min, Complete
✅ Scanning Phase: 5 agents, 17 min, Complete
✅ Analysis Phase: 1 agent (AI), 12 min, Complete
✅ Exploitation Phase: 2 agents, 35 min, Complete
✅ Post-Exploitation Phase: 1 agent, 25 min, Complete
──────────────────────────────────────────────
TOTAL TIME: 120 minutes (2 hours)
TOTAL AGENTS SPAWNED: 13 agents across 5 phases
FINDINGS: 40 vulnerabilities, 6 confirmed exploitable
```

### Real-World Parallel Execution Example

**Scenario: Full Pentest of Web App (target.com)**

```
TIME      AGENTS RUNNING                          STATUS
────────────────────────────────────────────────────────
00:00     [1][2][3][4]                            Phase 1: Spawn 4 agents (Recon)
00:05     [1][2][3][4]                            All 4 running in parallel
00:12     [1][2][3][4]                            Agent 1 completes (DNS)
00:15     [-][2][3][4] → [5][6][7][8][9]        Phase 2 spawns 5 agents
          (Wait for all Phase 1 to finish)
00:22     [5][6][7][8][9]                         Agent 2 completes, Phase 1 done
00:23     PHASE 1 ENDS → [5][6][7][8][9]         Agent 3 completes
00:32     [5][6][7][8][9]                         All Phase 2 agents running
00:35     [5][6][7][8][9]                         Agent 5 (nuclei) completes
00:42     [5][6][7][-][-] → [10]                 Phase 3 spawns (AI analyzer)
          (Phase 2 agents gradually finish)
00:45     PHASE 2 ENDS → [10]                     All Phase 2 agents done
00:52     [10]                                     AI analyzing all findings
01:00     [-] → [14][15]                         Phase 4 spawns (Exploit agents)
          (Phase 3 analysis complete)
01:05     [14][15]                                Both exploit agents running
01:35     [-][-] → [16]                          Phase 5 spawns (Post-exploitation)
          (Exploit agents finish)
01:40     PHASE 4 ENDS → [16]                     Starting post-exploitation
02:00     PHASE 5 ENDS ✅                        All agents complete
                                                  Report generated
```

### Key Parallel Execution Rules

1. **Phases are Sequential**
   - Phase 1 must complete before Phase 2 starts
   - Phase 2 must complete before Phase 3 starts
   - etc.

2. **Agents Within a Phase Run in Parallel**
   - All 4 Recon agents run simultaneously
   - All 5 Scanning agents run simultaneously
   - Maximum 10 concurrent agents

3. **Agent Communication**
   - Results stream to Dashboard in real-time via Socket.IO
   - Each agent emits events: `agent:started`, `agent:working`, `agent:completed`
   - Orchestrator aggregates findings after each phase

4. **Failure Handling**
   - If one agent fails, phase continues (configurable)
   - Failed agents marked red on Dashboard
   - Results aggregated from successful agents only

5. **Performance**
   - Parallel execution: 2-4 hours for full scan
   - Sequential would take: 6-8 hours
   - **2-4x speedup** from parallel agents

### Monitor Agents in Real-Time

```bash
# Watch agents spawning
ryha server
# Open http://localhost:3000 → Agents tab

# CLI monitoring
watch -n 1 'ryha agents status'

# Dashboard shows:
├─ Agent Name (e.g., "DNS Enumeration")
├─ Status (idle/working/completed/failed)
├─ Progress (if available)
├─ Current task description
└─ Real-time updates via WebSocket
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
