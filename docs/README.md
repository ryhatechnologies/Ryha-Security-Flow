# Ryha Security Flow

Enterprise Penetration Testing Platform with Multi-Agent AI Orchestration

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Installation](#installation)
4. [One-Time Setup](#one-time-setup)
5. [Web Dashboard (Primary Interface)](#web-dashboard)
6. [CLI Commands](#cli-commands)
7. [How It Works](#how-it-works)
8. [AI Models & Authentication](#ai-models--authentication)
9. [Tool Management](#tool-management)
10. [Phases of a Pentest](#phases-of-a-pentest)
11. [Agent System](#agent-system)
12. [Authorization & Compliance](#authorization--compliance)
13. [API Reference](#api-reference)
14. [Configuration](#configuration)
15. [Project Structure](#project-structure)
16. [Examples](#examples)
17. [Troubleshooting](#troubleshooting)

---

## Overview

Ryha Security Flow is a fully autonomous, AI-driven penetration testing platform for Kali Linux. It uses multi-agent orchestration powered by GitHub Copilot AI models (Claude Opus 4.6, Sonnet, GPT-4o) to plan attack strategies, select and run security tools, analyze results, and generate professional reports — all without human intervention.

### Key Features

- **Fully autonomous pentesting** — AI decides what tools to run, analyzes output, and adapts strategy in real-time
- **300+ security tools** across 18 categories, covering every Kali Linux metapackage
- **GitHub tool installer** — clone, build, and install any security tool from GitHub repositories
- **AI tool creator** — generates custom security tools on-the-fly in Python, Bash, Ruby, Perl, or Go
- **Auto-install missing tools** — cascading install via apt, pip, go install, or GitHub
- **Web dashboard** — real-time terminal, live agent status, vulnerability feed, launch pentests from browser
- **Multi-agent architecture** — parallel agent execution across 5 phases
- **GitHub Copilot auth** — one-time device flow login, no API keys needed
- **Authorization compliance** — legally validated scope documents with audit logging
- **Professional reports** — HTML/PDF/Markdown pentest reports with executive summaries

---

## Architecture

```
+------------------------------+
|        Web Dashboard         |   <-- http://localhost:3000
|  (Live Terminal, Agents,     |
|   Vulns, Launch Pentests)    |
+------------------------------+
         |  Socket.IO + REST
+------------------------------+
|       Express API Server     |   <-- RyhaServer
|  /api/pentest  /api/scope    |
|  /api/jobs     /api/tools    |
+------------------------------+
         |
+------------------------------+
|   Pentest Orchestrator       |   <-- Job management, phase execution
|   (EventEmitter)             |
+------------------------------+
     |         |         |
+--------+ +--------+ +--------+
| Recon  | | Scan   | | Exploit|   <-- Parallel agents per phase
| Agents | | Agents | | Agents |
+--------+ +--------+ +--------+
     |         |         |
+------------------------------+
|   AI Tool Selector           |   <-- Autonomous tool selection
|   (Copilot API)              |
+------------------------------+
     |         |         |
+--------+ +--------+ +--------+
| Kali   | | GitHub | | Custom |   <-- Tool sources
| Tools  | | Repos  | | AI Gen |
+--------+ +--------+ +--------+
     |
+------------------------------+
|   Scanner Agent              |   <-- Tool execution layer
|   (runDynamicScan)           |
+------------------------------+
     |
+------------------------------+
|   Copilot AI Analysis        |   <-- Vulnerability extraction
|   (claude-opus-4-6 / gpt-4o)|
+------------------------------+
```

### Core Components

| Component | File | Purpose |
|-----------|------|---------|
| CLI | `src/cli.ts` | 9 commands: auth, scope, pentest, agents, report, config, server, setup, tools |
| Server | `src/api/server.ts` | Express + Socket.IO web server with REST API |
| Dashboard | `src/ui/index.html` | Real-time web UI — the primary operational interface |
| Orchestrator | `src/orchestrator/orchestrator.ts` | Job lifecycle, phase execution, agent coordination |
| Agent Pool | `src/orchestrator/agent-pool.ts` | Spawns and manages parallel agents |
| Scanner Agent | `src/scanners/scanner-agent.ts` | Wraps Kali tools, parses output, emits findings |
| AI Tool Selector | `src/tools/ai-tool-selector.ts` | Autonomous tool selection, strategy planning, custom tool creation |
| Tool Manager | `src/tools/tool-manager.ts` | 300+ tool database, discovery, install, search |
| GitHub Installer | `src/tools/github-installer.ts` | Clone, detect build system, build, install from GitHub |
| Auth (Copilot) | `src/auth/copilot-auth.ts` | GitHub device flow, encrypted token storage, AI chat |
| Auth Document | `src/compliance/auth-document.ts` | Legal authorization documents (YAML, scope matching) |
| Auth Validator | `src/compliance/auth-validator.ts` | Pre-scan validation, audit logging |
| Executor Agent | `src/executors/executor-agent.ts` | Root command execution, Metasploit integration |
| Reporter Agent | `src/reporters/reporter-agent.ts` | Professional pentest report generation |
| Analyzer Agent | `src/analyzers/analyzer-agent.ts` | Deep vulnerability classification and CVSS scoring |
| Config Manager | `src/config/config-manager.ts` | Settings persistence |

---

## Installation

### Prerequisites

- **Kali Linux** (primary platform) or any Linux with security tools
- **Node.js 18+** and **npm**
- **GitHub account** with Copilot access (Free, Pro, or Enterprise)
- **Root/sudo access** (for tools like nmap SYN scan, masscan, etc.)

### Install

```bash
# Clone the repository
git clone https://github.com/your-org/ryha-security-flow.git
cd ryha-security-flow

# Install dependencies
npm install

# Build TypeScript
npm run build

# Link CLI globally
npm link
```

After this, the `ryha` command is available system-wide.

---

## One-Time Setup

Ryha only requires authentication **once**. After that, you never need to provide auth credentials or document IDs again.

### Method 1: Setup Wizard (Recommended)

```bash
ryha setup
```

This interactive wizard does everything:

1. **Step 1/2 — Authentication**: Initiates GitHub Copilot device flow login
   - Opens `https://github.com/login/device`
   - You enter the one-time code shown in terminal
   - Tokens are encrypted and stored at `~/.ryha/tokens.json`
2. **Step 2/2 — Authorization Document**: Creates your first scope document
   - Client name, target domain, in-scope/out-of-scope targets
   - Testing types (network, web, infrastructure, code, cloud, full)
   - Start/end dates, authorized by, digital signature
   - Saved as YAML in `~/.ryha/authorizations/`

### Method 2: Step by Step

```bash
# Step 1: Authenticate with GitHub Copilot
ryha auth login

# Step 2: Create authorization document
ryha scope create
```

### What Gets Stored

```
~/.ryha/
  tokens.json          # AES-256 encrypted GitHub + Copilot tokens
  .key                 # Encryption key (0600 permissions)
  authorizations/
    <uuid>.yaml        # Authorization documents
  audit-logs/
    validation-audit.log   # All validation attempts
    errors.log             # Validation failures
```

---

## Web Dashboard

The web dashboard is the **primary interface** for running pentests. Start it with:

```bash
ryha server
# or with custom port:
ryha server -p 8080
```

Then open **http://localhost:3000** in your browser.

### Dashboard Tabs

#### 1. Dashboard (Home)

The main overview with three sections:

- **Stats Bar**: Total vulnerabilities found, active agents, overall progress percentage
- **Live Terminal**: Real-time command output with color-coded entries
  - Blue = commands being executed
  - Gray = tool stdout
  - Orange = stderr/warnings
  - Green = success messages
  - Red = errors
  - Purple = agent activities
- **Right Sidebar**:
  - Current job status (running/completed/failed)
  - Phase timeline with status icons (pending/running/completed/failed)
  - Latest vulnerabilities with severity badges

#### 2. New Pentest

Launch a pentest directly from the browser:

- **Target Domain / IP** — e.g., `example.com` or `192.168.1.0/24`
- **Scan Type** — Full, Web Application, Network, Quick Scan, or Compliance
- **Client / Company Name** — for the authorization document
- **Authorized By** — person authorizing the test
- **In-Scope Targets** — comma-separated, e.g., `*.example.com, 10.0.0.0/24`
- **Out-of-Scope** — targets to exclude, e.g., `mail.example.com`

When you click **Launch Pentest**:
1. The server auto-creates an authorization document from the form data
2. Validates scope and authorization
3. Starts the pentest job
4. Automatically switches to the Dashboard tab to show live progress

Existing authorization documents are listed below the form.

#### 3. Live Terminal

Full-screen terminal view with all command output. Every tool execution, agent activity, and system message streams here in real-time via Socket.IO.

#### 4. Agents

Grid view of all active agents with:
- Status dot (gray=idle, yellow=working, green=completed, red=failed)
- Agent name (e.g., "DNS Enumeration", "Web Application Scan")
- Current status text

#### 5. Vulnerabilities

Scrollable list of all discovered vulnerabilities with:
- Severity badge (critical/high/medium/low/info) with color coding
- Vulnerability title
- Discovering agent name

### Real-Time Updates

The dashboard uses Socket.IO for real-time streaming:

| Event | Data | Description |
|-------|------|-------------|
| `terminal:history` | entries[] | Initial terminal log on connect |
| `terminal:entry` | entry | New terminal line |
| `job:started` | jobId | Pentest job started |
| `job:complete` | {jobId, vulnCount} | Job finished |
| `job:failed` | {jobId, error} | Job failed |
| `phase:started` | {jobId, phase} | Phase began |
| `phase:complete` | {jobId, phase, findings} | Phase finished |
| `agent:started` | {jobId, agentId, name} | Agent spawned |
| `agent:completed` | {jobId, agentId, name} | Agent finished |
| `agent:failed` | {jobId, agentId, name, error} | Agent errored |
| `vulnerability:found` | {jobId, vulnerability} | New vuln discovered |

---

## CLI Commands

### `ryha setup`

One-time interactive setup wizard. Handles authentication and authorization document creation.

### `ryha auth`

```bash
ryha auth login      # Start GitHub device flow authentication
ryha auth status     # Check if authenticated
ryha auth logout     # Clear stored tokens
```

### `ryha scope`

```bash
ryha scope create    # Interactive authorization document creation
ryha scope list      # List all authorization document IDs
ryha scope view <id> # View a specific document
```

### `ryha pentest`

```bash
# Start a pentest (auth doc auto-detected)
ryha pentest -d target.com -t full

# Specify scan type
ryha pentest -d 192.168.1.0/24 -t network

# Explicitly provide auth doc (optional)
ryha pentest -d target.com -t web -a <auth-doc-id>
```

**Options:**
- `-d, --domain <domain>` — Target domain or IP (required)
- `-t, --type <type>` — Scan type: `full`, `quick`, `web`, `network`, `compliance` (default: `full`)
- `-a, --auth <id>` — Authorization document ID (auto-detected if omitted)

**Auth auto-detection**: When `-a` is omitted, Ryha:
1. Searches all saved auth docs for one matching the target domain
2. Falls back to any valid (non-expired) auth doc
3. Gives a clear error if no valid docs exist

### `ryha server`

```bash
ryha server           # Start on port 3000
ryha server -p 8080   # Custom port
```

### `ryha tools`

```bash
ryha tools list                    # List all 300+ tools in database
ryha tools list -i                 # Show only installed tools
ryha tools list -c recon           # Filter by category
ryha tools categories              # List all 18 categories with tool counts
ryha tools info nmap               # Detailed info about a specific tool
ryha tools install nikto           # Install via apt-get
ryha tools search "sql injection"  # Search by capability
ryha tools github owner/repo       # Install from GitHub repo
ryha tools github-search "fuzzer"  # AI-powered GitHub search
ryha tools github-list             # List known GitHub security tool repos
ryha tools create                  # AI creates a custom security tool
ryha tools ensure nuclei           # Auto-install via any available method
```

### `ryha agents`

```bash
ryha agents list     # List active agents
ryha agents status   # Agent pool status
```

### `ryha report`

```bash
ryha report <jobId>               # Generate HTML report
ryha report <jobId> -f markdown   # Markdown format
ryha report <jobId> -f pdf        # PDF format
```

### `ryha config`

```bash
ryha config set key value   # Set a config value
ryha config get key         # Get a config value
ryha config list            # Show all config
```

---

## How It Works

### End-to-End Flow

```
1. USER: ryha pentest -d target.com -t full
       (or clicks "Launch Pentest" in web dashboard)
                    |
2. AUTH CHECK: Validates stored Copilot tokens
                    |
3. AUTH DOC: Auto-detects matching authorization document
             Validates target is in scope, not expired
                    |
4. JOB CREATED: UUID assigned, 5 phases initialized
                    |
5. FOR EACH PHASE:
   a. AGENT SPAWN: Multiple agents spawned in parallel
   b. TOOL DISCOVERY: AI scans system for available tools
   c. STRATEGY PLANNING: AI plans which tools + args to use
   d. EXECUTION: Tools run against target
   e. AI ANALYSIS: Output sent to Copilot API for vuln extraction
   f. VULNS EXTRACTED: Structured findings with CVSS scores
   g. ADAPTIVE: AI decides if more tools needed based on findings
                    |
6. REPORT: Professional report generated with executive summary
                    |
7. DASHBOARD: Everything streams live to web UI
```

### AI Decision Making

The AI Tool Selector (`AIToolSelector`) is the autonomous brain:

1. **Tool Discovery**: Scans the system for 150+ tool binaries using `which` command
2. **Strategy Planning**: Sends discovered tools + target info to Copilot API, which returns a structured `AttackStrategy` with phases, tool recommendations, and success criteria
3. **Dynamic Execution**: Runs each recommended tool via `runDynamicScan()` — a universal method that can execute any CLI tool
4. **Output Analysis**: Tool output is sent to AI for vulnerability extraction in structured JSON format
5. **Adaptive Response**: After each phase, AI reviews findings and recommends additional tools to run
6. **Custom Tool Creation**: If no existing tool fits a need, AI generates a custom tool in any supported language

### AI Analysis Prompt

For each tool's output, the AI receives:
```
Analyze the following [tool] output from a [scanType] scan
on target [target] during [phase] phase.

Extract all security findings and return ONLY valid JSON:
{
  "vulnerabilities": [{
    "severity": "critical|high|medium|low|info",
    "title": "Brief vulnerability title",
    "description": "Detailed description",
    "cve": "CVE-ID if applicable",
    "cvss": numeric score,
    "evidence": "Key evidence from output",
    "remediation": "Recommended fix"
  }],
  "summary": "Brief summary"
}
```

---

## AI Models & Authentication

### How Authentication Works

Ryha uses the **GitHub Copilot Device Flow** — the same authentication used by VS Code:

1. `ryha auth login` sends a request to `https://github.com/login/device/code` with client ID `Iv1.b507a08c87ecfe98`
2. GitHub returns a one-time user code
3. You visit `https://github.com/login/device` and enter the code
4. Ryha polls until authorized, then receives a GitHub access token
5. The access token is exchanged for a Copilot session token via `https://api.github.com/copilot_internal/v2/token`
6. Both tokens are **AES-256-CBC encrypted** and stored at `~/.ryha/tokens.json` (mode 0600)
7. The encryption key is stored at `~/.ryha/.key` (mode 0600)

### Token Refresh

- Copilot tokens expire periodically
- `getValidToken()` auto-refreshes 5 minutes before expiry
- If refresh fails, re-authentication is required

### Available AI Models

| Model ID | Name | Provider | Use Case |
|----------|------|----------|----------|
| `claude-opus-4-6` | Claude Opus 4.6 | Anthropic | Deep analysis, strategy planning |
| `claude-3-5-sonnet-20241022` | Claude 3.5 Sonnet | Anthropic | General analysis (default) |
| `gpt-4o` | GPT-4o | OpenAI | Fast analysis |
| `gpt-4` | GPT-4 | OpenAI | Complex reasoning |
| `o1-preview` | o1 Preview | OpenAI | Advanced reasoning |

All models are accessed through the Copilot proxy at `https://api.githubcopilot.com/chat/completions`.

---

## Tool Management

### 18 Tool Categories

| Category | Examples | Count |
|----------|----------|-------|
| `recon` | nmap, masscan, amass, subfinder, theHarvester | 50+ |
| `scanner` | nikto, nuclei, OpenVAS, nessus, wpscan | 40+ |
| `exploit` | metasploit, sqlmap, searchsploit, routersploit | 20+ |
| `web` | burpsuite, zaproxy, dirb, gobuster, wfuzz | 40+ |
| `password` | john, hashcat, hydra, medusa, ophcrack | 20+ |
| `wireless` | aircrack-ng, wifite, kismet, reaver | 15+ |
| `sniffing` | wireshark, tcpdump, ettercap, bettercap | 15+ |
| `forensics` | autopsy, volatility, binwalk, foremost | 15+ |
| `reverse-engineering` | ghidra, radare2, gdb, objdump | 10+ |
| `cloud` | prowler, ScoutSuite, cloudsploit, pacu | 10+ |
| `mobile` | apktool, frida, objection, drozer | 10+ |
| `api` | postman, insomnia, arjun, graphqlmap | 10+ |
| `post-exploitation` | mimikatz, bloodhound, empire, covenant | 10+ |
| `social-engineering` | setoolkit, gophish, beef-xss | 5+ |
| `reporting` | cherrytree, dradis, faraday, pipal | 5+ |
| `voip` | sipvicious, voiphopper | 3+ |
| `hardware` | baudrate, flashrom | 3+ |
| `custom` | AI-generated tools | Dynamic |

### Tool Discovery

```bash
ryha tools list -i   # Shows all tools found on your system
```

Discovery scans for 150+ tool binaries using the `which` command and records:
- Tool name, path, version
- Category, capabilities
- Whether root is required

### GitHub Tool Installer

Install any security tool from GitHub:

```bash
# Install from known repos (auto-detect build system)
ryha tools github projectdiscovery/nuclei

# AI-powered search for tools
ryha tools github-search "web application fuzzer golang"

# List all known repos
ryha tools github-list
```

**Supported build systems**: Go, Python (pip/setup.py), Rust (cargo), Node.js (npm), Ruby (gem), Make, CMake, shell scripts.

**Known repositories** include 60+ pre-configured tools from:
- ProjectDiscovery (nuclei, httpx, subfinder, katana, naabu, dnsx, etc.)
- OWASP (ZAP, Amass, dependency-check)
- Individual tools (ffuf, gobuster, feroxbuster, massdns, etc.)

### Auto-Install (Cascading)

```bash
ryha tools ensure nuclei
```

This tries install methods in order:
1. `apt-get install` — Kali package manager
2. `pip install` — Python packages
3. `go install` — Go tools
4. GitHub known repos — pre-configured repos
5. AI GitHub search — asks Copilot to find the repo

### AI Tool Creator

```bash
ryha tools create
```

Interactive prompts:
- **Purpose**: What should the tool do?
- **Target type**: web / network / api / host
- **Language**: python, bash, ruby, perl, go
- **Template**: 10 options — port-scanner, web-fuzzer, credential-tester, api-enumerator, subdomain-finder, vulnerability-checker, network-sniffer, log-analyzer, hash-cracker, or custom

The AI generates a complete, functional security tool with:
- Proper error handling and argument parsing
- Network-safe defaults
- Output formatting
- Auto-registration in the tool database

---

## Phases of a Pentest

### Full Scan (5 Phases)

#### Phase 1: Recon

| Agent | Task |
|-------|------|
| DNS Enumeration | DNS records, subdomains, zone transfers |
| WHOIS & OSINT | WHOIS, email harvesting, social media footprinting |
| Service Discovery | Full port scan, service detection, OS fingerprinting |
| Technology Fingerprinting | CMS detection, framework identification, WAF detection |

#### Phase 2: Scanning

| Agent | Task |
|-------|------|
| Vulnerability Scanning | nuclei/nikto/OpenVAS for known CVEs |
| Web Application Scan | OWASP Top 10 — XSS, SQLi, CSRF, SSRF, LFI/RFI |
| Directory & File Discovery | Directory brute-force, hidden files, backup exposure |
| SSL/TLS & Network Scan | Cipher analysis, certificate validation, service audit |

#### Phase 3: Deep Analysis

| Agent | Task |
|-------|------|
| AI Vulnerability Analysis | CVSS scoring, attack chain detection, zero-day identification |
| Authentication Testing | Default credentials, brute force, session management |
| API Security Testing | Auth bypass, IDOR, rate limiting, GraphQL introspection |

#### Phase 4: Exploitation

| Agent | Task |
|-------|------|
| Exploit Verification | Safe PoC exploitation for critical/high findings |
| Privilege Escalation | Local/remote escalation paths, kernel exploits, misconfigs |

#### Phase 5: Post-Exploitation

| Agent | Task |
|-------|------|
| Data Exposure Assessment | Sensitive files, credentials, PII, database dumps |
| Lateral Movement Analysis | Network pivoting, trust relationships, shared credentials |

### Scan Type Variations

| Type | Phases Included | Use Case |
|------|-----------------|----------|
| `full` | All 5 phases | Complete assessment |
| `quick` | Recon + Scanning | Fast overview |
| `web` | All 5 (web-focused agents) | Web application testing |
| `network` | All 5 (network-focused agents) | Infrastructure testing |
| `compliance` | Recon + Scanning + Deep Analysis | Compliance check (no exploitation) |

---

## Agent System

### Agent Types

| Type | Role |
|------|------|
| `recon` | Reconnaissance and information gathering |
| `network-scanner` | Network vulnerability scanning |
| `web-scanner` | Web application security testing |
| `vuln-analyzer` | Deep vulnerability analysis with AI |
| `exploit-tester` | Safe exploitation verification |

### Agent Lifecycle

1. **Spawn**: Agent is created by the orchestrator with a specific task and target
2. **Running**: Agent executes tools, collects output, emits events
3. **Analysis**: Output is sent to Copilot AI for structured vulnerability extraction
4. **Completed/Failed**: Agent reports results back to the orchestrator

### Parallel Execution

- Agents within the same phase run **in parallel** (up to 10 concurrent)
- Phases execute **sequentially** (Phase 2 starts after Phase 1 completes)
- Agent timeout is 10 minutes (configurable)

---

## Authorization & Compliance

### Why Authorization Matters

Ryha enforces legal authorization before any scan:

1. Every pentest requires a valid authorization document
2. Target must be explicitly within the authorized scope
3. Out-of-scope targets are blocked
4. Expired authorizations are rejected
5. All validation attempts are audit-logged

### Authorization Document Fields

| Field | Description |
|-------|-------------|
| Client Name | Company or individual authorizing the test |
| Target Domain | Primary domain under test |
| In-Scope | Comma-separated targets (supports wildcards like `*.example.com` and CIDR like `10.0.0.0/24`) |
| Out-of-Scope | Explicitly excluded targets |
| Start Date | Authorization start |
| End Date | Authorization expiry |
| Testing Types | Which scan types are authorized (network, web, full, etc.) |
| Authorized By | Name of the authorizing person |
| Signature | Digital signature |
| Notes | Special instructions |

### Auto-Detection

When launching a pentest (CLI or web dashboard), Ryha auto-detects the matching authorization document:

1. Searches all saved docs for domain match (exact or in-scope pattern)
2. Falls back to any valid (non-expired) doc
3. Web dashboard auto-creates a new doc from the form data

### Audit Trail

All authorization checks are logged to `~/.ryha/audit-logs/`:
- `validation-audit.log` — every validation attempt with timestamp, target, result
- `errors.log` — validation failures only

---

## API Reference

The server exposes a REST API at `http://localhost:3000/api/`.

### Health

```
GET /api/health
Response: { success: true, status: "healthy", timestamp: 1234567890 }
```

### Authentication

```
GET /api/auth/status
Response: { success: true, authenticated: true }

POST /api/auth/start
Response: { success: true, message: "Authentication completed" }

GET /api/models
Response: { success: true, models: [...] }
```

### Scope / Authorization Documents

```
GET /api/scope
Response: { success: true, documents: [{ id, clientName, targetDomain, valid, daysRemaining, ... }] }

POST /api/scope
Body: { clientName, targetDomain, inScope, outOfScope, startDate, endDate, testingType, authorizedBy, signature, notes }
Response: { success: true, id: "<uuid>" }
```

### Pentest

```
POST /api/pentest
Body: { target, scanType, clientName, authorizedBy, inScope, outOfScope }
Response: { success: true, jobId: "<uuid>", authDocId: "<uuid>" }
```

Notes:
- If no matching auth doc exists, one is auto-created from the request body
- `scanType` options: `full`, `quick`, `web`, `network`, `compliance`

### Jobs

```
GET /api/jobs
Response: { success: true, jobs: [{ id, target, scanType, status, progress, currentPhase, vulnerabilityCount, startedAt }] }

GET /api/jobs/:id
Response: { success: true, job: { id, target, scanType, status, progress, phases: [...], vulnerabilities: [...] } }

POST /api/jobs/:id/stop
Response: { success: true }
```

### Terminal

```
GET /api/terminal?since=0
Response: { success: true, entries: [{ id, timestamp, type, agent, content }] }
```

Entry types: `command`, `stdout`, `stderr`, `info`, `success`, `error`, `agent`

### Tools

```
GET /api/tools
Response: { success: true, installed: 47, tools: [{ name, category, version, description }] }
```

### System

```
GET /api/system
Response: { success: true, platform, hostname, uptime, memory: { total, free }, cpus, user, version }
```

---

## Configuration

### Config File

Settings are managed via the CLI and stored locally:

```bash
ryha config set logLevel debug
ryha config set maxParallelAgents 6
ryha config get logLevel
ryha config list
```

### Key Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `logLevel` | `info` | Logging level: debug, info, warn, error |
| `maxParallelAgents` | `10` | Maximum concurrent agents per phase |
| `dataDir` | `~/.ryha` | Data storage directory |
| `reportsDir` | `~/.ryha/reports` | Report output directory |

### Data Storage

All data is stored under `~/.ryha/`:

```
~/.ryha/
  tokens.json              # Encrypted authentication tokens
  .key                     # AES-256 encryption key
  authorizations/          # Authorization documents (YAML)
  audit-logs/              # Validation audit logs
  reports/                 # Generated pentest reports
  tools/custom/            # AI-generated custom tools
  config.json              # User configuration
```

---

## Project Structure

```
ryha-security-flow/
  src/
    cli.ts                          # CLI entry point (9 commands)
    index.ts                        # Module exports
    auth-cli.ts                     # Auth CLI helpers
    api/
      server.ts                     # Express + Socket.IO server
    auth/
      copilot-auth.ts               # GitHub Copilot device flow auth
    compliance/
      auth-document.ts              # Authorization documents (YAML)
      auth-validator.ts             # Pre-scan validation + audit logging
      audit-logger.ts               # Audit log management
      compliance-types.ts           # Compliance type definitions
      validator.ts                  # Validation utilities
      index.ts                      # Compliance module exports
    config/
      config-manager.ts             # Configuration management
      kali-integration.ts           # Kali Linux integration
      index.ts                      # Config module exports
    executors/
      executor-agent.ts             # Root command execution, Metasploit
      index.ts                      # Executor module exports
    models/
      types.ts                      # Core type definitions
    orchestrator/
      orchestrator.ts               # Pentest job lifecycle + phase execution
      agent-pool.ts                 # Agent spawning and management
    reporters/
      reporter-agent.ts             # Report generation (HTML/PDF/Markdown)
      templates/
        html-template.ts            # HTML report template
      example.ts                    # Example report output
      index.ts                      # Reporter module exports
    scanners/
      scanner-agent.ts              # Tool execution wrapper
      tool-wrappers.ts              # Individual tool parsers (nmap, nikto, etc.)
    tools/
      ai-tool-selector.ts           # Autonomous AI tool selection + creation
      tool-manager.ts               # 300+ tool database + discovery
      github-installer.ts           # GitHub repository installer
    analyzers/
      analyzer-agent.ts             # Vulnerability analysis agent
      vuln-classifier.ts            # Vulnerability classification
    cli/
      config-commands.ts            # Config CLI subcommands
      setup-wizard.ts               # Setup wizard helpers
    ui/
      index.html                    # Web dashboard (vanilla JS/CSS)
  dist/                              # Compiled JavaScript output
  docs/                              # Documentation
  package.json
  tsconfig.json
```

---

## Examples

### Example 1: Full Pentest via Web Dashboard

```bash
# Start the server
ryha server

# Open http://localhost:3000
# Go to "New Pentest" tab
# Fill in:
#   Target: example.com
#   Scan Type: Full (All Phases)
#   Client: Acme Corp
#   Authorized By: John Doe
#   In-Scope: *.example.com, 10.0.0.0/24
#   Out-of-Scope: mail.example.com
# Click "Launch Pentest"
# Watch live progress on the Dashboard tab
```

### Example 2: Quick CLI Scan

```bash
# One-time setup (skip if already done)
ryha setup

# Run a quick scan
ryha pentest -d target.com -t quick

# Open dashboard to watch progress
ryha server
```

### Example 3: Web Application Test

```bash
ryha pentest -d webapp.example.com -t web
```

### Example 4: Network Infrastructure Scan

```bash
ryha pentest -d 192.168.1.0/24 -t network
```

### Example 5: Install Tools from GitHub

```bash
# Install nuclei (auto-detected Go build)
ryha tools github projectdiscovery/nuclei

# Search for a fuzzer
ryha tools github-search "http fuzzer golang"

# Auto-install with fallback methods
ryha tools ensure feroxbuster
```

### Example 6: Create a Custom Tool

```bash
ryha tools create
# Purpose: Scan for exposed .env files on web servers
# Target type: web
# Language: python
# Template: vulnerability-checker
# AI generates and saves the tool automatically
```

### Example 7: Generate a Report

```bash
# After a pentest completes, get the job ID from dashboard or terminal
ryha report abc123-def456 -f html
```

---

## Troubleshooting

### "Not authenticated"

```bash
ryha auth login
# Follow the device code instructions
```

### "No valid auth documents found"

```bash
ryha scope create
# Or run the full setup wizard:
ryha setup
```

### "Authorization has expired"

Create a new authorization document with a future end date:

```bash
ryha scope create
```

### "Target is not in authorized scope"

Edit your authorization document to include the target in the in-scope list. Alternatively, create a new auth doc that covers the target.

### Tool not found

```bash
# Check if it's installed
ryha tools info <tool-name>

# Auto-install with fallback
ryha tools ensure <tool-name>

# Or install from GitHub
ryha tools github <owner/repo>
```

### Web dashboard not loading

```bash
# Make sure the server is running
ryha server

# Check if port 3000 is in use
netstat -tlnp | grep 3000

# Use a different port
ryha server -p 8080
```

### TypeScript build errors

```bash
npm run build
# If errors, try:
npm install
npm run build
```

---

## License

MIT License. See [LICENSE](../LICENSE) for details.

**Important**: This tool is designed for authorized security testing only. Always ensure you have proper written authorization before conducting any penetration testing. Unauthorized access to computer systems is illegal.
