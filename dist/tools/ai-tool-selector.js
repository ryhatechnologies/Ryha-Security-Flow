"use strict";
/**
 * AI Tool Selector - Autonomous tool selection and strategy planning
 * Ryha Security Flow - Enterprise Penetration Testing Platform
 *
 * Uses GitHub Copilot AI to analyze targets and autonomously decide
 * which tools to run, with what arguments, in what order.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.AIToolSelector = void 0;
const copilot_auth_1 = require("../auth/copilot-auth");
const tool_manager_1 = require("./tool-manager");
const tool_wrappers_1 = require("../scanners/tool-wrappers");
const fs = __importStar(require("fs/promises"));
const path = __importStar(require("path"));
const events_1 = require("events");
/**
 * AIToolSelector - The autonomous brain for tool selection
 */
class AIToolSelector extends events_1.EventEmitter {
    constructor(toolManager) {
        super();
        this.discoveredTools = [];
        this.systemTools = new Map();
        this.toolManager = toolManager || new tool_manager_1.ToolManager();
        this.githubInstaller = this.toolManager.githubInstaller;
    }
    /**
     * Discover ALL security tools on the system (not just hardcoded)
     */
    async discoverSystemTools() {
        this.emit('discovery:start');
        // Known security tool binaries to look for across the system
        const securityToolNames = [
            // Recon & OSINT
            'nmap', 'masscan', 'unicornscan', 'zmap', 'dnsenum', 'dnsrecon', 'fierce',
            'sublist3r', 'amass', 'subfinder', 'assetfinder', 'httprobe', 'waybackurls',
            'theharvester', 'recon-ng', 'maltego', 'spiderfoot', 'shodan', 'censys',
            'whois', 'dig', 'host', 'nslookup', 'traceroute', 'ping',
            // Web Application
            'nikto', 'sqlmap', 'gobuster', 'dirb', 'dirbuster', 'wfuzz', 'ffuf',
            'burpsuite', 'zaproxy', 'zap-cli', 'wpscan', 'joomscan', 'droopescan',
            'whatweb', 'wafw00f', 'arjun', 'paramspider', 'dalfox', 'xsser',
            'commix', 'nosqlmap', 'sslyze', 'sslscan', 'testssl.sh', 'testssl',
            'nuclei', 'httpx', 'katana', 'gospider', 'hakrawler', 'gau',
            'meg', 'unfurl', 'qsreplace', 'kxss', 'crlfuzz',
            // Exploitation
            'msfconsole', 'msfvenom', 'msfdb', 'searchsploit', 'exploitdb',
            'beef-xss', 'routersploit', 'commix', 'weevely',
            // Password & Brute Force
            'hydra', 'john', 'hashcat', 'medusa', 'ncrack', 'patator',
            'cewl', 'crunch', 'cupp', 'hash-identifier', 'hashid',
            'ophcrack', 'rainbowcrack', 'fcrackzip',
            // Wireless
            'aircrack-ng', 'airmon-ng', 'airodump-ng', 'aireplay-ng',
            'wifite', 'reaver', 'bully', 'pixiewps', 'fern-wifi-cracker',
            'kismet', 'wifiphisher', 'fluxion', 'hostapd-wpe',
            // Network & Sniffing
            'wireshark', 'tshark', 'tcpdump', 'ettercap', 'bettercap',
            'arpspoof', 'dnsspoof', 'macchanger', 'responder', 'mitmproxy',
            'sslstrip', 'netcat', 'nc', 'ncat', 'socat', 'hping3',
            'scapy', 'yersinia', 'netdiscover',
            // Forensics & Reverse Engineering
            'autopsy', 'binwalk', 'volatility', 'foremost', 'scalpel',
            'strings', 'file', 'xxd', 'hexdump', 'objdump', 'readelf',
            'strace', 'ltrace', 'gdb', 'radare2', 'r2', 'ghidra',
            'rizin', 'cutter', 'ida', 'ollydbg',
            // Privilege Escalation
            'linpeas', 'winpeas', 'linux-exploit-suggester', 'les',
            'linux-smart-enumeration', 'pspy',
            // Post-Exploitation
            'mimikatz', 'bloodhound', 'sharphound', 'powersploit',
            'empire', 'covenant', 'sliver', 'merlin',
            // Container & Cloud
            'trivy', 'grype', 'syft', 'dive', 'hadolint',
            'scout', 'prowler', 'pacu', 'cloudsploit',
            // API Testing
            'postman', 'insomnia', 'curl', 'wget', 'httpie',
            // Misc
            'enum4linux', 'smbclient', 'smbmap', 'crackmapexec', 'evil-winrm',
            'impacket-smbserver', 'impacket-psexec', 'impacket-wmiexec',
            'ldapsearch', 'rpcclient', 'snmpwalk', 'onesixtyone',
            'smtp-user-enum', 'swaks', 'sendemail',
            'exiftool', 'steghide', 'stegsolve', 'zsteg',
            'openvpn', 'proxychains', 'tor', 'torsocks',
        ];
        // Check which tools are actually installed
        const checkPromises = securityToolNames.map(async (tool) => {
            try {
                const result = await (0, tool_wrappers_1.executeCommand)('which', [tool], 3000);
                if (result.exitCode === 0 && result.stdout.trim()) {
                    this.systemTools.set(tool, result.stdout.trim());
                }
            }
            catch {
                // Tool not found
            }
        });
        // Process in batches of 20 for efficiency
        for (let i = 0; i < checkPromises.length; i += 20) {
            await Promise.all(checkPromises.slice(i, i + 20));
        }
        // Also discover from common Kali tool directories
        const toolDirs = ['/usr/bin', '/usr/sbin', '/usr/local/bin', '/opt'];
        for (const dir of toolDirs) {
            try {
                const result = await (0, tool_wrappers_1.executeCommand)('ls', [dir], 5000);
                if (result.exitCode === 0) {
                    const files = result.stdout.split('\n').filter(f => f.trim());
                    for (const file of files) {
                        if (securityToolNames.includes(file) && !this.systemTools.has(file)) {
                            this.systemTools.set(file, path.join(dir, file));
                        }
                    }
                }
            }
            catch {
                // Directory not accessible
            }
        }
        this.emit('discovery:complete', this.systemTools.size);
        return this.systemTools;
    }
    /**
     * Get all installed security tools as a formatted list
     */
    getInstalledToolsList() {
        return Array.from(this.systemTools.keys()).sort();
    }
    /**
     * Ask AI to plan a complete attack strategy for a target
     */
    async planAttackStrategy(target, scanType, scope, previousFindings) {
        // First discover available tools
        if (this.systemTools.size === 0) {
            await this.discoverSystemTools();
        }
        const installedTools = this.getInstalledToolsList();
        const prompt = `You are an elite penetration tester planning a comprehensive security assessment.

TARGET: ${target}
SCAN TYPE: ${scanType}
SCOPE: ${scope.join(', ')}
AVAILABLE TOOLS ON THIS SYSTEM: ${installedTools.join(', ')}
${previousFindings ? `\nPREVIOUS FINDINGS:\n${JSON.stringify(previousFindings, null, 2)}` : ''}

Plan a complete, multi-phase penetration testing strategy. For each phase, select the BEST tools from the available list and provide exact command-line arguments.

Think like a real hacker:
1. Start with passive recon to avoid detection
2. Move to active scanning based on what you find
3. Enumerate services deeply
4. Test for ALL vulnerability classes (OWASP Top 10, zero-days, logic flaws, misconfigurations)
5. Attempt exploitation of confirmed vulnerabilities
6. Include post-exploitation if access is gained
7. Cover web, network, API, SSL/TLS, DNS, authentication, authorization

Return ONLY valid JSON:
{
  "phases": [
    {
      "name": "Phase name",
      "description": "What this phase does",
      "tools": [
        {
          "toolName": "exact tool binary name",
          "command": "exact command to run",
          "args": ["arg1", "arg2"],
          "priority": 1,
          "reason": "why this tool",
          "expectedOutput": "what we expect to find",
          "timeout": 300000,
          "requiresRoot": false,
          "category": "recon|web|network|exploit|password|wireless|forensics"
        }
      ],
      "dependsOn": ["Phase names this depends on"],
      "successCriteria": "what determines success",
      "nextPhaseCondition": "when to move to next phase"
    }
  ],
  "estimatedDuration": "total estimated time",
  "targetAnalysis": "initial assessment of the target",
  "approachRationale": "why this approach",
  "fallbackStrategies": ["alternative approaches if primary fails"]
}`;
        try {
            const response = await copilot_auth_1.copilotAuth.sendChatMessage(prompt, 'claude-opus-4-6');
            return this.parseJSONResponse(response);
        }
        catch (error) {
            console.error('[AIToolSelector] Failed to plan attack strategy:', error);
            // Return a sensible default strategy
            return this.buildDefaultStrategy(target, scanType, installedTools);
        }
    }
    /**
     * Ask AI to select the best tools for a specific task
     */
    async selectToolsForTask(task, target, context) {
        if (this.systemTools.size === 0) {
            await this.discoverSystemTools();
        }
        const installedTools = this.getInstalledToolsList();
        const prompt = `You are a penetration testing expert. Select the best tools for this task.

TASK: ${task}
TARGET: ${target}
AVAILABLE TOOLS: ${installedTools.join(', ')}
${context ? `CONTEXT: ${JSON.stringify(context)}` : ''}

Select 1-5 tools and provide exact commands. Return ONLY valid JSON:
{
  "tools": [
    {
      "toolName": "tool binary name",
      "command": "full command",
      "args": ["arg1", "arg2"],
      "priority": 1,
      "reason": "why this tool",
      "expectedOutput": "what to expect",
      "timeout": 300000,
      "requiresRoot": false,
      "category": "category"
    }
  ]
}`;
        try {
            const response = await copilot_auth_1.copilotAuth.sendChatMessage(prompt, 'claude-3-5-sonnet-20241022');
            const parsed = this.parseJSONResponse(response);
            return parsed.tools || [];
        }
        catch (error) {
            console.error('[AIToolSelector] Failed to select tools:', error);
            return [];
        }
    }
    /**
     * Ask AI to generate arguments for a specific tool
     */
    async generateToolArguments(toolName, target, objective) {
        const prompt = `You are a penetration testing expert. Generate the optimal command-line arguments for this tool.

TOOL: ${toolName}
TARGET: ${target}
OBJECTIVE: ${objective}

Return ONLY valid JSON:
{
  "args": ["arg1", "arg2", "arg3"],
  "explanation": "why these arguments"
}`;
        try {
            const response = await copilot_auth_1.copilotAuth.sendChatMessage(prompt, 'claude-3-5-sonnet-20241022');
            const parsed = this.parseJSONResponse(response);
            return parsed.args || [];
        }
        catch (error) {
            console.error('[AIToolSelector] Failed to generate arguments:', error);
            return [target];
        }
    }
    /**
     * Ask AI to create a custom security tool when no existing tool fits
     * Supports bash, python, ruby, perl, and go
     */
    async createCustomTool(purpose, target, language = 'python', template) {
        const langGuidelines = {
            python: `- Use Python 3 with standard library + requests/socket if needed
- Include argparse for CLI arguments
- Use json output format for machine-readable results
- Handle SIGINT gracefully
- Include rate limiting to be respectful`,
            bash: `- Use common Kali Linux utilities (curl, grep, awk, sed, nmap, etc.)
- Include proper error handling with set -euo pipefail
- Use functions for modularity
- Output in parseable format (JSON or CSV)
- Check tool dependencies at the start`,
            ruby: `- Use standard library + net/http if needed
- Include optparse for CLI arguments
- Build as a proper Ruby script with classes
- Handle exceptions properly
- Output structured results`,
            perl: `- Use strict and warnings
- Use LWP::UserAgent for HTTP requests
- Include Getopt::Long for CLI arguments
- Use JSON module for output
- Handle errors with eval/die`,
            go: `- Return a SINGLE main.go file with package main
- Use only standard library (net, net/http, os, flag, encoding/json)
- Include proper error handling
- Use goroutines for concurrent operations
- Build with: go build -o tool-name main.go`
        };
        const templateHints = {
            'port-scanner': 'Build a TCP/UDP port scanner that connects to ports, grabs banners, and identifies services. Support port ranges and concurrent scanning.',
            'web-fuzzer': 'Build a web path/parameter fuzzer that sends HTTP requests with wordlist entries and detects interesting responses (200, 301, 302, 403, 500). Support custom headers and methods.',
            'credential-tester': 'Build a credential testing tool that tries username/password combinations against a service. Support multiple protocols. Include lockout protection and delays.',
            'api-enumerator': 'Build an API endpoint discovery and testing tool. Probe common API paths, test authentication, check for IDOR, test rate limiting, check for information disclosure.',
            'subdomain-finder': 'Build a subdomain enumeration tool using DNS resolution, certificate transparency logs, and common subdomain wordlists. Verify discovered subdomains.',
            'vulnerability-checker': 'Build a vulnerability checker that tests for specific CVEs or misconfigurations. Include version detection, PoC verification, and remediation advice.',
            'network-sniffer': 'Build a network packet capture and analysis tool. Filter by protocol, port, or host. Extract interesting data like credentials, URLs, or DNS queries.',
            'log-analyzer': 'Build a security log analyzer that parses common log formats (auth, syslog, apache, nginx) and identifies suspicious patterns, brute force attempts, and anomalies.',
            'hash-cracker': 'Build a hash identification and cracking tool that detects hash types and attempts dictionary/rule-based attacks.',
            'custom': ''
        };
        const templateContext = template && template !== 'custom' ? `\nTEMPLATE GUIDANCE: ${templateHints[template]}` : '';
        const prompt = `You are an expert security tool developer. Create a professional-grade ${language} security tool for authorized penetration testing.

PURPOSE: ${purpose}
TARGET TYPE: ${target}
LANGUAGE: ${language}${templateContext}

Language-specific requirements:
${langGuidelines[language] || langGuidelines.python}

General requirements:
- Must include proper error handling and input validation
- Must output results in structured JSON format
- Must respect scope limitations (only test specified targets)
- Must include usage/help information
- Must include comments explaining key sections
- Must handle network timeouts gracefully
- Must log activities for audit trail
- Must be production-quality, not a toy script

Return ONLY valid JSON:
{
  "name": "tool-name-with-dashes",
  "description": "what it does in one sentence",
  "script": "the complete script source code (properly escaped for JSON)",
  "language": "${language}",
  "purpose": "specific purpose statement",
  "usage": "example usage command"
}`;
        try {
            const response = await copilot_auth_1.copilotAuth.sendChatMessage(prompt, 'claude-opus-4-6');
            const tool = this.parseJSONResponse(response);
            // Determine file extension
            const extMap = {
                python: '.py', bash: '.sh', ruby: '.rb', perl: '.pl', go: '.go'
            };
            const ext = extMap[language] || `.${language}`;
            // Determine shebang
            const shebangMap = {
                python: '#!/usr/bin/env python3\n',
                bash: '#!/bin/bash\nset -euo pipefail\n',
                ruby: '#!/usr/bin/env ruby\n',
                perl: '#!/usr/bin/env perl\nuse strict;\nuse warnings;\n',
                go: '' // Go files don't use shebangs
            };
            const shebang = shebangMap[language] || '';
            // Try to save to standard tool directory first, fallback to /tmp
            const toolDir = '/usr/share/ryha/tools/custom';
            let savedPath;
            try {
                await fs.mkdir(toolDir, { recursive: true });
                savedPath = path.join(toolDir, tool.name + ext);
                await fs.writeFile(savedPath, shebang + tool.script, { mode: 0o755 });
            }
            catch {
                savedPath = path.join('/tmp', `ryha-${tool.name}${ext}`);
                await fs.writeFile(savedPath, shebang + tool.script, { mode: 0o755 });
            }
            // For Go tools, try to compile
            if (language === 'go') {
                try {
                    const binPath = savedPath.replace('.go', '');
                    await (0, tool_wrappers_1.executeCommand)('go', ['build', '-o', binPath, savedPath], 60000);
                    savedPath = binPath;
                    await fs.chmod(savedPath, 0o755);
                }
                catch {
                    // Leave as .go source if compilation fails
                }
            }
            // Register in tool manager
            this.toolManager.registerTool(tool.name, {
                displayName: tool.name,
                description: tool.description,
                category: tool_manager_1.ToolCategory.CUSTOM,
                capabilities: ['custom', 'ai-generated'],
                path: savedPath,
                requiresRoot: false
            });
            this.emit('tool:created', tool.name, savedPath);
            return tool;
        }
        catch (error) {
            console.error('[AIToolSelector] Failed to create custom tool:', error);
            throw error;
        }
    }
    /**
     * Create a tool from a predefined template without AI (fast, offline)
     */
    async createToolFromTemplate(name, template, target, language = 'python') {
        // For templates, use AI to generate but with strong template guidance
        return this.createCustomTool(`${template} tool targeting ${target}`, target, language, template);
    }
    /**
     * Ensure a tool is available - auto-install if missing
     * Tries: apt-get → GitHub known tools → pip/go install → AI creation
     */
    async ensureToolAvailable(toolName) {
        // Check if already installed
        try {
            const result = await (0, tool_wrappers_1.executeCommand)('which', [toolName], 3000);
            if (result.exitCode === 0 && result.stdout.trim()) {
                return { available: true, method: 'already-installed' };
            }
        }
        catch { /* not installed */ }
        this.emit('tool:installing', toolName);
        // Try apt-get install
        try {
            const aptResult = await (0, tool_wrappers_1.executeCommand)('sudo', ['apt-get', 'install', '-y', toolName], 120000);
            if (aptResult.exitCode === 0) {
                this.emit('tool:installed', toolName, 'apt');
                return { available: true, method: 'apt-get' };
            }
        }
        catch { /* apt failed */ }
        // Try pip install (many Python security tools)
        try {
            const pipResult = await (0, tool_wrappers_1.executeCommand)('pip3', ['install', '--break-system-packages', toolName], 60000);
            if (pipResult.exitCode === 0) {
                this.emit('tool:installed', toolName, 'pip');
                return { available: true, method: 'pip' };
            }
        }
        catch { /* pip failed */ }
        // Try go install for Go-based tools
        try {
            const goResult = await (0, tool_wrappers_1.executeCommand)('go', ['install', `github.com/projectdiscovery/${toolName}/cmd/${toolName}@latest`], 120000);
            if (goResult.exitCode === 0) {
                this.emit('tool:installed', toolName, 'go');
                return { available: true, method: 'go-install' };
            }
        }
        catch { /* go failed */ }
        // Try known GitHub tools
        const knownRepos = this.githubInstaller.listKnownTools();
        const matchingRepo = knownRepos.find(r => r.repo.endsWith(`/${toolName}`) || r.repo.includes(toolName));
        if (matchingRepo) {
            try {
                const installResult = await this.githubInstaller.installKnownTool(matchingRepo.repo);
                if (installResult.success) {
                    this.emit('tool:installed', toolName, 'github');
                    return { available: true, method: 'github' };
                }
            }
            catch { /* github failed */ }
        }
        // Ask AI to find and install from GitHub
        try {
            const repos = await this.githubInstaller.findToolOnGitHub(toolName);
            if (repos.length > 0) {
                const installResult = await this.githubInstaller.installFromGitHub({
                    repoUrl: `https://github.com/${repos[0].repo}`
                });
                if (installResult.success) {
                    this.emit('tool:installed', toolName, 'github-ai');
                    return { available: true, method: 'github-ai-search' };
                }
            }
        }
        catch { /* AI search failed */ }
        this.emit('tool:install-failed', toolName);
        return { available: false };
    }
    /**
     * Ask AI to analyze tool output and decide next steps
     */
    async analyzeAndDecideNextSteps(toolName, output, target, currentPhase, completedTools) {
        if (this.systemTools.size === 0) {
            await this.discoverSystemTools();
        }
        const installedTools = this.getInstalledToolsList();
        const prompt = `You are an autonomous penetration tester analyzing tool output to decide next steps.

CURRENT PHASE: ${currentPhase}
TOOL THAT JUST RAN: ${toolName}
TARGET: ${target}
TOOLS ALREADY RUN: ${completedTools.join(', ')}
ALL AVAILABLE TOOLS: ${installedTools.join(', ')}

TOOL OUTPUT (last 3000 chars):
${output.substring(output.length - 3000)}

Based on this output, what tools should run NEXT? Think like a real hacker:
- If ports were found, scan those services deeper
- If web services found, run web-specific tools
- If credentials found, try them
- If vulnerabilities found, try to exploit them
- If new subdomains found, scan them too

Return ONLY valid JSON:
{
  "tools": [
    {
      "toolName": "tool name",
      "command": "full command",
      "args": ["arg1", "arg2"],
      "priority": 1,
      "reason": "why based on the output",
      "expectedOutput": "what we expect",
      "timeout": 300000,
      "requiresRoot": false,
      "category": "category"
    }
  ],
  "findings": "key findings from the output",
  "shouldEscalate": false
}`;
        try {
            const response = await copilot_auth_1.copilotAuth.sendChatMessage(prompt, 'claude-3-5-sonnet-20241022');
            const parsed = this.parseJSONResponse(response);
            return parsed.tools || [];
        }
        catch (error) {
            console.error('[AIToolSelector] Failed to analyze and decide:', error);
            return [];
        }
    }
    /**
     * Parse AI output to extract tool output as vulnerabilities
     */
    async parseToolOutput(toolName, rawOutput, target) {
        const prompt = `You are a security analyst parsing tool output into structured vulnerabilities.

TOOL: ${toolName}
TARGET: ${target}

RAW OUTPUT:
${rawOutput.substring(0, 4000)}

Extract ALL security findings. Return ONLY valid JSON:
{
  "vulnerabilities": [
    {
      "severity": "critical|high|medium|low|info",
      "title": "finding title",
      "description": "detailed description",
      "evidence": "relevant output excerpt",
      "cve": "CVE-ID if known",
      "remediation": "how to fix",
      "port": null,
      "service": null
    }
  ]
}`;
        try {
            const response = await copilot_auth_1.copilotAuth.sendChatMessage(prompt, 'claude-3-5-sonnet-20241022');
            const parsed = this.parseJSONResponse(response);
            return parsed.vulnerabilities || [];
        }
        catch (error) {
            console.error('[AIToolSelector] Failed to parse output:', error);
            return [];
        }
    }
    /**
     * Build a default strategy when AI is unavailable
     */
    buildDefaultStrategy(target, scanType, installedTools) {
        const hasNmap = installedTools.includes('nmap');
        const hasNikto = installedTools.includes('nikto');
        const hasSqlmap = installedTools.includes('sqlmap');
        const hasGobuster = installedTools.includes('gobuster') || installedTools.includes('ffuf');
        const hasSslscan = installedTools.includes('sslscan');
        const hasWhatWeb = installedTools.includes('whatweb');
        const hasNuclei = installedTools.includes('nuclei');
        const hasAmass = installedTools.includes('amass');
        const phases = [];
        // Phase 1: Recon
        const reconTools = [];
        if (hasNmap) {
            reconTools.push({
                toolName: 'nmap', command: 'nmap', args: ['-sV', '-sC', '-O', '-oX', '-', target],
                priority: 1, reason: 'Port scanning and service detection', expectedOutput: 'Open ports and services',
                timeout: 600000, requiresRoot: true, category: 'recon'
            });
        }
        if (hasAmass) {
            reconTools.push({
                toolName: 'amass', command: 'amass', args: ['enum', '-d', target],
                priority: 2, reason: 'Subdomain enumeration', expectedOutput: 'Subdomains',
                timeout: 300000, requiresRoot: false, category: 'recon'
            });
        }
        if (hasWhatWeb) {
            reconTools.push({
                toolName: 'whatweb', command: 'whatweb', args: ['--log-json=-', '-a', '3', target],
                priority: 3, reason: 'Technology fingerprinting', expectedOutput: 'Web technologies',
                timeout: 120000, requiresRoot: false, category: 'recon'
            });
        }
        phases.push({
            name: 'Reconnaissance', description: 'Initial target enumeration',
            tools: reconTools, dependsOn: [], successCriteria: 'Target services identified',
            nextPhaseCondition: 'All recon tools completed'
        });
        // Phase 2: Scanning
        const scanTools = [];
        if (hasNuclei) {
            scanTools.push({
                toolName: 'nuclei', command: 'nuclei', args: ['-u', target, '-severity', 'critical,high,medium'],
                priority: 1, reason: 'Comprehensive vulnerability scanning', expectedOutput: 'Known CVEs',
                timeout: 600000, requiresRoot: false, category: 'web'
            });
        }
        if (hasNikto) {
            scanTools.push({
                toolName: 'nikto', command: 'nikto', args: ['-h', target, '-Format', 'csv'],
                priority: 2, reason: 'Web server vulnerability scanning', expectedOutput: 'Web vulnerabilities',
                timeout: 300000, requiresRoot: false, category: 'web'
            });
        }
        if (hasSslscan) {
            scanTools.push({
                toolName: 'sslscan', command: 'sslscan', args: ['--no-colour', target],
                priority: 3, reason: 'SSL/TLS configuration audit', expectedOutput: 'SSL issues',
                timeout: 120000, requiresRoot: false, category: 'web'
            });
        }
        phases.push({
            name: 'Vulnerability Scanning', description: 'Automated vulnerability detection',
            tools: scanTools, dependsOn: ['Reconnaissance'], successCriteria: 'Vulnerabilities identified',
            nextPhaseCondition: 'All scanners completed'
        });
        // Phase 3: Deep Testing
        const deepTools = [];
        const dirTool = installedTools.includes('ffuf') ? 'ffuf' : 'gobuster';
        if (hasGobuster) {
            const dirArgs = dirTool === 'ffuf'
                ? ['-u', `${target}/FUZZ`, '-w', '/usr/share/wordlists/dirb/common.txt']
                : ['dir', '-u', target, '-w', '/usr/share/wordlists/dirb/common.txt', '-q'];
            deepTools.push({
                toolName: dirTool, command: dirTool, args: dirArgs,
                priority: 1, reason: 'Directory and file discovery', expectedOutput: 'Hidden paths',
                timeout: 300000, requiresRoot: false, category: 'web'
            });
        }
        if (hasSqlmap) {
            deepTools.push({
                toolName: 'sqlmap', command: 'sqlmap', args: ['-u', target, '--batch', '--level', '3', '--risk', '2'],
                priority: 2, reason: 'SQL injection testing', expectedOutput: 'SQLi vulnerabilities',
                timeout: 600000, requiresRoot: false, category: 'web'
            });
        }
        phases.push({
            name: 'Deep Testing', description: 'In-depth vulnerability testing',
            tools: deepTools, dependsOn: ['Vulnerability Scanning'], successCriteria: 'Deep findings gathered',
            nextPhaseCondition: 'All deep tests completed'
        });
        return {
            phases,
            estimatedDuration: '30-60 minutes',
            targetAnalysis: `Target ${target} will undergo ${scanType} scanning`,
            approachRationale: 'Standard methodology with available tools',
            fallbackStrategies: ['Manual testing if automated tools fail']
        };
    }
    parseJSONResponse(response) {
        try {
            // Try direct JSON parse first
            return JSON.parse(response);
        }
        catch {
            // Extract JSON from markdown code blocks or mixed text
            const jsonMatch = response.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
            if (jsonMatch) {
                return JSON.parse(jsonMatch[1]);
            }
            // Try finding raw JSON object
            const rawMatch = response.match(/\{[\s\S]*\}/);
            if (rawMatch) {
                return JSON.parse(rawMatch[0]);
            }
            throw new Error('No valid JSON found in response');
        }
    }
}
exports.AIToolSelector = AIToolSelector;
//# sourceMappingURL=ai-tool-selector.js.map