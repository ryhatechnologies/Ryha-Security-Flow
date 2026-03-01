"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PentestOrchestrator = void 0;
const events_1 = require("events");
const crypto_1 = require("crypto");
const copilot_auth_1 = require("../auth/copilot-auth");
const auth_validator_1 = require("../compliance/auth-validator");
const agent_pool_1 = require("./agent-pool");
const ai_tool_selector_1 = require("../tools/ai-tool-selector");
const scanner_agent_1 = require("../scanners/scanner-agent");
const tool_manager_1 = require("../tools/tool-manager");
class PentestOrchestrator extends events_1.EventEmitter {
    constructor() {
        super();
        this.jobs = new Map();
        this.maxConcurrentAgents = 10;
        this.agentPool = new agent_pool_1.AgentPool();
        this.copilotAuth = new copilot_auth_1.CopilotAuth();
        this.authValidator = new auth_validator_1.AuthValidator();
        this.toolManager = new tool_manager_1.ToolManager();
        this.aiSelector = new ai_tool_selector_1.AIToolSelector(this.toolManager);
        this.scanner = new scanner_agent_1.ScannerAgent({ verbose: true });
        // Listen to agent pool events
        this.agentPool.on('agent:output', (agentId, output) => {
            this.handleAgentOutput(agentId, output);
        });
        this.agentPool.on('agent:error', (agentId, error) => {
            this.handleAgentError(agentId, error);
        });
        // Listen to scanner events
        this.scanner.on('finding', (vuln) => {
            this.emit('scanner:finding', vuln);
        });
        this.scanner.on('output', (msg) => {
            this.emit('scanner:output', msg);
        });
    }
    /**
     * Start a new penetration test job
     */
    async startPentest(target, scanType, authDocId) {
        // Validate authorization document and target scope
        const authValidation = await this.authValidator.validateBeforeScan(authDocId, target, scanType);
        if (!authValidation.isValid) {
            throw new Error(`Authorization validation failed: ${authValidation.errors?.join(', ')}`);
        }
        // Create job
        const jobId = (0, crypto_1.randomUUID)();
        const job = {
            id: jobId,
            target,
            scanType,
            authDocId,
            status: 'pending',
            currentPhase: null,
            phases: this.initializePhases(scanType),
            startedAt: new Date(),
            completedAt: null,
            vulnerabilities: [],
            agents: [],
            progress: 0,
        };
        this.jobs.set(jobId, job);
        this.emit('job:created', jobId);
        // Start execution asynchronously
        this.executeJob(jobId).catch((error) => {
            this.handleJobError(jobId, error);
        });
        return jobId;
    }
    /**
     * Execute a pentest job through all phases
     */
    async executeJob(jobId) {
        const job = this.jobs.get(jobId);
        if (!job)
            throw new Error(`Job ${jobId} not found`);
        try {
            job.status = 'running';
            this.emit('job:started', jobId);
            // Execute phases sequentially
            for (const phase of job.phases) {
                job.currentPhase = phase.name;
                await this.executePhase(jobId, phase);
                // Check if job was stopped
                if (job.status === 'stopped') {
                    return;
                }
            }
            job.status = 'completed';
            job.completedAt = new Date();
            job.progress = 100;
            this.emit('job:complete', jobId, job.vulnerabilities);
        }
        catch (error) {
            this.handleJobError(jobId, error);
        }
    }
    /**
     * Execute a single phase with parallel agent execution
     */
    async executePhase(jobId, phase) {
        const job = this.jobs.get(jobId);
        if (!job)
            throw new Error(`Job ${jobId} not found`);
        phase.status = 'running';
        phase.startedAt = new Date();
        this.emit('phase:started', jobId, phase.name);
        try {
            // Execute all agents in this phase in parallel
            const agentPromises = phase.agents.map((agentTask) => this.executeAgentTask(jobId, phase, agentTask));
            await Promise.all(agentPromises);
            phase.status = 'completed';
            phase.completedAt = new Date();
            this.updateJobProgress(jobId);
            this.emit('phase:complete', jobId, phase.name, phase.findings);
        }
        catch (error) {
            phase.status = 'failed';
            phase.completedAt = new Date();
            throw error;
        }
    }
    /**
     * Execute a single agent task
     */
    async executeAgentTask(jobId, phase, agentTask) {
        const job = this.jobs.get(jobId);
        if (!job)
            throw new Error(`Job ${jobId} not found`);
        try {
            agentTask.status = 'running';
            // Spawn agent
            const agent = await this.agentPool.spawn(agentTask.agentType, {
                name: agentTask.name,
                target: job.target,
                phase: phase.name,
                scanType: job.scanType,
                prompt: agentTask.prompt,
            }, job.target);
            agentTask.agentId = agent.id;
            job.agents.push(agent.id);
            this.emit('agent:started', jobId, agent.id, agentTask.name);
            // Wait for agent to complete
            await this.waitForAgent(agent);
            // Get agent results
            const output = agent.findings.map((f) => f.data).join('\n');
            // Analyze output with Copilot API
            const analysis = await this.analyzeTool(agentTask.name, output, {
                target: job.target,
                phase: phase.name,
                scanType: job.scanType,
            });
            agentTask.result = analysis;
            agentTask.status = 'completed';
            // Extract vulnerabilities from analysis
            if (analysis.vulnerabilities && Array.isArray(analysis.vulnerabilities)) {
                for (const vuln of analysis.vulnerabilities) {
                    const vulnerability = {
                        id: (0, crypto_1.randomUUID)(),
                        severity: vuln.severity || 'info',
                        title: vuln.title || 'Unknown vulnerability',
                        description: vuln.description || '',
                        cve: vuln.cve,
                        cvss: vuln.cvss,
                        foundBy: agentTask.name,
                        foundAt: new Date(),
                        target: job.target,
                        evidence: vuln.evidence || output.substring(0, 500),
                        remediation: vuln.remediation || 'Review and patch affected systems',
                    };
                    job.vulnerabilities.push(vulnerability);
                    phase.findings++;
                    this.emit('vulnerability:found', jobId, vulnerability);
                }
            }
            this.emit('agent:completed', jobId, agent.id, agentTask.name, agentTask.result);
        }
        catch (error) {
            agentTask.status = 'failed';
            agentTask.error = error.message;
            this.emit('agent:failed', jobId, agentTask.agentId, agentTask.name, error);
            throw error;
        }
    }
    /**
     * Wait for agent to complete execution
     */
    async waitForAgent(agent) {
        return new Promise((resolve, reject) => {
            const checkInterval = setInterval(() => {
                if (agent.status === 'completed') {
                    clearInterval(checkInterval);
                    resolve();
                }
                else if (agent.status === 'failed') {
                    clearInterval(checkInterval);
                    reject(new Error(`Agent ${agent.id} failed`));
                }
            }, 1000);
            // Timeout after 10 minutes
            setTimeout(() => {
                clearInterval(checkInterval);
                reject(new Error(`Agent ${agent.id} timed out`));
            }, 600000);
        });
    }
    /**
     * Analyze tool output using Copilot API
     */
    async analyzeTool(tool, output, context) {
        try {
            // Get Copilot token
            const token = await this.copilotAuth.getValidToken();
            // Prepare analysis prompt
            const prompt = this.buildAnalysisPrompt(tool, output, context);
            // Call Copilot API
            const response = await fetch('https://api.githubcopilot.com/chat/completions', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    'Editor-Version': 'vscode/1.85.0',
                },
                body: JSON.stringify({
                    messages: [
                        {
                            role: 'system',
                            content: 'You are a cybersecurity expert analyzing penetration testing tool output. Extract vulnerabilities, severity levels, and remediation steps.',
                        },
                        {
                            role: 'user',
                            content: prompt,
                        },
                    ],
                    model: 'gpt-4',
                    temperature: 0.3,
                    max_tokens: 2000,
                }),
            });
            if (!response.ok) {
                throw new Error(`Copilot API error: ${response.statusText}`);
            }
            const data = await response.json();
            const content = data.choices?.[0]?.message?.content || '';
            // Parse JSON response from Copilot
            try {
                return JSON.parse(content);
            }
            catch {
                // If not JSON, return raw analysis
                return { raw: content, vulnerabilities: [] };
            }
        }
        catch (error) {
            console.error('Copilot analysis error:', error);
            return { error: error.message, vulnerabilities: [] };
        }
    }
    /**
     * Build analysis prompt for Copilot
     */
    buildAnalysisPrompt(tool, output, context) {
        return `Analyze the following ${tool} output from a ${context.scanType} scan on target ${context.target} during ${context.phase} phase.

Extract all security findings and return ONLY valid JSON in this exact format:
{
  "vulnerabilities": [
    {
      "severity": "critical|high|medium|low|info",
      "title": "Brief vulnerability title",
      "description": "Detailed description",
      "cve": "CVE-ID if applicable",
      "cvss": numeric score if available,
      "evidence": "Key evidence from output",
      "remediation": "Recommended fix"
    }
  ],
  "summary": "Brief summary of findings"
}

Tool Output:
${output.substring(0, 5000)}`;
    }
    /**
     * Get job status with real-time progress
     */
    getJobStatus(jobId) {
        return this.jobs.get(jobId) || null;
    }
    /**
     * Stop a running job gracefully
     */
    async stopJob(jobId) {
        const job = this.jobs.get(jobId);
        if (!job) {
            return false;
        }
        if (job.status !== 'running') {
            return false;
        }
        job.status = 'stopped';
        // Kill all agents for this job
        for (const agentId of job.agents) {
            await this.agentPool.kill(agentId);
        }
        this.emit('job:stopped', jobId);
        return true;
    }
    /**
     * Initialize phases based on scan type
     * Uses AI to dynamically plan attack strategy when possible
     */
    initializePhases(scanType) {
        // Default phases (used while AI strategy loads, or as fallback)
        const phases = [
            {
                name: 'Recon',
                status: 'pending',
                agents: [
                    { agentType: 'recon', name: 'DNS Enumeration', prompt: 'Enumerate DNS records, subdomains, zone transfers using all available recon tools', status: 'pending' },
                    { agentType: 'recon', name: 'WHOIS & OSINT', prompt: 'Gather WHOIS, OSINT, email harvesting, social media footprinting', status: 'pending' },
                    { agentType: 'recon', name: 'Service Discovery', prompt: 'Full port scan, service detection, OS fingerprinting, banner grabbing', status: 'pending' },
                    { agentType: 'recon', name: 'Technology Fingerprinting', prompt: 'Identify web technologies, CMS, frameworks, WAF detection', status: 'pending' },
                ],
                startedAt: null, completedAt: null, findings: 0,
            },
            {
                name: 'Scanning',
                status: 'pending',
                agents: [
                    { agentType: 'network-scanner', name: 'Vulnerability Scanning', prompt: 'Run nuclei/nikto/OpenVAS against all discovered services for known CVEs', status: 'pending' },
                    { agentType: 'web-scanner', name: 'Web Application Scan', prompt: 'Full web app scan - OWASP Top 10, XSS, SQLi, CSRF, SSRF, LFI/RFI, command injection', status: 'pending' },
                    { agentType: 'web-scanner', name: 'Directory & File Discovery', prompt: 'Directory brute-force, hidden files, backup files, source code exposure', status: 'pending' },
                    { agentType: 'network-scanner', name: 'SSL/TLS & Network Scan', prompt: 'SSL/TLS audit, cipher analysis, certificate validation, network service analysis', status: 'pending' },
                ],
                startedAt: null, completedAt: null, findings: 0,
            },
            {
                name: 'Deep Analysis',
                status: 'pending',
                agents: [
                    { agentType: 'vuln-analyzer', name: 'AI Vulnerability Analysis', prompt: 'Deep analysis of all findings - classify, score CVSS, identify attack chains, detect zero-days', status: 'pending' },
                    { agentType: 'vuln-analyzer', name: 'Authentication Testing', prompt: 'Test authentication mechanisms - default creds, brute force, session management, JWT/token analysis', status: 'pending' },
                    { agentType: 'vuln-analyzer', name: 'API Security Testing', prompt: 'Test API endpoints - auth bypass, IDOR, rate limiting, input validation, GraphQL introspection', status: 'pending' },
                ],
                startedAt: null, completedAt: null, findings: 0,
            },
            {
                name: 'Exploitation',
                status: 'pending',
                agents: [
                    { agentType: 'exploit-tester', name: 'Exploit Verification', prompt: 'Verify exploitability of critical and high findings with safe PoC exploitation', status: 'pending' },
                    { agentType: 'exploit-tester', name: 'Privilege Escalation', prompt: 'Test for privilege escalation paths - local and remote, kernel exploits, misconfigurations', status: 'pending' },
                ],
                startedAt: null, completedAt: null, findings: 0,
            },
            {
                name: 'Post-Exploitation',
                status: 'pending',
                agents: [
                    { agentType: 'exploit-tester', name: 'Data Exposure Assessment', prompt: 'Assess data exposure - sensitive files, credentials, PII, configuration files, database dumps', status: 'pending' },
                    { agentType: 'exploit-tester', name: 'Lateral Movement Analysis', prompt: 'Assess lateral movement potential - network pivoting, trust relationships, shared credentials', status: 'pending' },
                ],
                startedAt: null, completedAt: null, findings: 0,
            },
        ];
        // For quick scans, use fewer phases
        if (scanType === 'quick') {
            return phases.slice(0, 2);
        }
        // For compliance scans, skip exploitation
        if (scanType === 'compliance') {
            return phases.slice(0, 3);
        }
        return phases;
    }
    /**
     * Execute AI-driven autonomous scanning
     * The AI plans the complete strategy and dynamically executes tools
     */
    async executeAIStrategy(jobId, target, scanType, scope) {
        const job = this.jobs.get(jobId);
        if (!job)
            throw new Error(`Job ${jobId} not found`);
        this.emit('ai:planning', jobId, 'AI is planning attack strategy...');
        try {
            // Discover tools on the system first
            await this.aiSelector.discoverSystemTools();
            const installedTools = this.aiSelector.getInstalledToolsList();
            this.emit('ai:tools-discovered', jobId, installedTools.length);
            // Ask AI to plan the full attack strategy
            const strategy = await this.aiSelector.planAttackStrategy(target, scanType, scope);
            this.emit('ai:strategy-ready', jobId, strategy);
            // Execute each phase
            for (const phase of strategy.phases) {
                if (job.status === 'stopped')
                    return;
                this.emit('ai:phase-start', jobId, phase.name, phase.description);
                // Execute tools in the phase in parallel (within concurrency limit)
                const toolGroups = this.chunkArray(phase.tools, 3); // Max 3 tools at a time
                for (const group of toolGroups) {
                    const toolPromises = group.map(async (tool) => {
                        try {
                            this.emit('ai:tool-start', jobId, tool.toolName, tool.reason);
                            const result = await this.scanner.runDynamicScan(tool.toolName, tool.args, target, { timeout: tool.timeout, requiresRoot: tool.requiresRoot });
                            // Parse output with AI for structured findings
                            const rawOutput = result.metadata.stdout || result.metadata.stderr || '';
                            if (rawOutput.length > 0) {
                                const findings = await this.aiSelector.parseToolOutput(tool.toolName, rawOutput, target);
                                for (const finding of findings) {
                                    const vuln = {
                                        id: (0, crypto_1.randomUUID)(),
                                        severity: finding.severity || 'info',
                                        title: finding.title || `${tool.toolName} finding`,
                                        description: finding.description || '',
                                        cve: finding.cve,
                                        foundBy: tool.toolName,
                                        foundAt: new Date(),
                                        target,
                                        evidence: finding.evidence || rawOutput.substring(0, 500),
                                        remediation: finding.remediation || 'Review and remediate',
                                    };
                                    job.vulnerabilities.push(vuln);
                                    this.emit('vulnerability:found', jobId, vuln);
                                }
                            }
                            this.emit('ai:tool-complete', jobId, tool.toolName, result.status);
                            return result;
                        }
                        catch (err) {
                            this.emit('ai:tool-error', jobId, tool.toolName, err.message);
                            return null;
                        }
                    });
                    await Promise.all(toolPromises);
                }
                // After each phase, ask AI what to do next based on findings
                if (job.vulnerabilities.length > 0) {
                    const completedToolNames = phase.tools.map(t => t.toolName);
                    const lastOutput = ''; // Summarized from findings
                    const nextTools = await this.aiSelector.analyzeAndDecideNextSteps(phase.name, JSON.stringify(job.vulnerabilities.slice(-10)), target, phase.name, completedToolNames);
                    // Execute additional tools AI recommends
                    for (const tool of nextTools.slice(0, 3)) {
                        try {
                            this.emit('ai:adaptive-tool', jobId, tool.toolName, tool.reason);
                            await this.scanner.runDynamicScan(tool.toolName, tool.args, target, {
                                timeout: tool.timeout,
                                requiresRoot: tool.requiresRoot
                            });
                        }
                        catch (err) {
                            // Continue even if adaptive tool fails
                        }
                    }
                }
                this.emit('ai:phase-complete', jobId, phase.name);
            }
        }
        catch (error) {
            this.emit('ai:error', jobId, error.message);
            // Fall back to default execution
            console.log('[Orchestrator] AI strategy failed, falling back to default phases');
        }
    }
    /**
     * Split array into chunks
     */
    chunkArray(arr, size) {
        const chunks = [];
        for (let i = 0; i < arr.length; i += size) {
            chunks.push(arr.slice(i, i + size));
        }
        return chunks;
    }
    /**
     * Update job progress based on completed phases
     */
    updateJobProgress(jobId) {
        const job = this.jobs.get(jobId);
        if (!job)
            return;
        const completedPhases = job.phases.filter((p) => p.status === 'completed').length;
        job.progress = Math.round((completedPhases / job.phases.length) * 100);
    }
    /**
     * Handle agent output
     */
    handleAgentOutput(agentId, output) {
        // Find job containing this agent
        for (const [jobId, job] of this.jobs) {
            if (job.agents.includes(agentId)) {
                this.emit('agent:output', jobId, agentId, output);
                break;
            }
        }
    }
    /**
     * Handle agent error
     */
    handleAgentError(agentId, error) {
        for (const [jobId, job] of this.jobs) {
            if (job.agents.includes(agentId)) {
                this.emit('agent:error', jobId, agentId, error);
                break;
            }
        }
    }
    /**
     * Handle job error
     */
    handleJobError(jobId, error) {
        const job = this.jobs.get(jobId);
        if (!job)
            return;
        job.status = 'failed';
        job.error = error.message;
        job.completedAt = new Date();
        this.emit('job:failed', jobId, error);
    }
    /**
     * Get all active jobs
     */
    getActiveJobs() {
        return Array.from(this.jobs.values()).filter((job) => job.status === 'running' || job.status === 'pending');
    }
    /**
     * Clean up completed jobs older than 24 hours
     */
    async cleanup() {
        const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
        let cleaned = 0;
        for (const [jobId, job] of this.jobs) {
            if ((job.status === 'completed' || job.status === 'failed') &&
                job.completedAt &&
                job.completedAt < cutoff) {
                this.jobs.delete(jobId);
                cleaned++;
            }
        }
        return cleaned;
    }
}
exports.PentestOrchestrator = PentestOrchestrator;
//# sourceMappingURL=orchestrator.js.map