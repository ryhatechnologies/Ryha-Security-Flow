"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AgentPool = void 0;
const events_1 = require("events");
const child_process_1 = require("child_process");
const crypto_1 = require("crypto");
class AgentPool extends events_1.EventEmitter {
    constructor() {
        super();
        this.agents = new Map();
        this.startTime = new Date();
        this.taskCompletionTimes = [];
        this.maxAgents = 50;
    }
    /**
     * Spawn a new agent to execute a task
     */
    async spawn(agentType, task, target) {
        // Check agent limit
        if (this.agents.size >= this.maxAgents) {
            throw new Error(`Agent pool limit reached (${this.maxAgents})`);
        }
        // Create agent
        const agent = {
            id: (0, crypto_1.randomUUID)(),
            name: task.name,
            type: agentType,
            status: 'running',
            currentTask: task,
            progress: 0,
            findings: [],
            startedAt: new Date(),
            completedAt: null,
        };
        this.agents.set(agent.id, agent);
        this.emit('agent:spawned', agent.id, agentType);
        // Execute agent task asynchronously
        this.executeAgent(agent, target).catch((error) => {
            this.handleAgentError(agent.id, error);
        });
        return agent;
    }
    /**
     * Execute agent task by running appropriate security tools
     */
    async executeAgent(agent, target) {
        try {
            const toolConfig = this.getToolConfig(agent.type, target, agent.currentTask);
            // Spawn process
            const process = (0, child_process_1.spawn)(toolConfig.command, toolConfig.args, {
                shell: true,
                stdio: ['pipe', 'pipe', 'pipe'],
            });
            agent.process = process;
            // Handle stdout
            process.stdout?.on('data', (data) => {
                const output = data.toString();
                this.handleAgentOutput(agent.id, output);
            });
            // Handle stderr
            process.stderr?.on('data', (data) => {
                const error = data.toString();
                this.handleAgentOutput(agent.id, error);
            });
            // Handle process completion
            await new Promise((resolve, reject) => {
                const timeout = setTimeout(() => {
                    process.kill('SIGTERM');
                    reject(new Error(`Agent ${agent.id} timed out after ${toolConfig.timeout}ms`));
                }, toolConfig.timeout);
                process.on('close', (code) => {
                    clearTimeout(timeout);
                    if (code === 0) {
                        resolve();
                    }
                    else {
                        reject(new Error(`Process exited with code ${code}`));
                    }
                });
                process.on('error', (error) => {
                    clearTimeout(timeout);
                    reject(error);
                });
            });
            // Mark agent as completed
            agent.status = 'completed';
            agent.completedAt = new Date();
            agent.progress = 100;
            const duration = agent.completedAt.getTime() - agent.startedAt.getTime();
            this.taskCompletionTimes.push(duration);
            this.emit('agent:completed', agent.id);
        }
        catch (error) {
            this.handleAgentError(agent.id, error);
            throw error;
        }
    }
    /**
     * Get tool configuration based on agent type
     */
    getToolConfig(agentType, target, task) {
        const sanitizedTarget = this.sanitizeTarget(target);
        switch (agentType) {
            case 'recon':
                if (task.name.includes('DNS')) {
                    return {
                        command: 'nslookup',
                        args: [sanitizedTarget],
                        timeout: 30000,
                    };
                }
                else if (task.name.includes('WHOIS')) {
                    return {
                        command: 'whois',
                        args: [sanitizedTarget],
                        timeout: 30000,
                    };
                }
                else {
                    // Service discovery with nmap
                    return {
                        command: 'nmap',
                        args: ['-sV', '-p', '80,443,22,21,25,3306,5432', sanitizedTarget],
                        timeout: 120000,
                    };
                }
            case 'network-scanner':
                return {
                    command: 'nmap',
                    args: ['-sS', '-sV', '-O', '-p-', '--max-retries', '2', sanitizedTarget],
                    timeout: 300000,
                };
            case 'web-scanner':
                return {
                    command: 'nikto',
                    args: ['-h', sanitizedTarget, '-Format', 'json', '-o', '/tmp/nikto-output.json'],
                    timeout: 600000,
                };
            case 'vuln-analyzer':
                return {
                    command: 'nmap',
                    args: ['--script', 'vuln', '-p', '1-10000', sanitizedTarget],
                    timeout: 600000,
                };
            case 'exploit-tester':
                // Use Metasploit framework (safe mode)
                return {
                    command: 'msfconsole',
                    args: [
                        '-q',
                        '-x',
                        `use auxiliary/scanner/http/http_version; set RHOSTS ${sanitizedTarget}; run; exit`,
                    ],
                    timeout: 300000,
                };
            case 'reporter':
                return {
                    command: 'echo',
                    args: [`Generating report for ${sanitizedTarget}`],
                    timeout: 10000,
                };
            default:
                throw new Error(`Unknown agent type: ${agentType}`);
        }
    }
    /**
     * Sanitize target to prevent command injection
     */
    sanitizeTarget(target) {
        // Remove dangerous characters
        const sanitized = target.replace(/[;&|`$(){}[\]<>]/g, '');
        // Validate format (IP or domain)
        const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
        const domainPattern = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        if (!ipPattern.test(sanitized) && !domainPattern.test(sanitized)) {
            throw new Error(`Invalid target format: ${target}`);
        }
        return sanitized;
    }
    /**
     * Handle agent output
     */
    handleAgentOutput(agentId, output) {
        const agent = this.agents.get(agentId);
        if (!agent)
            return;
        // Parse output for findings
        const finding = {
            timestamp: new Date(),
            type: this.classifyOutput(output),
            data: output.trim(),
        };
        agent.findings.push(finding);
        // Update progress based on output patterns
        if (output.includes('completed') || output.includes('finished')) {
            agent.progress = 100;
        }
        else if (output.includes('processing') || output.includes('scanning')) {
            agent.progress = Math.min(agent.progress + 10, 90);
        }
        this.emit('agent:output', agentId, output);
    }
    /**
     * Classify output type
     */
    classifyOutput(output) {
        const lowerOutput = output.toLowerCase();
        if (lowerOutput.includes('vulnerability') ||
            lowerOutput.includes('exploit') ||
            lowerOutput.includes('cve-')) {
            return 'vulnerability';
        }
        else if (lowerOutput.includes('warning') ||
            lowerOutput.includes('deprecated') ||
            lowerOutput.includes('weak')) {
            return 'warning';
        }
        return 'info';
    }
    /**
     * Handle agent error
     */
    handleAgentError(agentId, error) {
        const agent = this.agents.get(agentId);
        if (!agent)
            return;
        agent.status = 'failed';
        agent.error = error.message;
        agent.completedAt = new Date();
        if (agent.process) {
            agent.process.kill('SIGTERM');
        }
        this.emit('agent:error', agentId, error);
    }
    /**
     * Get all active agents
     */
    getActive() {
        return Array.from(this.agents.values()).filter((agent) => agent.status === 'running');
    }
    /**
     * Get agent by ID
     */
    getAgent(agentId) {
        return this.agents.get(agentId) || null;
    }
    /**
     * Kill a specific agent
     */
    async kill(agentId) {
        const agent = this.agents.get(agentId);
        if (!agent)
            return false;
        if (agent.process) {
            agent.process.kill('SIGTERM');
            // Force kill after 5 seconds if still running
            setTimeout(() => {
                if (agent.process && !agent.process.killed) {
                    agent.process.kill('SIGKILL');
                }
            }, 5000);
        }
        agent.status = 'stopped';
        agent.completedAt = new Date();
        this.emit('agent:killed', agentId);
        return true;
    }
    /**
     * Kill all agents
     */
    async killAll() {
        const activeAgents = this.getActive();
        let killed = 0;
        for (const agent of activeAgents) {
            const success = await this.kill(agent.id);
            if (success)
                killed++;
        }
        this.emit('pool:cleared', killed);
        return killed;
    }
    /**
     * Get pool metrics
     */
    getMetrics() {
        const agents = Array.from(this.agents.values());
        const agentsByType = {
            recon: 0,
            'network-scanner': 0,
            'web-scanner': 0,
            'vuln-analyzer': 0,
            'exploit-tester': 0,
            reporter: 0,
        };
        let totalVulns = 0;
        for (const agent of agents) {
            agentsByType[agent.type]++;
            totalVulns += agent.findings.filter((f) => f.type === 'vulnerability').length;
        }
        const completedAgents = agents.filter((a) => a.status === 'completed');
        const averageTaskDuration = this.taskCompletionTimes.length > 0
            ? this.taskCompletionTimes.reduce((a, b) => a + b, 0) / this.taskCompletionTimes.length
            : 0;
        return {
            totalAgents: this.agents.size,
            activeAgents: this.getActive().length,
            completedAgents: completedAgents.length,
            failedAgents: agents.filter((a) => a.status === 'failed').length,
            totalTasksCompleted: completedAgents.length,
            totalVulnerabilitiesFound: totalVulns,
            averageTaskDuration: Math.round(averageTaskDuration),
            uptime: Date.now() - this.startTime.getTime(),
            agentsByType,
        };
    }
    /**
     * Get agent pool size
     */
    getSize() {
        return this.agents.size;
    }
    /**
     * Clean up completed agents
     */
    cleanup() {
        let cleaned = 0;
        for (const [agentId, agent] of this.agents) {
            if (agent.status === 'completed' || agent.status === 'failed') {
                this.agents.delete(agentId);
                cleaned++;
            }
        }
        return cleaned;
    }
    /**
     * Check if specific tool is available
     */
    checkToolAvailability(tool) {
        try {
            (0, child_process_1.execSync)(`which ${tool}`, { stdio: 'ignore' });
            return true;
        }
        catch {
            return false;
        }
    }
    /**
     * Get all required tools for agent types
     */
    getRequiredTools() {
        return {
            recon: ['nslookup', 'whois', 'nmap'],
            'network-scanner': ['nmap'],
            'web-scanner': ['nikto'],
            'vuln-analyzer': ['nmap'],
            'exploit-tester': ['msfconsole'],
            reporter: ['echo'],
        };
    }
    /**
     * Validate all required tools are installed
     */
    validateTools() {
        const missing = [];
        const requiredTools = this.getRequiredTools();
        const uniqueTools = new Set();
        Object.values(requiredTools).forEach((tools) => {
            tools.forEach((tool) => uniqueTools.add(tool));
        });
        for (const tool of uniqueTools) {
            if (!this.checkToolAvailability(tool)) {
                missing.push(tool);
            }
        }
        return {
            valid: missing.length === 0,
            missing,
        };
    }
}
exports.AgentPool = AgentPool;
//# sourceMappingURL=agent-pool.js.map