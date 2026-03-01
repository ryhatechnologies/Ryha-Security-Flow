"use strict";
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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.RyhaServer = void 0;
const express_1 = __importDefault(require("express"));
const socket_io_1 = require("socket.io");
const http_1 = require("http");
const path = __importStar(require("path"));
const fs = __importStar(require("fs"));
const os = __importStar(require("os"));
const copilot_auth_1 = require("../auth/copilot-auth");
const auth_document_1 = require("../compliance/auth-document");
const auth_validator_1 = require("../compliance/auth-validator");
const orchestrator_1 = require("../orchestrator/orchestrator");
const tool_manager_1 = require("../tools/tool-manager");
class RyhaServer {
    constructor(port = 3000) {
        this.terminalLog = [];
        this.terminalId = 0;
        this.activeJobId = null;
        this.activeModel = 'claude-3-5-sonnet-20241022';
        this.summaries = [];
        this.summaryId = 0;
        this.summaryInterval = null;
        this.agentTerminals = new Map();
        this.app = (0, express_1.default)();
        this.server = (0, http_1.createServer)(this.app);
        this.io = new socket_io_1.Server(this.server, { cors: { origin: '*', methods: ['GET', 'POST'] } });
        this.port = port;
        this.orchestrator = new orchestrator_1.PentestOrchestrator();
        this.toolManager = new tool_manager_1.ToolManager();
        this.authValidator = new auth_validator_1.AuthValidator();
        this.setupMiddleware();
        this.setupRoutes();
        this.setupSocketIO();
        this.setupOrchestratorEvents();
    }
    addTerminalEntry(type, content, agent) {
        const entry = { id: ++this.terminalId, timestamp: Date.now(), type, content, agent };
        this.terminalLog.push(entry);
        if (this.terminalLog.length > 5000)
            this.terminalLog.splice(0, 1000);
        this.io.emit('terminal:entry', entry);
        // Track per-agent terminal output
        if (agent) {
            if (!this.agentTerminals.has(agent))
                this.agentTerminals.set(agent, []);
            const agentLog = this.agentTerminals.get(agent);
            agentLog.push(entry);
            if (agentLog.length > 1000)
                agentLog.splice(0, 200);
        }
    }
    addSummary(text) {
        const summary = { id: ++this.summaryId, timestamp: Date.now(), text };
        this.summaries.push(summary);
        if (this.summaries.length > 200)
            this.summaries.splice(0, 50);
        this.io.emit('summary:generated', { summary: text, timestamp: summary.timestamp });
    }
    startAutoSummary(intervalMinutes = 15) {
        if (this.summaryInterval)
            clearInterval(this.summaryInterval);
        this.summaryInterval = setInterval(() => {
            if (!this.activeJobId)
                return;
            const job = this.orchestrator.getJobStatus(this.activeJobId);
            if (!job)
                return;
            const activeAgents = job.phases.reduce((count, p) => count + (p.agents?.filter((a) => a.status === 'working').length || 0), 0);
            const completedPhases = job.phases.filter((p) => p.status === 'completed').length;
            const text = `Auto Summary: ${job.vulnerabilities.length} vulns found. ${activeAgents} agents active. ${completedPhases}/${job.phases.length} phases complete. Progress: ${job.progress || 0}%.`;
            this.addSummary(text);
        }, intervalMinutes * 60 * 1000);
    }
    setupOrchestratorEvents() {
        this.orchestrator.on('job:created', (jobId) => {
            this.addTerminalEntry('info', `Job created: ${jobId}`);
            this.io.emit('job:created', jobId);
        });
        this.orchestrator.on('job:started', (jobId) => {
            this.addTerminalEntry('success', `Pentest started: ${jobId}`);
            this.io.emit('job:started', jobId);
            this.startAutoSummary();
        });
        this.orchestrator.on('phase:started', (jobId, phase) => {
            this.addTerminalEntry('info', `Phase started: ${phase}`, 'orchestrator');
            this.io.emit('phase:started', { jobId, phase });
        });
        this.orchestrator.on('phase:complete', (jobId, phase, findings) => {
            this.addTerminalEntry('success', `Phase complete: ${phase} (${findings} findings)`, 'orchestrator');
            this.io.emit('phase:complete', { jobId, phase, findings });
        });
        this.orchestrator.on('agent:started', (jobId, agentId, name) => {
            this.addTerminalEntry('agent', `Agent spawned: ${name}`, name);
            this.io.emit('agent:started', { jobId, agentId, name });
        });
        this.orchestrator.on('agent:completed', (jobId, agentId, name) => {
            this.addTerminalEntry('success', `Agent completed: ${name}`, name);
            this.io.emit('agent:completed', { jobId, agentId, name });
        });
        this.orchestrator.on('agent:failed', (jobId, agentId, name, error) => {
            this.addTerminalEntry('error', `Agent failed: ${name} - ${error?.message || error}`, name);
            this.io.emit('agent:failed', { jobId, agentId, name, error: error?.message });
        });
        this.orchestrator.on('agent:output', (jobId, agentId, output) => {
            this.addTerminalEntry('stdout', output, agentId);
        });
        this.orchestrator.on('vulnerability:found', (jobId, vuln) => {
            this.addTerminalEntry('info', `[${vuln.severity.toUpperCase()}] ${vuln.title}`, vuln.foundBy);
            this.io.emit('vulnerability:found', { jobId, vulnerability: vuln });
        });
        this.orchestrator.on('job:complete', (jobId, vulns) => {
            this.addTerminalEntry('success', `Pentest complete! ${vulns.length} vulnerabilities found.`);
            this.io.emit('job:complete', { jobId, vulnerabilityCount: vulns.length });
            this.addSummary(`Pentest completed. ${vulns.length} total vulnerabilities discovered.`);
            if (this.summaryInterval)
                clearInterval(this.summaryInterval);
        });
        this.orchestrator.on('job:failed', (jobId, error) => {
            this.addTerminalEntry('error', `Pentest failed: ${error.message}`);
            this.io.emit('job:failed', { jobId, error: error.message });
            if (this.summaryInterval)
                clearInterval(this.summaryInterval);
        });
        // AI strategy events
        this.orchestrator.on('ai:planning', (jobId, msg) => {
            this.addTerminalEntry('info', msg, 'AI Planner');
        });
        this.orchestrator.on('ai:tools-discovered', (jobId, count) => {
            this.addTerminalEntry('success', `Discovered ${count} tools on system`, 'AI Planner');
        });
        this.orchestrator.on('ai:strategy-ready', (jobId, strategy) => {
            this.addTerminalEntry('success', `Attack strategy ready: ${strategy.phases?.length || 0} phases planned`, 'AI Planner');
        });
        this.orchestrator.on('ai:tool-start', (jobId, tool, reason) => {
            this.addTerminalEntry('command', `Running: ${tool} — ${reason}`, tool);
        });
        this.orchestrator.on('ai:tool-complete', (jobId, tool, status) => {
            this.addTerminalEntry('success', `${tool} completed (${status})`, tool);
        });
        this.orchestrator.on('ai:tool-error', (jobId, tool, err) => {
            this.addTerminalEntry('error', `${tool} failed: ${err}`, tool);
        });
        this.orchestrator.on('ai:adaptive-tool', (jobId, tool, reason) => {
            this.addTerminalEntry('info', `AI adaptive: running ${tool} — ${reason}`, 'AI Planner');
        });
        this.orchestrator.on('scanner:output', (msg) => {
            this.addTerminalEntry('stdout', msg, 'scanner');
        });
        this.orchestrator.on('scanner:finding', (vuln) => {
            this.addTerminalEntry('info', `Scanner finding: ${vuln.title || JSON.stringify(vuln)}`, 'scanner');
        });
    }
    setupMiddleware() {
        this.app.use(express_1.default.json());
        this.app.use(express_1.default.static(path.join(__dirname, '../ui')));
        this.app.use((req, res, next) => {
            res.header('Access-Control-Allow-Origin', '*');
            res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
            res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
            if (req.method === 'OPTIONS')
                return res.sendStatus(200);
            next();
        });
    }
    setupRoutes() {
        // Health
        this.app.get('/api/health', (req, res) => {
            res.json({ success: true, status: 'healthy', timestamp: Date.now(), model: this.activeModel });
        });
        // Auth status
        this.app.get('/api/auth/status', async (req, res) => {
            try {
                const authenticated = await copilot_auth_1.copilotAuth.isAuthenticated();
                res.json({ success: true, authenticated });
            }
            catch (error) {
                res.status(500).json({ success: false, error: error.message });
            }
        });
        // Auth start (device flow)
        this.app.post('/api/auth/start', async (req, res) => {
            try {
                await copilot_auth_1.copilotAuth.authenticate();
                res.json({ success: true, message: 'Authentication completed' });
            }
            catch (error) {
                res.status(500).json({ success: false, error: error.message });
            }
        });
        // Models
        this.app.get('/api/models', (req, res) => {
            res.json({ success: true, models: copilot_auth_1.copilotAuth.getAvailableModels(), activeModel: this.activeModel });
        });
        this.app.get('/api/models/current', (req, res) => {
            res.json({ success: true, model: this.activeModel });
        });
        this.app.post('/api/models/switch', (req, res) => {
            const { model } = req.body;
            const available = ['claude-opus-4-6', 'claude-3-5-sonnet-20241022', 'gpt-4o', 'gpt-4', 'o1-preview'];
            if (!model || !available.includes(model)) {
                return res.status(400).json({ success: false, error: 'Invalid model. Available: ' + available.join(', ') });
            }
            this.activeModel = model;
            this.addTerminalEntry('info', `AI model switched to: ${model}`);
            this.io.emit('model:switched', { model });
            res.json({ success: true, model });
        });
        // Scope / Auth documents
        this.app.get('/api/scope', (req, res) => {
            const ids = auth_document_1.AuthDocument.listAll();
            const docs = ids.map(id => {
                const doc = auth_document_1.AuthDocument.load(id);
                if (!doc)
                    return null;
                return { id: doc.id, clientName: doc.clientName, targetDomain: doc.targetDomain, startDate: doc.startDate, endDate: doc.endDate, testingType: doc.testingType, valid: doc.isValid(), daysRemaining: doc.getDaysRemaining(), inScope: doc.inScope, outOfScope: doc.outOfScope, authorizedBy: doc.authorizedBy };
            }).filter(Boolean);
            res.json({ success: true, documents: docs });
        });
        this.app.post('/api/scope', (req, res) => {
            try {
                const { clientName, targetDomain, inScope, outOfScope, startDate, endDate, testingType, authorizedBy, signature, notes } = req.body;
                const doc = new auth_document_1.AuthDocument(clientName, targetDomain, inScope || [targetDomain], outOfScope || [], new Date(startDate || Date.now()), new Date(endDate || Date.now() + 30 * 24 * 60 * 60 * 1000), testingType || ['full'], authorizedBy || 'web-ui', signature || 'digital-signature', notes || '');
                doc.save();
                res.json({ success: true, id: doc.id });
            }
            catch (error) {
                res.status(400).json({ success: false, error: error.message });
            }
        });
        // Start pentest from web UI
        this.app.post('/api/pentest', async (req, res) => {
            try {
                const { target, scanType, authDocId, inScope, clientName, authorizedBy } = req.body;
                if (!target)
                    return res.status(400).json({ success: false, error: 'Target is required' });
                let finalAuthDocId = authDocId;
                if (!finalAuthDocId) {
                    const ids = auth_document_1.AuthDocument.listAll();
                    const validDoc = ids.map(id => auth_document_1.AuthDocument.load(id)).find(d => d && d.isValid() && (d.targetDomain === target || d.inScope.some((s) => target.includes(s))));
                    if (validDoc) {
                        finalAuthDocId = validDoc.id;
                    }
                    else {
                        const doc = new auth_document_1.AuthDocument(clientName || 'Web Pentest', target, inScope || [target], [], new Date(), new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), [scanType || 'full'], authorizedBy || 'web-ui', 'web-digital-signature');
                        doc.save();
                        finalAuthDocId = doc.id;
                        this.addTerminalEntry('info', `Auto-created auth doc: ${doc.id.substring(0, 8)}...`);
                    }
                }
                this.agentTerminals.clear();
                const jobId = await this.orchestrator.startPentest(target, scanType || 'full', finalAuthDocId);
                this.activeJobId = jobId;
                this.addTerminalEntry('success', `Pentest launched on ${target} (${scanType || 'full'} scan, model: ${this.activeModel})`);
                res.json({ success: true, jobId, authDocId: finalAuthDocId });
            }
            catch (error) {
                res.status(500).json({ success: false, error: error.message });
            }
        });
        // Get job status
        this.app.get('/api/jobs', (req, res) => {
            const jobs = this.orchestrator.getActiveJobs();
            res.json({ success: true, jobs: jobs.map(j => ({ id: j.id, target: j.target, scanType: j.scanType, status: j.status, progress: j.progress, currentPhase: j.currentPhase, vulnerabilityCount: j.vulnerabilities.length, startedAt: j.startedAt })) });
        });
        this.app.get('/api/jobs/:id', (req, res) => {
            const job = this.orchestrator.getJobStatus(req.params.id);
            if (!job)
                return res.status(404).json({ success: false, error: 'Job not found' });
            res.json({ success: true, job: { id: job.id, target: job.target, scanType: job.scanType, status: job.status, progress: job.progress, currentPhase: job.currentPhase, phases: job.phases.map(p => ({ name: p.name, status: p.status, findings: p.findings, agents: p.agents.map(a => ({ name: a.name, status: a.status })) })), vulnerabilities: job.vulnerabilities, startedAt: job.startedAt, completedAt: job.completedAt } });
        });
        // Stop job
        this.app.post('/api/jobs/:id/stop', async (req, res) => {
            const stopped = await this.orchestrator.stopJob(req.params.id);
            res.json({ success: stopped });
        });
        // Terminal log
        this.app.get('/api/terminal', (req, res) => {
            const since = parseInt(req.query.since) || 0;
            const entries = this.terminalLog.filter(e => e.id > since);
            res.json({ success: true, entries });
        });
        // Per-agent terminal
        this.app.get('/api/agents/:id/terminal', (req, res) => {
            const agentId = req.params.id;
            const entries = this.agentTerminals.get(agentId) || [];
            res.json({ success: true, agentId, entries });
        });
        // Tools
        this.app.get('/api/tools', async (req, res) => {
            const installed = await this.toolManager.discoverTools();
            res.json({ success: true, installed: installed.length, tools: installed.map(t => ({ name: t.name, category: t.category, version: t.version, description: t.description })) });
        });
        // Create custom tool
        this.app.post('/api/tools/create', async (req, res) => {
            try {
                const { name, category, language, description, purpose } = req.body;
                if (!name || !purpose) {
                    return res.status(400).json({ success: false, error: 'Name and purpose are required' });
                }
                this.addTerminalEntry('info', `Creating custom tool: ${name} (${language || 'python'})`, 'Tool Creator');
                const toolDir = path.join(os.homedir(), '.ryha', 'custom-tools');
                if (!fs.existsSync(toolDir))
                    fs.mkdirSync(toolDir, { recursive: true });
                const ext = language === 'bash' ? 'sh' : language === 'ruby' ? 'rb' : language === 'perl' ? 'pl' : language === 'go' ? 'go' : language === 'nodejs' ? 'js' : 'py';
                const toolPath = path.join(toolDir, `${name}.${ext}`);
                // Generate a basic tool template
                let content = '';
                if (language === 'bash') {
                    content = `#!/bin/bash\n# ${name} - ${description || purpose}\n# Auto-generated by Ryha Security Flow\n\necho "[*] ${name} - ${description || 'Custom security tool'}"\necho "[*] Purpose: ${purpose}"\necho "[*] Running..."\n\n# TODO: Implement tool logic\necho "[+] ${name} complete"\n`;
                }
                else if (language === 'nodejs') {
                    content = `#!/usr/bin/env node\n// ${name} - ${description || purpose}\n// Auto-generated by Ryha Security Flow\n\nconsole.log('[*] ${name} - ${description || "Custom security tool"}');\nconsole.log('[*] Purpose: ${purpose}');\nconsole.log('[*] Running...');\n\n// TODO: Implement tool logic\nconsole.log('[+] ${name} complete');\n`;
                }
                else {
                    content = `#!/usr/bin/env python3\n"""${name} - ${description || purpose}\nAuto-generated by Ryha Security Flow\n"""\nimport sys\nimport argparse\n\ndef main():\n    print(f"[*] ${name} - ${description || 'Custom security tool'}")\n    print(f"[*] Purpose: ${purpose}")\n    print("[*] Running...")\n    \n    # TODO: Implement tool logic\n    \n    print("[+] ${name} complete")\n\nif __name__ == "__main__":\n    main()\n`;
                }
                fs.writeFileSync(toolPath, content, { mode: 0o755 });
                this.addTerminalEntry('success', `Custom tool created: ${toolPath}`, 'Tool Creator');
                res.json({ success: true, name, path: toolPath, language: language || 'python' });
            }
            catch (error) {
                res.status(500).json({ success: false, error: error.message });
            }
        });
        // Summaries
        this.app.get('/api/summaries', (req, res) => {
            res.json({ success: true, summaries: this.summaries });
        });
        this.app.get('/api/summaries/latest', (req, res) => {
            const latest = this.summaries.length > 0 ? this.summaries[this.summaries.length - 1] : null;
            res.json({ success: true, summary: latest });
        });
        // System info
        this.app.get('/api/system', (req, res) => {
            res.json({
                success: true,
                platform: os.platform(),
                hostname: os.hostname(),
                uptime: os.uptime(),
                memory: { total: os.totalmem(), free: os.freemem() },
                cpus: os.cpus().length,
                user: os.userInfo().username,
                version: '1.0.0',
                activeModel: this.activeModel,
                activeJob: this.activeJobId
            });
        });
        // Serve UI
        this.app.get('*', (req, res) => {
            res.sendFile(path.join(__dirname, '../ui/index.html'));
        });
    }
    setupSocketIO() {
        this.io.on('connection', socket => {
            socket.emit('terminal:history', this.terminalLog.slice(-200));
            const jobs = this.orchestrator.getActiveJobs();
            if (jobs.length > 0)
                socket.emit('jobs:state', jobs);
            socket.emit('model:current', { model: this.activeModel });
            socket.on('disconnect', () => { });
        });
    }
    start() {
        this.server.listen(this.port, () => {
            console.log(`\n  Ryha Security Flow Dashboard`);
            console.log(`  ────────────────────────────`);
            console.log(`  Dashboard:  http://localhost:${this.port}`);
            console.log(`  API:        http://localhost:${this.port}/api`);
            console.log(`  Health:     http://localhost:${this.port}/api/health`);
            console.log(`  Model:      ${this.activeModel}\n`);
        });
    }
}
exports.RyhaServer = RyhaServer;
if (require.main === module) {
    new RyhaServer(3000).start();
}
//# sourceMappingURL=server.js.map