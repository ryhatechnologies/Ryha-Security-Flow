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
    }
    setupOrchestratorEvents() {
        this.orchestrator.on('job:created', (jobId) => {
            this.addTerminalEntry('info', `Job created: ${jobId}`);
            this.io.emit('job:created', jobId);
        });
        this.orchestrator.on('job:started', (jobId) => {
            this.addTerminalEntry('success', `Pentest started: ${jobId}`);
            this.io.emit('job:started', jobId);
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
        });
        this.orchestrator.on('job:failed', (jobId, error) => {
            this.addTerminalEntry('error', `Pentest failed: ${error.message}`);
            this.io.emit('job:failed', { jobId, error: error.message });
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
            res.json({ success: true, status: 'healthy', timestamp: Date.now() });
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
            res.json({ success: true, models: copilot_auth_1.copilotAuth.getAvailableModels() });
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
                // Auto-find or create auth doc
                let finalAuthDocId = authDocId;
                if (!finalAuthDocId) {
                    const ids = auth_document_1.AuthDocument.listAll();
                    const validDoc = ids.map(id => auth_document_1.AuthDocument.load(id)).find(d => d && d.isValid() && (d.targetDomain === target || d.inScope.some((s) => target.includes(s))));
                    if (validDoc) {
                        finalAuthDocId = validDoc.id;
                    }
                    else {
                        // Auto-create auth doc from form data
                        const doc = new auth_document_1.AuthDocument(clientName || 'Web Pentest', target, inScope || [target], [], new Date(), new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), [scanType || 'full'], authorizedBy || 'web-ui', 'web-digital-signature');
                        doc.save();
                        finalAuthDocId = doc.id;
                        this.addTerminalEntry('info', `Auto-created auth doc: ${doc.id.substring(0, 8)}...`);
                    }
                }
                const jobId = await this.orchestrator.startPentest(target, scanType || 'full', finalAuthDocId);
                this.activeJobId = jobId;
                this.addTerminalEntry('success', `Pentest launched on ${target} (${scanType || 'full'} scan)`);
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
        // Tools
        this.app.get('/api/tools', async (req, res) => {
            const installed = await this.toolManager.discoverTools();
            res.json({ success: true, installed: installed.length, tools: installed.map(t => ({ name: t.name, category: t.category, version: t.version, description: t.description })) });
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
                version: '1.0.0'
            });
        });
        // Serve UI
        this.app.get('*', (req, res) => {
            res.sendFile(path.join(__dirname, '../ui/index.html'));
        });
    }
    setupSocketIO() {
        this.io.on('connection', socket => {
            // Send current state
            socket.emit('terminal:history', this.terminalLog.slice(-200));
            const jobs = this.orchestrator.getActiveJobs();
            if (jobs.length > 0)
                socket.emit('jobs:state', jobs);
            socket.on('disconnect', () => { });
        });
    }
    start() {
        this.server.listen(this.port, () => {
            console.log(`\n  Ryha Security Flow Dashboard`);
            console.log(`  ────────────────────────────`);
            console.log(`  Dashboard:  http://localhost:${this.port}`);
            console.log(`  API:        http://localhost:${this.port}/api`);
            console.log(`  Health:     http://localhost:${this.port}/api/health\n`);
        });
    }
}
exports.RyhaServer = RyhaServer;
if (require.main === module) {
    new RyhaServer(3000).start();
}
//# sourceMappingURL=server.js.map