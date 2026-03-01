import express, { Request, Response } from 'express';
import { Server as SocketIOServer } from 'socket.io';
import { createServer } from 'http';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { copilotAuth } from '../auth/copilot-auth';
import { AuthDocument, TestingType } from '../compliance/auth-document';
import { AuthValidator } from '../compliance/auth-validator';
import { PentestOrchestrator } from '../orchestrator/orchestrator';
import { ToolManager } from '../tools/tool-manager';

interface TerminalEntry {
  id: number;
  timestamp: number;
  type: 'command' | 'stdout' | 'stderr' | 'info' | 'success' | 'error' | 'agent';
  agent?: string;
  content: string;
}

class RyhaServer {
  private app: express.Application;
  private server: any;
  private io: SocketIOServer;
  private port: number;
  private orchestrator: PentestOrchestrator;
  private toolManager: ToolManager;
  private authValidator: AuthValidator;
  private terminalLog: TerminalEntry[] = [];
  private terminalId = 0;
  private activeJobId: string | null = null;

  constructor(port: number = 3000) {
    this.app = express();
    this.server = createServer(this.app);
    this.io = new SocketIOServer(this.server, { cors: { origin: '*', methods: ['GET', 'POST'] } });
    this.port = port;
    this.orchestrator = new PentestOrchestrator();
    this.toolManager = new ToolManager();
    this.authValidator = new AuthValidator();

    this.setupMiddleware();
    this.setupRoutes();
    this.setupSocketIO();
    this.setupOrchestratorEvents();
  }

  private addTerminalEntry(type: TerminalEntry['type'], content: string, agent?: string): void {
    const entry: TerminalEntry = { id: ++this.terminalId, timestamp: Date.now(), type, content, agent };
    this.terminalLog.push(entry);
    if (this.terminalLog.length > 5000) this.terminalLog.splice(0, 1000);
    this.io.emit('terminal:entry', entry);
  }

  private setupOrchestratorEvents(): void {
    this.orchestrator.on('job:created', (jobId: string) => {
      this.addTerminalEntry('info', `Job created: ${jobId}`);
      this.io.emit('job:created', jobId);
    });
    this.orchestrator.on('job:started', (jobId: string) => {
      this.addTerminalEntry('success', `Pentest started: ${jobId}`);
      this.io.emit('job:started', jobId);
    });
    this.orchestrator.on('phase:started', (jobId: string, phase: string) => {
      this.addTerminalEntry('info', `Phase started: ${phase}`, 'orchestrator');
      this.io.emit('phase:started', { jobId, phase });
    });
    this.orchestrator.on('phase:complete', (jobId: string, phase: string, findings: number) => {
      this.addTerminalEntry('success', `Phase complete: ${phase} (${findings} findings)`, 'orchestrator');
      this.io.emit('phase:complete', { jobId, phase, findings });
    });
    this.orchestrator.on('agent:started', (jobId: string, agentId: string, name: string) => {
      this.addTerminalEntry('agent', `Agent spawned: ${name}`, name);
      this.io.emit('agent:started', { jobId, agentId, name });
    });
    this.orchestrator.on('agent:completed', (jobId: string, agentId: string, name: string) => {
      this.addTerminalEntry('success', `Agent completed: ${name}`, name);
      this.io.emit('agent:completed', { jobId, agentId, name });
    });
    this.orchestrator.on('agent:failed', (jobId: string, agentId: string, name: string, error: any) => {
      this.addTerminalEntry('error', `Agent failed: ${name} - ${error?.message || error}`, name);
      this.io.emit('agent:failed', { jobId, agentId, name, error: error?.message });
    });
    this.orchestrator.on('agent:output', (jobId: string, agentId: string, output: string) => {
      this.addTerminalEntry('stdout', output, agentId);
    });
    this.orchestrator.on('vulnerability:found', (jobId: string, vuln: any) => {
      this.addTerminalEntry('info', `[${vuln.severity.toUpperCase()}] ${vuln.title}`, vuln.foundBy);
      this.io.emit('vulnerability:found', { jobId, vulnerability: vuln });
    });
    this.orchestrator.on('job:complete', (jobId: string, vulns: any[]) => {
      this.addTerminalEntry('success', `Pentest complete! ${vulns.length} vulnerabilities found.`);
      this.io.emit('job:complete', { jobId, vulnerabilityCount: vulns.length });
    });
    this.orchestrator.on('job:failed', (jobId: string, error: Error) => {
      this.addTerminalEntry('error', `Pentest failed: ${error.message}`);
      this.io.emit('job:failed', { jobId, error: error.message });
    });

    // AI strategy events
    this.orchestrator.on('ai:planning', (jobId: string, msg: string) => {
      this.addTerminalEntry('info', msg, 'AI Planner');
    });
    this.orchestrator.on('ai:tools-discovered', (jobId: string, count: number) => {
      this.addTerminalEntry('success', `Discovered ${count} tools on system`, 'AI Planner');
    });
    this.orchestrator.on('ai:strategy-ready', (jobId: string, strategy: any) => {
      this.addTerminalEntry('success', `Attack strategy ready: ${strategy.phases?.length || 0} phases planned`, 'AI Planner');
    });
    this.orchestrator.on('ai:tool-start', (jobId: string, tool: string, reason: string) => {
      this.addTerminalEntry('command', `Running: ${tool} — ${reason}`, tool);
    });
    this.orchestrator.on('ai:tool-complete', (jobId: string, tool: string, status: string) => {
      this.addTerminalEntry('success', `${tool} completed (${status})`, tool);
    });
    this.orchestrator.on('ai:tool-error', (jobId: string, tool: string, err: string) => {
      this.addTerminalEntry('error', `${tool} failed: ${err}`, tool);
    });
    this.orchestrator.on('ai:adaptive-tool', (jobId: string, tool: string, reason: string) => {
      this.addTerminalEntry('info', `AI adaptive: running ${tool} — ${reason}`, 'AI Planner');
    });
    this.orchestrator.on('scanner:output', (msg: string) => {
      this.addTerminalEntry('stdout', msg, 'scanner');
    });
    this.orchestrator.on('scanner:finding', (vuln: any) => {
      this.addTerminalEntry('info', `Scanner finding: ${vuln.title || JSON.stringify(vuln)}`, 'scanner');
    });
  }

  private setupMiddleware(): void {
    this.app.use(express.json());
    this.app.use(express.static(path.join(__dirname, '../ui')));
    this.app.use((req, res, next) => {
      res.header('Access-Control-Allow-Origin', '*');
      res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      if (req.method === 'OPTIONS') return res.sendStatus(200);
      next();
    });
  }

  private setupRoutes(): void {
    // Health
    this.app.get('/api/health', (req, res) => {
      res.json({ success: true, status: 'healthy', timestamp: Date.now() });
    });

    // Auth status
    this.app.get('/api/auth/status', async (req, res) => {
      try {
        const authenticated = await copilotAuth.isAuthenticated();
        res.json({ success: true, authenticated });
      } catch (error) {
        res.status(500).json({ success: false, error: (error as Error).message });
      }
    });

    // Auth start (device flow)
    this.app.post('/api/auth/start', async (req, res) => {
      try {
        await copilotAuth.authenticate();
        res.json({ success: true, message: 'Authentication completed' });
      } catch (error) {
        res.status(500).json({ success: false, error: (error as Error).message });
      }
    });

    // Models
    this.app.get('/api/models', (req, res) => {
      res.json({ success: true, models: copilotAuth.getAvailableModels() });
    });

    // Scope / Auth documents
    this.app.get('/api/scope', (req, res) => {
      const ids = AuthDocument.listAll();
      const docs = ids.map(id => {
        const doc = AuthDocument.load(id);
        if (!doc) return null;
        return { id: doc.id, clientName: doc.clientName, targetDomain: doc.targetDomain, startDate: doc.startDate, endDate: doc.endDate, testingType: doc.testingType, valid: doc.isValid(), daysRemaining: doc.getDaysRemaining(), inScope: doc.inScope, outOfScope: doc.outOfScope, authorizedBy: doc.authorizedBy };
      }).filter(Boolean);
      res.json({ success: true, documents: docs });
    });

    this.app.post('/api/scope', (req, res) => {
      try {
        const { clientName, targetDomain, inScope, outOfScope, startDate, endDate, testingType, authorizedBy, signature, notes } = req.body;
        const doc = new AuthDocument(clientName, targetDomain, inScope || [targetDomain], outOfScope || [], new Date(startDate || Date.now()), new Date(endDate || Date.now() + 30*24*60*60*1000), testingType || ['full'], authorizedBy || 'web-ui', signature || 'digital-signature', notes || '');
        doc.save();
        res.json({ success: true, id: doc.id });
      } catch (error) {
        res.status(400).json({ success: false, error: (error as Error).message });
      }
    });

    // Start pentest from web UI
    this.app.post('/api/pentest', async (req, res) => {
      try {
        const { target, scanType, authDocId, inScope, clientName, authorizedBy } = req.body;
        if (!target) return res.status(400).json({ success: false, error: 'Target is required' });

        // Auto-find or create auth doc
        let finalAuthDocId = authDocId;
        if (!finalAuthDocId) {
          const ids = AuthDocument.listAll();
          const validDoc = ids.map(id => AuthDocument.load(id)).find(d => d && d.isValid() && (d.targetDomain === target || d.inScope.some((s: string) => target.includes(s))));
          if (validDoc) {
            finalAuthDocId = validDoc.id;
          } else {
            // Auto-create auth doc from form data
            const doc = new AuthDocument(clientName || 'Web Pentest', target, inScope || [target], [], new Date(), new Date(Date.now() + 30*24*60*60*1000), [scanType as TestingType || 'full'], authorizedBy || 'web-ui', 'web-digital-signature');
            doc.save();
            finalAuthDocId = doc.id;
            this.addTerminalEntry('info', `Auto-created auth doc: ${doc.id.substring(0, 8)}...`);
          }
        }

        const jobId = await this.orchestrator.startPentest(target, scanType || 'full', finalAuthDocId);
        this.activeJobId = jobId;
        this.addTerminalEntry('success', `Pentest launched on ${target} (${scanType || 'full'} scan)`);

        res.json({ success: true, jobId, authDocId: finalAuthDocId });
      } catch (error) {
        res.status(500).json({ success: false, error: (error as Error).message });
      }
    });

    // Get job status
    this.app.get('/api/jobs', (req, res) => {
      const jobs = this.orchestrator.getActiveJobs();
      res.json({ success: true, jobs: jobs.map(j => ({ id: j.id, target: j.target, scanType: j.scanType, status: j.status, progress: j.progress, currentPhase: j.currentPhase, vulnerabilityCount: j.vulnerabilities.length, startedAt: j.startedAt })) });
    });

    this.app.get('/api/jobs/:id', (req, res) => {
      const job = this.orchestrator.getJobStatus(req.params.id);
      if (!job) return res.status(404).json({ success: false, error: 'Job not found' });
      res.json({ success: true, job: { id: job.id, target: job.target, scanType: job.scanType, status: job.status, progress: job.progress, currentPhase: job.currentPhase, phases: job.phases.map(p => ({ name: p.name, status: p.status, findings: p.findings, agents: p.agents.map(a => ({ name: a.name, status: a.status })) })), vulnerabilities: job.vulnerabilities, startedAt: job.startedAt, completedAt: job.completedAt } });
    });

    // Stop job
    this.app.post('/api/jobs/:id/stop', async (req, res) => {
      const stopped = await this.orchestrator.stopJob(req.params.id);
      res.json({ success: stopped });
    });

    // Terminal log
    this.app.get('/api/terminal', (req, res) => {
      const since = parseInt(req.query.since as string) || 0;
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

  private setupSocketIO(): void {
    this.io.on('connection', socket => {
      // Send current state
      socket.emit('terminal:history', this.terminalLog.slice(-200));
      const jobs = this.orchestrator.getActiveJobs();
      if (jobs.length > 0) socket.emit('jobs:state', jobs);

      socket.on('disconnect', () => {});
    });
  }

  start(): void {
    this.server.listen(this.port, () => {
      console.log(`\n  Ryha Security Flow Dashboard`);
      console.log(`  ────────────────────────────`);
      console.log(`  Dashboard:  http://localhost:${this.port}`);
      console.log(`  API:        http://localhost:${this.port}/api`);
      console.log(`  Health:     http://localhost:${this.port}/api/health\n`);
    });
  }
}

if (require.main === module) {
  new RyhaServer(3000).start();
}

export { RyhaServer };
