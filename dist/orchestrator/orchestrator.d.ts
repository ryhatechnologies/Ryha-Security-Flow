import { EventEmitter } from 'events';
import { AgentType } from './agent-pool';
export interface PentestJob {
    id: string;
    target: string;
    scanType: string;
    authDocId: string;
    status: 'pending' | 'running' | 'completed' | 'failed' | 'stopped';
    currentPhase: string | null;
    phases: PentestPhase[];
    startedAt: Date;
    completedAt: Date | null;
    vulnerabilities: Vulnerability[];
    agents: string[];
    progress: number;
    error?: string;
}
export interface PentestPhase {
    name: string;
    status: 'pending' | 'running' | 'completed' | 'failed';
    agents: AgentTask[];
    startedAt: Date | null;
    completedAt: Date | null;
    findings: number;
}
export interface AgentTask {
    agentType: AgentType;
    name: string;
    prompt: string;
    status: 'pending' | 'running' | 'completed' | 'failed';
    agentId?: string;
    result?: any;
    error?: string;
}
export interface Vulnerability {
    id: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    title: string;
    description: string;
    cve?: string;
    cvss?: number;
    foundBy: string;
    foundAt: Date;
    target: string;
    evidence: string;
    remediation: string;
}
export interface CopilotAnalysisRequest {
    tool: string;
    output: string;
    context: {
        target: string;
        phase: string;
        scanType: string;
    };
}
export declare class PentestOrchestrator extends EventEmitter {
    private jobs;
    private agentPool;
    private copilotAuth;
    private authValidator;
    private aiSelector;
    private scanner;
    private toolManager;
    private readonly maxConcurrentAgents;
    constructor();
    /**
     * Start a new penetration test job
     */
    startPentest(target: string, scanType: 'full' | 'quick' | 'compliance' | 'web' | 'network', authDocId: string): Promise<string>;
    /**
     * Execute a pentest job through all phases
     */
    private executeJob;
    /**
     * Execute a single phase with parallel agent execution
     */
    private executePhase;
    /**
     * Execute a single agent task
     */
    private executeAgentTask;
    /**
     * Wait for agent to complete execution
     */
    private waitForAgent;
    /**
     * Analyze tool output using Copilot API
     */
    private analyzeTool;
    /**
     * Build analysis prompt for Copilot
     */
    private buildAnalysisPrompt;
    /**
     * Get job status with real-time progress
     */
    getJobStatus(jobId: string): PentestJob | null;
    /**
     * Stop a running job gracefully
     */
    stopJob(jobId: string): Promise<boolean>;
    /**
     * Initialize phases based on scan type
     * Uses AI to dynamically plan attack strategy when possible
     */
    private initializePhases;
    /**
     * Execute AI-driven autonomous scanning
     * The AI plans the complete strategy and dynamically executes tools
     */
    executeAIStrategy(jobId: string, target: string, scanType: string, scope: string[]): Promise<void>;
    /**
     * Split array into chunks
     */
    private chunkArray;
    /**
     * Update job progress based on completed phases
     */
    private updateJobProgress;
    /**
     * Handle agent output
     */
    private handleAgentOutput;
    /**
     * Handle agent error
     */
    private handleAgentError;
    /**
     * Handle job error
     */
    private handleJobError;
    /**
     * Get all active jobs
     */
    getActiveJobs(): PentestJob[];
    /**
     * Clean up completed jobs older than 24 hours
     */
    cleanup(): Promise<number>;
}
//# sourceMappingURL=orchestrator.d.ts.map