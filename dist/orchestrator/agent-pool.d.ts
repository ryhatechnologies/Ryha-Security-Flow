import { EventEmitter } from 'events';
import { ChildProcess } from 'child_process';
export type AgentType = 'recon' | 'network-scanner' | 'web-scanner' | 'vuln-analyzer' | 'exploit-tester' | 'reporter';
export type AgentStatus = 'idle' | 'running' | 'completed' | 'failed' | 'stopped';
export interface Agent {
    id: string;
    name: string;
    type: AgentType;
    status: AgentStatus;
    currentTask: AgentTask | null;
    progress: number;
    findings: AgentFinding[];
    process?: ChildProcess;
    startedAt: Date;
    completedAt: Date | null;
    error?: string;
}
export interface AgentTask {
    name: string;
    target: string;
    phase: string;
    scanType: string;
    prompt: string;
}
export interface AgentFinding {
    timestamp: Date;
    type: 'info' | 'warning' | 'vulnerability';
    data: string;
}
export interface AgentMetrics {
    totalAgents: number;
    activeAgents: number;
    completedAgents: number;
    failedAgents: number;
    totalTasksCompleted: number;
    totalVulnerabilitiesFound: number;
    averageTaskDuration: number;
    uptime: number;
    agentsByType: Record<AgentType, number>;
}
export declare class AgentPool extends EventEmitter {
    private agents;
    private startTime;
    private taskCompletionTimes;
    private readonly maxAgents;
    constructor();
    /**
     * Spawn a new agent to execute a task
     */
    spawn(agentType: AgentType, task: AgentTask, target: string): Promise<Agent>;
    /**
     * Execute agent task by running appropriate security tools
     */
    private executeAgent;
    /**
     * Get tool configuration based on agent type
     */
    private getToolConfig;
    /**
     * Sanitize target to prevent command injection
     */
    private sanitizeTarget;
    /**
     * Handle agent output
     */
    private handleAgentOutput;
    /**
     * Classify output type
     */
    private classifyOutput;
    /**
     * Handle agent error
     */
    private handleAgentError;
    /**
     * Get all active agents
     */
    getActive(): Agent[];
    /**
     * Get agent by ID
     */
    getAgent(agentId: string): Agent | null;
    /**
     * Kill a specific agent
     */
    kill(agentId: string): Promise<boolean>;
    /**
     * Kill all agents
     */
    killAll(): Promise<number>;
    /**
     * Get pool metrics
     */
    getMetrics(): AgentMetrics;
    /**
     * Get agent pool size
     */
    getSize(): number;
    /**
     * Clean up completed agents
     */
    cleanup(): number;
    /**
     * Check if specific tool is available
     */
    checkToolAvailability(tool: string): boolean;
    /**
     * Get all required tools for agent types
     */
    getRequiredTools(): Record<AgentType, string[]>;
    /**
     * Validate all required tools are installed
     */
    validateTools(): {
        valid: boolean;
        missing: string[];
    };
}
//# sourceMappingURL=agent-pool.d.ts.map