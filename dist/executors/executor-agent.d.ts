import { EventEmitter } from 'events';
/**
 * Execution result interface
 */
export interface ExecutionResult {
    success: boolean;
    stdout: string;
    stderr: string;
    exitCode: number | null;
    duration: number;
    timestamp: Date;
    command: string;
    evidenceId: string;
}
/**
 * Tool execution options
 */
export interface ToolOptions {
    timeout?: number;
    env?: Record<string, string>;
    cwd?: string;
    silent?: boolean;
    captureEvidence?: boolean;
}
/**
 * Authorization document interface
 */
export interface AuthorizationDocument {
    id: string;
    targets: string[];
    ipRanges: string[];
    domains: string[];
    excludedTargets?: string[];
    validFrom: Date;
    validUntil: Date;
    scope: string[];
    restrictions?: string[];
}
/**
 * Metasploit options
 */
export interface MetasploitOptions {
    payload?: string;
    lhost?: string;
    lport?: number;
    options?: Record<string, string>;
}
/**
 * Burp Suite scan types
 */
export declare enum BurpScanType {
    PASSIVE = "passive",
    LIGHT_ACTIVE = "light-active",
    FULL_ACTIVE = "full-active",
    CRAWL_ONLY = "crawl-only"
}
/**
 * ExecutorAgent - Executes security tools with elevated permissions on Kali Linux
 *
 * CRITICAL: All executions are validated against authorization documents
 * CRITICAL: All inputs are sanitized to prevent command injection
 */
export declare class ExecutorAgent extends EventEmitter {
    private evidencePath;
    private activeProcesses;
    private executionHistory;
    private authDocument;
    constructor(evidencePath?: string);
    /**
     * Set the authorization document for target validation
     */
    setAuthorizationDocument(authDoc: AuthorizationDocument): void;
    /**
     * Validate target against authorization document
     *
     * @throws Error if target is not authorized
     */
    validateTarget(target: string, authDoc?: any): boolean;
    /**
     * Execute command with root privileges
     */
    executeWithRoot(command: string, args: string[], options?: ToolOptions): Promise<ExecutionResult>;
    /**
     * Execute a security tool with unified interface
     */
    executeTool(toolName: string, target: string, options?: Record<string, string>): Promise<ExecutionResult>;
    /**
     * Execute Metasploit module via resource script
     */
    executeMetasploit(module: string, target: string, options?: MetasploitOptions): Promise<ExecutionResult>;
    /**
     * Execute Burp Suite headless scanning
     */
    executeBurpSuite(target: string, scanType?: string): Promise<ExecutionResult>;
    /**
     * Execute custom security script
     */
    executeCustomScript(scriptPath: string, args?: string[]): Promise<ExecutionResult>;
    /**
     * Kill a running process
     */
    killProcess(executionId: string): Promise<boolean>;
    /**
     * Get execution history
     */
    getExecutionHistory(): ExecutionResult[];
    /**
     * Clear execution history
     */
    clearHistory(): void;
    private executeProcess;
    private sanitizeInput;
    private sanitizeCommand;
    private sanitizeFilePath;
    private matchesPattern;
    private isInIpRange;
    private matchesDomain;
    private generateExecutionId;
    private generateMetasploitResourceScript;
    private generateBurpConfig;
    private captureEvidence;
}
//# sourceMappingURL=executor-agent.d.ts.map