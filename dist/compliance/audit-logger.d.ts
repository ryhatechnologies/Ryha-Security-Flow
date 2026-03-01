/**
 * Audit Logger - Winston-based Structured Logging
 * Ryha Security Flow - SOC 2 / ISO 27001 Aligned
 *
 * Features:
 * - Structured JSON logging
 * - AES-256 encryption option
 * - Daily log rotation
 * - Configurable retention policies
 * - Evidence preservation with integrity hashing
 * - Export for compliance reviewers
 */
import { AuditEvent, Evidence, AuditLoggerConfig, ExportOptions, IntegrityCheck } from './compliance-types';
export declare class AuditLogger {
    private operationsLogger;
    private securityLogger;
    private errorsLogger;
    private config;
    private evidenceStore;
    private encryptionKey?;
    constructor(config?: Partial<AuditLoggerConfig>);
    private initializeLoggers;
    private loadEncryptionKey;
    private encrypt;
    private decrypt;
    private computeHash;
    private getLogger;
    log(event: Omit<AuditEvent, 'timestamp' | 'encrypted'>): Promise<void>;
    logScanStart(userId: string, jobId: string, targetDomain: string, details?: any): Promise<void>;
    logScanComplete(userId: string, jobId: string, targetDomain: string, results: any): Promise<void>;
    logVulnerability(userId: string, jobId: string, targetDomain: string, vulnerability: any): Promise<void>;
    logToolExecution(userId: string, jobId: string, tool: string, target: string, output: any): Promise<void>;
    logAgentSpawned(userId: string, jobId: string, agentType: string, config: any): Promise<void>;
    logScopeViolation(userId: string, jobId: string, targetDomain: string, violation: any): Promise<void>;
    preserveEvidence(jobId: string, type: Evidence['type'], data: any): Promise<Evidence>;
    retrieveEvidence(evidenceId: string): Promise<Evidence | null>;
    verifyIntegrity(jobId?: string): Promise<IntegrityCheck>;
    export(options: ExportOptions): Promise<string>;
    cleanup(): Promise<void>;
    close(): Promise<void>;
}
export declare function getAuditLogger(config?: Partial<AuditLoggerConfig>): AuditLogger;
export declare function setAuditLogger(logger: AuditLogger): void;
//# sourceMappingURL=audit-logger.d.ts.map