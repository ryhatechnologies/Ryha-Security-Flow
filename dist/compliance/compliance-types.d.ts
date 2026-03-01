/**
 * Compliance and Audit Type Definitions
 * Ryha Security Flow - SOC 2 / ISO 27001 Aligned
 */
export declare enum EventType {
    SCAN_START = "scan_start",
    SCAN_COMPLETE = "scan_complete",
    SCAN_FAILED = "scan_failed",
    VULNERABILITY_FOUND = "vulnerability_found",
    TOOL_EXECUTION = "tool_execution",
    AGENT_SPAWNED = "agent_spawned",
    AGENT_COMPLETED = "agent_completed",
    EVIDENCE_COLLECTED = "evidence_collected",
    AUTHORIZATION_VERIFIED = "authorization_verified",
    SCOPE_VIOLATION = "scope_violation",
    EXPORT_GENERATED = "export_generated",
    USER_ACTION = "user_action"
}
export declare enum Severity {
    INFO = "info",
    WARNING = "warning",
    ERROR = "error",
    CRITICAL = "critical"
}
export declare enum ComplianceFramework {
    SOC2 = "SOC2",
    ISO27001 = "ISO27001",
    GDPR = "GDPR",
    HIPAA = "HIPAA",
    PCI_DSS = "PCI_DSS"
}
export declare enum LogCategory {
    OPERATIONS = "operations",
    SECURITY = "security",
    ERRORS = "errors"
}
export declare enum RetentionPolicy {
    SHORT = 7,// 7 days
    MEDIUM = 30,// 30 days
    LONG = 90,// 90 days
    EXTENDED = 365
}
export interface AuditEvent {
    timestamp: string;
    eventType: EventType;
    userId: string;
    jobId?: string;
    targetDomain?: string;
    details: Record<string, any>;
    severity: Severity;
    category: LogCategory;
    evidenceHash?: string;
    encrypted?: boolean;
}
export interface Evidence {
    id: string;
    jobId: string;
    type: 'tool_output' | 'screenshot' | 'finding' | 'report';
    data: any;
    timestamp: string;
    hash: string;
    encrypted: boolean;
}
export interface ValidationResult {
    valid: boolean;
    errors: string[];
    warnings: string[];
    timestamp: string;
    validatedBy: string;
}
export interface AuthorizationDocument {
    id: string;
    clientName: string;
    targetDomains: string[];
    ipRanges: string[];
    expiryDate: string;
    issuedDate: string;
    authorizedBy: string;
    documentHash: string;
}
export interface ScopeDefinition {
    domains: string[];
    ipRanges: string[];
    excludedDomains: string[];
    excludedIPs: string[];
    allowedPorts: number[];
    allowedProtocols: string[];
}
export interface ComplianceReport {
    reportId: string;
    jobId: string;
    generatedAt: string;
    generatedBy: string;
    framework: ComplianceFramework;
    validationResults: ValidationResult;
    events: AuditEvent[];
    evidenceHashes: string[];
    scopeCompliance: {
        inScope: number;
        outOfScope: number;
        violations: string[];
    };
    integrity: {
        reportHash: string;
        evidenceIntegrity: boolean;
        tamperDetected: boolean;
    };
}
export interface LogRotationConfig {
    maxSize: number;
    maxFiles: number;
    compress: boolean;
}
export interface EncryptionConfig {
    enabled: boolean;
    algorithm: string;
    keyPath: string;
}
export interface AuditLoggerConfig {
    logDir: string;
    retention: RetentionPolicy;
    encryption: EncryptionConfig;
    rotation: LogRotationConfig;
    frameworks: ComplianceFramework[];
    realtime: boolean;
}
export interface ExportOptions {
    format: 'json' | 'csv' | 'pdf';
    includeEvidence: boolean;
    encrypted: boolean;
    startDate?: string;
    endDate?: string;
    eventTypes?: EventType[];
}
export interface IntegrityCheck {
    timestamp: string;
    checked: number;
    valid: number;
    corrupted: number;
    missing: number;
    details: Array<{
        id: string;
        status: 'valid' | 'corrupted' | 'missing';
        expectedHash: string;
        actualHash?: string;
    }>;
}
//# sourceMappingURL=compliance-types.d.ts.map