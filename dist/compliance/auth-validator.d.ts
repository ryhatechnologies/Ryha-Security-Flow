import { AuthDocument, TestingType } from './auth-document';
/**
 * Authorization validation result
 */
export interface AuthValidationResult {
    isValid: boolean;
    authorized: boolean;
    expired: boolean;
    inScope: boolean;
    authorized_for: TestingType[];
    errors: string[];
    warnings: string[];
    documentId: string;
    clientName: string;
    daysRemaining: number;
}
/**
 * Authorization validator for pre-scan verification
 * Ensures all security scans are properly authorized and within scope
 */
export declare class AuthValidator {
    private logger;
    private readonly auditDir;
    constructor();
    /**
     * Initialize logger with file and console transports
     */
    private initializeLogger;
    /**
     * Pre-scan validation: Check authorization before starting a scan
     */
    validateBeforeScan(authDocumentId: string, targetDomain: string, scanType: TestingType): AuthValidationResult;
    /**
     * Validate all targets in a list before batch scanning
     */
    validateTargetList(authDocumentId: string, targets: string[], scanType: TestingType): Map<string, AuthValidationResult>;
    /**
     * Get authorization details for a specific document
     */
    getAuthorizationDetails(authDocumentId: string): AuthDocument | null;
    /**
     * List all valid (non-expired) authorization documents
     */
    listValidAuthorizations(): AuthDocument[];
    /**
     * List all expired authorization documents
     */
    listExpiredAuthorizations(): AuthDocument[];
    /**
     * Get authorization status summary
     */
    getAuthorizationStatus(): {
        total: number;
        valid: number;
        expired: number;
        expiring_soon: number;
    };
    /**
     * Generate authorization compliance report
     */
    generateComplianceReport(): string;
    /**
     * Log validation failure with details
     */
    private logValidationFailure;
    /**
     * Ensure audit directory exists
     */
    private ensureAuditDirectory;
    /**
     * Export audit logs
     */
    exportAuditLog(days?: number): string;
}
//# sourceMappingURL=auth-validator.d.ts.map