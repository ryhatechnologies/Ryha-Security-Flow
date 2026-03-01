/**
 * Compliance Validator
 * Ryha Security Flow - SOC 2 / ISO 27001 Aligned
 *
 * Features:
 * - Pre-scan validation (authorization, scope, expiry)
 * - During-scan monitoring (out-of-scope detection)
 * - Post-scan verification (findings within scope)
 * - Compliance report generation
 * - Evidence integrity verification (SHA-256)
 */
import { AuthorizationDocument, ScopeDefinition, ValidationResult, ComplianceReport, ComplianceFramework } from './compliance-types';
export declare class ComplianceValidator {
    private auditLogger;
    private activeSessions;
    /**
     * Pre-Scan Validation
     * Validates authorization document and scope before scan execution
     */
    validatePreScan(jobId: string, authorization: AuthorizationDocument, scope: ScopeDefinition, userId: string): Promise<ValidationResult>;
    /**
     * Validate authorization document structure and content
     */
    private validateAuthorizationDocument;
    /**
     * Check if authorization document is expired
     */
    private checkExpiry;
    /**
     * Validate scope definition against authorization
     */
    private validateScope;
    /**
     * Verify document integrity using SHA-256 hash
     */
    private verifyDocumentIntegrity;
    /**
     * During-Scan Monitoring
     * Detects and alerts on out-of-scope targets during active scanning
     */
    monitorTarget(jobId: string, target: string, userId: string): Promise<{
        allowed: boolean;
        reason?: string;
    }>;
    /**
     * Post-Scan Verification
     * Verifies all findings are within scope and generates compliance report
     */
    validatePostScan(jobId: string, findings: any[], userId: string): Promise<ValidationResult>;
    /**
     * Generate compliance report with checksums and integrity verification
     */
    generateComplianceReport(jobId: string, framework: ComplianceFramework, userId: string): Promise<ComplianceReport>;
    /**
     * Verify compliance report integrity
     */
    verifyReportIntegrity(report: ComplianceReport): boolean;
    /**
     * End validation session
     */
    endSession(jobId: string): void;
    private isValidDomain;
    private isValidIPRange;
    private isDomainAuthorized;
    private isTargetInScope;
    private isTargetExcluded;
    private isIPInRanges;
    private computeHash;
}
export declare function getComplianceValidator(): ComplianceValidator;
export declare function setComplianceValidator(validator: ComplianceValidator): void;
//# sourceMappingURL=validator.d.ts.map