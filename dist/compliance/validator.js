"use strict";
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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ComplianceValidator = void 0;
exports.getComplianceValidator = getComplianceValidator;
exports.setComplianceValidator = setComplianceValidator;
const crypto_1 = __importDefault(require("crypto"));
const audit_logger_1 = require("./audit-logger");
const compliance_types_1 = require("./compliance-types");
class ComplianceValidator {
    constructor() {
        this.auditLogger = (0, audit_logger_1.getAuditLogger)();
        this.activeSessions = new Map();
    }
    /**
     * Pre-Scan Validation
     * Validates authorization document and scope before scan execution
     */
    async validatePreScan(jobId, authorization, scope, userId) {
        const errors = [];
        const warnings = [];
        // 1. Check authorization document validity
        const authValidation = this.validateAuthorizationDocument(authorization);
        errors.push(...(authValidation.errors || []));
        warnings.push(...(authValidation.warnings || []));
        // 2. Check authorization not expired
        const expiryCheck = this.checkExpiry(authorization);
        if (!expiryCheck.valid) {
            errors.push(...(expiryCheck.errors || []));
        }
        // 3. Verify scope coverage
        const scopeCheck = this.validateScope(scope, authorization);
        errors.push(...(scopeCheck.errors || []));
        warnings.push(...(scopeCheck.warnings || []));
        // 4. Verify document integrity
        const integrityCheck = this.verifyDocumentIntegrity(authorization);
        if (!integrityCheck.valid) {
            errors.push('Authorization document integrity check failed - possible tampering detected');
        }
        const result = {
            valid: errors.length === 0,
            errors,
            warnings,
            timestamp: new Date().toISOString(),
            validatedBy: userId
        };
        // Log validation result
        await this.auditLogger.log({
            eventType: compliance_types_1.EventType.AUTHORIZATION_VERIFIED,
            userId,
            jobId,
            details: {
                authorizationId: authorization.id,
                validationResult: result,
                framework: 'SOC2'
            },
            severity: result.valid ? compliance_types_1.Severity.INFO : compliance_types_1.Severity.CRITICAL,
            category: result.valid ? compliance_types_1.LogCategory.OPERATIONS : compliance_types_1.LogCategory.SECURITY
        });
        // Store session if valid
        if (result.valid) {
            this.activeSessions.set(jobId, {
                authorization,
                scope,
                violations: [],
                startTime: new Date()
            });
        }
        return result;
    }
    /**
     * Validate authorization document structure and content
     */
    validateAuthorizationDocument(auth) {
        const errors = [];
        const warnings = [];
        if (!auth.id || auth.id.trim() === '') {
            errors.push('Authorization document must have a valid ID');
        }
        if (!auth.clientName || auth.clientName.trim() === '') {
            errors.push('Client name is required');
        }
        if (!auth.authorizedBy || auth.authorizedBy.trim() === '') {
            errors.push('Authorization must specify who authorized the assessment');
        }
        if (!auth.targetDomains || auth.targetDomains.length === 0) {
            errors.push('At least one target domain must be specified');
        }
        if (!auth.issuedDate) {
            errors.push('Issued date is required');
        }
        if (!auth.expiryDate) {
            errors.push('Expiry date is required');
        }
        // Validate domains format
        if (auth.targetDomains) {
            auth.targetDomains.forEach(domain => {
                if (!this.isValidDomain(domain)) {
                    warnings.push(`Domain may be invalid: ${domain}`);
                }
            });
        }
        // Validate IP ranges format
        if (auth.ipRanges) {
            auth.ipRanges.forEach(range => {
                if (!this.isValidIPRange(range)) {
                    warnings.push(`IP range may be invalid: ${range}`);
                }
            });
        }
        return { errors, warnings, valid: errors.length === 0 };
    }
    /**
     * Check if authorization document is expired
     */
    checkExpiry(auth) {
        const errors = [];
        const now = new Date();
        const expiryDate = new Date(auth.expiryDate);
        const issuedDate = new Date(auth.issuedDate);
        if (expiryDate < now) {
            errors.push(`Authorization expired on ${auth.expiryDate}`);
        }
        if (issuedDate > now) {
            errors.push(`Authorization issued date is in the future: ${auth.issuedDate}`);
        }
        if (expiryDate <= issuedDate) {
            errors.push('Expiry date must be after issued date');
        }
        return { errors, valid: errors.length === 0 };
    }
    /**
     * Validate scope definition against authorization
     */
    validateScope(scope, auth) {
        const errors = [];
        const warnings = [];
        // Check all scope domains are authorized
        scope.domains.forEach(domain => {
            if (!this.isDomainAuthorized(domain, auth.targetDomains)) {
                errors.push(`Domain not authorized: ${domain}`);
            }
        });
        // Check IP ranges if specified
        if (scope.ipRanges && auth.ipRanges) {
            scope.ipRanges.forEach(range => {
                if (!auth.ipRanges.includes(range)) {
                    errors.push(`IP range not authorized: ${range}`);
                }
            });
        }
        // Warn about overly broad scopes
        if (scope.domains.some(d => d.includes('*'))) {
            warnings.push('Wildcard domains detected - ensure this is intentional');
        }
        if (!scope.allowedPorts || scope.allowedPorts.length === 0) {
            warnings.push('No port restrictions specified - all ports will be scanned');
        }
        return { errors, warnings, valid: errors.length === 0 };
    }
    /**
     * Verify document integrity using SHA-256 hash
     */
    verifyDocumentIntegrity(auth) {
        if (!auth.documentHash) {
            return { valid: false };
        }
        // Create hash from document without the hash field itself
        const { documentHash, ...docWithoutHash } = auth;
        const computedHash = this.computeHash(docWithoutHash);
        return { valid: computedHash === documentHash };
    }
    /**
     * During-Scan Monitoring
     * Detects and alerts on out-of-scope targets during active scanning
     */
    async monitorTarget(jobId, target, userId) {
        const session = this.activeSessions.get(jobId);
        if (!session) {
            return {
                allowed: false,
                reason: 'No active session found - pre-scan validation required'
            };
        }
        // Check if target is in scope
        const inScope = this.isTargetInScope(target, session.scope, session.authorization);
        if (!inScope) {
            // Log scope violation
            const violation = `Out-of-scope target detected: ${target}`;
            session.violations.push(violation);
            await this.auditLogger.logScopeViolation(userId, jobId, target, {
                target,
                authorizedDomains: session.authorization.targetDomains,
                scopeDefinition: session.scope,
                timestamp: new Date().toISOString()
            });
            return {
                allowed: false,
                reason: `Target ${target} is not within authorized scope`
            };
        }
        // Check if target is explicitly excluded
        if (this.isTargetExcluded(target, session.scope)) {
            const violation = `Excluded target detected: ${target}`;
            session.violations.push(violation);
            await this.auditLogger.logScopeViolation(userId, jobId, target, {
                target,
                excludedDomains: session.scope.excludedDomains,
                excludedIPs: session.scope.excludedIPs,
                timestamp: new Date().toISOString()
            });
            return {
                allowed: false,
                reason: `Target ${target} is explicitly excluded from scope`
            };
        }
        return { allowed: true };
    }
    /**
     * Post-Scan Verification
     * Verifies all findings are within scope and generates compliance report
     */
    async validatePostScan(jobId, findings, userId) {
        const session = this.activeSessions.get(jobId);
        const errors = [];
        const warnings = [];
        if (!session) {
            errors.push('No validation session found for this job');
            return {
                valid: false,
                errors,
                warnings,
                timestamp: new Date().toISOString(),
                validatedBy: userId
            };
        }
        // Verify all findings are within scope
        let inScopeCount = 0;
        let outOfScopeCount = 0;
        findings.forEach((finding, index) => {
            const target = finding.target || finding.domain || finding.ip;
            if (!target) {
                warnings.push(`Finding #${index} has no target specified`);
                return;
            }
            const inScope = this.isTargetInScope(target, session.scope, session.authorization);
            if (inScope) {
                inScopeCount++;
            }
            else {
                outOfScopeCount++;
                errors.push(`Finding for out-of-scope target: ${target}`);
            }
        });
        // Add any violations from monitoring
        if (session.violations.length > 0) {
            errors.push(...session.violations.map(v => `Scope violation during scan: ${v}`));
        }
        const result = {
            valid: errors.length === 0,
            errors,
            warnings,
            timestamp: new Date().toISOString(),
            validatedBy: userId
        };
        await this.auditLogger.log({
            eventType: compliance_types_1.EventType.SCAN_COMPLETE,
            userId,
            jobId,
            details: {
                totalFindings: findings.length,
                inScope: inScopeCount,
                outOfScope: outOfScopeCount,
                violations: session.violations.length,
                validationResult: result
            },
            severity: result.valid ? compliance_types_1.Severity.INFO : compliance_types_1.Severity.WARNING,
            category: compliance_types_1.LogCategory.OPERATIONS
        });
        return result;
    }
    /**
     * Generate compliance report with checksums and integrity verification
     */
    async generateComplianceReport(jobId, framework, userId) {
        const session = this.activeSessions.get(jobId);
        if (!session) {
            throw new Error('No validation session found for this job');
        }
        // Collect all audit events for this job
        // In production, this would query the audit logs
        const events = [];
        // Collect evidence hashes
        const evidenceHashes = [];
        // Verify evidence integrity
        const integrityCheck = await this.auditLogger.verifyIntegrity(jobId);
        const evidenceIntegrity = integrityCheck.corrupted === 0 && integrityCheck.missing === 0;
        const report = {
            reportId: crypto_1.default.randomUUID(),
            jobId,
            generatedAt: new Date().toISOString(),
            generatedBy: userId,
            framework,
            validationResults: {
                valid: session.violations.length === 0,
                errors: session.violations,
                warnings: [],
                timestamp: new Date().toISOString(),
                validatedBy: userId
            },
            events,
            evidenceHashes,
            scopeCompliance: {
                inScope: 0, // Would be computed from actual findings
                outOfScope: session.violations.length,
                violations: session.violations
            },
            integrity: {
                reportHash: '', // Computed below
                evidenceIntegrity,
                tamperDetected: !evidenceIntegrity
            }
        };
        // Compute report hash for integrity
        const { integrity, ...reportWithoutHash } = report;
        report.integrity.reportHash = this.computeHash(reportWithoutHash);
        // Log report generation
        await this.auditLogger.log({
            eventType: compliance_types_1.EventType.EXPORT_GENERATED,
            userId,
            jobId,
            details: {
                reportId: report.reportId,
                framework,
                integrityHash: report.integrity.reportHash
            },
            severity: compliance_types_1.Severity.INFO,
            category: compliance_types_1.LogCategory.OPERATIONS
        });
        return report;
    }
    /**
     * Verify compliance report integrity
     */
    verifyReportIntegrity(report) {
        const { integrity, ...reportWithoutHash } = report;
        const computedHash = this.computeHash(reportWithoutHash);
        return computedHash === integrity.reportHash;
    }
    /**
     * End validation session
     */
    endSession(jobId) {
        this.activeSessions.delete(jobId);
    }
    // Helper methods
    isValidDomain(domain) {
        const domainRegex = /^(?:[a-zA-Z0-9*](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
        return domainRegex.test(domain);
    }
    isValidIPRange(range) {
        // Simple validation - could be enhanced
        const ipRegex = /^(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?$/;
        return ipRegex.test(range) || range.includes('-');
    }
    isDomainAuthorized(domain, authorizedDomains) {
        return authorizedDomains.some(authDomain => {
            if (authDomain.includes('*')) {
                const pattern = authDomain.replace(/\*/g, '.*');
                const regex = new RegExp(`^${pattern}$`);
                return regex.test(domain);
            }
            return domain === authDomain || domain.endsWith(`.${authDomain}`);
        });
    }
    isTargetInScope(target, scope, auth) {
        // Check domains
        if (this.isDomainAuthorized(target, scope.domains)) {
            return true;
        }
        // Check IP ranges
        if (scope.ipRanges && this.isIPInRanges(target, scope.ipRanges)) {
            return true;
        }
        // Check authorized domains from auth doc
        if (this.isDomainAuthorized(target, auth.targetDomains)) {
            return true;
        }
        return false;
    }
    isTargetExcluded(target, scope) {
        if (scope.excludedDomains && this.isDomainAuthorized(target, scope.excludedDomains)) {
            return true;
        }
        if (scope.excludedIPs && this.isIPInRanges(target, scope.excludedIPs)) {
            return true;
        }
        return false;
    }
    isIPInRanges(ip, ranges) {
        // Simple IP matching - would need proper CIDR/range checking in production
        return ranges.some(range => {
            if (range.includes('/')) {
                // CIDR notation
                return ip.startsWith(range.split('/')[0].split('.').slice(0, 3).join('.'));
            }
            if (range.includes('-')) {
                // Range notation
                return true; // Simplified
            }
            return ip === range;
        });
    }
    computeHash(data) {
        const serialized = typeof data === 'string' ? data : JSON.stringify(data);
        return crypto_1.default.createHash('sha256').update(serialized).digest('hex');
    }
}
exports.ComplianceValidator = ComplianceValidator;
// Singleton instance
let validatorInstance = null;
function getComplianceValidator() {
    if (!validatorInstance) {
        validatorInstance = new ComplianceValidator();
    }
    return validatorInstance;
}
function setComplianceValidator(validator) {
    validatorInstance = validator;
}
//# sourceMappingURL=validator.js.map