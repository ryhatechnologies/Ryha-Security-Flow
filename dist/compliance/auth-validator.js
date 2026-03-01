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
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthValidator = void 0;
const winston = __importStar(require("winston"));
const path = __importStar(require("path"));
const os = __importStar(require("os"));
const fs = __importStar(require("fs"));
const auth_document_1 = require("./auth-document");
/**
 * Authorization validator for pre-scan verification
 * Ensures all security scans are properly authorized and within scope
 */
class AuthValidator {
    constructor() {
        this.auditDir = path.join(os.homedir(), '.ryha', 'audit-logs');
        this.logger = this.initializeLogger();
        this.ensureAuditDirectory();
    }
    /**
     * Initialize logger with file and console transports
     */
    initializeLogger() {
        return winston.createLogger({
            level: 'info',
            format: winston.format.combine(winston.format.timestamp(), winston.format.errors({ stack: true }), winston.format.json()),
            defaultMeta: { service: 'auth-validator' },
            transports: [
                new winston.transports.File({
                    filename: path.join(this.auditDir, 'validation-audit.log'),
                    maxsize: 5242880, // 5MB
                    maxFiles: 10,
                }),
                new winston.transports.File({
                    filename: path.join(this.auditDir, 'errors.log'),
                    level: 'error',
                    maxsize: 5242880,
                    maxFiles: 10,
                }),
            ],
        });
    }
    /**
     * Pre-scan validation: Check authorization before starting a scan
     */
    validateBeforeScan(authDocumentId, targetDomain, scanType) {
        const result = {
            isValid: false,
            authorized: false,
            expired: false,
            inScope: false,
            authorized_for: [],
            errors: [],
            warnings: [],
            documentId: authDocumentId,
            clientName: '',
            daysRemaining: 0,
        };
        // Log validation attempt
        this.logger.info('Validation request', {
            authDocumentId,
            targetDomain,
            scanType,
            timestamp: new Date().toISOString(),
        });
        // Check if authorization document exists
        const authDoc = auth_document_1.AuthDocument.load(authDocumentId);
        if (!authDoc) {
            result.errors.push(`Authorization document not found: ${authDocumentId}`);
            this.logValidationFailure(result, 'Authorization document not found');
            return result;
        }
        result.clientName = authDoc.clientName;
        result.authorized_for = authDoc.testingType;
        result.daysRemaining = authDoc.getDaysRemaining();
        // Check if authorization is still valid (not expired)
        if (!authDoc.isValid()) {
            result.expired = true;
            result.errors.push(`Authorization has expired. End date: ${authDoc.endDate.toISOString().split('T')[0]}`);
            this.logValidationFailure(result, 'Authorization document expired');
            return result;
        }
        // Check if target domain matches the authorization
        if (authDoc.targetDomain !== targetDomain) {
            result.warnings.push(`Target domain '${targetDomain}' does not match primary domain '${authDoc.targetDomain}'`);
        }
        // Check if target is in scope
        if (!authDoc.isTargetInScope(targetDomain)) {
            result.errors.push(`Target '${targetDomain}' is not in authorized scope`);
            this.logValidationFailure(result, 'Target not in scope');
            return result;
        }
        result.inScope = true;
        // Check if target is explicitly out of scope
        if (authDoc.isTargetOutOfScope(targetDomain)) {
            result.errors.push(`Target '${targetDomain}' is explicitly marked as out-of-scope`);
            this.logValidationFailure(result, 'Target explicitly out of scope');
            return result;
        }
        // Check if scan type is authorized
        if (!authDoc.testingType.includes(scanType)) {
            result.errors.push(`Scan type '${scanType}' is not authorized. Authorized types: ${authDoc.testingType.join(', ')}`);
            this.logValidationFailure(result, 'Scan type not authorized for this document');
            return result;
        }
        // All checks passed
        result.isValid = true;
        result.authorized = true;
        // Log successful validation
        this.logger.info('Validation successful', {
            authDocumentId,
            targetDomain,
            scanType,
            clientName: authDoc.clientName,
            daysRemaining: result.daysRemaining,
        });
        return result;
    }
    /**
     * Validate all targets in a list before batch scanning
     */
    validateTargetList(authDocumentId, targets, scanType) {
        const results = new Map();
        const authDoc = auth_document_1.AuthDocument.load(authDocumentId);
        if (!authDoc) {
            const error = {
                isValid: false,
                authorized: false,
                expired: false,
                inScope: false,
                authorized_for: [],
                errors: [`Authorization document not found: ${authDocumentId}`],
                warnings: [],
                documentId: authDocumentId,
                clientName: '',
                daysRemaining: 0,
            };
            targets.forEach((target) => {
                results.set(target, { ...error });
            });
            return results;
        }
        for (const target of targets) {
            results.set(target, this.validateBeforeScan(authDocumentId, target, scanType));
        }
        return results;
    }
    /**
     * Get authorization details for a specific document
     */
    getAuthorizationDetails(authDocumentId) {
        return auth_document_1.AuthDocument.load(authDocumentId);
    }
    /**
     * List all valid (non-expired) authorization documents
     */
    listValidAuthorizations() {
        const authIds = auth_document_1.AuthDocument.listAll();
        const validAuths = [];
        for (const id of authIds) {
            const auth = auth_document_1.AuthDocument.load(id);
            if (auth && auth.isValid()) {
                validAuths.push(auth);
            }
        }
        return validAuths;
    }
    /**
     * List all expired authorization documents
     */
    listExpiredAuthorizations() {
        const authIds = auth_document_1.AuthDocument.listAll();
        const expiredAuths = [];
        for (const id of authIds) {
            const auth = auth_document_1.AuthDocument.load(id);
            if (auth && !auth.isValid()) {
                expiredAuths.push(auth);
            }
        }
        return expiredAuths;
    }
    /**
     * Get authorization status summary
     */
    getAuthorizationStatus() {
        const authIds = auth_document_1.AuthDocument.listAll();
        let valid = 0;
        let expired = 0;
        let expiring_soon = 0;
        for (const id of authIds) {
            const auth = auth_document_1.AuthDocument.load(id);
            if (!auth)
                continue;
            if (auth.isValid()) {
                valid++;
                const daysRemaining = auth.getDaysRemaining();
                if (daysRemaining <= 7 && daysRemaining > 0) {
                    expiring_soon++;
                }
            }
            else {
                expired++;
            }
        }
        return {
            total: authIds.length,
            valid,
            expired,
            expiring_soon,
        };
    }
    /**
     * Generate authorization compliance report
     */
    generateComplianceReport() {
        const status = this.getAuthorizationStatus();
        const validAuths = this.listValidAuthorizations();
        const expiredAuths = this.listExpiredAuthorizations();
        let report = `
================================================================================
                    AUTHORIZATION COMPLIANCE REPORT
================================================================================

Generated: ${new Date().toISOString()}

SUMMARY
-------
Total Documents:      ${status.total}
Valid Documents:      ${status.valid}
Expired Documents:    ${status.expired}
Expiring Soon (7d):   ${status.expiring_soon}

VALID AUTHORIZATIONS
--------------------
`;
        if (validAuths.length === 0) {
            report += 'None\n';
        }
        else {
            validAuths.forEach((auth) => {
                report += `
  - Document ID: ${auth.id}
    Client: ${auth.clientName}
    Target: ${auth.targetDomain}
    Expires: ${auth.endDate.toISOString().split('T')[0]}
    Days Remaining: ${auth.getDaysRemaining()}
    Testing Types: ${auth.testingType.join(', ')}
`;
            });
        }
        report += `

EXPIRED AUTHORIZATIONS
----------------------
`;
        if (expiredAuths.length === 0) {
            report += 'None\n';
        }
        else {
            expiredAuths.forEach((auth) => {
                report += `
  - Document ID: ${auth.id}
    Client: ${auth.clientName}
    Target: ${auth.targetDomain}
    Expired: ${auth.endDate.toISOString().split('T')[0]}
    Days Past Expiration: ${Math.abs(auth.getDaysRemaining())}
`;
            });
        }
        report += `
================================================================================
`;
        return report;
    }
    /**
     * Log validation failure with details
     */
    logValidationFailure(result, reason) {
        this.logger.warn('Validation failed', {
            authorizedFor: result.authorized_for,
            clientName: result.clientName,
            daysRemaining: result.daysRemaining,
            errors: result.errors,
            warnings: result.warnings,
            reason,
            timestamp: new Date().toISOString(),
        });
    }
    /**
     * Ensure audit directory exists
     */
    ensureAuditDirectory() {
        if (!fs.existsSync(this.auditDir)) {
            fs.mkdirSync(this.auditDir, { recursive: true });
        }
    }
    /**
     * Export audit logs
     */
    exportAuditLog(days = 7) {
        const logFile = path.join(this.auditDir, 'validation-audit.log');
        if (!fs.existsSync(logFile)) {
            return 'No audit logs available';
        }
        const content = fs.readFileSync(logFile, 'utf-8');
        const cutoffTime = new Date();
        cutoffTime.setDate(cutoffTime.getDate() - days);
        const lines = content.split('\n');
        const filteredLines = lines.filter((line) => {
            try {
                const logEntry = JSON.parse(line);
                const logTime = new Date(logEntry.timestamp);
                return logTime >= cutoffTime;
            }
            catch {
                return false;
            }
        });
        return filteredLines.join('\n');
    }
}
exports.AuthValidator = AuthValidator;
//# sourceMappingURL=auth-validator.js.map