import * as winston from 'winston';
import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs';
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
export class AuthValidator {
  private logger: winston.Logger;
  private readonly auditDir = path.join(os.homedir(), '.ryha', 'audit-logs');

  constructor() {
    this.logger = this.initializeLogger();
    this.ensureAuditDirectory();
  }

  /**
   * Initialize logger with file and console transports
   */
  private initializeLogger(): winston.Logger {
    return winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
      ),
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
  validateBeforeScan(
    authDocumentId: string,
    targetDomain: string,
    scanType: TestingType
  ): AuthValidationResult {
    const result: AuthValidationResult = {
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
    const authDoc = AuthDocument.load(authDocumentId);
    if (!authDoc) {
      result.errors.push(
        `Authorization document not found: ${authDocumentId}`
      );
      this.logValidationFailure(result, 'Authorization document not found');
      return result;
    }

    result.clientName = authDoc.clientName;
    result.authorized_for = authDoc.testingType;
    result.daysRemaining = authDoc.getDaysRemaining();

    // Check if authorization is still valid (not expired)
    if (!authDoc.isValid()) {
      result.expired = true;
      result.errors.push(
        `Authorization has expired. End date: ${authDoc.endDate.toISOString().split('T')[0]}`
      );
      this.logValidationFailure(result, 'Authorization document expired');
      return result;
    }

    // Check if target domain matches the authorization
    if (authDoc.targetDomain !== targetDomain) {
      result.warnings.push(
        `Target domain '${targetDomain}' does not match primary domain '${authDoc.targetDomain}'`
      );
    }

    // Check if target is in scope
    if (!authDoc.isTargetInScope(targetDomain)) {
      result.errors.push(
        `Target '${targetDomain}' is not in authorized scope`
      );
      this.logValidationFailure(result, 'Target not in scope');
      return result;
    }

    result.inScope = true;

    // Check if target is explicitly out of scope
    if (authDoc.isTargetOutOfScope(targetDomain)) {
      result.errors.push(
        `Target '${targetDomain}' is explicitly marked as out-of-scope`
      );
      this.logValidationFailure(result, 'Target explicitly out of scope');
      return result;
    }

    // Check if scan type is authorized
    if (!authDoc.testingType.includes(scanType)) {
      result.errors.push(
        `Scan type '${scanType}' is not authorized. Authorized types: ${authDoc.testingType.join(', ')}`
      );
      this.logValidationFailure(
        result,
        'Scan type not authorized for this document'
      );
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
  validateTargetList(
    authDocumentId: string,
    targets: string[],
    scanType: TestingType
  ): Map<string, AuthValidationResult> {
    const results = new Map<string, AuthValidationResult>();

    const authDoc = AuthDocument.load(authDocumentId);
    if (!authDoc) {
      const error: AuthValidationResult = {
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
      results.set(
        target,
        this.validateBeforeScan(authDocumentId, target, scanType)
      );
    }

    return results;
  }

  /**
   * Get authorization details for a specific document
   */
  getAuthorizationDetails(authDocumentId: string): AuthDocument | null {
    return AuthDocument.load(authDocumentId);
  }

  /**
   * List all valid (non-expired) authorization documents
   */
  listValidAuthorizations(): AuthDocument[] {
    const authIds = AuthDocument.listAll();
    const validAuths: AuthDocument[] = [];

    for (const id of authIds) {
      const auth = AuthDocument.load(id);
      if (auth && auth.isValid()) {
        validAuths.push(auth);
      }
    }

    return validAuths;
  }

  /**
   * List all expired authorization documents
   */
  listExpiredAuthorizations(): AuthDocument[] {
    const authIds = AuthDocument.listAll();
    const expiredAuths: AuthDocument[] = [];

    for (const id of authIds) {
      const auth = AuthDocument.load(id);
      if (auth && !auth.isValid()) {
        expiredAuths.push(auth);
      }
    }

    return expiredAuths;
  }

  /**
   * Get authorization status summary
   */
  getAuthorizationStatus(): {
    total: number;
    valid: number;
    expired: number;
    expiring_soon: number;
  } {
    const authIds = AuthDocument.listAll();
    let valid = 0;
    let expired = 0;
    let expiring_soon = 0;

    for (const id of authIds) {
      const auth = AuthDocument.load(id);
      if (!auth) continue;

      if (auth.isValid()) {
        valid++;
        const daysRemaining = auth.getDaysRemaining();
        if (daysRemaining <= 7 && daysRemaining > 0) {
          expiring_soon++;
        }
      } else {
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
  generateComplianceReport(): string {
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
    } else {
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
    } else {
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
  private logValidationFailure(
    result: AuthValidationResult,
    reason: string
  ): void {
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
  private ensureAuditDirectory(): void {
    if (!fs.existsSync(this.auditDir)) {
      fs.mkdirSync(this.auditDir, { recursive: true });
    }
  }

  /**
   * Export audit logs
   */
  exportAuditLog(days: number = 7): string {
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
      } catch {
        return false;
      }
    });

    return filteredLines.join('\n');
  }
}
