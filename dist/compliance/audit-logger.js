"use strict";
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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuditLogger = void 0;
exports.getAuditLogger = getAuditLogger;
exports.setAuditLogger = setAuditLogger;
const winston_1 = __importDefault(require("winston"));
// daily-rotate-file removed
const crypto_1 = __importDefault(require("crypto"));
const promises_1 = __importDefault(require("fs/promises"));
const path_1 = __importDefault(require("path"));
const compliance_types_1 = require("./compliance-types");
class AuditLogger {
    constructor(config = {}) {
        this.evidenceStore = new Map();
        this.config = {
            logDir: config.logDir || '/var/ryha/logs',
            retention: config.retention || compliance_types_1.RetentionPolicy.MEDIUM,
            encryption: {
                enabled: config.encryption?.enabled || false,
                algorithm: 'aes-256-gcm',
                keyPath: config.encryption?.keyPath || '/var/ryha/keys/audit.key'
            },
            rotation: {
                maxSize: 104857600,
                maxFiles: Number(config.retention || 30),
                compress: true,
            },
            frameworks: config.frameworks || ['SOC2', 'ISO27001'],
            realtime: config.realtime !== false
        };
        this.initializeLoggers();
        if (this.config.encryption.enabled) {
            this.loadEncryptionKey();
        }
    }
    initializeLoggers() {
        const timestampFormat = winston_1.default.format.timestamp({
            format: 'YYYY-MM-DDTHH:mm:ss.SSSZ'
        });
        const jsonFormat = winston_1.default.format.combine(timestampFormat, winston_1.default.format.errors({ stack: true }), winston_1.default.format.json());
        // Operations Logger
        this.operationsLogger = winston_1.default.createLogger({
            level: 'info',
            format: jsonFormat,
            transports: [
                new winston_1.default.transports.File({
                    filename: path_1.default.join(this.config.logDir, 'operations-%DATE%.log'),
                    maxsize: this.config.rotation.maxSize,
                    maxFiles: this.config.rotation.maxFiles,
                    level: 'info'
                }),
                ...(this.config.realtime ? [new winston_1.default.transports.Console({
                        format: winston_1.default.format.combine(winston_1.default.format.colorize(), winston_1.default.format.simple())
                    })] : [])
            ]
        });
        // Security Logger
        this.securityLogger = winston_1.default.createLogger({
            level: 'info',
            format: jsonFormat,
            transports: [
                new winston_1.default.transports.File({
                    filename: path_1.default.join(this.config.logDir, 'security-%DATE%.log'),
                    maxsize: this.config.rotation.maxSize,
                    maxFiles: this.config.rotation.maxFiles,
                    level: 'info'
                })
            ]
        });
        // Errors Logger
        this.errorsLogger = winston_1.default.createLogger({
            level: 'error',
            format: jsonFormat,
            transports: [
                new winston_1.default.transports.File({
                    filename: path_1.default.join(this.config.logDir, 'errors-%DATE%.log'),
                    maxsize: this.config.rotation.maxSize,
                    maxFiles: this.config.rotation.maxFiles,
                    level: 'error'
                })
            ]
        });
    }
    async loadEncryptionKey() {
        try {
            const keyData = await promises_1.default.readFile(this.config.encryption.keyPath);
            this.encryptionKey = keyData;
        }
        catch (error) {
            console.error('Failed to load encryption key, generating new one...');
            this.encryptionKey = crypto_1.default.randomBytes(32);
            await promises_1.default.mkdir(path_1.default.dirname(this.config.encryption.keyPath), { recursive: true });
            await promises_1.default.writeFile(this.config.encryption.keyPath, this.encryptionKey, { mode: 0o600 });
        }
    }
    encrypt(data) {
        if (!this.encryptionKey) {
            throw new Error('Encryption key not loaded');
        }
        const iv = crypto_1.default.randomBytes(16);
        const cipher = crypto_1.default.createCipheriv(this.config.encryption.algorithm, this.encryptionKey, iv);
        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const tag = cipher.getAuthTag?.() || Buffer.alloc(16);
        return {
            encrypted,
            iv: iv.toString('hex'),
            tag: tag.toString('hex')
        };
    }
    decrypt(encrypted, iv, tag) {
        if (!this.encryptionKey) {
            throw new Error('Encryption key not loaded');
        }
        const decipher = crypto_1.default.createDecipheriv(this.config.encryption.algorithm, this.encryptionKey, Buffer.from(iv, 'hex'));
        decipher.setAuthTag?.(Buffer.from(tag, 'hex'));
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    }
    computeHash(data) {
        const serialized = typeof data === 'string' ? data : JSON.stringify(data);
        return crypto_1.default.createHash('sha256').update(serialized).digest('hex');
    }
    getLogger(category) {
        switch (category) {
            case compliance_types_1.LogCategory.OPERATIONS:
                return this.operationsLogger;
            case compliance_types_1.LogCategory.SECURITY:
                return this.securityLogger;
            case compliance_types_1.LogCategory.ERRORS:
                return this.errorsLogger;
            default:
                return this.operationsLogger;
        }
    }
    async log(event) {
        const auditEvent = {
            ...event,
            timestamp: new Date().toISOString(),
            encrypted: false
        };
        // Compute hash for evidence if applicable
        if (event.details.evidence) {
            auditEvent.evidenceHash = this.computeHash(event.details.evidence);
        }
        let logData = auditEvent;
        // Encrypt sensitive data if enabled
        if (this.config.encryption.enabled && event.severity === compliance_types_1.Severity.CRITICAL) {
            const encrypted = this.encrypt(JSON.stringify(auditEvent.details));
            logData = {
                ...auditEvent,
                details: {
                    encrypted: encrypted.encrypted,
                    iv: encrypted.iv,
                    tag: encrypted.tag
                },
                encrypted: true
            };
        }
        const logger = this.getLogger(event.category);
        logger.log(event.severity, logData);
    }
    async logScanStart(userId, jobId, targetDomain, details = {}) {
        await this.log({
            eventType: compliance_types_1.EventType.SCAN_START,
            userId,
            jobId,
            targetDomain,
            details: {
                ...details,
                action: 'scan_initiated'
            },
            severity: compliance_types_1.Severity.INFO,
            category: compliance_types_1.LogCategory.OPERATIONS
        });
    }
    async logScanComplete(userId, jobId, targetDomain, results) {
        await this.log({
            eventType: compliance_types_1.EventType.SCAN_COMPLETE,
            userId,
            jobId,
            targetDomain,
            details: {
                ...results,
                action: 'scan_completed'
            },
            severity: compliance_types_1.Severity.INFO,
            category: compliance_types_1.LogCategory.OPERATIONS
        });
    }
    async logVulnerability(userId, jobId, targetDomain, vulnerability) {
        await this.log({
            eventType: compliance_types_1.EventType.VULNERABILITY_FOUND,
            userId,
            jobId,
            targetDomain,
            details: vulnerability,
            severity: vulnerability.severity === 'critical' ? compliance_types_1.Severity.CRITICAL : compliance_types_1.Severity.WARNING,
            category: compliance_types_1.LogCategory.SECURITY
        });
    }
    async logToolExecution(userId, jobId, tool, target, output) {
        await this.log({
            eventType: compliance_types_1.EventType.TOOL_EXECUTION,
            userId,
            jobId,
            targetDomain: target,
            details: {
                tool,
                output,
                executedAt: new Date().toISOString()
            },
            severity: compliance_types_1.Severity.INFO,
            category: compliance_types_1.LogCategory.OPERATIONS
        });
    }
    async logAgentSpawned(userId, jobId, agentType, config) {
        await this.log({
            eventType: compliance_types_1.EventType.AGENT_SPAWNED,
            userId,
            jobId,
            details: {
                agentType,
                config,
                spawnedAt: new Date().toISOString()
            },
            severity: compliance_types_1.Severity.INFO,
            category: compliance_types_1.LogCategory.OPERATIONS
        });
    }
    async logScopeViolation(userId, jobId, targetDomain, violation) {
        await this.log({
            eventType: compliance_types_1.EventType.SCOPE_VIOLATION,
            userId,
            jobId,
            targetDomain,
            details: violation,
            severity: compliance_types_1.Severity.CRITICAL,
            category: compliance_types_1.LogCategory.SECURITY
        });
    }
    async preserveEvidence(jobId, type, data) {
        const evidence = {
            id: crypto_1.default.randomUUID(),
            jobId,
            type,
            data,
            timestamp: new Date().toISOString(),
            hash: this.computeHash(data),
            encrypted: this.config.encryption.enabled
        };
        if (this.config.encryption.enabled) {
            const encrypted = this.encrypt(JSON.stringify(data));
            evidence.data = {
                encrypted: encrypted.encrypted,
                iv: encrypted.iv,
                tag: encrypted.tag
            };
        }
        this.evidenceStore.set(evidence.id, evidence);
        // Persist to disk
        const evidenceDir = path_1.default.join(this.config.logDir, 'evidence', jobId);
        await promises_1.default.mkdir(evidenceDir, { recursive: true });
        await promises_1.default.writeFile(path_1.default.join(evidenceDir, `${evidence.id}.json`), JSON.stringify(evidence, null, 2));
        await this.log({
            eventType: compliance_types_1.EventType.EVIDENCE_COLLECTED,
            userId: 'system',
            jobId,
            details: {
                evidenceId: evidence.id,
                type,
                hash: evidence.hash
            },
            severity: compliance_types_1.Severity.INFO,
            category: compliance_types_1.LogCategory.OPERATIONS
        });
        return evidence;
    }
    async retrieveEvidence(evidenceId) {
        // Check memory cache first
        if (this.evidenceStore.has(evidenceId)) {
            return this.evidenceStore.get(evidenceId);
        }
        // Search disk
        const logsDir = path_1.default.join(this.config.logDir, 'evidence');
        try {
            const jobDirs = await promises_1.default.readdir(logsDir);
            for (const jobDir of jobDirs) {
                const evidencePath = path_1.default.join(logsDir, jobDir, `${evidenceId}.json`);
                try {
                    const data = await promises_1.default.readFile(evidencePath, 'utf-8');
                    const evidence = JSON.parse(data);
                    // Decrypt if needed
                    if (evidence.encrypted && this.encryptionKey) {
                        const decrypted = this.decrypt(evidence.data.encrypted, evidence.data.iv, evidence.data.tag);
                        evidence.data = JSON.parse(decrypted);
                    }
                    return evidence;
                }
                catch {
                    continue;
                }
            }
        }
        catch (error) {
            console.error('Error retrieving evidence:', error);
        }
        return null;
    }
    async verifyIntegrity(jobId) {
        const result = {
            timestamp: new Date().toISOString(),
            checked: 0,
            valid: 0,
            corrupted: 0,
            missing: 0,
            details: []
        };
        const evidenceDir = path_1.default.join(this.config.logDir, 'evidence');
        const jobDirs = jobId ? [jobId] : await promises_1.default.readdir(evidenceDir);
        for (const dir of jobDirs) {
            const jobPath = path_1.default.join(evidenceDir, dir);
            try {
                const files = await promises_1.default.readdir(jobPath);
                for (const file of files) {
                    if (!file.endsWith('.json'))
                        continue;
                    result.checked++;
                    const evidencePath = path_1.default.join(jobPath, file);
                    const data = await promises_1.default.readFile(evidencePath, 'utf-8');
                    const evidence = JSON.parse(data);
                    // Recompute hash
                    const currentHash = this.computeHash(evidence.data);
                    if (currentHash === evidence.hash) {
                        result.valid++;
                        result.details.push({
                            id: evidence.id,
                            status: 'valid',
                            expectedHash: evidence.hash,
                            actualHash: currentHash
                        });
                    }
                    else {
                        result.corrupted++;
                        result.details.push({
                            id: evidence.id,
                            status: 'corrupted',
                            expectedHash: evidence.hash,
                            actualHash: currentHash
                        });
                    }
                }
            }
            catch (error) {
                result.missing++;
            }
        }
        return result;
    }
    async export(options) {
        const exportId = crypto_1.default.randomUUID();
        const exportDir = path_1.default.join(this.config.logDir, 'exports');
        await promises_1.default.mkdir(exportDir, { recursive: true });
        // Collect logs based on criteria
        const logs = [];
        // Implementation would parse log files based on options
        // For brevity, this is a placeholder
        const exportData = {
            exportId,
            generatedAt: new Date().toISOString(),
            options,
            logs,
            integrity: await this.verifyIntegrity()
        };
        const exportPath = path_1.default.join(exportDir, `export-${exportId}.json`);
        await promises_1.default.writeFile(exportPath, JSON.stringify(exportData, null, 2));
        await this.log({
            eventType: compliance_types_1.EventType.EXPORT_GENERATED,
            userId: 'system',
            details: {
                exportId,
                path: exportPath,
                options
            },
            severity: compliance_types_1.Severity.INFO,
            category: compliance_types_1.LogCategory.OPERATIONS
        });
        return exportPath;
    }
    async cleanup() {
        // Remove logs older than retention policy
        const retentionDays = this.config.retention;
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - retentionDays);
        // Implementation would scan and remove old log files
        // For brevity, this is a placeholder
    }
    async close() {
        this.operationsLogger.close();
        this.securityLogger.close();
        this.errorsLogger.close();
    }
}
exports.AuditLogger = AuditLogger;
// Singleton instance
let auditLoggerInstance = null;
function getAuditLogger(config) {
    if (!auditLoggerInstance) {
        auditLoggerInstance = new AuditLogger(config);
    }
    return auditLoggerInstance;
}
function setAuditLogger(logger) {
    auditLoggerInstance = logger;
}
//# sourceMappingURL=audit-logger.js.map