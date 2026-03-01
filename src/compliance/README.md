# Compliance & Audit Logging Framework

SOC 2 / ISO 27001 aligned audit logging and compliance validation for Ryha Security Flow.

## Features

- **Winston-based Structured Logging**: JSON formatted logs with daily rotation
- **AES-256 Encryption**: Optional encryption for sensitive audit data
- **Evidence Preservation**: SHA-256 integrity hashing for all collected evidence
- **Scope Validation**: Pre/during/post scan compliance checking
- **Retention Policies**: Configurable retention (7, 30, 90, 365 days)
- **Compliance Reports**: Generate SOC 2/ISO 27001 aligned reports

## Architecture

```
compliance/
├── compliance-types.ts    # Type definitions and enums
├── audit-logger.ts        # Winston-based audit logging
├── validator.ts           # Compliance validation engine
├── index.ts               # Barrel exports
└── README.md              # Documentation
```

## Log Files

Three separate log streams with daily rotation:

- `/var/ryha/logs/operations-YYYY-MM-DD.log` - All operational events
- `/var/ryha/logs/security-YYYY-MM-DD.log` - Security-related events only
- `/var/ryha/logs/errors-YYYY-MM-DD.log` - Errors and failures
- `/var/ryha/logs/evidence/[jobId]/[evidenceId].json` - Preserved evidence

## Usage

### 1. Initialize Audit Logger

```typescript
import { getAuditLogger, RetentionPolicy } from './compliance';

const logger = getAuditLogger({
  logDir: '/var/ryha/logs',
  retention: RetentionPolicy.LONG, // 90 days
  encryption: {
    enabled: true,
    algorithm: 'aes-256-gcm',
    keyPath: '/var/ryha/keys/audit.key'
  },
  frameworks: ['SOC2', 'ISO27001'],
  realtime: true // Also log to console
});
```

### 2. Log Security Scan Events

```typescript
// Scan start
await logger.logScanStart(
  'user@company.com',
  'scan-001',
  'example.com',
  { scanType: 'full', tools: ['nmap', 'nikto', 'nuclei'] }
);

// Tool execution
await logger.logToolExecution(
  'user@company.com',
  'scan-001',
  'nmap',
  'example.com',
  { ports: '80,443', results: {...} }
);

// Vulnerability found
await logger.logVulnerability(
  'user@company.com',
  'scan-001',
  'example.com',
  {
    title: 'SQL Injection',
    severity: 'critical',
    cve: 'CVE-2024-1234',
    description: '...'
  }
);

// Scan complete
await logger.logScanComplete(
  'user@company.com',
  'scan-001',
  'example.com',
  {
    duration: '45m',
    vulnerabilities: 3,
    status: 'completed'
  }
);
```

### 3. Pre-Scan Validation

```typescript
import { getComplianceValidator } from './compliance';

const validator = getComplianceValidator();

// Define authorization document
const authorization = {
  id: 'auth-001',
  clientName: 'Acme Corp',
  targetDomains: ['example.com', '*.example.com'],
  ipRanges: ['192.168.1.0/24'],
  expiryDate: '2026-12-31',
  issuedDate: '2026-01-01',
  authorizedBy: 'john.doe@acme.com',
  documentHash: 'sha256:...' // Computed hash
};

// Define scan scope
const scope = {
  domains: ['example.com', 'app.example.com'],
  ipRanges: ['192.168.1.0/24'],
  excludedDomains: ['internal.example.com'],
  excludedIPs: ['192.168.1.1'],
  allowedPorts: [80, 443, 8080],
  allowedProtocols: ['http', 'https']
};

// Validate before scanning
const validation = await validator.validatePreScan(
  'scan-001',
  authorization,
  scope,
  'user@company.com'
);

if (!validation.valid) {
  console.error('Pre-scan validation failed:', validation.errors);
  return;
}

console.log('Validation passed. Scan authorized.');
if (validation.warnings.length > 0) {
  console.warn('Warnings:', validation.warnings);
}
```

### 4. During-Scan Monitoring

```typescript
// Before scanning each target, check if it's in scope
const checkTarget = async (target: string) => {
  const result = await validator.monitorTarget(
    'scan-001',
    target,
    'user@company.com'
  );

  if (!result.allowed) {
    console.error(`Target blocked: ${result.reason}`);
    // Alert user, stop scan, log violation
    return false;
  }

  return true;
};

// During scan
if (await checkTarget('example.com')) {
  // Proceed with scan
}

if (await checkTarget('out-of-scope.com')) {
  // This will be blocked and logged as violation
}
```

### 5. Post-Scan Verification

```typescript
// After scan completes, validate all findings
const findings = [
  { target: 'example.com', vulnerability: 'XSS', severity: 'high' },
  { target: 'app.example.com', vulnerability: 'SQLi', severity: 'critical' }
];

const postValidation = await validator.validatePostScan(
  'scan-001',
  findings,
  'user@company.com'
);

if (!postValidation.valid) {
  console.error('Post-scan validation failed:', postValidation.errors);
  // Handle out-of-scope findings
}
```

### 6. Evidence Preservation

```typescript
// Preserve tool output as evidence
const evidence = await logger.preserveEvidence(
  'scan-001',
  'tool_output',
  {
    tool: 'nmap',
    command: 'nmap -sV -p- example.com',
    output: '...',
    timestamp: new Date().toISOString()
  }
);

console.log('Evidence preserved:', evidence.id);
console.log('Hash:', evidence.hash);

// Later, retrieve evidence
const retrieved = await logger.retrieveEvidence(evidence.id);
console.log('Retrieved evidence:', retrieved);
```

### 7. Integrity Verification

```typescript
// Verify integrity of all evidence for a job
const integrity = await logger.verifyIntegrity('scan-001');

console.log(`Checked: ${integrity.checked}`);
console.log(`Valid: ${integrity.valid}`);
console.log(`Corrupted: ${integrity.corrupted}`);
console.log(`Missing: ${integrity.missing}`);

// Check specific evidence
integrity.details.forEach(detail => {
  if (detail.status !== 'valid') {
    console.error(`Evidence ${detail.id} is ${detail.status}`);
  }
});
```

### 8. Generate Compliance Report

```typescript
// Generate full compliance report
const report = await validator.generateComplianceReport(
  'scan-001',
  'SOC2',
  'user@company.com'
);

console.log('Report ID:', report.reportId);
console.log('Scope violations:', report.scopeCompliance.violations);
console.log('Evidence integrity:', report.integrity.evidenceIntegrity);
console.log('Report hash:', report.integrity.reportHash);

// Verify report integrity
const isValid = validator.verifyReportIntegrity(report);
console.log('Report integrity verified:', isValid);
```

### 9. Export Logs for Compliance Review

```typescript
// Export logs for external auditor
const exportPath = await logger.export({
  format: 'json',
  includeEvidence: true,
  encrypted: false,
  startDate: '2026-01-01',
  endDate: '2026-12-31',
  eventTypes: [EventType.VULNERABILITY_FOUND, EventType.SCOPE_VIOLATION]
});

console.log('Logs exported to:', exportPath);
// Send to compliance reviewer
```

### 10. Cleanup Old Logs

```typescript
// Remove logs older than retention policy
await logger.cleanup();
```

## Event Types

```typescript
enum EventType {
  SCAN_START = 'scan_start',
  SCAN_COMPLETE = 'scan_complete',
  SCAN_FAILED = 'scan_failed',
  VULNERABILITY_FOUND = 'vulnerability_found',
  TOOL_EXECUTION = 'tool_execution',
  AGENT_SPAWNED = 'agent_spawned',
  AGENT_COMPLETED = 'agent_completed',
  EVIDENCE_COLLECTED = 'evidence_collected',
  AUTHORIZATION_VERIFIED = 'authorization_verified',
  SCOPE_VIOLATION = 'scope_violation',
  EXPORT_GENERATED = 'export_generated',
  USER_ACTION = 'user_action'
}
```

## Log Format

All logs follow this structured JSON format:

```json
{
  "timestamp": "2026-01-15T10:30:00.000Z",
  "eventType": "vulnerability_found",
  "userId": "user@company.com",
  "jobId": "scan-001",
  "targetDomain": "example.com",
  "details": {
    "title": "SQL Injection",
    "severity": "critical",
    "cve": "CVE-2024-1234",
    "description": "SQL injection in login form"
  },
  "severity": "critical",
  "category": "security",
  "evidenceHash": "sha256:abc123...",
  "encrypted": false
}
```

## Compliance Frameworks Supported

- **SOC 2 Type II**: Audit trail, access controls, change management
- **ISO 27001**: Information security management, incident logging
- **GDPR**: Data protection, consent tracking (future)
- **HIPAA**: Healthcare compliance (future)
- **PCI DSS**: Payment card security (future)

## Retention Policies

```typescript
enum RetentionPolicy {
  SHORT = 7,      // 7 days
  MEDIUM = 30,    // 30 days (default)
  LONG = 90,      // 90 days (recommended for compliance)
  EXTENDED = 365  // 1 year
}
```

## Security Features

1. **AES-256-GCM Encryption**: Encrypts sensitive log data and evidence
2. **SHA-256 Hashing**: Integrity verification for all evidence
3. **Secure Key Storage**: Encryption keys stored with restricted permissions (0o600)
4. **Tamper Detection**: Detects if evidence has been modified
5. **Audit Trail**: Immutable log of all operations
6. **Access Logging**: All operations tied to user identity

## Integration Example

```typescript
import { getAuditLogger, getComplianceValidator, RetentionPolicy } from './compliance';

class RyhaScanner {
  private logger = getAuditLogger({
    retention: RetentionPolicy.LONG,
    encryption: { enabled: true }
  });

  private validator = getComplianceValidator();

  async executeScan(
    jobId: string,
    authorization: AuthorizationDocument,
    scope: ScopeDefinition,
    userId: string
  ) {
    // 1. Pre-scan validation
    const validation = await this.validator.validatePreScan(
      jobId,
      authorization,
      scope,
      userId
    );

    if (!validation.valid) {
      throw new Error(`Validation failed: ${validation.errors.join(', ')}`);
    }

    // 2. Log scan start
    await this.logger.logScanStart(userId, jobId, scope.domains[0]);

    // 3. Execute scan with monitoring
    const findings = [];
    for (const target of scope.domains) {
      const allowed = await this.validator.monitorTarget(jobId, target, userId);

      if (!allowed.allowed) {
        continue; // Skip out-of-scope targets
      }

      // Run scan tools
      const result = await this.runTools(target, userId, jobId);
      findings.push(...result);
    }

    // 4. Post-scan validation
    await this.validator.validatePostScan(jobId, findings, userId);

    // 5. Generate compliance report
    const report = await this.validator.generateComplianceReport(
      jobId,
      'SOC2',
      userId
    );

    // 6. Log completion
    await this.logger.logScanComplete(userId, jobId, scope.domains[0], {
      findings: findings.length,
      report: report.reportId
    });

    // 7. End session
    this.validator.endSession(jobId);

    return { findings, report };
  }

  private async runTools(target: string, userId: string, jobId: string) {
    // Tool execution with evidence preservation
    const output = await executeNmap(target);

    await this.logger.logToolExecution(userId, jobId, 'nmap', target, output);
    await this.logger.preserveEvidence(jobId, 'tool_output', {
      tool: 'nmap',
      target,
      output
    });

    return output.findings;
  }
}
```

## Best Practices

1. **Always validate before scanning**: Run `validatePreScan()` first
2. **Monitor during scans**: Use `monitorTarget()` for each target
3. **Preserve evidence**: Call `preserveEvidence()` for all tool outputs
4. **Verify integrity**: Run `verifyIntegrity()` before generating reports
5. **Generate reports**: Create compliance reports for each engagement
6. **Export regularly**: Export logs for external auditors
7. **Cleanup old logs**: Run `cleanup()` periodically based on retention policy

## Troubleshooting

### Encryption Key Not Found

```typescript
// Generate new encryption key manually
import crypto from 'crypto';
import fs from 'fs/promises';

const key = crypto.randomBytes(32);
await fs.mkdir('/var/ryha/keys', { recursive: true });
await fs.writeFile('/var/ryha/keys/audit.key', key, { mode: 0o600 });
```

### Evidence Corrupted

```typescript
// Check integrity and identify corrupted evidence
const integrity = await logger.verifyIntegrity('scan-001');
const corrupted = integrity.details.filter(d => d.status === 'corrupted');

console.error('Corrupted evidence:', corrupted);
// Re-run scan or restore from backup
```

### Scope Violations

```typescript
// Review all scope violations for a job
const report = await validator.generateComplianceReport('scan-001', 'SOC2', userId);
console.log('Violations:', report.scopeCompliance.violations);

// Take corrective action: exclude from report, re-run scan, etc.
```

## License

MIT
