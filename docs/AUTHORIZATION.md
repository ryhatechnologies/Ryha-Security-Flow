# Authorization & Compliance Module

The Authorization & Compliance module provides secure management of penetration testing authorization documents and scope validation to ensure all security assessments are properly authorized and within legal boundaries.

## Overview

This module consists of two core components:

1. **AuthDocument** - Manages authorization documents with scope definitions
2. **AuthValidator** - Validates targets and scans against active authorizations

## Features

- Create and manage authorization documents
- Define in-scope and out-of-scope targets with wildcard and CIDR support
- Validate authorization expiration dates
- Pre-scan validation before launching security tests
- Batch target validation
- Compliance reporting
- Audit logging
- Multiple export formats (Markdown, Text, YAML)

## Installation

The module is included in the Ryha Security Flow package. Import it in your code:

```typescript
import { AuthDocument, AuthValidator } from './src/compliance';
```

## Quick Start

### 1. Create Authorization Document

```typescript
import { AuthDocument } from './src/compliance';

const authDoc = new AuthDocument(
  'Acme Corporation',           // clientName
  'acme.com',                   // targetDomain
  ['acme.com', '*.acme.com'],   // inScope
  ['prod.acme.com'],            // outOfScope
  new Date('2024-01-15'),       // startDate
  new Date('2024-02-15'),       // endDate
  ['network', 'web'],           // testingType
  'John Smith, CEO',            // authorizedBy
  'JS-2024-0115',               // signature
  'Avoid business hours'        // notes (optional)
);

// Validate
const validation = authDoc.validate();
if (validation.isValid) {
  authDoc.save(); // Saves to ~/.ryha/authorizations/[id].yaml
}
```

### 2. Validate Before Scanning

```typescript
import { AuthValidator } from './src/compliance';

const validator = new AuthValidator();

// Check if target is authorized
const result = validator.validateBeforeScan(
  'auth-doc-id',    // authDocumentId
  'api.acme.com',   // targetDomain
  'web'             // scanType
);

if (result.isValid) {
  // Safe to proceed with scan
  console.log('Scan authorized');
} else {
  // Cannot scan - show errors
  console.error('Scan blocked:', result.errors);
}
```

### 3. Load and Inspect Authorization

```typescript
const authDoc = AuthDocument.load('auth-doc-id');

if (authDoc && authDoc.isValid()) {
  console.log(`Client: ${authDoc.clientName}`);
  console.log(`Days Remaining: ${authDoc.getDaysRemaining()}`);
  console.log(`In Scope: ${authDoc.isTargetInScope('api.acme.com')}`);
}
```

## AuthDocument API

### Constructor

```typescript
new AuthDocument(
  clientName: string,
  targetDomain: string,
  inScope: string[],
  outOfScope: string[],
  startDate: Date,
  endDate: Date,
  testingType: TestingType[],
  authorizedBy: string,
  signature: string,
  notes?: string
)
```

**Parameters:**
- `clientName` - Organization name being tested
- `targetDomain` - Primary domain for the engagement
- `inScope` - Array of authorized targets (supports wildcards and CIDR)
- `outOfScope` - Array of explicitly forbidden targets
- `startDate` - Authorization start date
- `endDate` - Authorization end date
- `testingType` - Array of allowed test types: `'network' | 'web' | 'infrastructure' | 'code' | 'cloud' | 'full'`
- `authorizedBy` - Name and title of authorizing person
- `signature` - Digital signature or authorization code
- `notes` - Optional special instructions

### Methods

#### validate()
Validates the document structure and returns validation result:
```typescript
const { isValid, errors } = authDoc.validate();
```

#### isValid()
Check if authorization is still valid (not expired):
```typescript
if (authDoc.isValid()) {
  // Authorization is current
}
```

#### isTargetInScope(target)
Check if target is authorized:
```typescript
if (authDoc.isTargetInScope('api.acme.com')) {
  // Target is in-scope
}
```

#### isTargetOutOfScope(target)
Check if target is explicitly forbidden:
```typescript
if (authDoc.isTargetOutOfScope('prod.acme.com')) {
  // Target is out-of-scope
}
```

#### getDaysRemaining()
Get days until authorization expiration:
```typescript
const days = authDoc.getDaysRemaining();
if (days < 7) {
  console.warn('Authorization expiring soon');
}
```

#### save()
Save authorization to file (creates `~/.ryha/authorizations/[id].yaml`):
```typescript
const filepath = authDoc.save();
console.log(`Saved to: ${filepath}`);
```

#### toYAML()
Convert to YAML format:
```typescript
const yaml = authDoc.toYAML();
console.log(yaml);
```

#### exportAsMarkdown()
Export as printable Markdown:
```typescript
const markdown = authDoc.exportAsMarkdown();
```

#### exportAsText()
Export as formatted text (good for printing):
```typescript
const text = authDoc.exportAsText();
```

### Static Methods

#### load(id)
Load authorization document from file:
```typescript
const authDoc = AuthDocument.load('auth-doc-id');
if (authDoc) {
  // Document found
}
```

#### listAll()
List all authorization document IDs:
```typescript
const ids = AuthDocument.listAll();
```

#### delete(id)
Delete authorization document:
```typescript
if (AuthDocument.delete('auth-doc-id')) {
  console.log('Document deleted');
}
```

## AuthValidator API

### validateBeforeScan(authDocumentId, targetDomain, scanType)

Main validation method - checks everything before a scan:

```typescript
const result = validator.validateBeforeScan(
  'auth-001',
  'api.acme.com',
  'web'
);

if (result.isValid) {
  // Proceed with scan
  startScan(result.targetDomain);
} else {
  // Log errors
  result.errors.forEach(error => console.error(error));
}
```

**Returns: AuthValidationResult**
```typescript
{
  isValid: boolean;                    // Safe to proceed
  authorized: boolean;                 // Document exists and is valid
  expired: boolean;                    // Authorization has expired
  inScope: boolean;                    // Target is in authorized scope
  authorized_for: TestingType[];       // Allowed testing types
  errors: string[];                    // Validation failures
  warnings: string[];                  // Non-blocking warnings
  documentId: string;                  // Document ID used
  clientName: string;                  // Client name
  daysRemaining: number;               // Days until expiration
}
```

### validateTargetList(authDocumentId, targets, scanType)

Validate multiple targets at once:

```typescript
const targets = ['www.acme.com', 'api.acme.com', 'prod.acme.com'];
const results = validator.validateTargetList('auth-001', targets, 'web');

results.forEach((result, target) => {
  if (.isValid) {
    console.log(`${target}: AUTHORIZED`);
  } else {
    console.log(`${target}: BLOCKED`);
  }
});
```

### getAuthorizationDetails(authDocumentId)

Get full authorization document:

```typescript
const authDoc = validator.getAuthorizationDetails('auth-001');
```

### listValidAuthorizations()

Get all non-expired authorizations:

```typescript
const validAuths = validator.listValidAuthorizations();
validAuths.forEach(auth => {
  console.log(`${auth.clientName}: expires in ${auth.getDaysRemaining()} days`);
});
```

### listExpiredAuthorizations()

Get all expired authorizations:

```typescript
const expiredAuths = validator.listExpiredAuthorizations();
```

### getAuthorizationStatus()

Get authorization statistics:

```typescript
const status = validator.getAuthorizationStatus();
console.log(`Valid: ${status.valid}`);
console.log(`Expired: ${status.expired}`);
console.log(`Expiring Soon: ${status.expiring_soon}`);
```

### generateComplianceReport()

Generate detailed compliance report:

```typescript
const report = validator.generateComplianceReport();
console.log(report);
```

### exportAuditLog(days)

Export audit logs from the last N days:

```typescript
const logs = validator.exportAuditLog(7); // Last 7 days
```

## Target Matching

The module supports multiple formats for target specification:

### Exact Match
```yaml
inScope:
  - "acme.com"
  - "www.acme.com"
  - "192.168.1.1"
```

### Wildcard (Domain)
```yaml
inScope:
  - "*.acme.com"           # Matches www.acme.com, api.acme.com, etc.
  - "*.internal.acme.com"  # Nested wildcards
```

### CIDR Notation (IP Ranges)
```yaml
inScope:
  - "10.0.0.0/24"    # 10.0.0.0 to 10.0.0.255
  - "192.168.0.0/16" # 192.168.0.0 to 192.168.255.255
  - "172.16.0.0/12"  # 172.16.0.0 to 172.31.255.255
```

## Testing Types

Allowed values for `testingType`:

- `network` - Network-level scanning and penetration testing
- `web` - Web application testing
- `infrastructure` - Server and infrastructure assessment
- `code` - Source code security review
- `cloud` - Cloud infrastructure testing (AWS, GCP, Azure, etc.)
- `full` - All testing types authorized

## Storage

Authorization documents are stored in YAML format at:
```
~/.ryha/authorizations/[document-id].yaml
```

Audit logs are stored at:
```
~/.ryha/audit-logs/validation-audit.log
~/.ryha/audit-logs/errors.log
```

## Sample Authorization Document

See `config/sample-authorization.yaml` for a complete example with:
- Multiple in-scope targets (FQDN, wildcards, CIDR)
- Out-of-scope exclusions
- Testing constraints
- Contact information
- Special instructions

## Use Cases

### 1. Pre-Scan Validation Gate

```typescript
async function scanTarget(authId: string, target: string, type: TestingType) {
  const validator = new AuthValidator();
  const validation = validator.validateBeforeScan(authId, target, type);

  if (!validation.isValid) {
    logger.error('Scan blocked', validation.errors);
    return;
  }

  // Proceed with authenticated scan
  await launchScan(target, type);
}
```

### 2. Compliance Dashboard

```typescript
function getComplianceStatus() {
  const validator = new AuthValidator();
  const status = validator.getAuthorizationStatus();
  const report = validator.generateComplianceReport();

  return {
    stats: status,
    report: report,
    expiring: validator.listValidAuthorizations()
      .filter(a => a.getDaysRemaining() <= 7)
  };
}
```

### 3. Bulk Target Import

```typescript
async function importTargets(authId: string, targets: string[]) {
  const validator = new AuthValidator();
  const results = validator.validateTargetList(authId, targets, 'web');

  const authorized = Array.from(results.entries())
    .filter(([_, result]) => result.isValid)
    .map(([target, _]) => target);

  const unauthorized = Array.from(results.entries())
    .filter(([_, result]) => !result.isValid)
    .map(([target, _]) => target);

  return { authorized, unauthorized };
}
```

## Security Considerations

1. **Auditing**: All validation attempts are logged to `~/.ryha/audit-logs/validation-audit.log`
2. **Authorization Expiration**: Always check `isValid()` before proceeding
3. **Out-of-Scope Protection**: Out-of-scope targets are checked even if they match in-scope patterns
4. **Permission Checks**: Store authorization files securely (owned by user, mode 0600)
5. **Signature Verification**: Use digital signatures to prevent unauthorized modifications

## Error Handling

```typescript
try {
  const result = validator.validateBeforeScan(authId, target, type);

  if (!result.isValid) {
    // Handle validation failure
    result.errors.forEach(error => {
      logger.warn('Validation error:', error);
    });

    if (result.expired) {
      logger.error('Authorization has expired');
    }

    if (!result.inScope) {
      logger.error('Target is out of scope');
    }

    throw new Error('Scan authorization failed');
  }
} catch (error) {
  logger.error('Fatal authorization error:', error);
}
```

## CLI Integration

When integrated with the Ryha CLI, use:

```bash
# Create authorization
ryha auth create --client "Acme" --domain "acme.com" --duration 30

# List authorizations
ryha auth list

# Validate target
ryha auth validate --auth-id auth-001 --target api.acme.com --type web

# Generate compliance report
ryha auth report --format markdown > authorization-report.md

# Load authorization details
ryha auth show --id auth-001
```

## Troubleshooting

### "Authorization document not found"
- Check document ID spelling
- Ensure document hasn't been deleted
- Use `AuthDocument.listAll()` to see available documents

### "Authorization has expired"
- Check end date in authorization document
- Create new authorization if still testing
- Validate with `authDoc.getDaysRemaining()`

### "Target is not in authorized scope"
- Verify target matches in-scope list or patterns
- Check for typos in domain names
- Ensure CIDR notation is correct

### "Scan type not authorized"
- Verify `testingType` in authorization
- Check if specific test type is allowed
- May need to create new authorization for different test type

## Contributing

When adding new features:
1. Update both `AuthDocument` and `AuthValidator` as needed
2. Add comprehensive unit tests
3. Update sample configuration
4. Add example usage code
5. Update this documentation

## License

MIT
