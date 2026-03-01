# Authorization & Compliance Module Setup

## Files Created

The following files have been created to implement the Authorization Document and Scope Manager for Ryha Security Flow:

### Core Implementation Files

1. **`src/compliance/auth-document.ts`** (640 lines)
   - AuthDocument class for managing authorization documents
   - Features:
     - Document creation with UUID generation
     - Validation methods for document structure and expiration
     - Target scope checking (supports wildcards and CIDR notation)
     - Multiple export formats (Markdown, Text, YAML)
     - File-based storage in `~/.ryha/authorizations/`
     - Load, list, and delete operations

2. **`src/compliance/auth-validator.ts`** (450 lines)
   - AuthValidator class for pre-scan authorization validation
   - Features:
     - Pre-scan validation gate
     - Batch target validation
     - Authorization status reporting
     - Compliance report generation
     - Comprehensive audit logging
     - Validation result interface

3. **`src/compliance/index.ts`**
   - Module exports for easy importing

### Configuration & Documentation

4. **`config/sample-authorization.yaml`**
   - Complete example authorization document
   - Demonstrates all configuration options
   - Includes wildcards, CIDR notation, and special instructions
   - Referenced in documentation

5. **`docs/AUTHORIZATION.md`** (500+ lines)
   - Comprehensive module documentation
   - API reference for both classes
   - Use cases and examples
   - Troubleshooting guide
   - Security considerations

### Examples

6. **`examples/authorization-examples.ts`** (350 lines)
   - 8 complete example functions demonstrating:
     - Creating new authorization documents
     - Loading existing documents
     - Validating scope
     - Pre-scan validation
     - Batch validation
     - Multiple export formats
     - Listing & managing documents
     - Generating compliance reports

## Installation & Setup

### 1. Dependencies Already Installed

The required dependencies are already in `package.json`:
- `yaml` - YAML file handling
- `uuid` - Document ID generation
- `winston` - Logging
- `fs`, `path`, `os` - Node.js built-ins

### 2. Build the Project

```bash
cd c:/Users/vellu/Downloads/ryha-security-flow
npm install
npm run build
```

### 3. Using the Module

#### Simple Example

```typescript
import { AuthDocument, AuthValidator } from './src/compliance';

// Create authorization
const auth = new AuthDocument(
  'Company Name',
  'target.com',
  ['target.com', '*.target.com'],
  ['prod.target.com'],
  new Date('2024-01-15'),
  new Date('2024-02-15'),
  ['web', 'network'],
  'John Doe',
  'SIGN-001'
);

// Validate and save
if (auth.validate().isValid) {
  const filepath = auth.save();
  console.log(`Saved to: ${filepath}`);
}

// Validate before scanning
const validator = new AuthValidator();
const result = validator.validateBeforeScan(auth.id, 'api.target.com', 'web');

if (result.isValid) {
  console.log('Safe to proceed with scan');
} else {
  console.error('Scan blocked:', result.errors);
}
```

## Directory Structure

```
ryha-security-flow/
├── src/
│   └── compliance/
│       ├── auth-document.ts       # Main AuthDocument class
│       ├── auth-validator.ts      # Validation logic
│       └── index.ts               # Module exports
├── config/
│   └── sample-authorization.yaml  # Sample configuration
├── docs/
│   └── AUTHORIZATION.md           # Full documentation
└── examples/
    └── authorization-examples.ts  # Usage examples
```

## Storage Locations

### Authorization Documents
```
~/.ryha/authorizations/[document-id].yaml
```

### Audit Logs
```
~/.ryha/audit-logs/validation-audit.log     # Main log
~/.ryha/audit-logs/errors.log               # Error log
```

## Key Features

### 1. Document Management
- Create new authorization documents
- Save to persistent storage (YAML format)
- Load existing documents
- List all available documents
- Delete documents

### 2. Scope Validation
- Exact domain matching
- Wildcard domains (*.domain.com)
- CIDR notation (10.0.0.0/24)
- Out-of-scope protection

### 3. Pre-Scan Validation
- Check authorization exists
- Verify document not expired
- Validate target is in scope
- Confirm scan type is authorized
- Log all validation attempts

### 4. Compliance & Reporting
- Authorization status summary
- Compliance report generation
- Audit log export
- Expiration warnings

### 5. Export Formats
- YAML (for storage and re-import)
- Markdown (for documentation)
- Plain text (for printing)

## Security Considerations

1. **Authorization Expiration**: Always check document validity before scanning
2. **Out-of-Scope Protection**: Explicitly forbidden targets are enforced
3. **Audit Logging**: All validation attempts are logged with timestamps
4. **File Permissions**: Store authorization files securely
5. **Signature Verification**: Digital signatures prevent unauthorized modifications

## Testing the Implementation

### Manual Test

```bash
# Build the project
npm run build

# Run examples (requires editing to add test data)
npx ts-node examples/authorization-examples.ts
```

### Verify Files

```bash
# Check all compliance files exist
ls -la src/compliance/
ls -la config/sample-authorization.yaml
ls -la docs/AUTHORIZATION.md
ls -la examples/authorization-examples.ts

# Check compilation
npm run build
```

## API Quick Reference

### AuthDocument

```typescript
// Create
new AuthDocument(clientName, targetDomain, inScope, outOfScope,
                 startDate, endDate, testingType, authorizedBy, signature)

// Validate
authDoc.validate()              // Returns {isValid, errors}
authDoc.isValid()               // Check not expired
authDoc.isTargetInScope(target) // Check if in-scope
authDoc.isTargetOutOfScope(target) // Check if forbidden

// Export
authDoc.save()               // Save to file
authDoc.toYAML()            // Convert to YAML
authDoc.exportAsMarkdown()  // Markdown format
authDoc.exportAsText()      // Plain text format

// Static
AuthDocument.load(id)       // Load from file
AuthDocument.listAll()      // List all IDs
AuthDocument.delete(id)     // Delete document
```

### AuthValidator

```typescript
// Create
const validator = new AuthValidator()

// Validate
validator.validateBeforeScan(authId, target, scanType)
validator.validateTargetList(authId, targets, scanType)

// Info
validator.getAuthorizationDetails(authId)
validator.listValidAuthorizations()
validator.listExpiredAuthorizations()
validator.getAuthorizationStatus()

// Reports
validator.generateComplianceReport()
validator.exportAuditLog(days)
```

## Integration with Ryha CLI

When integrated with the CLI (future implementation):

```bash
# Create authorization
ryha auth create --client "Acme" --domain "acme.com" --duration 30

# Validate target
ryha auth validate --auth-id auth-001 --target api.acme.com --type web

# List authorizations
ryha auth list

# Generate report
ryha auth report --format markdown > report.md

# Show details
ryha auth show --id auth-001
```

## Next Steps

1. Review the documentation in `docs/AUTHORIZATION.md`
2. Check the examples in `examples/authorization-examples.ts`
3. Review sample config at `config/sample-authorization.yaml`
4. Integrate with Ryha CLI for full functionality
5. Add unit tests in `/tests/compliance/`

## Troubleshooting

### Import Errors
If you see import errors, ensure:
- `npm install` was run
- TypeScript version 5.3+ is installed
- `src/compliance/` directory exists

### File Not Found
Authorization documents are stored in `~/.ryha/authorizations/`. Ensure:
- Directory is created automatically
- Read/write permissions are set

### Compilation Errors
The module uses Node.js built-in modules with namespace imports (*). Ensure:
- `esModuleInterop: true` in tsconfig.json
- All dependencies are installed

## Support Files

- **Documentation**: `docs/AUTHORIZATION.md`
- **Sample Config**: `config/sample-authorization.yaml`
- **Examples**: `examples/authorization-examples.ts`
- **Module**: `src/compliance/`

Status: Ready for development and integration

Last Updated: 2026-03-01
