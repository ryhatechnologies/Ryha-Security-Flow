import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { v4 as uuidv4 } from 'uuid';
import * as YAML from 'yaml';
import * as winston from 'winston';

/**
 * Supported testing types for security assessments
 */
export type TestingType = 'network' | 'web' | 'infrastructure' | 'code' | 'cloud' | 'full';

/**
 * Authorization document for penetration testing and security assessments
 * Ensures compliance and legal authorization before conducting security scans
 */
export class AuthDocument {
  id: string;
  clientName: string;
  targetDomain: string;
  inScope: string[];
  outOfScope: string[];
  startDate: Date;
  endDate: Date;
  testingType: TestingType[];
  authorizedBy: string;
  signature: string;
  notes: string;
  createdAt: Date;
  updatedAt: Date;

  private logger: winston.Logger;
  private readonly authDir = path.join(os.homedir(), '.ryha', 'authorizations');

  constructor(
    clientName: string,
    targetDomain: string,
    inScope: string[],
    outOfScope: string[],
    startDate: Date,
    endDate: Date,
    testingType: TestingType[],
    authorizedBy: string,
    signature: string,
    notes: string = ''
  ) {
    this.id = uuidv4();
    this.clientName = clientName;
    this.targetDomain = targetDomain;
    this.inScope = inScope;
    this.outOfScope = outOfScope;
    this.startDate = startDate;
    this.endDate = endDate;
    this.testingType = testingType;
    this.authorizedBy = authorizedBy;
    this.signature = signature;
    this.notes = notes;
    this.createdAt = new Date();
    this.updatedAt = new Date();

    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.json(),
      transports: [
        new winston.transports.File({
          filename: path.join(this.authDir, 'auth.log'),
          maxsize: 5242880, // 5MB
          maxFiles: 5,
        }),
      ],
    });

    // Ensure auth directory exists
    this.ensureAuthDirectory();
  }

  /**
   * Validate the authorization document
   */
  validate(): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!this.clientName || this.clientName.trim() === '') {
      errors.push('Client name is required');
    }

    if (!this.targetDomain || this.targetDomain.trim() === '') {
      errors.push('Target domain is required');
    }

    if (this.inScope.length === 0) {
      errors.push('At least one in-scope target is required');
    }

    if (this.startDate >= this.endDate) {
      errors.push('Start date must be before end date');
    }

    if (this.testingType.length === 0) {
      errors.push('At least one testing type must be specified');
    }

    if (!this.authorizedBy || this.authorizedBy.trim() === '') {
      errors.push('Authorized by person name is required');
    }

    if (!this.signature || this.signature.trim() === '') {
      errors.push('Digital signature is required');
    }

    return {
      isValid: errors.length === 0,
      errors,
    };
  }

  /**
   * Check if authorization is still valid (not expired)
   */
  isValid(): boolean {
    const now = new Date();
    return now >= this.startDate && now <= this.endDate;
  }

  /**
   * Check if a target is within the authorized scope
   */
  isTargetInScope(target: string): boolean {
    return this.inScope.some((scope) => this.matchesScope(target, scope));
  }

  /**
   * Check if a target is in the out-of-scope list
   */
  isTargetOutOfScope(target: string): boolean {
    return this.outOfScope.some((scope) => this.matchesScope(target, scope));
  }

  /**
   * Match target against scope pattern (supports wildcards and CIDR notation)
   */
  private matchesScope(target: string, scopePattern: string): boolean {
    // Direct match
    if (target === scopePattern) {
      return true;
    }

    // Wildcard matching (e.g., *.acme.com)
    if (scopePattern.includes('*')) {
      const regexPattern = scopePattern
        .replace(/\./g, '\\.')
        .replace(/\*/g, '.*');
      const regex = new RegExp(`^${regexPattern}$`);
      return regex.test(target);
    }

    // CIDR notation matching (basic implementation)
    if (scopePattern.includes('/')) {
      return this.isCIDRMatch(target, scopePattern);
    }

    return false;
  }

  /**
   * Simple CIDR notation matching (IPv4)
   */
  private isCIDRMatch(ip: string, cidr: string): boolean {
    const [network, bits] = cidr.split('/');
    const networkParts = network.split('.');
    const ipParts = ip.split('.');

    if (networkParts.length !== 4 || ipParts.length !== 4) {
      return false;
    }

    const maskBits = parseInt(bits, 10);
    const networkNum = this.ipToNumber(networkParts.map(Number));
    const ipNum = this.ipToNumber(ipParts.map(Number));

    const mask = (0xffffffff << (32 - maskBits)) & 0xffffffff;

    return (networkNum & mask) === (ipNum & mask);
  }

  /**
   * Convert IP address to 32-bit number
   */
  private ipToNumber(parts: number[]): number {
    return (
      ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>>
      0
    );
  }

  /**
   * Get days remaining until authorization expiration
   */
  getDaysRemaining(): number {
    const now = new Date();
    const diff = this.endDate.getTime() - now.getTime();
    return Math.ceil(diff / (1000 * 60 * 60 * 24));
  }

  /**
   * Export authorization as markdown (printable format)
   */
  exportAsMarkdown(): string {
    return `# Authorization Document

**Document ID:** ${this.id}

## Client Information
- **Client Name:** ${this.clientName}
- **Target Domain:** ${this.targetDomain}

## Authorization Period
- **Start Date:** ${this.startDate.toISOString().split('T')[0]}
- **End Date:** ${this.endDate.toISOString().split('T')[0]}
- **Days Remaining:** ${this.getDaysRemaining()}

## Testing Scope
- **Testing Types:** ${this.testingType.join(', ')}

### In-Scope Targets
${this.inScope.map((s) => `- ${s}`).join('\n')}

### Out-of-Scope Targets
${this.outOfScope.map((s) => `- ${s}`).join('\n')}

## Authorization Details
- **Authorized By:** ${this.authorizedBy}
- **Digital Signature:** ${this.signature}

## Special Instructions
${this.notes || 'None'}

## Metadata
- **Created:** ${this.createdAt.toISOString()}
- **Updated:** ${this.updatedAt.toISOString()}

---
*This is an official authorization document. Keep this document secure and confidential.*
`;
  }

  /**
   * Convert to YAML format
   */
  toYAML(): string {
    const data = {
      id: this.id,
      clientName: this.clientName,
      targetDomain: this.targetDomain,
      inScope: this.inScope,
      outOfScope: this.outOfScope,
      startDate: this.startDate.toISOString().split('T')[0],
      endDate: this.endDate.toISOString().split('T')[0],
      testingType: this.testingType,
      authorizedBy: this.authorizedBy,
      signature: this.signature,
      notes: this.notes,
      createdAt: this.createdAt.toISOString(),
      updatedAt: this.updatedAt.toISOString(),
    };

    return YAML.stringify(data);
  }

  /**
   * Save authorization document to file
   */
  save(): string {
    const validation = this.validate();
    if (!validation.isValid) {
      throw new Error(
        `Authorization validation failed: ${validation.errors.join(', ')}`
      );
    }

    this.ensureAuthDirectory();

    const filename = `${this.id}.yaml`;
    const filepath = path.join(this.authDir, filename);

    fs.writeFileSync(filepath, this.toYAML(), 'utf-8');

    this.logger.info(`Authorization document saved: ${filepath}`, {
      id: this.id,
      clientName: this.clientName,
    });

    return filepath;
  }

  /**
   * Load authorization document from file
   */
  static load(id: string): AuthDocument | null {
    const authDir = path.join(os.homedir(), '.ryha', 'authorizations');
    const filepath = path.join(authDir, `${id}.yaml`);

    if (!fs.existsSync(filepath)) {
      return null;
    }

    const content = fs.readFileSync(filepath, 'utf-8');
    const data = YAML.parse(content);

    const authDoc = new AuthDocument(
      data.clientName,
      data.targetDomain,
      data.inScope,
      data.outOfScope,
      new Date(data.startDate),
      new Date(data.endDate),
      data.testingType,
      data.authorizedBy,
      data.signature,
      data.notes
    );

    authDoc.id = data.id;
    authDoc.createdAt = new Date(data.createdAt);
    authDoc.updatedAt = new Date(data.updatedAt);

    return authDoc;
  }

  /**
   * List all available authorization documents
   */
  static listAll(): string[] {
    const authDir = path.join(os.homedir(), '.ryha', 'authorizations');

    if (!fs.existsSync(authDir)) {
      return [];
    }

    return fs
      .readdirSync(authDir)
      .filter((f) => f.endsWith('.yaml'))
      .map((f) => f.replace('.yaml', ''));
  }

  /**
   * Delete authorization document
   */
  static delete(id: string): boolean {
    const authDir = path.join(os.homedir(), '.ryha', 'authorizations');
    const filepath = path.join(authDir, `${id}.yaml`);

    if (!fs.existsSync(filepath)) {
      return false;
    }

    fs.unlinkSync(filepath);
    return true;
  }

  /**
   * Export document as plain text (for printing)
   */
  exportAsText(): string {
    return `
================================================================================
                        AUTHORIZATION DOCUMENT
================================================================================

Document ID: ${this.id}

CLIENT INFORMATION
------------------
Client Name:    ${this.clientName}
Target Domain:  ${this.targetDomain}

AUTHORIZATION PERIOD
--------------------
Start Date:     ${this.startDate.toISOString().split('T')[0]}
End Date:       ${this.endDate.toISOString().split('T')[0]}
Days Remaining: ${this.getDaysRemaining()} days

TESTING SCOPE
-------------
Testing Types:  ${this.testingType.join(', ')}

In-Scope Targets:
${this.inScope.map((s) => `  - ${s}`).join('\n')}

Out-of-Scope Targets:
${this.outOfScope.map((s) => `  - ${s}`).join('\n')}

AUTHORIZATION DETAILS
---------------------
Authorized By:     ${this.authorizedBy}
Digital Signature: ${this.signature}

SPECIAL INSTRUCTIONS
--------------------
${this.notes || 'None'}

METADATA
--------
Created:  ${this.createdAt.toISOString()}
Updated:  ${this.updatedAt.toISOString()}

================================================================================
This is an official authorization document. Keep this document secure and
confidential. Unauthorized access or distribution of this document is prohibited.
================================================================================
`;
  }

  /**
   * Ensure authorization directory exists
   */
  private ensureAuthDirectory(): void {
    if (!fs.existsSync(this.authDir)) {
      fs.mkdirSync(this.authDir, { recursive: true });
    }
  }
}
