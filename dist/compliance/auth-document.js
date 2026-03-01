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
exports.AuthDocument = void 0;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const os = __importStar(require("os"));
const uuid_1 = require("uuid");
const YAML = __importStar(require("yaml"));
const winston = __importStar(require("winston"));
/**
 * Authorization document for penetration testing and security assessments
 * Ensures compliance and legal authorization before conducting security scans
 */
class AuthDocument {
    constructor(clientName, targetDomain, inScope, outOfScope, startDate, endDate, testingType, authorizedBy, signature, notes = '') {
        this.authDir = path.join(os.homedir(), '.ryha', 'authorizations');
        this.id = (0, uuid_1.v4)();
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
    validate() {
        const errors = [];
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
    isValid() {
        const now = new Date();
        return now >= this.startDate && now <= this.endDate;
    }
    /**
     * Check if a target is within the authorized scope
     */
    isTargetInScope(target) {
        return this.inScope.some((scope) => this.matchesScope(target, scope));
    }
    /**
     * Check if a target is in the out-of-scope list
     */
    isTargetOutOfScope(target) {
        return this.outOfScope.some((scope) => this.matchesScope(target, scope));
    }
    /**
     * Match target against scope pattern (supports wildcards and CIDR notation)
     */
    matchesScope(target, scopePattern) {
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
    isCIDRMatch(ip, cidr) {
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
    ipToNumber(parts) {
        return (((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>>
            0);
    }
    /**
     * Get days remaining until authorization expiration
     */
    getDaysRemaining() {
        const now = new Date();
        const diff = this.endDate.getTime() - now.getTime();
        return Math.ceil(diff / (1000 * 60 * 60 * 24));
    }
    /**
     * Export authorization as markdown (printable format)
     */
    exportAsMarkdown() {
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
    toYAML() {
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
    save() {
        const validation = this.validate();
        if (!validation.isValid) {
            throw new Error(`Authorization validation failed: ${validation.errors.join(', ')}`);
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
    static load(id) {
        const authDir = path.join(os.homedir(), '.ryha', 'authorizations');
        const filepath = path.join(authDir, `${id}.yaml`);
        if (!fs.existsSync(filepath)) {
            return null;
        }
        const content = fs.readFileSync(filepath, 'utf-8');
        const data = YAML.parse(content);
        const authDoc = new AuthDocument(data.clientName, data.targetDomain, data.inScope, data.outOfScope, new Date(data.startDate), new Date(data.endDate), data.testingType, data.authorizedBy, data.signature, data.notes);
        authDoc.id = data.id;
        authDoc.createdAt = new Date(data.createdAt);
        authDoc.updatedAt = new Date(data.updatedAt);
        return authDoc;
    }
    /**
     * List all available authorization documents
     */
    static listAll() {
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
    static delete(id) {
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
    exportAsText() {
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
    ensureAuthDirectory() {
        if (!fs.existsSync(this.authDir)) {
            fs.mkdirSync(this.authDir, { recursive: true });
        }
    }
}
exports.AuthDocument = AuthDocument;
//# sourceMappingURL=auth-document.js.map