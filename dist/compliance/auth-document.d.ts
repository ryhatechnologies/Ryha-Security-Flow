/**
 * Supported testing types for security assessments
 */
export type TestingType = 'network' | 'web' | 'infrastructure' | 'code' | 'cloud' | 'full';
/**
 * Authorization document for penetration testing and security assessments
 * Ensures compliance and legal authorization before conducting security scans
 */
export declare class AuthDocument {
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
    private logger;
    private readonly authDir;
    constructor(clientName: string, targetDomain: string, inScope: string[], outOfScope: string[], startDate: Date, endDate: Date, testingType: TestingType[], authorizedBy: string, signature: string, notes?: string);
    /**
     * Validate the authorization document
     */
    validate(): {
        isValid: boolean;
        errors: string[];
    };
    /**
     * Check if authorization is still valid (not expired)
     */
    isValid(): boolean;
    /**
     * Check if a target is within the authorized scope
     */
    isTargetInScope(target: string): boolean;
    /**
     * Check if a target is in the out-of-scope list
     */
    isTargetOutOfScope(target: string): boolean;
    /**
     * Match target against scope pattern (supports wildcards and CIDR notation)
     */
    private matchesScope;
    /**
     * Simple CIDR notation matching (IPv4)
     */
    private isCIDRMatch;
    /**
     * Convert IP address to 32-bit number
     */
    private ipToNumber;
    /**
     * Get days remaining until authorization expiration
     */
    getDaysRemaining(): number;
    /**
     * Export authorization as markdown (printable format)
     */
    exportAsMarkdown(): string;
    /**
     * Convert to YAML format
     */
    toYAML(): string;
    /**
     * Save authorization document to file
     */
    save(): string;
    /**
     * Load authorization document from file
     */
    static load(id: string): AuthDocument | null;
    /**
     * List all available authorization documents
     */
    static listAll(): string[];
    /**
     * Delete authorization document
     */
    static delete(id: string): boolean;
    /**
     * Export document as plain text (for printing)
     */
    exportAsText(): string;
    /**
     * Ensure authorization directory exists
     */
    private ensureAuthDirectory;
}
//# sourceMappingURL=auth-document.d.ts.map