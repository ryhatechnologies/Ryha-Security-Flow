/**
 * CVSS 3.1 Metrics
 */
export interface CVSSMetrics {
    attackVector: 'N' | 'A' | 'L' | 'P';
    attackComplexity: 'L' | 'H';
    privilegesRequired: 'N' | 'L' | 'H';
    userInteraction: 'N' | 'R';
    scope: 'U' | 'C';
    confidentiality: 'N' | 'L' | 'H';
    integrity: 'N' | 'L' | 'H';
    availability: 'N' | 'L' | 'H';
}
/**
 * CVSS Score Result
 */
export interface CVSSScore {
    baseScore: number;
    vector: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
    impactScore: number;
    exploitabilityScore: number;
}
/**
 * Vulnerability with classification
 */
export interface ClassifiedVulnerability {
    id: string;
    name: string;
    type: string;
    cvss: CVSSScore;
    cwe: string | null;
    owasp: string | null;
    priority: number;
    exploitability: number;
    businessImpact: number;
    rawData: any;
}
/**
 * Remediation plan
 */
export interface RemediationPlan {
    immediate: RemediationItem[];
    shortTerm: RemediationItem[];
    longTerm: RemediationItem[];
    estimatedTotalEffort: string;
}
/**
 * Remediation item
 */
export interface RemediationItem {
    vulnerability: string;
    severity: string;
    action: string;
    effort: string;
    priority: number;
    dependencies: string[];
}
/**
 * Local vulnerability classifier (no AI required)
 */
export declare class VulnerabilityClassifier {
    /**
     * Calculate CVSS 3.1 base score
     */
    static calculateCVSS(vuln: any): CVSSScore;
    /**
     * Map vulnerability type to CWE ID
     */
    static mapToCWE(vulnType: string): string | null;
    /**
     * Map vulnerability type to OWASP Top 10 (2021)
     */
    static mapToOWASP(vulnType: string): string | null;
    /**
     * Prioritize findings by severity, exploitability, and business impact
     */
    static prioritizeFindings(vulns: any[]): ClassifiedVulnerability[];
    /**
     * Deduplicate findings from different tools
     */
    static deduplicateFindings(vulns: any[]): any[];
    /**
     * Generate remediation plan
     */
    static generateRemediationPlan(vulns: ClassifiedVulnerability[]): RemediationPlan;
    private static extractMetrics;
    private static parseVectorString;
    private static inferAttackVector;
    private static inferAttackComplexity;
    private static inferPrivilegesRequired;
    private static inferUserInteraction;
    private static inferScope;
    private static inferConfidentiality;
    private static inferIntegrity;
    private static inferAvailability;
    private static getAttackVectorScore;
    private static getAttackComplexityScore;
    private static getPrivilegesRequiredScore;
    private static getUserInteractionScore;
    private static getConfidentialityImpact;
    private static getIntegrityImpact;
    private static getAvailabilityImpact;
    private static getSeverityRating;
    private static calculateExploitability;
    private static calculateBusinessImpact;
    private static generateDeduplicationKey;
    private static mergeVulnerabilities;
    private static getRemediationAction;
    private static estimateEffort;
    private static identifyDependencies;
    private static calculateTotalEffort;
}
//# sourceMappingURL=vuln-classifier.d.ts.map