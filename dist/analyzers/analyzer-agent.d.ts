/**
 * Vulnerability severity classification
 */
export declare enum VulnerabilitySeverity {
    CRITICAL = "CRITICAL",
    HIGH = "HIGH",
    MEDIUM = "MEDIUM",
    LOW = "LOW",
    INFO = "INFO"
}
/**
 * Analysis result interface
 */
export interface AnalysisResult {
    summary: string;
    vulnerabilities: VulnerabilityAnalysis[];
    attackChains: AttackChain[];
    riskScore: number;
    recommendations: string[];
    executiveSummary: string;
}
/**
 * Vulnerability analysis result
 */
export interface VulnerabilityAnalysis {
    id: string;
    name: string;
    severity: VulnerabilitySeverity;
    cvssScore: number;
    cvssVector: string;
    description: string;
    impact: string;
    likelihood: string;
    remediation: RemediationSteps;
    references: string[];
    cwe?: string;
    owasp?: string;
    exploitability: number;
    technicalDetails?: string;
}
/**
 * Remediation steps
 */
export interface RemediationSteps {
    immediate: string[];
    shortTerm: string[];
    longTerm: string[];
    estimatedEffort: string;
    priority: number;
}
/**
 * Attack chain representation
 */
export interface AttackChain {
    id: string;
    steps: string[];
    vulnerabilities: string[];
    impact: string;
    likelihood: string;
    overallRisk: string;
    mitigation: string[];
}
/**
 * Zero-day detection result
 */
export interface ZeroDayAnalysis {
    potentialZeroDays: PotentialZeroDay[];
    confidence: number;
    analysisNotes: string;
    recommendedActions: string[];
}
/**
 * Potential zero-day vulnerability
 */
export interface PotentialZeroDay {
    description: string;
    indicators: string[];
    confidence: number;
    affectedComponents: string[];
    proposedVerification: string[];
}
/**
 * Exploit POC result
 */
export interface ExploitPOC {
    vulnerability: string;
    exploitType: string;
    prerequisites: string[];
    steps: string[];
    code: string;
    verification: string[];
    warnings: string[];
    legalNotice: string;
}
/**
 * Risk assessment result
 */
export interface RiskAssessment {
    overallScore: number;
    breakdown: {
        technicalRisk: number;
        businessImpact: number;
        exploitability: number;
        dataExposure: number;
    };
    criticalFindings: number;
    highFindings: number;
    mediumFindings: number;
    lowFindings: number;
    topRisks: string[];
    immediateActions: string[];
}
/**
 * AI-powered vulnerability analyzer using Claude
 */
export declare class AnalyzerAgent {
    private static readonly OPUS_MODEL;
    private static readonly SONNET_MODEL;
    /**
     * Analyze scan results using AI
     */
    analyzeScanResults(results: any[], target: string): Promise<AnalysisResult>;
    /**
     * Classify a single vulnerability using AI
     */
    classifyVulnerability(vuln: any): Promise<VulnerabilityAnalysis>;
    /**
     * Detect potential zero-day vulnerabilities using advanced AI analysis
     */
    detectZeroDays(findings: any[], target: string): Promise<ZeroDayAnalysis>;
    /**
     * Correlate findings to identify attack chains
     */
    correlateFindings(vulns: any[]): Promise<AttackChain[]>;
    /**
     * Generate exploit proof-of-concept (for authorized testing only)
     */
    generateExploitPOC(vuln: any): Promise<ExploitPOC>;
    /**
     * Assess overall risk from vulnerabilities
     */
    assessRisk(vulns: any[]): Promise<RiskAssessment>;
    /**
     * Build comprehensive analysis prompt
     */
    private buildAnalysisPrompt;
    /**
     * Parse AI analysis response into structured result
     */
    private parseAnalysisResponse;
    /**
     * Parse JSON from AI response
     */
    private parseJSONResponse;
    /**
     * Generate unique ID for vulnerability
     */
    private generateId;
    /**
     * Infer severity from vulnerability data
     */
    private inferSeverity;
}
//# sourceMappingURL=analyzer-agent.d.ts.map