/**
 * Reporter Agent - Evidence Collection & Report Generation
 * Ryha Security Flow - Enterprise Penetration Testing Platform
 */
import { ReportBranding } from './templates/html-template';
import { Vulnerability, PentestReport, SeverityLevel, ScanJob } from '../models/types';
import { ComplianceFramework, AuditEvent } from '../compliance/compliance-types';
/**
 * Report format options
 */
export type ReportFormat = 'html' | 'pdf' | 'json';
/**
 * Report generation options
 */
export interface ReportOptions {
    format: ReportFormat[];
    includeCVSS: boolean;
    includeEvidence: boolean;
    includeCompliance: boolean;
    branding?: Partial<ReportBranding>;
    outputDir: string;
}
/**
 * Risk level classification
 */
export type RiskLevel = 'critical' | 'high' | 'medium' | 'low';
/**
 * Evidence collection result
 */
export interface EvidenceCollection {
    scanId: string;
    vulnerabilities: Vulnerability[];
    auditEvents: AuditEvent[];
    toolsUsed: Set<string>;
    collectedAt: Date;
}
/**
 * Executive summary structure
 */
export interface ExecutiveSummary {
    overview: string;
    keyFindings: string[];
    criticalIssues: string[];
    businessImpact: string;
    recommendations: string[];
}
/**
 * Reporter Agent Configuration
 */
export interface ReporterConfig {
    claudeApiKey?: string;
    claudeModel: string;
    maxSummaryLength: number;
    defaultBranding: ReportBranding;
    complianceFrameworks: ComplianceFramework[];
}
/**
 * Reporter Agent Class
 * Collects evidence from scanners/analyzers and generates comprehensive reports
 */
export declare class ReporterAgent {
    private config;
    private evidenceCache;
    constructor(config?: Partial<ReporterConfig>);
    /**
     * Collect evidence from scan job
     */
    collectEvidence(scanJob: ScanJob): Promise<EvidenceCollection>;
    /**
     * Calculate risk score (0-100 scale)
     * Based on vulnerability counts and severity
     */
    calculateRiskScore(vulnerabilities: Vulnerability[]): number;
    /**
     * Determine risk level from score
     */
    getRiskLevel(score: number): RiskLevel;
    /**
     * Prioritize vulnerabilities by severity and CVSS
     */
    prioritizeVulnerabilities(vulnerabilities: Vulnerability[]): Vulnerability[];
    /**
     * Generate remediation recommendations
     */
    generateRemediationRecommendations(vulnerabilities: Vulnerability[]): string[];
    /**
     * Generate executive summary using Claude API
     */
    generateExecutiveSummary(vulnerabilities: Vulnerability[], clientName: string, targetDomain: string): Promise<ExecutiveSummary>;
    /**
     * Generate fallback summary when Claude API is unavailable
     */
    private generateFallbackSummary;
    /**
     * Generate compliance attestation
     */
    generateComplianceAttestation(): string;
    /**
     * Generate digital signature for report
     */
    generateSignature(reportData: any): string;
    /**
     * Generate complete report in specified formats
     */
    generateReport(scanJob: ScanJob, options?: Partial<ReportOptions>): Promise<{
        html?: string;
        pdf?: string;
        json?: string;
        report: PentestReport;
    }>;
    /**
     * Get vulnerability statistics
     */
    getVulnerabilityStatistics(vulnerabilities: Vulnerability[]): {
        bySeverity: Record<SeverityLevel, number>;
        byType: Record<string, number>;
        avgCVSS: number;
        zeroDay: number;
    };
    /**
     * Clear evidence cache
     */
    clearCache(): void;
}
/**
 * Create reporter agent with default configuration
 */
export declare function createReporterAgent(config?: Partial<ReporterConfig>): ReporterAgent;
//# sourceMappingURL=reporter-agent.d.ts.map