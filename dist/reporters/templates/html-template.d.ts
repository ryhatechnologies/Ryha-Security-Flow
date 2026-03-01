/**
 * Professional HTML Report Template
 * Ryha Security Flow - Enterprise Penetration Testing Report
 */
export interface ReportBranding {
    companyName: string;
    logoUrl?: string;
    accentColor: string;
    headerColor: string;
}
export interface TemplateData {
    reportId: string;
    clientName: string;
    targetDomain: string;
    executiveSummary: string;
    riskScore: number;
    riskLevel: string;
    vulnerabilities: Array<{
        id: string;
        title: string;
        severity: string;
        cvss: number;
        description: string;
        evidence: string[];
        remediation: string;
        cveId?: string;
        affectedAsset: string;
        toolSource: string;
    }>;
    recommendations: string[];
    toolsUsed: string[];
    testedAt: Date;
    reportedAt: Date;
    compliance: {
        soc2: boolean;
        iso27001: boolean;
        attestation: string;
    };
    statistics: {
        critical: number;
        high: number;
        medium: number;
        low: number;
        info: number;
        total: number;
    };
    branding: ReportBranding;
    signature: string;
}
export declare function generateHTMLReport(data: TemplateData): string;
//# sourceMappingURL=html-template.d.ts.map