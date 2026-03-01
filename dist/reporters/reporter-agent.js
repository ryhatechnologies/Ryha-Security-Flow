"use strict";
/**
 * Reporter Agent - Evidence Collection & Report Generation
 * Ryha Security Flow - Enterprise Penetration Testing Platform
 */
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
exports.ReporterAgent = void 0;
exports.createReporterAgent = createReporterAgent;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const crypto = __importStar(require("crypto"));
const html_template_1 = require("./templates/html-template");
const compliance_types_1 = require("../compliance/compliance-types");
const copilot_auth_1 = require("../auth/copilot-auth");
/**
 * Reporter Agent Class
 * Collects evidence from scanners/analyzers and generates comprehensive reports
 */
class ReporterAgent {
    constructor(config = {}) {
        this.config = {
            claudeApiKey: config.claudeApiKey || process.env.ANTHROPIC_API_KEY,
            claudeModel: config.claudeModel || 'claude-3-5-sonnet-20241022',
            maxSummaryLength: config.maxSummaryLength || 2000,
            defaultBranding: config.defaultBranding || {
                companyName: 'Ryha Security',
                accentColor: '#0066cc',
                headerColor: '#003d7a',
            },
            complianceFrameworks: config.complianceFrameworks || [
                compliance_types_1.ComplianceFramework.SOC2,
                compliance_types_1.ComplianceFramework.ISO27001,
            ],
        };
        this.evidenceCache = new Map();
    }
    /**
     * Collect evidence from scan job
     */
    async collectEvidence(scanJob) {
        console.log(`[ReporterAgent] Collecting evidence for job: ${scanJob.id}`);
        const toolsUsed = new Set();
        scanJob.vulnerabilities.forEach((vuln) => {
            toolsUsed.add(vuln.toolSource);
        });
        const collection = {
            scanId: scanJob.id,
            vulnerabilities: scanJob.vulnerabilities,
            auditEvents: [],
            toolsUsed,
            collectedAt: new Date(),
        };
        // Cache the evidence
        this.evidenceCache.set(scanJob.id, collection);
        console.log(`[ReporterAgent] Collected ${collection.vulnerabilities.length} vulnerabilities from ${collection.toolsUsed.size} tools`);
        return collection;
    }
    /**
     * Calculate risk score (0-100 scale)
     * Based on vulnerability counts and severity
     */
    calculateRiskScore(vulnerabilities) {
        if (vulnerabilities.length === 0)
            return 0;
        const weights = {
            critical: 25,
            high: 10,
            medium: 5,
            low: 2,
            info: 0.5,
        };
        let totalScore = 0;
        vulnerabilities.forEach((vuln) => {
            totalScore += weights[vuln.severity] || 0;
        });
        // Cap at 100
        const riskScore = Math.min(100, totalScore);
        return Math.round(riskScore);
    }
    /**
     * Determine risk level from score
     */
    getRiskLevel(score) {
        if (score >= 80)
            return 'critical';
        if (score >= 60)
            return 'high';
        if (score >= 40)
            return 'medium';
        return 'low';
    }
    /**
     * Prioritize vulnerabilities by severity and CVSS
     */
    prioritizeVulnerabilities(vulnerabilities) {
        const severityOrder = {
            critical: 0,
            high: 1,
            medium: 2,
            low: 3,
            info: 4,
        };
        return [...vulnerabilities].sort((a, b) => {
            // First sort by severity
            const severityDiff = severityOrder[a.severity] - severityOrder[b.severity];
            if (severityDiff !== 0)
                return severityDiff;
            // Then by CVSS score (descending)
            return b.cvss - a.cvss;
        });
    }
    /**
     * Generate remediation recommendations
     */
    generateRemediationRecommendations(vulnerabilities) {
        const recommendations = [];
        const criticalVulns = vulnerabilities.filter((v) => v.severity === 'critical');
        const highVulns = vulnerabilities.filter((v) => v.severity === 'high');
        // Critical recommendations
        if (criticalVulns.length > 0) {
            recommendations.push(`Immediately address ${criticalVulns.length} critical vulnerabilit${criticalVulns.length > 1 ? 'ies' : 'y'}. These pose severe risk to your infrastructure and should be patched within 24-48 hours.`);
        }
        // High priority recommendations
        if (highVulns.length > 0) {
            recommendations.push(`Prioritize remediation of ${highVulns.length} high-severity vulnerabilit${highVulns.length > 1 ? 'ies' : 'y'}. These should be addressed within the next 7 days.`);
        }
        // Specific recommendations based on vulnerability types
        const vulnTypes = new Map();
        vulnerabilities.forEach((v) => {
            vulnTypes.set(v.type, (vulnTypes.get(v.type) || 0) + 1);
        });
        if (vulnTypes.get('injection')) {
            recommendations.push('Implement input validation and parameterized queries to prevent injection attacks. Use prepared statements and ORM frameworks where possible.');
        }
        if (vulnTypes.get('weak-auth')) {
            recommendations.push('Strengthen authentication mechanisms by implementing multi-factor authentication (MFA), enforcing strong password policies, and using secure session management.');
        }
        if (vulnTypes.get('misconfig')) {
            recommendations.push('Review and harden system configurations. Remove default credentials, disable unnecessary services, and apply security best practices for all deployed systems.');
        }
        if (vulnTypes.get('exposure')) {
            recommendations.push('Minimize attack surface by restricting public exposure of sensitive services. Implement proper access controls and network segmentation.');
        }
        // General recommendations
        recommendations.push('Establish a regular vulnerability scanning and patch management program to identify and address security issues proactively.');
        recommendations.push('Implement security monitoring and logging to detect and respond to potential security incidents in real-time.');
        recommendations.push('Provide security awareness training to development and operations teams to prevent common security mistakes.');
        return recommendations;
    }
    /**
     * Generate executive summary using Claude API
     */
    async generateExecutiveSummary(vulnerabilities, clientName, targetDomain) {
        console.log('[ReporterAgent] Generating executive summary via Claude API...');
        const stats = {
            critical: vulnerabilities.filter((v) => v.severity === 'critical').length,
            high: vulnerabilities.filter((v) => v.severity === 'high').length,
            medium: vulnerabilities.filter((v) => v.severity === 'medium').length,
            low: vulnerabilities.filter((v) => v.severity === 'low').length,
            info: vulnerabilities.filter((v) => v.severity === 'info').length,
        };
        const prompt = `You are a senior security consultant preparing an executive summary for a penetration testing report.

Client: ${clientName}
Target: ${targetDomain}

Vulnerability Statistics:
- Critical: ${stats.critical}
- High: ${stats.high}
- Medium: ${stats.medium}
- Low: ${stats.low}
- Info: ${stats.info}

Top Vulnerabilities:
${vulnerabilities
            .slice(0, 5)
            .map((v, i) => `${i + 1}. ${v.title} (${v.severity.toUpperCase()}) - ${v.description.substring(0, 100)}...`)
            .join('\n')}

Generate a professional executive summary that includes:
1. A concise overview (2-3 paragraphs) suitable for C-level executives
2. Key findings (3-5 bullet points)
3. Critical issues requiring immediate attention
4. Business impact assessment
5. High-level recommendations

Keep the tone professional but accessible to non-technical stakeholders. Focus on business risk and impact rather than technical details.

Return your response in JSON format:
{
  "overview": "string",
  "keyFindings": ["string"],
  "criticalIssues": ["string"],
  "businessImpact": "string",
  "recommendations": ["string"]
}`;
        try {
            // Check if authenticated with GitHub Copilot
            const isAuth = await copilot_auth_1.copilotAuth.isAuthenticated();
            if (!isAuth) {
                console.warn('[ReporterAgent] Not authenticated with GitHub Copilot, using fallback summary');
                return this.generateFallbackSummary(vulnerabilities, stats);
            }
            // Use GitHub Copilot API via copilotAuth
            const content = await copilot_auth_1.copilotAuth.sendChatMessage(prompt, this.config.claudeModel);
            // Extract JSON from response (handle markdown code blocks)
            let jsonText = content;
            const jsonMatch = content.match(/```json\s*([\s\S]*?)\s*```/);
            if (jsonMatch) {
                jsonText = jsonMatch[1];
            }
            const summary = JSON.parse(jsonText);
            console.log('[ReporterAgent] Executive summary generated successfully');
            return summary;
        }
        catch (error) {
            console.error('[ReporterAgent] Failed to generate summary via Copilot API:', error);
            console.log('[ReporterAgent] Using fallback summary');
            return this.generateFallbackSummary(vulnerabilities, stats);
        }
    }
    /**
     * Generate fallback summary when Claude API is unavailable
     */
    generateFallbackSummary(vulnerabilities, stats) {
        const totalVulns = vulnerabilities.length;
        const criticalAndHigh = stats.critical + stats.high;
        return {
            overview: `This penetration testing engagement identified ${totalVulns} security vulnerabilities across the target environment, including ${stats.critical} critical and ${stats.high} high-severity issues that require immediate attention. The assessment reveals significant security gaps that could be exploited by malicious actors to compromise system confidentiality, integrity, or availability. Immediate remediation actions are recommended to reduce organizational risk to an acceptable level.`,
            keyFindings: [
                `${totalVulns} total vulnerabilities discovered across multiple attack surfaces`,
                `${criticalAndHigh} high-priority issues requiring immediate remediation`,
                `Multiple vulnerability classes identified including configuration weaknesses and potential exploitation paths`,
                `Security controls require strengthening to meet industry best practices`,
            ],
            criticalIssues: vulnerabilities
                .filter((v) => v.severity === 'critical')
                .slice(0, 3)
                .map((v) => `${v.title}: ${v.description.substring(0, 100)}...`),
            businessImpact: `The identified vulnerabilities pose significant risk to business operations. Critical and high-severity issues could lead to unauthorized access, data breaches, service disruption, and potential regulatory compliance violations. Immediate action is required to mitigate these risks and protect organizational assets.`,
            recommendations: [
                'Prioritize remediation of critical and high-severity vulnerabilities within the next 7-14 days',
                'Implement security monitoring and incident response capabilities',
                'Establish regular security testing cadence (quarterly recommended)',
                'Enhance security awareness training for development and operations teams',
            ],
        };
    }
    /**
     * Generate compliance attestation
     */
    generateComplianceAttestation() {
        const frameworks = this.config.complianceFrameworks.join(', ');
        return `This penetration testing engagement was conducted in accordance with industry-standard methodologies aligned with ${frameworks} requirements. All testing activities were performed within the scope of written authorization, and findings have been documented with complete chain-of-custody for evidence collection. The assessment methodology included reconnaissance, vulnerability identification, exploitation attempts (where authorized), and comprehensive documentation. All activities were logged for audit purposes and comply with relevant regulatory requirements for security testing and vulnerability disclosure.`;
    }
    /**
     * Generate digital signature for report
     */
    generateSignature(reportData) {
        const dataString = JSON.stringify(reportData);
        const hash = crypto.createHash('sha256').update(dataString).digest('hex');
        return `SHA256:${hash}`;
    }
    /**
     * Generate complete report in specified formats
     */
    async generateReport(scanJob, options = {}) {
        console.log(`[ReporterAgent] Generating report for job: ${scanJob.id}`);
        const opts = {
            format: options.format || ['html', 'json'],
            includeCVSS: options.includeCVSS !== false,
            includeEvidence: options.includeEvidence !== false,
            includeCompliance: options.includeCompliance !== false,
            branding: { ...this.config.defaultBranding, ...options.branding },
            outputDir: options.outputDir || './reports',
        };
        // Collect evidence
        const evidence = await this.collectEvidence(scanJob);
        // Prioritize vulnerabilities
        const prioritizedVulns = this.prioritizeVulnerabilities(evidence.vulnerabilities);
        // Calculate risk score
        const riskScore = this.calculateRiskScore(prioritizedVulns);
        const riskLevel = this.getRiskLevel(riskScore);
        // Generate executive summary
        const executiveSummary = await this.generateExecutiveSummary(prioritizedVulns, 'Client', // Should come from scanJob or config
        scanJob.targetDomain);
        // Generate recommendations
        const recommendations = this.generateRemediationRecommendations(prioritizedVulns);
        // Build report object
        const report = {
            id: `RPT-${Date.now()}`,
            jobId: scanJob.id,
            clientName: 'Client', // Should come from scanJob
            targetDomain: scanJob.targetDomain,
            executiveSummary: executiveSummary.overview,
            vulnerabilities: prioritizedVulns,
            riskScore,
            recommendations,
            tools_used: Array.from(evidence.toolsUsed),
            testedAt: scanJob.startedAt,
            reportedAt: new Date(),
        };
        // Generate signature
        const signature = this.generateSignature(report);
        // Statistics
        const statistics = {
            critical: prioritizedVulns.filter((v) => v.severity === 'critical').length,
            high: prioritizedVulns.filter((v) => v.severity === 'high').length,
            medium: prioritizedVulns.filter((v) => v.severity === 'medium').length,
            low: prioritizedVulns.filter((v) => v.severity === 'low').length,
            info: prioritizedVulns.filter((v) => v.severity === 'info').length,
            total: prioritizedVulns.length,
        };
        // Ensure output directory exists
        if (!fs.existsSync(opts.outputDir)) {
            fs.mkdirSync(opts.outputDir, { recursive: true });
        }
        const result = { report };
        // Generate HTML
        if (opts.format.includes('html')) {
            const templateData = {
                reportId: report.id,
                clientName: report.clientName,
                targetDomain: report.targetDomain,
                executiveSummary: executiveSummary.overview,
                riskScore,
                riskLevel: riskLevel.toUpperCase(),
                vulnerabilities: prioritizedVulns.map((v) => ({
                    id: v.id,
                    title: v.title,
                    severity: v.severity,
                    cvss: v.cvss,
                    description: v.description,
                    evidence: v.evidence,
                    remediation: v.remediationAdvice,
                    cveId: v.cveId,
                    affectedAsset: v.affectedAsset,
                    toolSource: v.toolSource,
                })),
                recommendations,
                toolsUsed: report.tools_used,
                testedAt: report.testedAt,
                reportedAt: report.reportedAt,
                compliance: {
                    soc2: opts.includeCompliance && this.config.complianceFrameworks.includes(compliance_types_1.ComplianceFramework.SOC2),
                    iso27001: opts.includeCompliance && this.config.complianceFrameworks.includes(compliance_types_1.ComplianceFramework.ISO27001),
                    attestation: opts.includeCompliance ? this.generateComplianceAttestation() : '',
                },
                statistics,
                branding: opts.branding,
                signature,
            };
            const htmlContent = (0, html_template_1.generateHTMLReport)(templateData);
            const htmlPath = path.join(opts.outputDir, `${report.id}.html`);
            fs.writeFileSync(htmlPath, htmlContent, 'utf8');
            result.html = htmlPath;
            console.log(`[ReporterAgent] HTML report saved: ${htmlPath}`);
        }
        // Generate JSON
        if (opts.format.includes('json')) {
            const jsonData = {
                ...report,
                riskLevel,
                statistics,
                executiveSummary,
                signature,
                compliance: {
                    frameworks: this.config.complianceFrameworks,
                    attestation: this.generateComplianceAttestation(),
                },
            };
            const jsonPath = path.join(opts.outputDir, `${report.id}.json`);
            fs.writeFileSync(jsonPath, JSON.stringify(jsonData, null, 2), 'utf8');
            result.json = jsonPath;
            console.log(`[ReporterAgent] JSON report saved: ${jsonPath}`);
        }
        // Generate PDF (requires additional library like puppeteer or html-pdf-node)
        if (opts.format.includes('pdf')) {
            console.warn('[ReporterAgent] PDF generation requires puppeteer or html-pdf-node library. HTML report can be converted manually.');
            // Placeholder for PDF generation
            // const pdfPath = path.join(opts.outputDir, `${report.id}.pdf`);
            // await this.generatePDF(htmlContent, pdfPath);
            // result.pdf = pdfPath;
        }
        console.log('[ReporterAgent] Report generation complete');
        return result;
    }
    /**
     * Get vulnerability statistics
     */
    getVulnerabilityStatistics(vulnerabilities) {
        const bySeverity = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
        };
        const byType = {};
        let totalCVSS = 0;
        let zeroDay = 0;
        vulnerabilities.forEach((vuln) => {
            bySeverity[vuln.severity]++;
            byType[vuln.type] = (byType[vuln.type] || 0) + 1;
            totalCVSS += vuln.cvss;
            if (vuln.isZeroDay)
                zeroDay++;
        });
        return {
            bySeverity,
            byType,
            avgCVSS: vulnerabilities.length > 0 ? totalCVSS / vulnerabilities.length : 0,
            zeroDay,
        };
    }
    /**
     * Clear evidence cache
     */
    clearCache() {
        this.evidenceCache.clear();
        console.log('[ReporterAgent] Evidence cache cleared');
    }
}
exports.ReporterAgent = ReporterAgent;
/**
 * Create reporter agent with default configuration
 */
function createReporterAgent(config) {
    return new ReporterAgent(config);
}
//# sourceMappingURL=reporter-agent.js.map