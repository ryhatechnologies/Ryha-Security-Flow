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

export function generateHTMLReport(data: TemplateData): string {
  const criticalBar = (data.statistics.critical / data.statistics.total) * 100;
  const highBar = (data.statistics.high / data.statistics.total) * 100;
  const mediumBar = (data.statistics.medium / data.statistics.total) * 100;
  const lowBar = (data.statistics.low / data.statistics.total) * 100;

  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - ${data.clientName}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }

        /* Header */
        .header {
            background: linear-gradient(135deg, ${data.branding.headerColor} 0%, ${data.branding.accentColor} 100%);
            color: white;
            padding: 40px;
            position: relative;
            overflow: hidden;
        }

        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg width="100" height="100" xmlns="http://www.w3.org/2000/svg"><defs><pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse"><path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="1"/></pattern></defs><rect width="100%" height="100%" fill="url(%23grid)" /></svg>');
            opacity: 0.3;
        }

        .header-content {
            position: relative;
            z-index: 1;
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 20px;
        }

        .logo img {
            height: 60px;
            filter: brightness(0) invert(1);
        }

        .logo h1 {
            font-size: 32px;
            font-weight: 700;
        }

        .header-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }

        .info-box {
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 8px;
            backdrop-filter: blur(10px);
        }

        .info-box label {
            display: block;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            opacity: 0.9;
            margin-bottom: 5px;
        }

        .info-box .value {
            font-size: 18px;
            font-weight: 600;
        }

        /* Risk Score Dashboard */
        .risk-dashboard {
            padding: 40px;
            background: linear-gradient(to bottom, #fff 0%, #f8f9fa 100%);
            border-bottom: 3px solid #e9ecef;
        }

        .risk-score-circle {
            width: 200px;
            height: 200px;
            margin: 0 auto 30px;
            position: relative;
        }

        .risk-score-circle svg {
            transform: rotate(-90deg);
        }

        .risk-score-circle .score-text {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
        }

        .risk-score-circle .score-number {
            display: block;
            font-size: 48px;
            font-weight: 700;
            color: #333;
        }

        .risk-score-circle .score-label {
            display: block;
            font-size: 14px;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 2px;
        }

        .risk-level {
            text-align: center;
            margin-bottom: 30px;
        }

        .risk-badge {
            display: inline-block;
            padding: 10px 30px;
            border-radius: 50px;
            font-size: 18px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 2px;
        }

        .risk-critical { background: #dc3545; color: white; }
        .risk-high { background: #fd7e14; color: white; }
        .risk-medium { background: #ffc107; color: #333; }
        .risk-low { background: #28a745; color: white; }

        /* Statistics */
        .statistics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }

        .stat-card {
            text-align: center;
            padding: 20px;
            background: white;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            border-top: 4px solid;
        }

        .stat-card.critical { border-top-color: #dc3545; }
        .stat-card.high { border-top-color: #fd7e14; }
        .stat-card.medium { border-top-color: #ffc107; }
        .stat-card.low { border-top-color: #28a745; }
        .stat-card.info { border-top-color: #17a2b8; }

        .stat-number {
            display: block;
            font-size: 36px;
            font-weight: 700;
            margin-bottom: 5px;
        }

        .stat-label {
            display: block;
            font-size: 14px;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        /* Content Sections */
        .section {
            padding: 40px;
            border-bottom: 1px solid #e9ecef;
        }

        .section-title {
            font-size: 28px;
            font-weight: 700;
            color: ${data.branding.accentColor};
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid ${data.branding.accentColor};
        }

        .executive-summary {
            background: #f8f9fa;
            padding: 30px;
            border-radius: 12px;
            border-left: 5px solid ${data.branding.accentColor};
            margin-top: 20px;
            font-size: 16px;
            line-height: 1.8;
        }

        /* Vulnerabilities */
        .vulnerability {
            background: white;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            margin-bottom: 30px;
            overflow: hidden;
            border-left: 5px solid;
        }

        .vulnerability.critical { border-left-color: #dc3545; }
        .vulnerability.high { border-left-color: #fd7e14; }
        .vulnerability.medium { border-left-color: #ffc107; }
        .vulnerability.low { border-left-color: #28a745; }

        .vuln-header {
            padding: 20px;
            background: #f8f9fa;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }

        .vuln-title {
            font-size: 20px;
            font-weight: 700;
            margin-bottom: 5px;
        }

        .vuln-meta {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            margin-top: 10px;
        }

        .badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }

        .badge.critical { background: #dc3545; color: white; }
        .badge.high { background: #fd7e14; color: white; }
        .badge.medium { background: #ffc107; color: #333; }
        .badge.low { background: #28a745; color: white; }

        .cvss-score {
            background: #17a2b8;
            color: white;
            padding: 8px 15px;
            border-radius: 8px;
            font-weight: 700;
        }

        .vuln-body {
            padding: 25px;
        }

        .vuln-section {
            margin-bottom: 20px;
        }

        .vuln-section h4 {
            color: #495057;
            margin-bottom: 10px;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .vuln-section p {
            color: #666;
            line-height: 1.8;
        }

        .evidence-list {
            list-style: none;
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
        }

        .evidence-list li {
            padding: 8px;
            border-left: 3px solid ${data.branding.accentColor};
            margin-bottom: 8px;
            background: white;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }

        .remediation-box {
            background: #d1ecf1;
            border: 1px solid #bee5eb;
            padding: 20px;
            border-radius: 8px;
            border-left: 5px solid #17a2b8;
        }

        /* Recommendations */
        .recommendations-list {
            list-style: none;
            counter-reset: recommendation;
        }

        .recommendations-list li {
            counter-increment: recommendation;
            background: white;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            position: relative;
            padding-left: 60px;
        }

        .recommendations-list li::before {
            content: counter(recommendation);
            position: absolute;
            left: 20px;
            top: 20px;
            width: 30px;
            height: 30px;
            background: ${data.branding.accentColor};
            color: white;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
        }

        /* Tools Table */
        .tools-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }

        .tools-table th {
            background: ${data.branding.accentColor};
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }

        .tools-table td {
            padding: 15px;
            border-bottom: 1px solid #e9ecef;
        }

        .tools-table tr:hover {
            background: #f8f9fa;
        }

        /* Compliance */
        .compliance-badges {
            display: flex;
            gap: 20px;
            margin-top: 20px;
            flex-wrap: wrap;
        }

        .compliance-badge {
            background: white;
            border: 2px solid;
            padding: 20px 30px;
            border-radius: 12px;
            text-align: center;
            flex: 1;
            min-width: 200px;
        }

        .compliance-badge.verified {
            border-color: #28a745;
            background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%);
        }

        .compliance-badge .icon {
            font-size: 36px;
            margin-bottom: 10px;
        }

        .compliance-badge .label {
            display: block;
            font-weight: 700;
            font-size: 18px;
            margin-bottom: 5px;
        }

        .compliance-badge .status {
            display: block;
            font-size: 14px;
            color: #666;
        }

        .attestation {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-top: 20px;
            font-style: italic;
            border-left: 5px solid #6c757d;
        }

        /* Footer */
        .footer {
            padding: 30px 40px;
            background: #343a40;
            color: white;
            text-align: center;
        }

        .signature {
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #495057;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            word-break: break-all;
        }

        /* Print Styles */
        @media print {
            body {
                background: white;
            }
            .container {
                box-shadow: none;
            }
            .vulnerability {
                page-break-inside: avoid;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-content">
                <div class="logo">
                    ${data.branding.logoUrl ? `<img src="${data.branding.logoUrl}" alt="${data.branding.companyName}">` : ''}
                    <h1>${data.branding.companyName}</h1>
                </div>
                <h2>PENETRATION TESTING REPORT</h2>
                <div class="header-info">
                    <div class="info-box">
                        <label>Report ID</label>
                        <div class="value">${data.reportId}</div>
                    </div>
                    <div class="info-box">
                        <label>Client</label>
                        <div class="value">${data.clientName}</div>
                    </div>
                    <div class="info-box">
                        <label>Target</label>
                        <div class="value">${data.targetDomain}</div>
                    </div>
                    <div class="info-box">
                        <label>Tested</label>
                        <div class="value">${data.testedAt.toLocaleDateString()}</div>
                    </div>
                    <div class="info-box">
                        <label>Reported</label>
                        <div class="value">${data.reportedAt.toLocaleDateString()}</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Risk Dashboard -->
        <div class="risk-dashboard">
            <div class="risk-score-circle">
                <svg width="200" height="200">
                    <circle cx="100" cy="100" r="90" fill="none" stroke="#e9ecef" stroke-width="20"/>
                    <circle cx="100" cy="100" r="90" fill="none"
                            stroke="${data.riskScore >= 80 ? '#dc3545' : data.riskScore >= 60 ? '#fd7e14' : data.riskScore >= 40 ? '#ffc107' : '#28a745'}"
                            stroke-width="20"
                            stroke-dasharray="${(data.riskScore / 100) * 565.48} 565.48"
                            stroke-linecap="round"/>
                </svg>
                <div class="score-text">
                    <span class="score-number">${data.riskScore}</span>
                    <span class="score-label">Risk Score</span>
                </div>
            </div>

            <div class="risk-level">
                <span class="risk-badge ${data.riskLevel.toLowerCase()}">${data.riskLevel} RISK</span>
            </div>

            <div class="statistics">
                <div class="stat-card critical">
                    <span class="stat-number">${data.statistics.critical}</span>
                    <span class="stat-label">Critical</span>
                </div>
                <div class="stat-card high">
                    <span class="stat-number">${data.statistics.high}</span>
                    <span class="stat-label">High</span>
                </div>
                <div class="stat-card medium">
                    <span class="stat-number">${data.statistics.medium}</span>
                    <span class="stat-label">Medium</span>
                </div>
                <div class="stat-card low">
                    <span class="stat-number">${data.statistics.low}</span>
                    <span class="stat-label">Low</span>
                </div>
                <div class="stat-card info">
                    <span class="stat-number">${data.statistics.info}</span>
                    <span class="stat-label">Info</span>
                </div>
            </div>
        </div>

        <!-- Executive Summary -->
        <div class="section">
            <h2 class="section-title">Executive Summary</h2>
            <div class="executive-summary">
                ${data.executiveSummary}
            </div>
        </div>

        <!-- Vulnerabilities -->
        <div class="section">
            <h2 class="section-title">Vulnerability Details</h2>
            ${data.vulnerabilities.map((vuln) => `
                <div class="vulnerability ${vuln.severity}">
                    <div class="vuln-header">
                        <div>
                            <div class="vuln-title">${vuln.title}</div>
                            <div class="vuln-meta">
                                <span class="badge ${vuln.severity}">${vuln.severity}</span>
                                ${vuln.cveId ? `<span class="badge" style="background: #6c757d; color: white;">${vuln.cveId}</span>` : ''}
                                <span class="cvss-score">CVSS: ${vuln.cvss.toFixed(1)}</span>
                            </div>
                        </div>
                    </div>
                    <div class="vuln-body">
                        <div class="vuln-section">
                            <h4>Description</h4>
                            <p>${vuln.description}</p>
                        </div>
                        <div class="vuln-section">
                            <h4>Affected Asset</h4>
                            <p><strong>${vuln.affectedAsset}</strong></p>
                        </div>
                        <div class="vuln-section">
                            <h4>Evidence</h4>
                            <ul class="evidence-list">
                                ${vuln.evidence.map(e => `<li>${e}</li>`).join('')}
                            </ul>
                        </div>
                        <div class="vuln-section">
                            <h4>Remediation</h4>
                            <div class="remediation-box">
                                ${vuln.remediation}
                            </div>
                        </div>
                        <div class="vuln-section">
                            <h4>Discovery</h4>
                            <p><em>Discovered by: ${vuln.toolSource}</em></p>
                        </div>
                    </div>
                </div>
            `).join('')}
        </div>

        <!-- Recommendations -->
        <div class="section">
            <h2 class="section-title">Remediation Recommendations</h2>
            <ul class="recommendations-list">
                ${data.recommendations.map(rec => `<li>${rec}</li>`).join('')}
            </ul>
        </div>

        <!-- Tools Used -->
        <div class="section">
            <h2 class="section-title">Testing Methodology & Tools</h2>
            <table class="tools-table">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Tool / Technique</th>
                        <th>Purpose</th>
                    </tr>
                </thead>
                <tbody>
                    ${data.toolsUsed.map((tool, index) => `
                        <tr>
                            <td>${index + 1}</td>
                            <td><strong>${tool}</strong></td>
                            <td>Security assessment and vulnerability discovery</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>

        <!-- Compliance -->
        <div class="section">
            <h2 class="section-title">Compliance & Attestation</h2>
            <div class="compliance-badges">
                <div class="compliance-badge ${data.compliance.soc2 ? 'verified' : ''}">
                    <div class="icon">✓</div>
                    <span class="label">SOC 2</span>
                    <span class="status">${data.compliance.soc2 ? 'Aligned' : 'Not Aligned'}</span>
                </div>
                <div class="compliance-badge ${data.compliance.iso27001 ? 'verified' : ''}">
                    <div class="icon">✓</div>
                    <span class="label">ISO 27001</span>
                    <span class="status">${data.compliance.iso27001 ? 'Aligned' : 'Not Aligned'}</span>
                </div>
            </div>
            <div class="attestation">
                ${data.compliance.attestation}
            </div>
        </div>

        <!-- Footer -->
        <div class="footer">
            <p><strong>${data.branding.companyName}</strong></p>
            <p>Enterprise Penetration Testing Platform</p>
            <p>Report Generated: ${data.reportedAt.toISOString()}</p>
            <div class="signature">
                <strong>Digital Signature:</strong><br>
                ${data.signature}
            </div>
        </div>
    </div>
</body>
</html>`;
}
