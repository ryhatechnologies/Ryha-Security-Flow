# Reporter Agent - Ryha Security Flow

Enterprise-grade penetration testing report generation with AI-powered executive summaries.

## Features

- **Multi-Format Reports**: Generate reports in HTML, PDF, and JSON formats
- **AI-Powered Summaries**: Executive summaries generated via Claude API
- **Risk Scoring**: Automated 0-100 risk score calculation based on vulnerability severity
- **Vulnerability Prioritization**: Intelligent sorting by severity and CVSS scores
- **Remediation Recommendations**: Actionable fix recommendations
- **Compliance Attestation**: SOC 2 and ISO 27001 aligned documentation
- **Evidence Collection**: Complete audit trail with tool tracking
- **Custom Branding**: White-label reports with company branding
- **Digital Signatures**: SHA-256 hashing for report integrity

## Installation

```bash
npm install
```

Set up environment variables:

```bash
ANTHROPIC_API_KEY=sk-ant-your-api-key
```

## Quick Start

```typescript
import { createReporterAgent } from './reporters/reporter-agent';
import { ScanJob } from './models/types';

// Create reporter agent
const reporter = createReporterAgent({
  claudeApiKey: process.env.ANTHROPIC_API_KEY,
  claudeModel: 'claude-3-5-sonnet-20241022',
});

// Generate report
const result = await reporter.generateReport(scanJob, {
  format: ['html', 'json'],
  includeCVSS: true,
  includeEvidence: true,
  includeCompliance: true,
  outputDir: './reports',
});

console.log(`HTML Report: ${result.html}`);
console.log(`Risk Score: ${result.report.riskScore}/100`);
```

## API Reference

### ReporterAgent

Main class for report generation and evidence collection.

#### Constructor

```typescript
new ReporterAgent(config?: Partial<ReporterConfig>)
```

**Config Options:**
- `claudeApiKey`: Anthropic API key for executive summary generation
- `claudeModel`: Claude model to use (default: claude-3-5-sonnet-20241022)
- `maxSummaryLength`: Maximum summary length in characters
- `defaultBranding`: Company branding configuration
- `complianceFrameworks`: Array of compliance frameworks to include

#### Methods

##### generateReport()

Generate comprehensive penetration testing report.

```typescript
async generateReport(
  scanJob: ScanJob,
  options?: Partial<ReportOptions>
): Promise<{
  html?: string;
  pdf?: string;
  json?: string;
  report: PentestReport;
}>
```

**Options:**
- `format`: Array of formats ['html', 'pdf', 'json']
- `includeCVSS`: Include CVSS scores (default: true)
- `includeEvidence`: Include evidence data (default: true)
- `includeCompliance`: Include compliance attestation (default: true)
- `branding`: Custom branding configuration
- `outputDir`: Output directory for reports (default: './reports')

##### collectEvidence()

Collect evidence from scan job.

```typescript
async collectEvidence(scanJob: ScanJob): Promise<EvidenceCollection>
```

##### calculateRiskScore()

Calculate risk score (0-100 scale) based on vulnerability severity.

```typescript
calculateRiskScore(vulnerabilities: Vulnerability[]): number
```

**Scoring Weights:**
- Critical: 25 points per vulnerability
- High: 10 points per vulnerability
- Medium: 5 points per vulnerability
- Low: 2 points per vulnerability
- Info: 0.5 points per vulnerability

##### prioritizeVulnerabilities()

Sort vulnerabilities by severity and CVSS score.

```typescript
prioritizeVulnerabilities(vulnerabilities: Vulnerability[]): Vulnerability[]
```

##### generateRemediationRecommendations()

Generate actionable remediation recommendations.

```typescript
generateRemediationRecommendations(vulnerabilities: Vulnerability[]): string[]
```

##### generateExecutiveSummary()

Generate AI-powered executive summary via Claude API.

```typescript
async generateExecutiveSummary(
  vulnerabilities: Vulnerability[],
  clientName: string,
  targetDomain: string
): Promise<ExecutiveSummary>
```

##### getVulnerabilityStatistics()

Get detailed vulnerability statistics.

```typescript
getVulnerabilityStatistics(vulnerabilities: Vulnerability[]): {
  bySeverity: Record<SeverityLevel, number>;
  byType: Record<string, number>;
  avgCVSS: number;
  zeroDay: number;
}
```

## Risk Scoring System

Risk scores are calculated on a 0-100 scale:

| Risk Level | Score Range | Implications |
|------------|-------------|--------------|
| Critical   | 80-100      | Severe vulnerabilities requiring immediate action |
| High       | 60-79       | Significant risks requiring urgent remediation |
| Medium     | 40-59       | Moderate risks to address within weeks |
| Low        | 0-39        | Minor issues with minimal risk |

## Report Formats

### HTML Report

Professional HTML report with:
- Executive dashboard with risk score visualization
- Detailed vulnerability sections with evidence
- Remediation recommendations
- Tools methodology documentation
- Compliance attestation
- Digital signature

### JSON Report

Structured JSON output for programmatic consumption:

```json
{
  "id": "RPT-1234567890",
  "jobId": "SCAN-001",
  "riskScore": 75,
  "riskLevel": "high",
  "vulnerabilities": [...],
  "executiveSummary": {...},
  "statistics": {...},
  "compliance": {...},
  "signature": "SHA256:..."
}
```

### PDF Report

PDF generation requires additional setup:

```bash
npm install puppeteer
```

Or manually convert HTML reports to PDF using browser print functionality.

## Custom Branding

Configure white-label reports with company branding:

```typescript
const reporter = createReporterAgent({
  defaultBranding: {
    companyName: 'Acme Security',
    logoUrl: 'https://example.com/logo.png',
    accentColor: '#0066cc',
    headerColor: '#003d7a',
  },
});
```

## Compliance Frameworks

Supported compliance frameworks:
- **SOC 2**: Service Organization Control 2
- **ISO 27001**: Information Security Management
- **GDPR**: General Data Protection Regulation
- **HIPAA**: Health Insurance Portability and Accountability Act
- **PCI DSS**: Payment Card Industry Data Security Standard

Configure frameworks:

```typescript
const reporter = createReporterAgent({
  complianceFrameworks: [
    ComplianceFramework.SOC2,
    ComplianceFramework.ISO27001,
  ],
});
```

## Examples

See `example.ts` for complete usage examples:

1. **Basic Report Generation**: Generate HTML and JSON reports
2. **Risk Score Calculation**: Calculate risk scores for different scenarios
3. **Vulnerability Prioritization**: Sort vulnerabilities intelligently
4. **Evidence Collection**: Collect and track evidence from scans
5. **Vulnerability Statistics**: Get detailed vulnerability breakdowns
6. **Custom Branding**: Configure white-label reports
7. **Remediation Recommendations**: Generate actionable recommendations

Run examples:

```bash
npm run dev -- reporters/example.ts
```

## Best Practices

### Security

- Never commit API keys to version control
- Store sensitive data encrypted at rest
- Use digital signatures to verify report integrity
- Implement access controls for report distribution

### Report Generation

- Generate reports immediately after scan completion
- Include comprehensive evidence for all findings
- Prioritize vulnerabilities consistently
- Provide actionable remediation guidance
- Include business impact context for executives

### Executive Summaries

- Keep summaries concise (2-3 paragraphs)
- Focus on business risk, not technical details
- Highlight critical issues requiring immediate attention
- Provide clear recommendations with timelines
- Use accessible language for non-technical stakeholders

## Architecture

```
reporters/
├── reporter-agent.ts       # Main reporter agent class
├── templates/
│   └── html-template.ts   # HTML report template
├── example.ts             # Usage examples
└── README.md              # Documentation
```

### Component Responsibilities

- **ReporterAgent**: Core report generation logic
- **HTML Template**: Professional report styling
- **Evidence Collection**: Audit trail management
- **Risk Scoring**: Automated risk calculation
- **AI Summaries**: Claude API integration
- **Compliance**: Framework attestation

## Integration

### With Scan Jobs

```typescript
import { ReporterAgent } from './reporters/reporter-agent';

async function onScanComplete(scanJob: ScanJob) {
  const reporter = new ReporterAgent();
  const result = await reporter.generateReport(scanJob);

  console.log(`Report generated: ${result.html}`);
  await notifyClient(result.report);
}
```

### With CI/CD

```yaml
# .github/workflows/security-scan.yml
- name: Generate Security Report
  run: |
    npm run scan
    npm run report
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

### With Alerting

```typescript
if (report.riskScore >= 80) {
  await sendAlert({
    severity: 'critical',
    message: `Critical security issues detected (Risk: ${report.riskScore}/100)`,
    report: report,
  });
}
```

## Troubleshooting

### Claude API Errors

If executive summary generation fails, the reporter falls back to a template-based summary. Check:

- API key is valid and has credits
- Network connectivity to api.anthropic.com
- Rate limits are not exceeded

### Missing Reports

Ensure output directory exists and has write permissions:

```bash
mkdir -p ./reports
chmod 755 ./reports
```

### PDF Generation

PDF support requires additional libraries. For now, use browser print-to-PDF:

1. Open HTML report in browser
2. Press Ctrl+P (Cmd+P on Mac)
3. Select "Save as PDF"
4. Adjust margins and scaling as needed

## Contributing

When adding new features:

1. Follow TypeScript strict mode
2. Add comprehensive error handling
3. Update examples and documentation
4. Test with various scan scenarios
5. Maintain backward compatibility

## License

MIT License - See LICENSE file for details

## Support

For issues or questions:
- GitHub Issues: https://github.com/ruvnet/ryha-security-flow/issues
- Documentation: https://docs.ryha-security.com

---

Built with ❤️ for Enterprise Security Teams
