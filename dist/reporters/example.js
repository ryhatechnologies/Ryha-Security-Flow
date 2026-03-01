"use strict";
/**
 * Reporter Agent Usage Examples
 * Ryha Security Flow - Enterprise Penetration Testing Platform
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.example1_basicReport = example1_basicReport;
exports.example2_riskScoring = example2_riskScoring;
exports.example3_prioritization = example3_prioritization;
exports.example4_evidenceCollection = example4_evidenceCollection;
exports.example5_statistics = example5_statistics;
exports.example6_customBranding = example6_customBranding;
exports.example7_recommendations = example7_recommendations;
const reporter_agent_1 = require("./reporter-agent");
/**
 * Example 1: Basic Report Generation
 */
async function example1_basicReport() {
    console.log('\n=== Example 1: Basic Report Generation ===\n');
    // Create reporter agent (uses GitHub Copilot auth for AI summaries)
    const reporter = (0, reporter_agent_1.createReporterAgent)({
        claudeModel: 'claude-3-5-sonnet-20241022',
    });
    // Sample scan job with vulnerabilities
    const scanJob = {
        id: 'SCAN-2026-001',
        authDocId: 'AUTH-001',
        targetDomain: 'example.com',
        scanType: 'web',
        status: 'completed',
        startedAt: new Date('2026-03-01T10:00:00Z'),
        completedAt: new Date('2026-03-01T12:30:00Z'),
        vulnerabilities: [
            {
                id: 'VULN-001',
                title: 'SQL Injection in Login Form',
                description: 'The login form is vulnerable to SQL injection attacks via the username parameter. An attacker can bypass authentication and gain unauthorized access to the database.',
                type: 'injection',
                severity: 'critical',
                cvss: 9.8,
                cveId: undefined,
                cwePrimary: 'CWE-89',
                affectedAsset: 'https://example.com/login',
                discoveredAt: new Date(),
                evidence: [
                    "Payload: admin' OR '1'='1",
                    'Response: 200 OK with session token',
                    'Database error: syntax error near OR',
                ],
                remediationAdvice: 'Use parameterized queries or prepared statements for all database operations. Never concatenate user input directly into SQL queries. Implement input validation and use an ORM framework.',
                toolSource: 'SQLMap',
                isZeroDay: false,
            },
            {
                id: 'VULN-002',
                title: 'Weak Password Policy',
                description: 'The application allows weak passwords with no complexity requirements. Users can set passwords as short as 4 characters with no special character requirements.',
                type: 'weak-auth',
                severity: 'high',
                cvss: 7.5,
                affectedAsset: 'https://example.com/register',
                discoveredAt: new Date(),
                evidence: [
                    'Successfully created account with password: "1234"',
                    'No password complexity validation observed',
                    'No account lockout after failed attempts',
                ],
                remediationAdvice: 'Implement strong password policy requiring: minimum 12 characters, uppercase and lowercase letters, numbers, and special characters. Implement account lockout after 5 failed attempts. Consider implementing MFA.',
                toolSource: 'Manual Testing',
                isZeroDay: false,
            },
            {
                id: 'VULN-003',
                title: 'Exposed API Endpoints',
                description: 'Several API endpoints are publicly accessible without authentication, exposing sensitive user data and administrative functions.',
                type: 'exposure',
                severity: 'high',
                cvss: 8.2,
                affectedAsset: 'https://api.example.com/*',
                discoveredAt: new Date(),
                evidence: [
                    'GET /api/users - Returns list of all users with emails',
                    'GET /api/admin/logs - Accessible without authentication',
                    'POST /api/admin/config - Allows configuration changes',
                ],
                remediationAdvice: 'Implement proper authentication and authorization for all API endpoints. Use OAuth 2.0 or JWT tokens. Implement role-based access control (RBAC) and validate permissions on every request.',
                toolSource: 'Burp Suite',
                isZeroDay: false,
            },
            {
                id: 'VULN-004',
                title: 'Missing Security Headers',
                description: 'Critical security headers are missing, increasing vulnerability to XSS, clickjacking, and other client-side attacks.',
                type: 'misconfig',
                severity: 'medium',
                cvss: 5.3,
                affectedAsset: 'https://example.com',
                discoveredAt: new Date(),
                evidence: [
                    'Missing: Content-Security-Policy',
                    'Missing: X-Frame-Options',
                    'Missing: X-Content-Type-Options',
                    'Missing: Strict-Transport-Security',
                ],
                remediationAdvice: 'Implement all recommended security headers including CSP, X-Frame-Options (DENY), X-Content-Type-Options (nosniff), and HSTS with max-age of at least 31536000 seconds.',
                toolSource: 'Nmap',
                isZeroDay: false,
            },
            {
                id: 'VULN-005',
                title: 'Outdated JavaScript Libraries',
                description: 'The application uses outdated versions of JavaScript libraries with known security vulnerabilities.',
                type: 'cve',
                severity: 'medium',
                cvss: 6.1,
                cveId: 'CVE-2023-26116',
                cwePrimary: 'CWE-1104',
                affectedAsset: 'https://example.com/static/js/*',
                discoveredAt: new Date(),
                evidence: [
                    'jQuery v2.1.4 detected (vulnerable to XSS)',
                    'Lodash v3.10.1 detected (prototype pollution)',
                    'Angular v1.5.8 detected (multiple CVEs)',
                ],
                remediationAdvice: 'Update all JavaScript libraries to their latest stable versions. Implement automated dependency scanning in your CI/CD pipeline using tools like npm audit or Snyk.',
                toolSource: 'Retire.js',
                isZeroDay: false,
            },
        ],
        agentsAssigned: ['scanner-01', 'analyzer-01'],
        progressPercent: 100,
        totalVulnerabilitiesFound: 5,
        criticalCount: 1,
        highCount: 2,
    };
    // Generate HTML and JSON reports
    const options = {
        format: ['html', 'json'],
        includeCVSS: true,
        includeEvidence: true,
        includeCompliance: true,
        outputDir: './reports',
        branding: {
            companyName: 'Acme Security',
            accentColor: '#0066cc',
            headerColor: '#003d7a',
        },
    };
    const result = await reporter.generateReport(scanJob, options);
    console.log('Report generated successfully:');
    console.log(`- HTML: ${result.html}`);
    console.log(`- JSON: ${result.json}`);
    console.log(`- Risk Score: ${result.report.riskScore}/100`);
    console.log(`- Total Vulnerabilities: ${result.report.vulnerabilities.length}`);
}
/**
 * Example 2: Risk Score Calculation
 */
function example2_riskScoring() {
    console.log('\n=== Example 2: Risk Score Calculation ===\n');
    const reporter = (0, reporter_agent_1.createReporterAgent)();
    const scenarios = [
        {
            name: 'Low Risk',
            vulns: [
                { severity: 'low', cvss: 3.1 },
                { severity: 'low', cvss: 2.5 },
                { severity: 'info', cvss: 0.0 },
            ],
        },
        {
            name: 'Medium Risk',
            vulns: [
                { severity: 'medium', cvss: 5.3 },
                { severity: 'medium', cvss: 6.1 },
                { severity: 'low', cvss: 3.7 },
            ],
        },
        {
            name: 'High Risk',
            vulns: [
                { severity: 'high', cvss: 7.5 },
                { severity: 'high', cvss: 8.2 },
                { severity: 'medium', cvss: 5.3 },
            ],
        },
        {
            name: 'Critical Risk',
            vulns: [
                { severity: 'critical', cvss: 9.8 },
                { severity: 'critical', cvss: 9.1 },
                { severity: 'high', cvss: 8.5 },
                { severity: 'high', cvss: 7.8 },
            ],
        },
    ];
    scenarios.forEach((scenario) => {
        const mockVulns = scenario.vulns.map((v, i) => ({
            id: `V${i}`,
            title: `Test Vulnerability ${i}`,
            description: 'Test',
            type: 'cve',
            severity: v.severity,
            cvss: v.cvss,
            affectedAsset: 'test',
            discoveredAt: new Date(),
            evidence: [],
            remediationAdvice: 'Test',
            toolSource: 'Test',
            isZeroDay: false,
        }));
        const riskScore = reporter.calculateRiskScore(mockVulns);
        const riskLevel = reporter.getRiskLevel(riskScore);
        console.log(`${scenario.name}:`);
        console.log(`  Score: ${riskScore}/100`);
        console.log(`  Level: ${riskLevel.toUpperCase()}`);
        console.log();
    });
}
/**
 * Example 3: Vulnerability Prioritization
 */
function example3_prioritization() {
    console.log('\n=== Example 3: Vulnerability Prioritization ===\n');
    const reporter = (0, reporter_agent_1.createReporterAgent)();
    const unsortedVulns = [
        {
            id: 'V1',
            title: 'Medium CVSS 6.0',
            description: 'Test',
            type: 'cve',
            severity: 'medium',
            cvss: 6.0,
            affectedAsset: 'test',
            discoveredAt: new Date(),
            evidence: [],
            remediationAdvice: 'Test',
            toolSource: 'Test',
            isZeroDay: false,
        },
        {
            id: 'V2',
            title: 'Critical CVSS 9.8',
            description: 'Test',
            type: 'cve',
            severity: 'critical',
            cvss: 9.8,
            affectedAsset: 'test',
            discoveredAt: new Date(),
            evidence: [],
            remediationAdvice: 'Test',
            toolSource: 'Test',
            isZeroDay: false,
        },
        {
            id: 'V3',
            title: 'High CVSS 7.5',
            description: 'Test',
            type: 'cve',
            severity: 'high',
            cvss: 7.5,
            affectedAsset: 'test',
            discoveredAt: new Date(),
            evidence: [],
            remediationAdvice: 'Test',
            toolSource: 'Test',
            isZeroDay: false,
        },
        {
            id: 'V4',
            title: 'Critical CVSS 9.1',
            description: 'Test',
            type: 'cve',
            severity: 'critical',
            cvss: 9.1,
            affectedAsset: 'test',
            discoveredAt: new Date(),
            evidence: [],
            remediationAdvice: 'Test',
            toolSource: 'Test',
            isZeroDay: false,
        },
        {
            id: 'V5',
            title: 'Low CVSS 3.1',
            description: 'Test',
            type: 'cve',
            severity: 'low',
            cvss: 3.1,
            affectedAsset: 'test',
            discoveredAt: new Date(),
            evidence: [],
            remediationAdvice: 'Test',
            toolSource: 'Test',
            isZeroDay: false,
        },
    ];
    const prioritized = reporter.prioritizeVulnerabilities(unsortedVulns);
    console.log('Prioritized Vulnerabilities:');
    prioritized.forEach((vuln, index) => {
        console.log(`${index + 1}. [${vuln.severity.toUpperCase()}] ${vuln.title} (CVSS: ${vuln.cvss})`);
    });
}
/**
 * Example 4: Evidence Collection
 */
async function example4_evidenceCollection() {
    console.log('\n=== Example 4: Evidence Collection ===\n');
    const reporter = (0, reporter_agent_1.createReporterAgent)();
    const scanJob = {
        id: 'SCAN-2026-002',
        authDocId: 'AUTH-001',
        targetDomain: 'example.com',
        scanType: 'full',
        status: 'completed',
        startedAt: new Date(),
        completedAt: new Date(),
        vulnerabilities: [
            {
                id: 'V1',
                title: 'Test Vulnerability 1',
                description: 'Test',
                type: 'cve',
                severity: 'critical',
                cvss: 9.8,
                affectedAsset: 'test',
                discoveredAt: new Date(),
                evidence: ['Evidence 1', 'Evidence 2'],
                remediationAdvice: 'Test',
                toolSource: 'Nmap',
                isZeroDay: false,
            },
            {
                id: 'V2',
                title: 'Test Vulnerability 2',
                description: 'Test',
                type: 'cve',
                severity: 'high',
                cvss: 8.2,
                affectedAsset: 'test',
                discoveredAt: new Date(),
                evidence: ['Evidence 3'],
                remediationAdvice: 'Test',
                toolSource: 'Burp Suite',
                isZeroDay: false,
            },
            {
                id: 'V3',
                title: 'Test Vulnerability 3',
                description: 'Test',
                type: 'cve',
                severity: 'medium',
                cvss: 5.3,
                affectedAsset: 'test',
                discoveredAt: new Date(),
                evidence: ['Evidence 4', 'Evidence 5'],
                remediationAdvice: 'Test',
                toolSource: 'SQLMap',
                isZeroDay: false,
            },
        ],
        agentsAssigned: ['scanner-01'],
        progressPercent: 100,
        totalVulnerabilitiesFound: 3,
        criticalCount: 1,
        highCount: 1,
    };
    const evidence = await reporter.collectEvidence(scanJob);
    console.log('Evidence Collection Results:');
    console.log(`- Scan ID: ${evidence.scanId}`);
    console.log(`- Total Vulnerabilities: ${evidence.vulnerabilities.length}`);
    console.log(`- Tools Used: ${Array.from(evidence.toolsUsed).join(', ')}`);
    console.log(`- Collected At: ${evidence.collectedAt.toISOString()}`);
}
/**
 * Example 5: Vulnerability Statistics
 */
function example5_statistics() {
    console.log('\n=== Example 5: Vulnerability Statistics ===\n');
    const reporter = (0, reporter_agent_1.createReporterAgent)();
    const vulnerabilities = [
        {
            id: 'V1',
            title: 'SQLi',
            description: 'Test',
            type: 'injection',
            severity: 'critical',
            cvss: 9.8,
            affectedAsset: 'test',
            discoveredAt: new Date(),
            evidence: [],
            remediationAdvice: 'Test',
            toolSource: 'Test',
            isZeroDay: true,
        },
        {
            id: 'V2',
            title: 'XSS',
            description: 'Test',
            type: 'injection',
            severity: 'high',
            cvss: 7.5,
            affectedAsset: 'test',
            discoveredAt: new Date(),
            evidence: [],
            remediationAdvice: 'Test',
            toolSource: 'Test',
            isZeroDay: false,
        },
        {
            id: 'V3',
            title: 'Weak Auth',
            description: 'Test',
            type: 'weak-auth',
            severity: 'high',
            cvss: 8.2,
            affectedAsset: 'test',
            discoveredAt: new Date(),
            evidence: [],
            remediationAdvice: 'Test',
            toolSource: 'Test',
            isZeroDay: false,
        },
        {
            id: 'V4',
            title: 'Misconfig',
            description: 'Test',
            type: 'misconfig',
            severity: 'medium',
            cvss: 5.3,
            affectedAsset: 'test',
            discoveredAt: new Date(),
            evidence: [],
            remediationAdvice: 'Test',
            toolSource: 'Test',
            isZeroDay: false,
        },
    ];
    const stats = reporter.getVulnerabilityStatistics(vulnerabilities);
    console.log('Vulnerability Statistics:');
    console.log('\nBy Severity:');
    Object.entries(stats.bySeverity).forEach(([severity, count]) => {
        if (count > 0) {
            console.log(`  ${severity}: ${count}`);
        }
    });
    console.log('\nBy Type:');
    Object.entries(stats.byType).forEach(([type, count]) => {
        console.log(`  ${type}: ${count}`);
    });
    console.log(`\nAverage CVSS: ${stats.avgCVSS.toFixed(1)}`);
    console.log(`Zero-Day Vulnerabilities: ${stats.zeroDay}`);
}
/**
 * Example 6: Custom Branding
 */
async function example6_customBranding() {
    console.log('\n=== Example 6: Custom Branding ===\n');
    const reporter = (0, reporter_agent_1.createReporterAgent)({
        defaultBranding: {
            companyName: 'SecureOps Pro',
            logoUrl: 'https://example.com/logo.png',
            accentColor: '#ff6b35',
            headerColor: '#1a1a2e',
        },
    });
    console.log('Reporter configured with custom branding:');
    console.log('- Company: SecureOps Pro');
    console.log('- Accent Color: #ff6b35');
    console.log('- Header Color: #1a1a2e');
}
/**
 * Example 7: Generating Remediation Recommendations
 */
function example7_recommendations() {
    console.log('\n=== Example 7: Remediation Recommendations ===\n');
    const reporter = (0, reporter_agent_1.createReporterAgent)();
    const vulnerabilities = [
        {
            id: 'V1',
            title: 'SQL Injection',
            description: 'Test',
            type: 'injection',
            severity: 'critical',
            cvss: 9.8,
            affectedAsset: 'test',
            discoveredAt: new Date(),
            evidence: [],
            remediationAdvice: 'Test',
            toolSource: 'Test',
            isZeroDay: false,
        },
        {
            id: 'V2',
            title: 'Weak Password',
            description: 'Test',
            type: 'weak-auth',
            severity: 'high',
            cvss: 7.5,
            affectedAsset: 'test',
            discoveredAt: new Date(),
            evidence: [],
            remediationAdvice: 'Test',
            toolSource: 'Test',
            isZeroDay: false,
        },
        {
            id: 'V3',
            title: 'Exposed Service',
            description: 'Test',
            type: 'exposure',
            severity: 'high',
            cvss: 8.2,
            affectedAsset: 'test',
            discoveredAt: new Date(),
            evidence: [],
            remediationAdvice: 'Test',
            toolSource: 'Test',
            isZeroDay: false,
        },
    ];
    const recommendations = reporter.generateRemediationRecommendations(vulnerabilities);
    console.log('Generated Recommendations:');
    recommendations.forEach((rec, index) => {
        console.log(`${index + 1}. ${rec}\n`);
    });
}
/**
 * Run all examples
 */
async function runAllExamples() {
    try {
        await example1_basicReport();
        example2_riskScoring();
        example3_prioritization();
        await example4_evidenceCollection();
        example5_statistics();
        await example6_customBranding();
        example7_recommendations();
        console.log('\n=== All Examples Completed ===\n');
    }
    catch (error) {
        console.error('Error running examples:', error);
    }
}
// Run examples if executed directly
if (require.main === module) {
    runAllExamples();
}
//# sourceMappingURL=example.js.map