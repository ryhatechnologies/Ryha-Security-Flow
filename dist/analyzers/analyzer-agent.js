"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AnalyzerAgent = exports.VulnerabilitySeverity = void 0;
const copilot_auth_1 = require("../auth/copilot-auth");
/**
 * Vulnerability severity classification
 */
var VulnerabilitySeverity;
(function (VulnerabilitySeverity) {
    VulnerabilitySeverity["CRITICAL"] = "CRITICAL";
    VulnerabilitySeverity["HIGH"] = "HIGH";
    VulnerabilitySeverity["MEDIUM"] = "MEDIUM";
    VulnerabilitySeverity["LOW"] = "LOW";
    VulnerabilitySeverity["INFO"] = "INFO";
})(VulnerabilitySeverity || (exports.VulnerabilitySeverity = VulnerabilitySeverity = {}));
/**
 * AI-powered vulnerability analyzer using Claude
 */
class AnalyzerAgent {
    /**
     * Analyze scan results using AI
     */
    async analyzeScanResults(results, target) {
        const prompt = this.buildAnalysisPrompt(results, target);
        try {
            const response = await copilot_auth_1.copilotAuth.sendChatMessage(prompt, AnalyzerAgent.SONNET_MODEL);
            return this.parseAnalysisResponse(response, results);
        }
        catch (error) {
            console.error('Failed to analyze scan results:', error);
            throw new Error(`Analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
    /**
     * Classify a single vulnerability using AI
     */
    async classifyVulnerability(vuln) {
        const prompt = `You are a cybersecurity expert. Analyze this vulnerability and provide a detailed classification.

Vulnerability Details:
${JSON.stringify(vuln, null, 2)}

Provide your analysis in the following JSON format:
{
  "name": "vulnerability name",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "cvssScore": 0.0-10.0,
  "cvssVector": "CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_",
  "description": "detailed description",
  "impact": "what could happen if exploited",
  "likelihood": "how likely exploitation is",
  "remediation": {
    "immediate": ["step 1", "step 2"],
    "shortTerm": ["step 1", "step 2"],
    "longTerm": ["step 1", "step 2"],
    "estimatedEffort": "hours/days/weeks",
    "priority": 1-5
  },
  "references": ["https://cve...", "https://..."],
  "cwe": "CWE-XXX",
  "owasp": "A01:2021",
  "exploitability": 0.0-10.0,
  "technicalDetails": "technical explanation"
}

Respond ONLY with valid JSON, no additional text.`;
        try {
            const response = await copilot_auth_1.copilotAuth.sendChatMessage(prompt, AnalyzerAgent.SONNET_MODEL);
            const parsed = this.parseJSONResponse(response);
            return {
                id: this.generateId(vuln),
                ...parsed
            };
        }
        catch (error) {
            console.error('Failed to classify vulnerability:', error);
            throw new Error(`Classification failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
    /**
     * Detect potential zero-day vulnerabilities using advanced AI analysis
     */
    async detectZeroDays(findings, target) {
        const prompt = `You are an elite security researcher specializing in zero-day vulnerability discovery. Analyze these security findings for patterns that might indicate previously unknown vulnerabilities.

Target: ${target}

Findings:
${JSON.stringify(findings, null, 2)}

Look for:
1. Unusual behavior patterns not matching known vulnerabilities
2. Novel attack vectors or combinations
3. Unexpected system responses or error conditions
4. Anomalies in security controls
5. Logic flaws that could bypass standard protections

Provide your analysis in JSON format:
{
  "potentialZeroDays": [
    {
      "description": "what you found",
      "indicators": ["indicator 1", "indicator 2"],
      "confidence": 0.0-1.0,
      "affectedComponents": ["component 1", "component 2"],
      "proposedVerification": ["verification step 1", "verification step 2"]
    }
  ],
  "confidence": 0.0-1.0,
  "analysisNotes": "detailed analysis",
  "recommendedActions": ["action 1", "action 2"]
}

Respond ONLY with valid JSON, no additional text.`;
        try {
            const response = await copilot_auth_1.copilotAuth.sendChatMessage(prompt, AnalyzerAgent.OPUS_MODEL);
            return this.parseJSONResponse(response);
        }
        catch (error) {
            console.error('Failed to detect zero-days:', error);
            throw new Error(`Zero-day detection failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
    /**
     * Correlate findings to identify attack chains
     */
    async correlateFindings(vulns) {
        const prompt = `You are a penetration testing expert. Analyze these vulnerabilities and identify potential attack chains where multiple vulnerabilities can be combined for greater impact.

Vulnerabilities:
${JSON.stringify(vulns, null, 2)}

For each attack chain, consider:
1. How vulnerabilities can be chained together
2. What access or privileges each step provides
3. The cumulative impact of the chain
4. Real-world feasibility

Provide your analysis in JSON format:
{
  "attackChains": [
    {
      "steps": ["step 1", "step 2", "step 3"],
      "vulnerabilities": ["vuln id 1", "vuln id 2"],
      "impact": "what the attacker achieves",
      "likelihood": "how feasible this is",
      "overallRisk": "CRITICAL|HIGH|MEDIUM|LOW",
      "mitigation": ["mitigation 1", "mitigation 2"]
    }
  ]
}

Respond ONLY with valid JSON containing the attackChains array, no additional text.`;
        try {
            const response = await copilot_auth_1.copilotAuth.sendChatMessage(prompt, AnalyzerAgent.SONNET_MODEL);
            const parsed = this.parseJSONResponse(response);
            return (parsed.attackChains || []).map((chain, index) => ({
                id: `chain-${index + 1}`,
                ...chain
            }));
        }
        catch (error) {
            console.error('Failed to correlate findings:', error);
            throw new Error(`Correlation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
    /**
     * Generate exploit proof-of-concept (for authorized testing only)
     */
    async generateExploitPOC(vuln) {
        const prompt = `You are a security researcher creating proof-of-concept exploits for authorized penetration testing.

⚠️ LEGAL NOTICE: This POC is for AUTHORIZED TESTING ONLY. Unauthorized use is illegal.

Vulnerability:
${JSON.stringify(vuln, null, 2)}

Create a detailed proof-of-concept in JSON format:
{
  "vulnerability": "vulnerability name",
  "exploitType": "type of exploit",
  "prerequisites": ["prerequisite 1", "prerequisite 2"],
  "steps": ["step 1", "step 2", "step 3"],
  "code": "actual exploit code with comments",
  "verification": ["how to verify step 1", "how to verify step 2"],
  "warnings": ["warning 1", "warning 2"],
  "legalNotice": "This POC is for authorized testing only"
}

Include:
- Clear step-by-step instructions
- Working code with comments
- Verification steps
- Safety warnings

Respond ONLY with valid JSON, no additional text.`;
        try {
            const response = await copilot_auth_1.copilotAuth.sendChatMessage(prompt, AnalyzerAgent.OPUS_MODEL);
            return this.parseJSONResponse(response);
        }
        catch (error) {
            console.error('Failed to generate POC:', error);
            throw new Error(`POC generation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
    /**
     * Assess overall risk from vulnerabilities
     */
    async assessRisk(vulns) {
        const prompt = `You are a cybersecurity risk analyst. Assess the overall risk from these vulnerabilities.

Vulnerabilities:
${JSON.stringify(vulns, null, 2)}

Evaluate:
1. Technical risk (exploitability, attack surface)
2. Business impact (data loss, service disruption, reputation)
3. Exploitability (skill required, automation potential)
4. Data exposure (PII, credentials, business data)

Provide your assessment in JSON format:
{
  "overallScore": 0-100,
  "breakdown": {
    "technicalRisk": 0-100,
    "businessImpact": 0-100,
    "exploitability": 0-100,
    "dataExposure": 0-100
  },
  "criticalFindings": 0,
  "highFindings": 0,
  "mediumFindings": 0,
  "lowFindings": 0,
  "topRisks": ["risk 1", "risk 2", "risk 3"],
  "immediateActions": ["action 1", "action 2", "action 3"]
}

Respond ONLY with valid JSON, no additional text.`;
        try {
            const response = await copilot_auth_1.copilotAuth.sendChatMessage(prompt, AnalyzerAgent.SONNET_MODEL);
            return this.parseJSONResponse(response);
        }
        catch (error) {
            console.error('Failed to assess risk:', error);
            throw new Error(`Risk assessment failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
    /**
     * Build comprehensive analysis prompt
     */
    buildAnalysisPrompt(results, target) {
        return `You are a senior penetration testing consultant. Analyze these security scan results and provide a comprehensive assessment.

Target: ${target}

Scan Results:
${JSON.stringify(results, null, 2)}

Provide a detailed analysis including:
1. Summary of findings
2. Vulnerability classifications with CVSS scores
3. Potential attack chains
4. Risk assessment
5. Prioritized remediation recommendations
6. Executive summary for management

Focus on:
- Real-world exploitability
- Business impact
- Remediation effort vs risk reduction
- Compliance implications (if applicable)

Provide your analysis in a structured format suitable for a professional penetration testing report.`;
    }
    /**
     * Parse AI analysis response into structured result
     */
    parseAnalysisResponse(response, originalResults) {
        try {
            // Try to parse as JSON first
            const jsonMatch = response.match(/\{[\s\S]*\}/);
            if (jsonMatch) {
                return JSON.parse(jsonMatch[0]);
            }
            // Fallback: construct from text response
            return {
                summary: response.substring(0, 500),
                vulnerabilities: originalResults.map((r, i) => ({
                    id: `vuln-${i + 1}`,
                    name: r.name || r.title || 'Unknown',
                    severity: this.inferSeverity(r),
                    cvssScore: r.cvssScore || 0,
                    cvssVector: r.cvssVector || '',
                    description: r.description || '',
                    impact: r.impact || '',
                    likelihood: r.likelihood || 'Unknown',
                    remediation: {
                        immediate: [],
                        shortTerm: [],
                        longTerm: [],
                        estimatedEffort: 'Unknown',
                        priority: 3
                    },
                    references: r.references || [],
                    exploitability: r.exploitability || 0
                })),
                attackChains: [],
                riskScore: 50,
                recommendations: [],
                executiveSummary: response.substring(0, 300)
            };
        }
        catch (error) {
            console.error('Failed to parse analysis response:', error);
            throw new Error('Invalid analysis response format');
        }
    }
    /**
     * Parse JSON from AI response
     */
    parseJSONResponse(response) {
        try {
            // Extract JSON from response
            const jsonMatch = response.match(/\{[\s\S]*\}/);
            if (!jsonMatch) {
                throw new Error('No JSON found in response');
            }
            return JSON.parse(jsonMatch[0]);
        }
        catch (error) {
            console.error('Failed to parse JSON response:', error);
            throw new Error('Invalid JSON response format');
        }
    }
    /**
     * Generate unique ID for vulnerability
     */
    generateId(vuln) {
        const name = vuln.name || vuln.title || 'unknown';
        const timestamp = Date.now();
        return `vuln-${name.toLowerCase().replace(/\s+/g, '-')}-${timestamp}`;
    }
    /**
     * Infer severity from vulnerability data
     */
    inferSeverity(vuln) {
        if (vuln.severity) {
            return vuln.severity.toUpperCase();
        }
        const score = vuln.cvssScore || 0;
        if (score >= 9.0)
            return VulnerabilitySeverity.CRITICAL;
        if (score >= 7.0)
            return VulnerabilitySeverity.HIGH;
        if (score >= 4.0)
            return VulnerabilitySeverity.MEDIUM;
        if (score >= 0.1)
            return VulnerabilitySeverity.LOW;
        return VulnerabilitySeverity.INFO;
    }
}
exports.AnalyzerAgent = AnalyzerAgent;
AnalyzerAgent.OPUS_MODEL = 'claude-opus-4-6';
AnalyzerAgent.SONNET_MODEL = 'claude-3-5-sonnet-20241022';
//# sourceMappingURL=analyzer-agent.js.map