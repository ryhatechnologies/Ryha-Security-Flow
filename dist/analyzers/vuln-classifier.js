"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.VulnerabilityClassifier = void 0;
/**
 * Local vulnerability classifier (no AI required)
 */
class VulnerabilityClassifier {
    /**
     * Calculate CVSS 3.1 base score
     */
    static calculateCVSS(vuln) {
        const metrics = this.extractMetrics(vuln);
        // Calculate Impact Sub Score (ISS)
        const impactBase = 1 - ((1 - this.getConfidentialityImpact(metrics.confidentiality)) *
            (1 - this.getIntegrityImpact(metrics.integrity)) *
            (1 - this.getAvailabilityImpact(metrics.availability)));
        let impact;
        if (metrics.scope === 'U') {
            impact = 6.42 * impactBase;
        }
        else {
            impact = 7.52 * (impactBase - 0.029) - 3.25 * Math.pow(impactBase - 0.02, 15);
        }
        // Calculate Exploitability Sub Score (ESS)
        const exploitability = 8.22 *
            this.getAttackVectorScore(metrics.attackVector) *
            this.getAttackComplexityScore(metrics.attackComplexity) *
            this.getPrivilegesRequiredScore(metrics.privilegesRequired, metrics.scope) *
            this.getUserInteractionScore(metrics.userInteraction);
        // Calculate Base Score
        let baseScore;
        if (impact <= 0) {
            baseScore = 0;
        }
        else if (metrics.scope === 'U') {
            baseScore = Math.min(impact + exploitability, 10);
        }
        else {
            baseScore = Math.min(1.08 * (impact + exploitability), 10);
        }
        baseScore = Math.ceil(baseScore * 10) / 10;
        const vector = `CVSS:3.1/AV:${metrics.attackVector}/AC:${metrics.attackComplexity}/PR:${metrics.privilegesRequired}/UI:${metrics.userInteraction}/S:${metrics.scope}/C:${metrics.confidentiality}/I:${metrics.integrity}/A:${metrics.availability}`;
        return {
            baseScore,
            vector,
            severity: this.getSeverityRating(baseScore),
            impactScore: Math.ceil(impact * 10) / 10,
            exploitabilityScore: Math.ceil(exploitability * 10) / 10
        };
    }
    /**
     * Map vulnerability type to CWE ID
     */
    static mapToCWE(vulnType) {
        const cweMap = {
            // Injection vulnerabilities
            'sql-injection': 'CWE-89',
            'sqli': 'CWE-89',
            'command-injection': 'CWE-78',
            'code-injection': 'CWE-94',
            'xss': 'CWE-79',
            'cross-site-scripting': 'CWE-79',
            'ldap-injection': 'CWE-90',
            'xpath-injection': 'CWE-643',
            'xml-injection': 'CWE-91',
            // Authentication & Session
            'broken-authentication': 'CWE-287',
            'session-fixation': 'CWE-384',
            'weak-password': 'CWE-521',
            'missing-2fa': 'CWE-308',
            // Authorization
            'broken-access-control': 'CWE-285',
            'privilege-escalation': 'CWE-269',
            'idor': 'CWE-639',
            'insecure-direct-object-reference': 'CWE-639',
            'path-traversal': 'CWE-22',
            // Cryptography
            'weak-crypto': 'CWE-327',
            'hardcoded-credentials': 'CWE-798',
            'sensitive-data-exposure': 'CWE-311',
            'insecure-storage': 'CWE-922',
            // Configuration
            'security-misconfiguration': 'CWE-16',
            'default-credentials': 'CWE-1188',
            'debug-enabled': 'CWE-489',
            // Business Logic
            'business-logic-flaw': 'CWE-840',
            'race-condition': 'CWE-362',
            // Data Validation
            'improper-input-validation': 'CWE-20',
            'buffer-overflow': 'CWE-119',
            'integer-overflow': 'CWE-190',
            // File Operations
            'file-upload': 'CWE-434',
            'unrestricted-file-upload': 'CWE-434',
            'xxe': 'CWE-611',
            // SSRF & Redirects
            'ssrf': 'CWE-918',
            'open-redirect': 'CWE-601',
            // CSRF
            'csrf': 'CWE-352',
            'cross-site-request-forgery': 'CWE-352',
            // Deserialization
            'insecure-deserialization': 'CWE-502',
            // Components
            'vulnerable-component': 'CWE-1035',
            'outdated-component': 'CWE-1104'
        };
        const normalizedType = vulnType.toLowerCase().replace(/\s+/g, '-');
        return cweMap[normalizedType] || null;
    }
    /**
     * Map vulnerability type to OWASP Top 10 (2021)
     */
    static mapToOWASP(vulnType) {
        const owaspMap = {
            'broken-access-control': 'A01:2021',
            'idor': 'A01:2021',
            'privilege-escalation': 'A01:2021',
            'path-traversal': 'A01:2021',
            'cryptographic-failure': 'A02:2021',
            'weak-crypto': 'A02:2021',
            'sensitive-data-exposure': 'A02:2021',
            'insecure-storage': 'A02:2021',
            'sql-injection': 'A03:2021',
            'sqli': 'A03:2021',
            'xss': 'A03:2021',
            'command-injection': 'A03:2021',
            'code-injection': 'A03:2021',
            'ldap-injection': 'A03:2021',
            'insecure-design': 'A04:2021',
            'business-logic-flaw': 'A04:2021',
            'security-misconfiguration': 'A05:2021',
            'default-credentials': 'A05:2021',
            'debug-enabled': 'A05:2021',
            'vulnerable-component': 'A06:2021',
            'outdated-component': 'A06:2021',
            'broken-authentication': 'A07:2021',
            'session-fixation': 'A07:2021',
            'weak-password': 'A07:2021',
            'integrity-failure': 'A08:2021',
            'insecure-deserialization': 'A08:2021',
            'logging-failure': 'A09:2021',
            'insufficient-logging': 'A09:2021',
            'ssrf': 'A10:2021',
            'open-redirect': 'A10:2021'
        };
        const normalizedType = vulnType.toLowerCase().replace(/\s+/g, '-');
        return owaspMap[normalizedType] || null;
    }
    /**
     * Prioritize findings by severity, exploitability, and business impact
     */
    static prioritizeFindings(vulns) {
        const classified = vulns.map(vuln => {
            const cvss = this.calculateCVSS(vuln);
            const exploitability = this.calculateExploitability(vuln);
            const businessImpact = this.calculateBusinessImpact(vuln);
            // Priority formula: (CVSS * 0.5) + (Exploitability * 0.3) + (BusinessImpact * 0.2)
            const priority = (cvss.baseScore * 0.5) + (exploitability * 0.3) + (businessImpact * 0.2);
            return {
                id: vuln.id || `vuln-${Date.now()}-${Math.random()}`,
                name: vuln.name || vuln.title || 'Unknown',
                type: vuln.type || 'Unknown',
                cvss,
                cwe: this.mapToCWE(vuln.type),
                owasp: this.mapToOWASP(vuln.type),
                priority,
                exploitability,
                businessImpact,
                rawData: vuln
            };
        });
        // Sort by priority (descending)
        return classified.sort((a, b) => b.priority - a.priority);
    }
    /**
     * Deduplicate findings from different tools
     */
    static deduplicateFindings(vulns) {
        const uniqueVulns = new Map();
        for (const vuln of vulns) {
            const key = this.generateDeduplicationKey(vuln);
            if (!uniqueVulns.has(key)) {
                uniqueVulns.set(key, vuln);
            }
            else {
                // Merge findings if duplicate has additional info
                const existing = uniqueVulns.get(key);
                uniqueVulns.set(key, this.mergeVulnerabilities(existing, vuln));
            }
        }
        return Array.from(uniqueVulns.values());
    }
    /**
     * Generate remediation plan
     */
    static generateRemediationPlan(vulns) {
        const immediate = [];
        const shortTerm = [];
        const longTerm = [];
        for (const vuln of vulns) {
            const item = {
                vulnerability: vuln.name,
                severity: vuln.cvss.severity,
                action: this.getRemediationAction(vuln),
                effort: this.estimateEffort(vuln),
                priority: Math.round(vuln.priority),
                dependencies: this.identifyDependencies(vuln)
            };
            // Categorize by severity and exploitability
            if (vuln.cvss.severity === 'CRITICAL' || (vuln.cvss.severity === 'HIGH' && vuln.exploitability > 7)) {
                immediate.push(item);
            }
            else if (vuln.cvss.severity === 'HIGH' || vuln.cvss.severity === 'MEDIUM') {
                shortTerm.push(item);
            }
            else {
                longTerm.push(item);
            }
        }
        return {
            immediate,
            shortTerm,
            longTerm,
            estimatedTotalEffort: this.calculateTotalEffort(immediate, shortTerm, longTerm)
        };
    }
    // Private helper methods
    static extractMetrics(vuln) {
        // Try to extract from existing CVSS vector
        if (vuln.cvssVector) {
            return this.parseVectorString(vuln.cvssVector);
        }
        // Infer from vulnerability data
        return {
            attackVector: this.inferAttackVector(vuln),
            attackComplexity: this.inferAttackComplexity(vuln),
            privilegesRequired: this.inferPrivilegesRequired(vuln),
            userInteraction: this.inferUserInteraction(vuln),
            scope: this.inferScope(vuln),
            confidentiality: this.inferConfidentiality(vuln),
            integrity: this.inferIntegrity(vuln),
            availability: this.inferAvailability(vuln)
        };
    }
    static parseVectorString(vector) {
        const parts = vector.split('/');
        const metrics = {};
        for (const part of parts) {
            const [key, value] = part.split(':');
            if (key && value) {
                metrics[key] = value;
            }
        }
        return {
            attackVector: metrics.AV || 'N',
            attackComplexity: metrics.AC || 'L',
            privilegesRequired: metrics.PR || 'N',
            userInteraction: metrics.UI || 'N',
            scope: metrics.S || 'U',
            confidentiality: metrics.C || 'H',
            integrity: metrics.I || 'H',
            availability: metrics.A || 'H'
        };
    }
    static inferAttackVector(vuln) {
        const type = (vuln.type || '').toLowerCase();
        if (type.includes('remote') || type.includes('network'))
            return 'N';
        if (type.includes('adjacent'))
            return 'A';
        if (type.includes('local'))
            return 'L';
        return 'N'; // Default to network
    }
    static inferAttackComplexity(vuln) {
        const type = (vuln.type || '').toLowerCase();
        if (type.includes('race') || type.includes('timing'))
            return 'H';
        return 'L';
    }
    static inferPrivilegesRequired(vuln) {
        const type = (vuln.type || '').toLowerCase();
        if (type.includes('unauthenticated') || type.includes('anonymous'))
            return 'N';
        if (type.includes('admin') || type.includes('privileged'))
            return 'H';
        return 'L';
    }
    static inferUserInteraction(vuln) {
        const type = (vuln.type || '').toLowerCase();
        if (type.includes('xss') || type.includes('csrf') || type.includes('phishing'))
            return 'R';
        return 'N';
    }
    static inferScope(vuln) {
        const type = (vuln.type || '').toLowerCase();
        if (type.includes('container escape') || type.includes('sandbox escape'))
            return 'C';
        return 'U';
    }
    static inferConfidentiality(vuln) {
        const type = (vuln.type || '').toLowerCase();
        if (type.includes('disclosure') || type.includes('leak'))
            return 'H';
        if (type.includes('info'))
            return 'L';
        return 'H';
    }
    static inferIntegrity(vuln) {
        const type = (vuln.type || '').toLowerCase();
        if (type.includes('injection') || type.includes('upload'))
            return 'H';
        if (type.includes('xss'))
            return 'L';
        return 'H';
    }
    static inferAvailability(vuln) {
        const type = (vuln.type || '').toLowerCase();
        if (type.includes('dos') || type.includes('denial'))
            return 'H';
        if (type.includes('resource'))
            return 'L';
        return 'L';
    }
    static getAttackVectorScore(av) {
        const scores = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
        return scores[av] || 0.85;
    }
    static getAttackComplexityScore(ac) {
        return ac === 'L' ? 0.77 : 0.44;
    }
    static getPrivilegesRequiredScore(pr, scope) {
        if (scope === 'U') {
            const scores = { N: 0.85, L: 0.62, H: 0.27 };
            return scores[pr] || 0.85;
        }
        else {
            const scores = { N: 0.85, L: 0.68, H: 0.5 };
            return scores[pr] || 0.85;
        }
    }
    static getUserInteractionScore(ui) {
        return ui === 'N' ? 0.85 : 0.62;
    }
    static getConfidentialityImpact(c) {
        const impacts = { N: 0, L: 0.22, H: 0.56 };
        return impacts[c] || 0.56;
    }
    static getIntegrityImpact(i) {
        const impacts = { N: 0, L: 0.22, H: 0.56 };
        return impacts[i] || 0.56;
    }
    static getAvailabilityImpact(a) {
        const impacts = { N: 0, L: 0.22, H: 0.56 };
        return impacts[a] || 0.56;
    }
    static getSeverityRating(score) {
        if (score >= 9.0)
            return 'CRITICAL';
        if (score >= 7.0)
            return 'HIGH';
        if (score >= 4.0)
            return 'MEDIUM';
        if (score > 0.0)
            return 'LOW';
        return 'NONE';
    }
    static calculateExploitability(vuln) {
        let score = 5.0;
        // Adjust based on known exploit availability
        if (vuln.exploitAvailable || vuln.publicExploit)
            score += 3.0;
        if (vuln.metasploitModule)
            score += 2.0;
        // Adjust based on ease of exploitation
        const type = (vuln.type || '').toLowerCase();
        if (type.includes('sql-injection') || type.includes('command-injection'))
            score += 2.0;
        if (type.includes('xss') || type.includes('csrf'))
            score += 1.0;
        return Math.min(score, 10);
    }
    static calculateBusinessImpact(vuln) {
        let score = 5.0;
        // Adjust based on asset criticality
        if (vuln.assetCriticality === 'critical')
            score += 3.0;
        if (vuln.assetCriticality === 'high')
            score += 2.0;
        // Adjust based on data sensitivity
        if (vuln.dataExposure?.includes('pii'))
            score += 2.0;
        if (vuln.dataExposure?.includes('credentials'))
            score += 3.0;
        return Math.min(score, 10);
    }
    static generateDeduplicationKey(vuln) {
        const type = (vuln.type || '').toLowerCase().trim();
        const location = (vuln.location || vuln.url || vuln.parameter || '').toLowerCase().trim();
        return `${type}::${location}`;
    }
    static mergeVulnerabilities(existing, newVuln) {
        return {
            ...existing,
            sources: [...(existing.sources || [existing.source]), newVuln.source].filter(Boolean),
            references: [...(existing.references || []), ...(newVuln.references || [])],
            evidence: [...(existing.evidence || []), ...(newVuln.evidence || [])]
        };
    }
    static getRemediationAction(vuln) {
        const actions = {
            'sql-injection': 'Use parameterized queries/prepared statements',
            'xss': 'Implement output encoding and Content-Security-Policy',
            'command-injection': 'Avoid system calls, use safe APIs',
            'broken-authentication': 'Implement MFA and secure session management',
            'path-traversal': 'Validate and sanitize file paths',
            'weak-crypto': 'Use modern encryption algorithms (AES-256, RSA-2048+)',
            'csrf': 'Implement CSRF tokens on all state-changing operations',
            'vulnerable-component': 'Update to latest patched version'
        };
        return actions[vuln.type] || 'Review and remediate according to security best practices';
    }
    static estimateEffort(vuln) {
        const type = vuln.type.toLowerCase();
        // Quick fixes
        if (type.includes('configuration') || type.includes('default'))
            return '2-4 hours';
        if (type.includes('component') || type.includes('outdated'))
            return '4-8 hours';
        // Medium effort
        if (type.includes('crypto') || type.includes('session'))
            return '1-2 days';
        if (type.includes('authentication') || type.includes('authorization'))
            return '2-3 days';
        // Complex fixes
        if (type.includes('architecture') || type.includes('design'))
            return '1-2 weeks';
        return '3-5 days';
    }
    static identifyDependencies(vuln) {
        const deps = [];
        const type = vuln.type.toLowerCase();
        if (type.includes('authentication')) {
            deps.push('Session management review');
            deps.push('Password policy update');
        }
        if (type.includes('crypto')) {
            deps.push('Key rotation procedure');
            deps.push('Certificate renewal');
        }
        if (type.includes('component')) {
            deps.push('Dependency compatibility check');
            deps.push('Regression testing');
        }
        return deps;
    }
    static calculateTotalEffort(immediate, shortTerm, longTerm) {
        const totalItems = immediate.length + shortTerm.length + longTerm.length;
        if (totalItems === 0)
            return '0 hours';
        if (totalItems <= 5)
            return '1-2 weeks';
        if (totalItems <= 15)
            return '3-4 weeks';
        return '1-2 months';
    }
}
exports.VulnerabilityClassifier = VulnerabilityClassifier;
//# sourceMappingURL=vuln-classifier.js.map