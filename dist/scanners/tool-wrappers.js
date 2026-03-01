"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.executeCommand = executeCommand;
exports.checkToolInstalled = checkToolInstalled;
exports.getToolVersion = getToolVersion;
exports.sanitizeTarget = sanitizeTarget;
exports.parseNmapXML = parseNmapXML;
exports.parseNiktoOutput = parseNiktoOutput;
exports.parseSqlmapOutput = parseSqlmapOutput;
exports.parseGobusterOutput = parseGobusterOutput;
exports.parseSSLScanOutput = parseSSLScanOutput;
exports.parseWhatWebOutput = parseWhatWebOutput;
const child_process_1 = require("child_process");
// xml2js removed - using regex parsing
const crypto_1 = require("crypto");
/**
 * Execute a command with timeout support
 * @param command - Command to execute
 * @param args - Command arguments
 * @param timeout - Timeout in milliseconds
 */
async function executeCommand(command, args, timeout = 300000) {
    return new Promise((resolve, reject) => {
        let stdout = '';
        let stderr = '';
        let timedOut = false;
        const child = (0, child_process_1.spawn)(command, args, {
            shell: false,
            windowsHide: true
        });
        // Timeout handler
        const timeoutHandle = setTimeout(() => {
            timedOut = true;
            child.kill('SIGTERM');
            // Force kill after 5 seconds
            setTimeout(() => {
                if (!child.killed) {
                    child.kill('SIGKILL');
                }
            }, 5000);
            reject(new Error(`Command timeout after ${timeout}ms: ${command} ${args.join(' ')}`));
        }, timeout);
        // Capture stdout
        child.stdout?.on('data', (data) => {
            stdout += data.toString();
        });
        // Capture stderr
        child.stderr?.on('data', (data) => {
            stderr += data.toString();
        });
        // Handle errors
        child.on('error', (error) => {
            clearTimeout(timeoutHandle);
            reject(new Error(`Failed to execute ${command}: ${error.message}`));
        });
        // Handle completion
        child.on('close', (code) => {
            clearTimeout(timeoutHandle);
            if (timedOut) {
                return; // Already rejected
            }
            resolve({
                stdout,
                stderr,
                exitCode: code ?? -1
            });
        });
    });
}
/**
 * Check if a tool is installed on the system
 * @param toolName - Name of the tool
 */
async function checkToolInstalled(toolName) {
    try {
        const result = await executeCommand('which', [toolName], 5000);
        return result.exitCode === 0 && result.stdout.trim().length > 0;
    }
    catch {
        return false;
    }
}
/**
 * Get the version of an installed tool
 * @param toolName - Name of the tool
 */
async function getToolVersion(toolName) {
    try {
        // Try common version flags
        const versionFlags = ['--version', '-v', '-V', 'version'];
        for (const flag of versionFlags) {
            try {
                const result = await executeCommand(toolName, [flag], 5000);
                if (result.exitCode === 0 || result.stdout.trim().length > 0) {
                    // Extract version from first line
                    const firstLine = (result.stdout || result.stderr).split('\n')[0];
                    return firstLine.trim() || 'unknown';
                }
            }
            catch {
                continue;
            }
        }
        return 'unknown';
    }
    catch {
        return 'unknown';
    }
}
/**
 * Sanitize target to prevent command injection
 * @param target - Target string to sanitize
 */
function sanitizeTarget(target) {
    // Remove dangerous characters
    const dangerous = /[;&|`$(){}[\]<>'"\\]/g;
    // Check for obvious injection attempts
    if (dangerous.test(target)) {
        throw new Error(`Invalid target: contains potentially dangerous characters`);
    }
    // Trim whitespace
    target = target.trim();
    // Validate URL format (basic check)
    if (target.includes('://')) {
        try {
            new URL(target);
        }
        catch {
            throw new Error(`Invalid URL format: ${target}`);
        }
    }
    // Validate IP/CIDR format
    const ipCidrPattern = /^[\d./:-]+$/;
    const domainPattern = /^[a-zA-Z0-9.-]+$/;
    const urlPattern = /^https?:\/\//;
    if (!urlPattern.test(target) && !ipCidrPattern.test(target) && !domainPattern.test(target)) {
        throw new Error(`Invalid target format: ${target}`);
    }
    return target;
}
/**
 * Parse Nmap XML output to structured vulnerabilities
 * @param xml - Nmap XML output
 */
function parseNmapXML(xml) {
    const vulnerabilities = [];
    try {
        // Parse XML synchronously using a simple regex-based approach
        // This is more reliable than async parsing for our use case
        // Extract hosts
        const hostMatches = xml.matchAll(/<host[^>]*>(.*?)<\/host>/gs);
        for (const hostMatch of hostMatches) {
            const hostXml = hostMatch[1];
            // Extract IP address
            const addrMatch = hostXml.match(/<address addr="([^"]+)"/);
            const ipAddress = addrMatch ? addrMatch[1] : 'unknown';
            // Extract hostname
            const hostnameMatch = hostXml.match(/<hostname name="([^"]+)"/);
            const hostname = hostnameMatch ? hostnameMatch[1] : ipAddress;
            // Extract OS detection
            const osMatches = hostXml.matchAll(/<osmatch name="([^"]+)" accuracy="(\d+)"/g);
            for (const osMatch of osMatches) {
                const osName = osMatch[1];
                const accuracy = parseInt(osMatch[2]);
                if (accuracy >= 80) {
                    vulnerabilities.push({
                        id: (0, crypto_1.randomUUID)(),
                        severity: 'info',
                        title: 'Operating System Detected',
                        description: `Detected OS: ${osName} (${accuracy}% confidence)`,
                        target: hostname,
                        evidence: `OS fingerprinting detected: ${osName}`,
                        timestamp: new Date()
                    });
                }
            }
            // Extract ports
            const portMatches = hostXml.matchAll(/<port protocol="([^"]+)" portid="(\d+)">(.*?)<\/port>/gs);
            for (const portMatch of portMatches) {
                const protocol = portMatch[1];
                const portId = parseInt(portMatch[2]);
                const portXml = portMatch[3];
                // Extract state
                const stateMatch = portXml.match(/<state state="([^"]+)"/);
                const state = stateMatch ? stateMatch[1] : 'unknown';
                if (state !== 'open')
                    continue;
                // Extract service
                const serviceMatch = portXml.match(/<service name="([^"]*)".*?(?:product="([^"]*)")?.*?(?:version="([^"]*)")?/);
                const serviceName = serviceMatch ? serviceMatch[1] : 'unknown';
                const product = serviceMatch && serviceMatch[2] ? serviceMatch[2] : '';
                const version = serviceMatch && serviceMatch[3] ? serviceMatch[3] : '';
                const serviceInfo = [product, version].filter(Boolean).join(' ');
                // Determine severity based on port and service
                let severity = 'info';
                let title = `Open Port: ${portId}/${protocol}`;
                let description = `Port ${portId}/${protocol} is open`;
                if (serviceName) {
                    description += ` running ${serviceName}`;
                    if (serviceInfo) {
                        description += ` (${serviceInfo})`;
                    }
                }
                // Flag potentially dangerous services
                const dangerousServices = ['telnet', 'ftp', 'rlogin', 'rsh', 'rexec'];
                if (dangerousServices.includes(serviceName.toLowerCase())) {
                    severity = 'high';
                    title = `Insecure Service: ${serviceName}`;
                    description += '. This service transmits data in cleartext and should be replaced with a secure alternative.';
                }
                // Flag outdated protocols
                if (portId === 21)
                    severity = 'medium'; // FTP
                if (portId === 23)
                    severity = 'high'; // Telnet
                if (portId === 445)
                    severity = 'medium'; // SMB
                vulnerabilities.push({
                    id: (0, crypto_1.randomUUID)(),
                    severity,
                    title,
                    description,
                    target: hostname,
                    port: portId,
                    protocol,
                    service: serviceName || undefined,
                    evidence: serviceInfo || `${serviceName} service detected`,
                    timestamp: new Date()
                });
                // Extract script results
                const scriptMatches = portXml.matchAll(/<script id="([^"]+)" output="([^"]+)"/g);
                for (const scriptMatch of scriptMatches) {
                    const scriptId = scriptMatch[1];
                    const output = scriptMatch[2];
                    // Flag vulnerability-related scripts
                    if (scriptId.includes('vuln') || output.toLowerCase().includes('vulnerable')) {
                        vulnerabilities.push({
                            id: (0, crypto_1.randomUUID)(),
                            severity: 'high',
                            title: `Vulnerability Detected: ${scriptId}`,
                            description: output,
                            target: hostname,
                            port: portId,
                            protocol,
                            service: serviceName,
                            evidence: output,
                            timestamp: new Date()
                        });
                    }
                }
            }
        }
    }
    catch (error) {
        // If parsing fails, return basic vulnerability with error info
        vulnerabilities.push({
            id: (0, crypto_1.randomUUID)(),
            severity: 'info',
            title: 'Nmap Scan Completed',
            description: `Scan completed but parsing encountered issues: ${error.message}`,
            target: 'unknown',
            evidence: xml.substring(0, 500),
            timestamp: new Date()
        });
    }
    return vulnerabilities;
}
/**
 * Parse Nikto CSV/text output
 * @param output - Nikto output
 * @param target - Target URL
 */
function parseNiktoOutput(output, target) {
    const vulnerabilities = [];
    try {
        const lines = output.split('\n');
        for (const line of lines) {
            if (!line.trim() || line.startsWith('#'))
                continue;
            // Nikto output format: "host","ip","port","vulnerability_id","method","url","description"
            const csvMatch = line.match(/"([^"]*)","([^"]*)","([^"]*)","([^"]*)","([^"]*)","([^"]*)","([^"]*)"/);
            if (csvMatch) {
                const [, , , port, vulnId, method, url, description] = csvMatch;
                // Determine severity
                let severity = 'info';
                const lowerDesc = description.toLowerCase();
                if (lowerDesc.includes('remote code execution') || lowerDesc.includes('sql injection')) {
                    severity = 'critical';
                }
                else if (lowerDesc.includes('xss') || lowerDesc.includes('csrf') || lowerDesc.includes('directory traversal')) {
                    severity = 'high';
                }
                else if (lowerDesc.includes('information disclosure') || lowerDesc.includes('misconfiguration')) {
                    severity = 'medium';
                }
                else if (lowerDesc.includes('deprecated') || lowerDesc.includes('outdated')) {
                    severity = 'low';
                }
                vulnerabilities.push({
                    id: (0, crypto_1.randomUUID)(),
                    severity,
                    title: `Nikto Finding: ${vulnId}`,
                    description,
                    target,
                    port: parseInt(port) || undefined,
                    evidence: `${method} ${url}`,
                    references: [`OSVDB-${vulnId}`],
                    timestamp: new Date()
                });
            }
            else {
                // Try parsing plain text format
                if (line.includes('OSVDB-') || line.includes('+')) {
                    const severity = line.includes('ERROR') ? 'high' : 'info';
                    vulnerabilities.push({
                        id: (0, crypto_1.randomUUID)(),
                        severity,
                        title: 'Nikto Finding',
                        description: line.trim(),
                        target,
                        evidence: line.trim(),
                        timestamp: new Date()
                    });
                }
            }
        }
    }
    catch (error) {
        vulnerabilities.push({
            id: (0, crypto_1.randomUUID)(),
            severity: 'info',
            title: 'Nikto Scan Completed',
            description: `Scan completed. Raw output available.`,
            target,
            evidence: output.substring(0, 500),
            timestamp: new Date()
        });
    }
    return vulnerabilities;
}
/**
 * Parse SQLMap output
 * @param output - SQLMap output
 * @param target - Target URL
 */
function parseSqlmapOutput(output, target) {
    const vulnerabilities = [];
    try {
        const lines = output.split('\n');
        let isVulnerable = false;
        let injectionType = '';
        let dbms = '';
        for (const line of lines) {
            const lower = line.toLowerCase();
            // Check for vulnerability indicators
            if (lower.includes('parameter') && lower.includes('is vulnerable')) {
                isVulnerable = true;
                // Extract parameter name
                const paramMatch = line.match(/Parameter:\s+([^\s]+)/i);
                const param = paramMatch ? paramMatch[1] : 'unknown';
                vulnerabilities.push({
                    id: (0, crypto_1.randomUUID)(),
                    severity: 'critical',
                    title: 'SQL Injection Vulnerability',
                    description: `SQL injection vulnerability found in parameter: ${param}`,
                    target,
                    evidence: line.trim(),
                    solution: 'Use parameterized queries or prepared statements. Implement input validation and sanitization.',
                    timestamp: new Date()
                });
            }
            // Extract injection type
            if (lower.includes('type:') && lower.includes('injection')) {
                const typeMatch = line.match(/Type:\s+([^\n]+)/i);
                if (typeMatch) {
                    injectionType = typeMatch[1].trim();
                }
            }
            // Extract DBMS
            if (lower.includes('back-end dbms:')) {
                const dbmsMatch = line.match(/back-end DBMS:\s+([^\n]+)/i);
                if (dbmsMatch) {
                    dbms = dbmsMatch[1].trim();
                    vulnerabilities.push({
                        id: (0, crypto_1.randomUUID)(),
                        severity: 'info',
                        title: 'Database Management System Detected',
                        description: `DBMS: ${dbms}`,
                        target,
                        evidence: line.trim(),
                        timestamp: new Date()
                    });
                }
            }
            // Extract database names
            if (lower.includes('available databases')) {
                vulnerabilities.push({
                    id: (0, crypto_1.randomUUID)(),
                    severity: 'high',
                    title: 'Database Enumeration',
                    description: 'SQL injection allows enumeration of database names',
                    target,
                    evidence: 'Databases can be enumerated through SQL injection',
                    timestamp: new Date()
                });
            }
            // Extract table names
            if (lower.includes('database tables found')) {
                vulnerabilities.push({
                    id: (0, crypto_1.randomUUID)(),
                    severity: 'high',
                    title: 'Table Enumeration',
                    description: 'SQL injection allows enumeration of database tables',
                    target,
                    evidence: 'Tables can be enumerated through SQL injection',
                    timestamp: new Date()
                });
            }
        }
        // If no specific vulnerabilities found but scan completed
        if (vulnerabilities.length === 0) {
            if (output.includes('sqlmap identified the following')) {
                isVulnerable = true;
            }
            vulnerabilities.push({
                id: (0, crypto_1.randomUUID)(),
                severity: isVulnerable ? 'medium' : 'info',
                title: isVulnerable ? 'Potential SQL Injection' : 'SQLMap Scan Completed',
                description: isVulnerable
                    ? 'SQLMap detected potential SQL injection vectors. Review full output for details.'
                    : 'No SQL injection vulnerabilities detected in tested parameters.',
                target,
                evidence: output.substring(0, 500),
                timestamp: new Date()
            });
        }
    }
    catch (error) {
        vulnerabilities.push({
            id: (0, crypto_1.randomUUID)(),
            severity: 'info',
            title: 'SQLMap Scan Completed',
            description: `Scan completed. Error parsing output: ${error.message}`,
            target,
            evidence: output.substring(0, 500),
            timestamp: new Date()
        });
    }
    return vulnerabilities;
}
/**
 * Parse Gobuster output
 * @param output - Gobuster output
 * @param target - Target URL
 */
function parseGobusterOutput(output, target) {
    const vulnerabilities = [];
    try {
        const lines = output.split('\n');
        for (const line of lines) {
            // Gobuster format: /path (Status: 200) [Size: 1234]
            const match = line.match(/^(\/[^\s]+)\s+\(Status:\s+(\d+)\)\s+\[Size:\s+(\d+)\]/);
            if (match) {
                const [, path, status, size] = match;
                const statusCode = parseInt(status);
                let severity = 'info';
                let title = `Directory/File Found: ${path}`;
                // Flag sensitive paths
                const sensitivePaths = ['/admin', '/backup', '/.git', '/.env', '/config', '/database', '/.svn'];
                const isSensitive = sensitivePaths.some(p => path.toLowerCase().includes(p));
                if (isSensitive) {
                    severity = 'high';
                    title = `Sensitive Path Exposed: ${path}`;
                }
                else if (statusCode === 200) {
                    severity = 'low';
                }
                vulnerabilities.push({
                    id: (0, crypto_1.randomUUID)(),
                    severity,
                    title,
                    description: `Accessible path found: ${path} (HTTP ${statusCode}, ${size} bytes)`,
                    target: `${target}${path}`,
                    evidence: line.trim(),
                    solution: isSensitive ? 'Restrict access to sensitive directories using proper authentication and authorization.' : undefined,
                    timestamp: new Date()
                });
            }
        }
        if (vulnerabilities.length === 0) {
            vulnerabilities.push({
                id: (0, crypto_1.randomUUID)(),
                severity: 'info',
                title: 'Gobuster Scan Completed',
                description: 'No directories or files found with current wordlist.',
                target,
                timestamp: new Date()
            });
        }
    }
    catch (error) {
        vulnerabilities.push({
            id: (0, crypto_1.randomUUID)(),
            severity: 'info',
            title: 'Gobuster Scan Completed',
            description: `Scan completed. Error parsing output: ${error.message}`,
            target,
            evidence: output.substring(0, 500),
            timestamp: new Date()
        });
    }
    return vulnerabilities;
}
/**
 * Parse SSLScan output
 * @param output - SSLScan output
 * @param target - Target host:port
 */
function parseSSLScanOutput(output, target) {
    const vulnerabilities = [];
    try {
        const lines = output.split('\n');
        for (const line of lines) {
            const lower = line.toLowerCase();
            // Check for weak ciphers
            if (line.includes('Accepted') && (lower.includes('sslv2') || lower.includes('sslv3') || lower.includes('tls 1.0'))) {
                vulnerabilities.push({
                    id: (0, crypto_1.randomUUID)(),
                    severity: 'high',
                    title: 'Weak SSL/TLS Protocol Enabled',
                    description: `Outdated SSL/TLS protocol detected: ${line.trim()}`,
                    target,
                    evidence: line.trim(),
                    solution: 'Disable SSLv2, SSLv3, and TLS 1.0. Use TLS 1.2 or higher.',
                    cve: ['CVE-2014-3566'], // POODLE
                    timestamp: new Date()
                });
            }
            // Check for weak ciphers
            if (line.includes('Accepted') && (lower.includes('rc4') || lower.includes('des') || lower.includes('md5'))) {
                vulnerabilities.push({
                    id: (0, crypto_1.randomUUID)(),
                    severity: 'medium',
                    title: 'Weak Cipher Suite Enabled',
                    description: `Weak cipher suite detected: ${line.trim()}`,
                    target,
                    evidence: line.trim(),
                    solution: 'Disable weak cipher suites. Use strong ciphers like AES-GCM.',
                    timestamp: new Date()
                });
            }
            // Check for certificate issues
            if (lower.includes('certificate') && (lower.includes('expired') || lower.includes('invalid'))) {
                vulnerabilities.push({
                    id: (0, crypto_1.randomUUID)(),
                    severity: 'high',
                    title: 'SSL Certificate Issue',
                    description: line.trim(),
                    target,
                    evidence: line.trim(),
                    solution: 'Renew or replace the SSL certificate.',
                    timestamp: new Date()
                });
            }
            // Check for self-signed certificates
            if (lower.includes('self-signed') || lower.includes('self signed')) {
                vulnerabilities.push({
                    id: (0, crypto_1.randomUUID)(),
                    severity: 'medium',
                    title: 'Self-Signed Certificate',
                    description: 'Server is using a self-signed certificate',
                    target,
                    evidence: line.trim(),
                    solution: 'Use a certificate from a trusted Certificate Authority.',
                    timestamp: new Date()
                });
            }
        }
        if (vulnerabilities.length === 0) {
            vulnerabilities.push({
                id: (0, crypto_1.randomUUID)(),
                severity: 'info',
                title: 'SSL/TLS Scan Completed',
                description: 'No major SSL/TLS issues detected.',
                target,
                timestamp: new Date()
            });
        }
    }
    catch (error) {
        vulnerabilities.push({
            id: (0, crypto_1.randomUUID)(),
            severity: 'info',
            title: 'SSLScan Completed',
            description: `Scan completed. Error parsing output: ${error.message}`,
            target,
            evidence: output.substring(0, 500),
            timestamp: new Date()
        });
    }
    return vulnerabilities;
}
/**
 * Parse WhatWeb JSON output
 * @param output - WhatWeb output
 * @param target - Target URL
 */
function parseWhatWebOutput(output, target) {
    const vulnerabilities = [];
    try {
        // WhatWeb outputs JSON per line
        const lines = output.split('\n').filter(l => l.trim());
        for (const line of lines) {
            try {
                const data = JSON.parse(line);
                if (data.plugins) {
                    const technologies = [];
                    // Extract detected technologies
                    for (const [pluginName, pluginData] of Object.entries(data.plugins)) {
                        if (Array.isArray(pluginData)) {
                            pluginData.forEach((item) => {
                                if (item.version) {
                                    technologies.push(`${pluginName} ${item.version.join('.')}`);
                                }
                                else {
                                    technologies.push(pluginName);
                                }
                                // Check for vulnerable versions
                                if (item.version && (pluginName.toLowerCase().includes('php') || pluginName.toLowerCase().includes('apache'))) {
                                    const versionStr = item.version.join('.');
                                    vulnerabilities.push({
                                        id: (0, crypto_1.randomUUID)(),
                                        severity: 'info',
                                        title: `Technology Detected: ${pluginName}`,
                                        description: `Detected ${pluginName} version ${versionStr}`,
                                        target,
                                        evidence: `${pluginName} ${versionStr}`,
                                        timestamp: new Date()
                                    });
                                }
                            });
                        }
                    }
                    if (technologies.length > 0) {
                        vulnerabilities.push({
                            id: (0, crypto_1.randomUUID)(),
                            severity: 'info',
                            title: 'Web Technologies Detected',
                            description: `Detected technologies: ${technologies.join(', ')}`,
                            target,
                            evidence: technologies.join(', '),
                            timestamp: new Date()
                        });
                    }
                }
            }
            catch {
                continue;
            }
        }
        if (vulnerabilities.length === 0) {
            vulnerabilities.push({
                id: (0, crypto_1.randomUUID)(),
                severity: 'info',
                title: 'WhatWeb Scan Completed',
                description: 'Technology fingerprinting completed.',
                target,
                timestamp: new Date()
            });
        }
    }
    catch (error) {
        vulnerabilities.push({
            id: (0, crypto_1.randomUUID)(),
            severity: 'info',
            title: 'WhatWeb Scan Completed',
            description: `Scan completed. Error parsing output: ${error.message}`,
            target,
            evidence: output.substring(0, 500),
            timestamp: new Date()
        });
    }
    return vulnerabilities;
}
//# sourceMappingURL=tool-wrappers.js.map