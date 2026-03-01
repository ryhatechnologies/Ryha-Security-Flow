"use strict";
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
exports.ExecutorAgent = exports.BurpScanType = void 0;
const events_1 = require("events");
const child_process_1 = require("child_process");
const fs = __importStar(require("fs/promises"));
const path = __importStar(require("path"));
const crypto = __importStar(require("crypto"));
/**
 * Burp Suite scan types
 */
var BurpScanType;
(function (BurpScanType) {
    BurpScanType["PASSIVE"] = "passive";
    BurpScanType["LIGHT_ACTIVE"] = "light-active";
    BurpScanType["FULL_ACTIVE"] = "full-active";
    BurpScanType["CRAWL_ONLY"] = "crawl-only";
})(BurpScanType || (exports.BurpScanType = BurpScanType = {}));
/**
 * ExecutorAgent - Executes security tools with elevated permissions on Kali Linux
 *
 * CRITICAL: All executions are validated against authorization documents
 * CRITICAL: All inputs are sanitized to prevent command injection
 */
class ExecutorAgent extends events_1.EventEmitter {
    constructor(evidencePath = '/var/ryha/evidence') {
        super();
        this.evidencePath = evidencePath;
        this.activeProcesses = new Map();
        this.executionHistory = [];
        this.authDocument = null;
    }
    /**
     * Set the authorization document for target validation
     */
    setAuthorizationDocument(authDoc) {
        this.authDocument = authDoc;
        this.emit('auth:updated', authDoc);
    }
    /**
     * Validate target against authorization document
     *
     * @throws Error if target is not authorized
     */
    validateTarget(target, authDoc) {
        const doc = authDoc || this.authDocument;
        if (!doc) {
            throw new Error('No authorization document loaded. Cannot execute against target.');
        }
        // Check if authorization is still valid
        const now = new Date();
        const validFrom = new Date(doc.validFrom);
        const validUntil = new Date(doc.validUntil);
        if (now < validFrom || now > validUntil) {
            throw new Error(`Authorization document is not valid. Valid period: ${validFrom} - ${validUntil}`);
        }
        // Sanitize target
        const sanitizedTarget = this.sanitizeInput(target);
        // Check excluded targets first
        if (doc.excludedTargets?.some((excluded) => this.matchesPattern(sanitizedTarget, excluded))) {
            throw new Error(`Target ${target} is explicitly excluded from testing scope`);
        }
        // Check if target matches any authorized targets
        const isAuthorized = doc.targets?.some((authorized) => this.matchesPattern(sanitizedTarget, authorized)) ||
            doc.ipRanges?.some((range) => this.isInIpRange(sanitizedTarget, range)) ||
            doc.domains?.some((domain) => this.matchesDomain(sanitizedTarget, domain));
        if (!isAuthorized) {
            throw new Error(`Target ${target} is not in authorized scope`);
        }
        return true;
    }
    /**
     * Execute command with root privileges
     */
    async executeWithRoot(command, args, options = {}) {
        const startTime = Date.now();
        const executionId = this.generateExecutionId();
        const evidenceId = `evidence-${executionId}`;
        // Sanitize command and arguments
        const sanitizedCommand = this.sanitizeCommand(command);
        const sanitizedArgs = args.map(arg => this.sanitizeInput(arg));
        const fullCommand = `sudo ${sanitizedCommand} ${sanitizedArgs.join(' ')}`;
        this.emit('tool:started', {
            executionId,
            command: fullCommand,
            timestamp: new Date()
        });
        try {
            const result = await this.executeProcess('sudo', [sanitizedCommand, ...sanitizedArgs], options, executionId);
            const executionResult = {
                ...result,
                command: fullCommand,
                duration: Date.now() - startTime,
                timestamp: new Date(),
                evidenceId
            };
            // Capture evidence if enabled
            if (options.captureEvidence !== false) {
                await this.captureEvidence(executionResult);
            }
            this.executionHistory.push(executionResult);
            this.emit('tool:complete', executionResult);
            return executionResult;
        }
        catch (error) {
            const errorResult = {
                success: false,
                stdout: '',
                stderr: error instanceof Error ? error.message : String(error),
                exitCode: -1,
                duration: Date.now() - startTime,
                timestamp: new Date(),
                command: fullCommand,
                evidenceId
            };
            this.emit('tool:error', errorResult);
            return errorResult;
        }
    }
    /**
     * Execute a security tool with unified interface
     */
    async executeTool(toolName, target, options = {}) {
        // Validate target before execution
        this.validateTarget(target);
        const sanitizedTool = this.sanitizeCommand(toolName);
        const sanitizedTarget = this.sanitizeInput(target);
        // Build arguments from options
        const args = [sanitizedTarget];
        for (const [key, value] of Object.entries(options)) {
            args.push(`--${this.sanitizeInput(key)}`);
            if (value !== 'true' && value !== '') {
                args.push(this.sanitizeInput(value));
            }
        }
        return this.executeWithRoot(sanitizedTool, args, {
            timeout: options.timeout ? parseInt(options.timeout) : 3600000, // 1 hour default
            captureEvidence: true
        });
    }
    /**
     * Execute Metasploit module via resource script
     */
    async executeMetasploit(module, target, options = {}) {
        // Validate target
        this.validateTarget(target);
        const sanitizedModule = this.sanitizeInput(module);
        const sanitizedTarget = this.sanitizeInput(target);
        // Create resource script
        const resourceScript = this.generateMetasploitResourceScript(sanitizedModule, sanitizedTarget, options);
        const scriptPath = path.join('/tmp', `msf-${Date.now()}.rc`);
        await fs.writeFile(scriptPath, resourceScript, 'utf8');
        try {
            const result = await this.executeWithRoot('msfconsole', ['-q', '-r', scriptPath], {
                timeout: options.options?.timeout ? parseInt(options.options.timeout) : 7200000, // 2 hours
                captureEvidence: true
            });
            // Clean up resource script
            await fs.unlink(scriptPath).catch(() => { });
            return result;
        }
        catch (error) {
            // Clean up on error
            await fs.unlink(scriptPath).catch(() => { });
            throw error;
        }
    }
    /**
     * Execute Burp Suite headless scanning
     */
    async executeBurpSuite(target, scanType = BurpScanType.LIGHT_ACTIVE) {
        // Validate target
        this.validateTarget(target);
        const sanitizedTarget = this.sanitizeInput(target);
        const sanitizedScanType = this.sanitizeInput(scanType);
        // Generate Burp configuration
        const configPath = await this.generateBurpConfig(sanitizedTarget, sanitizedScanType);
        const reportPath = path.join(this.evidencePath, `burp-${Date.now()}.html`);
        try {
            const result = await this.executeWithRoot('java', [
                '-jar',
                '/usr/share/burpsuite/burpsuite_pro.jar',
                '--headless',
                '--config-file=' + configPath,
                '--project-file=/tmp/burp-project.burp',
                '--unpause-spider-and-scanner'
            ], {
                timeout: 14400000, // 4 hours
                captureEvidence: true
            });
            // Clean up config
            await fs.unlink(configPath).catch(() => { });
            return result;
        }
        catch (error) {
            await fs.unlink(configPath).catch(() => { });
            throw error;
        }
    }
    /**
     * Execute custom security script
     */
    async executeCustomScript(scriptPath, args = []) {
        // Validate script path (prevent path traversal)
        const sanitizedPath = this.sanitizeFilePath(scriptPath);
        // Check if script exists
        try {
            await fs.access(sanitizedPath, fs.constants.X_OK);
        }
        catch (error) {
            throw new Error(`Script not found or not executable: ${sanitizedPath}`);
        }
        // Sanitize arguments
        const sanitizedArgs = args.map(arg => this.sanitizeInput(arg));
        // Extract target from args for validation (assume first arg is target)
        if (sanitizedArgs.length > 0) {
            this.validateTarget(sanitizedArgs[0]);
        }
        return this.executeWithRoot(sanitizedPath, sanitizedArgs, {
            captureEvidence: true
        });
    }
    /**
     * Kill a running process
     */
    async killProcess(executionId) {
        const process = this.activeProcesses.get(executionId);
        if (!process) {
            return false;
        }
        process.kill('SIGTERM');
        // Force kill after 5 seconds if still running
        setTimeout(() => {
            if (!process.killed) {
                process.kill('SIGKILL');
            }
        }, 5000);
        this.activeProcesses.delete(executionId);
        return true;
    }
    /**
     * Get execution history
     */
    getExecutionHistory() {
        return [...this.executionHistory];
    }
    /**
     * Clear execution history
     */
    clearHistory() {
        this.executionHistory = [];
    }
    // Private helper methods
    async executeProcess(command, args, options, executionId) {
        return new Promise((resolve, reject) => {
            let stdout = '';
            let stderr = '';
            const proc = (0, child_process_1.spawn)(command, args, {
                env: { ...process.env, ...options.env },
                cwd: options.cwd
            });
            this.activeProcesses.set(executionId, proc);
            // Set timeout if specified
            let timeoutId = null;
            if (options.timeout) {
                timeoutId = setTimeout(() => {
                    proc.kill('SIGTERM');
                    reject(new Error(`Execution timeout after ${options.timeout}ms`));
                }, options.timeout);
            }
            proc.stdout?.on('data', (data) => {
                const output = data.toString();
                stdout += output;
                if (!options.silent) {
                    this.emit('tool:output', { executionId, type: 'stdout', data: output });
                }
            });
            proc.stderr?.on('data', (data) => {
                const output = data.toString();
                stderr += output;
                if (!options.silent) {
                    this.emit('tool:output', { executionId, type: 'stderr', data: output });
                }
            });
            proc.on('error', (error) => {
                if (timeoutId)
                    clearTimeout(timeoutId);
                this.activeProcesses.delete(executionId);
                reject(error);
            });
            proc.on('close', (exitCode) => {
                if (timeoutId)
                    clearTimeout(timeoutId);
                this.activeProcesses.delete(executionId);
                resolve({
                    success: exitCode === 0,
                    stdout,
                    stderr,
                    exitCode
                });
            });
        });
    }
    sanitizeInput(input) {
        // Remove dangerous characters and command injection attempts
        return input
            .replace(/[;&|`$(){}[\]<>]/g, '')
            .replace(/\.\./g, '')
            .trim();
    }
    sanitizeCommand(command) {
        // Only allow alphanumeric, dash, underscore, and forward slash for paths
        if (!/^[a-zA-Z0-9/_-]+$/.test(command)) {
            throw new Error(`Invalid command: ${command}`);
        }
        return command;
    }
    sanitizeFilePath(filePath) {
        // Prevent path traversal
        const normalized = path.normalize(filePath);
        if (normalized.includes('..')) {
            throw new Error('Path traversal detected');
        }
        return normalized;
    }
    matchesPattern(target, pattern) {
        // Simple wildcard matching
        const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
        return regex.test(target);
    }
    isInIpRange(ip, range) {
        // Simplified IP range check (CIDR notation)
        // In production, use a proper IP library
        if (!range.includes('/')) {
            return ip === range;
        }
        // For now, just check if IP starts with the network prefix
        const [network] = range.split('/');
        return ip.startsWith(network.substring(0, network.lastIndexOf('.')));
    }
    matchesDomain(target, domain) {
        return target.endsWith(domain) || target === domain;
    }
    generateExecutionId() {
        return crypto.randomBytes(8).toString('hex');
    }
    generateMetasploitResourceScript(module, target, options) {
        const lines = [
            `use ${module}`,
            `set RHOSTS ${target}`
        ];
        if (options.payload) {
            lines.push(`set PAYLOAD ${options.payload}`);
        }
        if (options.lhost) {
            lines.push(`set LHOST ${options.lhost}`);
        }
        if (options.lport) {
            lines.push(`set LPORT ${options.lport}`);
        }
        if (options.options) {
            for (const [key, value] of Object.entries(options.options)) {
                lines.push(`set ${key} ${value}`);
            }
        }
        lines.push('run');
        lines.push('exit');
        return lines.join('\n');
    }
    async generateBurpConfig(target, scanType) {
        const config = {
            target: {
                scope: {
                    include: [{ host: target }]
                }
            },
            scanner: {
                scan_type: scanType,
                crawl_depth: scanType === BurpScanType.CRAWL_ONLY ? 10 : 5
            }
        };
        const configPath = path.join('/tmp', `burp-config-${Date.now()}.json`);
        await fs.writeFile(configPath, JSON.stringify(config, null, 2));
        return configPath;
    }
    async captureEvidence(result) {
        try {
            await fs.mkdir(this.evidencePath, { recursive: true });
            const evidenceFile = path.join(this.evidencePath, `${result.evidenceId}.json`);
            await fs.writeFile(evidenceFile, JSON.stringify(result, null, 2));
            this.emit('evidence:captured', {
                evidenceId: result.evidenceId,
                path: evidenceFile
            });
        }
        catch (error) {
            this.emit('evidence:error', {
                evidenceId: result.evidenceId,
                error
            });
        }
    }
}
exports.ExecutorAgent = ExecutorAgent;
//# sourceMappingURL=executor-agent.js.map