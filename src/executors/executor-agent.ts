import { EventEmitter } from 'events';
import { spawn, ChildProcess } from 'child_process';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';

/**
 * Execution result interface
 */
export interface ExecutionResult {
  success: boolean;
  stdout: string;
  stderr: string;
  exitCode: number | null;
  duration: number;
  timestamp: Date;
  command: string;
  evidenceId: string;
}

/**
 * Tool execution options
 */
export interface ToolOptions {
  timeout?: number;
  env?: Record<string, string>;
  cwd?: string;
  silent?: boolean;
  captureEvidence?: boolean;
}

/**
 * Authorization document interface
 */
export interface AuthorizationDocument {
  id: string;
  targets: string[];
  ipRanges: string[];
  domains: string[];
  excludedTargets?: string[];
  validFrom: Date;
  validUntil: Date;
  scope: string[];
  restrictions?: string[];
}

/**
 * Metasploit options
 */
export interface MetasploitOptions {
  payload?: string;
  lhost?: string;
  lport?: number;
  options?: Record<string, string>;
}

/**
 * Burp Suite scan types
 */
export enum BurpScanType {
  PASSIVE = 'passive',
  LIGHT_ACTIVE = 'light-active',
  FULL_ACTIVE = 'full-active',
  CRAWL_ONLY = 'crawl-only'
}

/**
 * ExecutorAgent - Executes security tools with elevated permissions on Kali Linux
 *
 * CRITICAL: All executions are validated against authorization documents
 * CRITICAL: All inputs are sanitized to prevent command injection
 */
export class ExecutorAgent extends EventEmitter {
  private evidencePath: string;
  private activeProcesses: Map<string, ChildProcess>;
  private executionHistory: ExecutionResult[];
  private authDocument: AuthorizationDocument | null;

  constructor(evidencePath: string = '/var/ryha/evidence') {
    super();
    this.evidencePath = evidencePath;
    this.activeProcesses = new Map();
    this.executionHistory = [];
    this.authDocument = null;
  }

  /**
   * Set the authorization document for target validation
   */
  public setAuthorizationDocument(authDoc: AuthorizationDocument): void {
    this.authDocument = authDoc;
    this.emit('auth:updated', authDoc);
  }

  /**
   * Validate target against authorization document
   *
   * @throws Error if target is not authorized
   */
  public validateTarget(target: string, authDoc?: any): boolean {
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
    if (doc.excludedTargets?.some((excluded: string) => this.matchesPattern(sanitizedTarget, excluded))) {
      throw new Error(`Target ${target} is explicitly excluded from testing scope`);
    }

    // Check if target matches any authorized targets
    const isAuthorized = doc.targets?.some((authorized: string) => this.matchesPattern(sanitizedTarget, authorized)) ||
                         doc.ipRanges?.some((range: string) => this.isInIpRange(sanitizedTarget, range)) ||
                         doc.domains?.some((domain: string) => this.matchesDomain(sanitizedTarget, domain));

    if (!isAuthorized) {
      throw new Error(`Target ${target} is not in authorized scope`);
    }

    return true;
  }

  /**
   * Execute command with root privileges
   */
  public async executeWithRoot(
    command: string,
    args: string[],
    options: ToolOptions = {}
  ): Promise<ExecutionResult> {
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
      const result = await this.executeProcess(
        'sudo',
        [sanitizedCommand, ...sanitizedArgs],
        options,
        executionId
      );

      const executionResult: ExecutionResult = {
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
    } catch (error) {
      const errorResult: ExecutionResult = {
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
  public async executeTool(
    toolName: string,
    target: string,
    options: Record<string, string> = {}
  ): Promise<ExecutionResult> {
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
  public async executeMetasploit(
    module: string,
    target: string,
    options: MetasploitOptions = {}
  ): Promise<ExecutionResult> {
    // Validate target
    this.validateTarget(target);

    const sanitizedModule = this.sanitizeInput(module);
    const sanitizedTarget = this.sanitizeInput(target);

    // Create resource script
    const resourceScript = this.generateMetasploitResourceScript(
      sanitizedModule,
      sanitizedTarget,
      options
    );

    const scriptPath = path.join('/tmp', `msf-${Date.now()}.rc`);
    await fs.writeFile(scriptPath, resourceScript, 'utf8');

    try {
      const result = await this.executeWithRoot(
        'msfconsole',
        ['-q', '-r', scriptPath],
        {
          timeout: options.options?.timeout ? parseInt(options.options.timeout) : 7200000, // 2 hours
          captureEvidence: true
        }
      );

      // Clean up resource script
      await fs.unlink(scriptPath).catch(() => {});

      return result;
    } catch (error) {
      // Clean up on error
      await fs.unlink(scriptPath).catch(() => {});
      throw error;
    }
  }

  /**
   * Execute Burp Suite headless scanning
   */
  public async executeBurpSuite(
    target: string,
    scanType: string = BurpScanType.LIGHT_ACTIVE
  ): Promise<ExecutionResult> {
    // Validate target
    this.validateTarget(target);

    const sanitizedTarget = this.sanitizeInput(target);
    const sanitizedScanType = this.sanitizeInput(scanType);

    // Generate Burp configuration
    const configPath = await this.generateBurpConfig(sanitizedTarget, sanitizedScanType);
    const reportPath = path.join(this.evidencePath, `burp-${Date.now()}.html`);

    try {
      const result = await this.executeWithRoot(
        'java',
        [
          '-jar',
          '/usr/share/burpsuite/burpsuite_pro.jar',
          '--headless',
          '--config-file=' + configPath,
          '--project-file=/tmp/burp-project.burp',
          '--unpause-spider-and-scanner'
        ],
        {
          timeout: 14400000, // 4 hours
          captureEvidence: true
        }
      );

      // Clean up config
      await fs.unlink(configPath).catch(() => {});

      return result;
    } catch (error) {
      await fs.unlink(configPath).catch(() => {});
      throw error;
    }
  }

  /**
   * Execute custom security script
   */
  public async executeCustomScript(
    scriptPath: string,
    args: string[] = []
  ): Promise<ExecutionResult> {
    // Validate script path (prevent path traversal)
    const sanitizedPath = this.sanitizeFilePath(scriptPath);

    // Check if script exists
    try {
      await fs.access(sanitizedPath, fs.constants.X_OK);
    } catch (error) {
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
  public async killProcess(executionId: string): Promise<boolean> {
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
  public getExecutionHistory(): ExecutionResult[] {
    return [...this.executionHistory];
  }

  /**
   * Clear execution history
   */
  public clearHistory(): void {
    this.executionHistory = [];
  }

  // Private helper methods

  private async executeProcess(
    command: string,
    args: string[],
    options: ToolOptions,
    executionId: string
  ): Promise<Omit<ExecutionResult, 'command' | 'duration' | 'timestamp' | 'evidenceId'>> {
    return new Promise((resolve, reject) => {
      let stdout = '';
      let stderr = '';

      const proc = spawn(command, args, {
        env: { ...process.env, ...options.env },
        cwd: options.cwd
      });

      this.activeProcesses.set(executionId, proc);

      // Set timeout if specified
      let timeoutId: NodeJS.Timeout | null = null;
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
        if (timeoutId) clearTimeout(timeoutId);
        this.activeProcesses.delete(executionId);
        reject(error);
      });

      proc.on('close', (exitCode) => {
        if (timeoutId) clearTimeout(timeoutId);
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

  private sanitizeInput(input: string): string {
    // Remove dangerous characters and command injection attempts
    return input
      .replace(/[;&|`$(){}[\]<>]/g, '')
      .replace(/\.\./g, '')
      .trim();
  }

  private sanitizeCommand(command: string): string {
    // Only allow alphanumeric, dash, underscore, and forward slash for paths
    if (!/^[a-zA-Z0-9/_-]+$/.test(command)) {
      throw new Error(`Invalid command: ${command}`);
    }
    return command;
  }

  private sanitizeFilePath(filePath: string): string {
    // Prevent path traversal
    const normalized = path.normalize(filePath);
    if (normalized.includes('..')) {
      throw new Error('Path traversal detected');
    }
    return normalized;
  }

  private matchesPattern(target: string, pattern: string): boolean {
    // Simple wildcard matching
    const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
    return regex.test(target);
  }

  private isInIpRange(ip: string, range: string): boolean {
    // Simplified IP range check (CIDR notation)
    // In production, use a proper IP library
    if (!range.includes('/')) {
      return ip === range;
    }

    // For now, just check if IP starts with the network prefix
    const [network] = range.split('/');
    return ip.startsWith(network.substring(0, network.lastIndexOf('.')));
  }

  private matchesDomain(target: string, domain: string): boolean {
    return target.endsWith(domain) || target === domain;
  }

  private generateExecutionId(): string {
    return crypto.randomBytes(8).toString('hex');
  }

  private generateMetasploitResourceScript(
    module: string,
    target: string,
    options: MetasploitOptions
  ): string {
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

  private async generateBurpConfig(target: string, scanType: string): Promise<string> {
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

  private async captureEvidence(result: ExecutionResult): Promise<void> {
    try {
      await fs.mkdir(this.evidencePath, { recursive: true });

      const evidenceFile = path.join(this.evidencePath, `${result.evidenceId}.json`);
      await fs.writeFile(evidenceFile, JSON.stringify(result, null, 2));

      this.emit('evidence:captured', {
        evidenceId: result.evidenceId,
        path: evidenceFile
      });
    } catch (error) {
      this.emit('evidence:error', {
        evidenceId: result.evidenceId,
        error
      });
    }
  }
}
