import { EventEmitter } from 'events';
import {
  executeCommand,
  parseNmapXML,
  parseNiktoOutput,
  parseSqlmapOutput,
  parseGobusterOutput,
  parseSSLScanOutput,
  parseWhatWebOutput,
  checkToolInstalled,
  getToolVersion,
  sanitizeTarget
} from './tool-wrappers';

// Types and Interfaces
export interface Vulnerability {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  target: string;
  port?: number;
  protocol?: string;
  service?: string;
  cve?: string[];
  references?: string[];
  solution?: string;
  evidence?: string;
  timestamp: Date;
}

export interface ScanResult {
  status: 'success' | 'error' | 'timeout';
  tool: string;
  target: string;
  startTime: Date;
  endTime: Date;
  duration: number;
  vulnerabilities: Vulnerability[];
  metadata: {
    toolVersion?: string;
    exitCode: number;
    stdout?: string;
    stderr?: string;
    error?: string;
  };
}

export interface ScanOptions {
  timeout?: number; // milliseconds
  verbose?: boolean;
  outputPath?: string;
}

export interface NmapOptions extends ScanOptions {
  flags?: string[]; // e.g., ['-sV', '-O', '-A']
  ports?: string; // e.g., '1-1000' or '80,443'
  scanType?: 'tcp' | 'udp' | 'syn' | 'full';
}

export interface SqlmapOptions extends ScanOptions {
  params?: string[];
  level?: number; // 1-5
  risk?: number; // 1-3
  dbms?: string;
}

export interface GobusterOptions extends ScanOptions {
  wordlist?: string;
  extensions?: string[];
  threads?: number;
}

/**
 * ScannerAgent - Main scanner orchestrator that wraps Kali Linux security tools
 * Emits events: 'output', 'finding', 'error', 'complete', 'progress'
 *
 * Supports both hardcoded tool methods AND dynamic tool execution via runDynamicScan()
 */
export class ScannerAgent extends EventEmitter {
  private defaultTimeout: number = 300000; // 5 minutes
  private verbose: boolean = false;

  constructor(options?: { defaultTimeout?: number; verbose?: boolean }) {
    super();
    if (options?.defaultTimeout) this.defaultTimeout = options.defaultTimeout;
    if (options?.verbose !== undefined) this.verbose = options.verbose;
  }

  /**
   * Run ANY tool dynamically with AI-parsed output
   * This is the universal method that can execute any security tool on the system.
   * The output is returned raw - use AIToolSelector.parseToolOutput() for structured results.
   *
   * @param toolName - Binary name of the tool (e.g., 'nuclei', 'ffuf', 'burpsuite')
   * @param args - Command-line arguments
   * @param options - Scan options including timeout
   */
  async runDynamicScan(
    toolName: string,
    args: string[],
    target: string,
    options?: ScanOptions & { requiresRoot?: boolean }
  ): Promise<ScanResult> {
    const startTime = new Date();

    try {
      const installed = await checkToolInstalled(toolName);
      if (!installed) {
        throw new Error(`${toolName} is not installed. Install with: sudo apt-get install ${toolName}`);
      }

      const version = await getToolVersion(toolName);
      this.emit('output', `[${toolName}] Version: ${version}`);

      // Sanitize all args that look like targets
      const sanitizedArgs = args.map(arg => {
        // Only sanitize args that look like URLs, IPs, or domains
        if (arg.match(/^https?:\/\//) || arg.match(/^\d+\.\d+\.\d+\.\d+/) || arg.match(/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/)) {
          return sanitizeTarget(arg);
        }
        return arg;
      });

      this.emit('progress', { tool: toolName, phase: 'scanning', progress: 0 });

      // Execute with or without sudo
      const command = options?.requiresRoot ? 'sudo' : toolName;
      const execArgs = options?.requiresRoot ? [toolName, ...sanitizedArgs] : sanitizedArgs;

      this.emit('output', `[${toolName}] Executing: ${options?.requiresRoot ? 'sudo ' : ''}${toolName} ${sanitizedArgs.join(' ')}`);

      const timeout = options?.timeout || this.defaultTimeout;
      const result = await executeCommand(command, execArgs, timeout);

      this.emit('progress', { tool: toolName, phase: 'complete', progress: 100 });

      const endTime = new Date();
      const scanResult: ScanResult = {
        status: result.exitCode === 0 ? 'success' : 'error',
        tool: toolName,
        target,
        startTime,
        endTime,
        duration: endTime.getTime() - startTime.getTime(),
        vulnerabilities: [], // Caller uses AIToolSelector.parseToolOutput() for structured parsing
        metadata: {
          toolVersion: version,
          exitCode: result.exitCode,
          stdout: result.stdout,
          stderr: result.stderr
        }
      };

      this.emit('complete', scanResult);
      return scanResult;

    } catch (error: any) {
      const endTime = new Date();
      this.emit('error', { tool: toolName, error: error.message });

      return {
        status: error.message.includes('timeout') ? 'timeout' : 'error',
        tool: toolName,
        target,
        startTime,
        endTime,
        duration: endTime.getTime() - startTime.getTime(),
        vulnerabilities: [],
        metadata: {
          exitCode: -1,
          error: error.message
        }
      };
    }
  }

  /**
   * Run a chain of tools sequentially, passing context between them
   * Each tool's output informs the next tool's arguments
   */
  async runToolChain(
    tools: Array<{ name: string; args: string[]; requiresRoot?: boolean }>,
    target: string,
    options?: ScanOptions
  ): Promise<ScanResult[]> {
    const results: ScanResult[] = [];

    for (const tool of tools) {
      this.emit('output', `[ToolChain] Running ${tool.name}...`);
      const result = await this.runDynamicScan(
        tool.name,
        tool.args,
        target,
        { ...options, requiresRoot: tool.requiresRoot }
      );
      results.push(result);

      // If tool failed, emit warning but continue
      if (result.status === 'error') {
        this.emit('output', `[ToolChain] ${tool.name} failed, continuing with next tool...`);
      }
    }

    return results;
  }

  /**
   * Nmap Scanner - Port scanning, OS detection, service enumeration
   * Parses XML output for structured results
   * @param target - IP address, hostname, or CIDR range (e.g., '192.168.1.0/24')
   * @param options - Scan options including flags and ports
   */
  async runNmapScan(target: string, options?: NmapOptions): Promise<ScanResult> {
    const startTime = new Date();
    const tool = 'nmap';

    try {
      // Validate tool installation
      const installed = await checkToolInstalled(tool);
      if (!installed) {
        throw new Error(`Nmap is not installed. Install with: sudo apt-get install nmap`);
      }

      // Sanitize target
      const sanitizedTarget = sanitizeTarget(target);

      // Get tool version
      const version = await getToolVersion(tool);
      this.emit('output', `[Nmap] Version: ${version}`);

      // Build command arguments
      const args: string[] = ['-oX', '-']; // XML output to stdout

      // Add scan type
      if (options?.scanType === 'syn') args.push('-sS');
      else if (options?.scanType === 'udp') args.push('-sU');
      else if (options?.scanType === 'full') args.push('-sT');

      // Add custom flags
      if (options?.flags && options.flags.length > 0) {
        args.push(...options.flags);
      } else {
        // Default: service/version detection
        args.push('-sV', '-sC');
      }

      // Add port specification
      if (options?.ports) {
        args.push('-p', options.ports);
      }

      // Add target
      args.push(sanitizedTarget);

      this.emit('progress', { tool, phase: 'scanning', progress: 0 });
      this.emit('output', `[Nmap] Executing: nmap ${args.join(' ')}`);

      // Execute command
      const timeout = options?.timeout || this.defaultTimeout;
      const result = await executeCommand(tool, args, timeout);

      this.emit('progress', { tool, phase: 'parsing', progress: 50 });

      // Parse XML output
      const vulnerabilities = parseNmapXML(result.stdout);

      // Emit individual findings
      vulnerabilities.forEach(vuln => {
        this.emit('finding', vuln);
      });

      const endTime = new Date();
      const scanResult: ScanResult = {
        status: result.exitCode === 0 ? 'success' : 'error',
        tool,
        target: sanitizedTarget,
        startTime,
        endTime,
        duration: endTime.getTime() - startTime.getTime(),
        vulnerabilities,
        metadata: {
          toolVersion: version,
          exitCode: result.exitCode,
          stdout: options?.verbose ? result.stdout : undefined,
          stderr: result.stderr
        }
      };

      this.emit('complete', scanResult);
      this.emit('progress', { tool, phase: 'complete', progress: 100 });

      return scanResult;

    } catch (error: any) {
      const endTime = new Date();
      this.emit('error', { tool, error: error.message });

      return {
        status: error.message.includes('timeout') ? 'timeout' : 'error',
        tool,
        target,
        startTime,
        endTime,
        duration: endTime.getTime() - startTime.getTime(),
        vulnerabilities: [],
        metadata: {
          exitCode: -1,
          error: error.message
        }
      };
    }
  }

  /**
   * Nikto Scanner - Web server vulnerability scanner
   * Parses CSV output for findings
   * @param target - URL (e.g., 'http://example.com')
   * @param options - Scan options
   */
  async runNiktoScan(target: string, options?: ScanOptions): Promise<ScanResult> {
    const startTime = new Date();
    const tool = 'nikto';

    try {
      const installed = await checkToolInstalled(tool);
      if (!installed) {
        throw new Error(`Nikto is not installed. Install with: sudo apt-get install nikto`);
      }

      const sanitizedTarget = sanitizeTarget(target);
      const version = await getToolVersion(tool);
      this.emit('output', `[Nikto] Version: ${version}`);

      const args = ['-h', sanitizedTarget, '-Format', 'csv', '-o', 'stdout'];

      this.emit('progress', { tool, phase: 'scanning', progress: 0 });
      this.emit('output', `[Nikto] Executing: nikto ${args.join(' ')}`);

      const timeout = options?.timeout || this.defaultTimeout;
      const result = await executeCommand(tool, args, timeout);

      this.emit('progress', { tool, phase: 'parsing', progress: 50 });

      const vulnerabilities = parseNiktoOutput(result.stdout, sanitizedTarget);

      vulnerabilities.forEach(vuln => {
        this.emit('finding', vuln);
      });

      const endTime = new Date();
      const scanResult: ScanResult = {
        status: result.exitCode === 0 ? 'success' : 'error',
        tool,
        target: sanitizedTarget,
        startTime,
        endTime,
        duration: endTime.getTime() - startTime.getTime(),
        vulnerabilities,
        metadata: {
          toolVersion: version,
          exitCode: result.exitCode,
          stdout: options?.verbose ? result.stdout : undefined,
          stderr: result.stderr
        }
      };

      this.emit('complete', scanResult);
      this.emit('progress', { tool, phase: 'complete', progress: 100 });

      return scanResult;

    } catch (error: any) {
      const endTime = new Date();
      this.emit('error', { tool, error: error.message });

      return {
        status: error.message.includes('timeout') ? 'timeout' : 'error',
        tool,
        target,
        startTime,
        endTime,
        duration: endTime.getTime() - startTime.getTime(),
        vulnerabilities: [],
        metadata: {
          exitCode: -1,
          error: error.message
        }
      };
    }
  }

  /**
   * SQLMap Scanner - SQL injection detection and exploitation
   * @param target - Target URL with parameter (e.g., 'http://example.com/page?id=1')
   * @param options - SQLMap specific options
   */
  async runSqlmapScan(target: string, options?: SqlmapOptions): Promise<ScanResult> {
    const startTime = new Date();
    const tool = 'sqlmap';

    try {
      const installed = await checkToolInstalled(tool);
      if (!installed) {
        throw new Error(`SQLMap is not installed. Install with: sudo apt-get install sqlmap`);
      }

      const sanitizedTarget = sanitizeTarget(target);
      const version = await getToolVersion(tool);
      this.emit('output', `[SQLMap] Version: ${version}`);

      const args = [
        '-u', sanitizedTarget,
        '--batch', // Non-interactive
        '--level', String(options?.level || 1),
        '--risk', String(options?.risk || 1)
      ];

      if (options?.dbms) {
        args.push('--dbms', options.dbms);
      }

      if (options?.params) {
        args.push(...options.params);
      }

      this.emit('progress', { tool, phase: 'scanning', progress: 0 });
      this.emit('output', `[SQLMap] Executing: sqlmap ${args.join(' ')}`);

      const timeout = options?.timeout || this.defaultTimeout * 2; // SQLMap can be slow
      const result = await executeCommand(tool, args, timeout);

      this.emit('progress', { tool, phase: 'parsing', progress: 50 });

      const vulnerabilities = parseSqlmapOutput(result.stdout, sanitizedTarget);

      vulnerabilities.forEach(vuln => {
        this.emit('finding', vuln);
      });

      const endTime = new Date();
      const scanResult: ScanResult = {
        status: result.exitCode === 0 ? 'success' : 'error',
        tool,
        target: sanitizedTarget,
        startTime,
        endTime,
        duration: endTime.getTime() - startTime.getTime(),
        vulnerabilities,
        metadata: {
          toolVersion: version,
          exitCode: result.exitCode,
          stdout: options?.verbose ? result.stdout : undefined,
          stderr: result.stderr
        }
      };

      this.emit('complete', scanResult);
      this.emit('progress', { tool, phase: 'complete', progress: 100 });

      return scanResult;

    } catch (error: any) {
      const endTime = new Date();
      this.emit('error', { tool, error: error.message });

      return {
        status: error.message.includes('timeout') ? 'timeout' : 'error',
        tool,
        target,
        startTime,
        endTime,
        duration: endTime.getTime() - startTime.getTime(),
        vulnerabilities: [],
        metadata: {
          exitCode: -1,
          error: error.message
        }
      };
    }
  }

  /**
   * Gobuster Scanner - Directory and file brute forcing
   * @param target - Base URL (e.g., 'http://example.com')
   * @param options - Gobuster options including wordlist
   */
  async runGobusterScan(target: string, options?: GobusterOptions): Promise<ScanResult> {
    const startTime = new Date();
    const tool = 'gobuster';

    try {
      const installed = await checkToolInstalled(tool);
      if (!installed) {
        throw new Error(`Gobuster is not installed. Install with: sudo apt-get install gobuster`);
      }

      const sanitizedTarget = sanitizeTarget(target);
      const version = await getToolVersion(tool);
      this.emit('output', `[Gobuster] Version: ${version}`);

      const wordlist = options?.wordlist || '/usr/share/wordlists/dirb/common.txt';
      const args = [
        'dir',
        '-u', sanitizedTarget,
        '-w', wordlist,
        '-q' // Quiet mode
      ];

      if (options?.extensions) {
        args.push('-x', options.extensions.join(','));
      }

      if (options?.threads) {
        args.push('-t', String(options.threads));
      }

      this.emit('progress', { tool, phase: 'scanning', progress: 0 });
      this.emit('output', `[Gobuster] Executing: gobuster ${args.join(' ')}`);

      const timeout = options?.timeout || this.defaultTimeout;
      const result = await executeCommand(tool, args, timeout);

      this.emit('progress', { tool, phase: 'parsing', progress: 50 });

      const vulnerabilities = parseGobusterOutput(result.stdout, sanitizedTarget);

      vulnerabilities.forEach(vuln => {
        this.emit('finding', vuln);
      });

      const endTime = new Date();
      const scanResult: ScanResult = {
        status: result.exitCode === 0 ? 'success' : 'error',
        tool,
        target: sanitizedTarget,
        startTime,
        endTime,
        duration: endTime.getTime() - startTime.getTime(),
        vulnerabilities,
        metadata: {
          toolVersion: version,
          exitCode: result.exitCode,
          stdout: options?.verbose ? result.stdout : undefined,
          stderr: result.stderr
        }
      };

      this.emit('complete', scanResult);
      this.emit('progress', { tool, phase: 'complete', progress: 100 });

      return scanResult;

    } catch (error: any) {
      const endTime = new Date();
      this.emit('error', { tool, error: error.message });

      return {
        status: error.message.includes('timeout') ? 'timeout' : 'error',
        tool,
        target,
        startTime,
        endTime,
        duration: endTime.getTime() - startTime.getTime(),
        vulnerabilities: [],
        metadata: {
          exitCode: -1,
          error: error.message
        }
      };
    }
  }

  /**
   * SSLScan - SSL/TLS configuration scanner
   * @param target - Host:port (e.g., 'example.com:443')
   * @param options - Scan options
   */
  async runSSLScan(target: string, options?: ScanOptions): Promise<ScanResult> {
    const startTime = new Date();
    const tool = 'sslscan';

    try {
      const installed = await checkToolInstalled(tool);
      if (!installed) {
        throw new Error(`SSLScan is not installed. Install with: sudo apt-get install sslscan`);
      }

      const sanitizedTarget = sanitizeTarget(target);
      const version = await getToolVersion(tool);
      this.emit('output', `[SSLScan] Version: ${version}`);

      const args = ['--no-colour', sanitizedTarget];

      this.emit('progress', { tool, phase: 'scanning', progress: 0 });
      this.emit('output', `[SSLScan] Executing: sslscan ${args.join(' ')}`);

      const timeout = options?.timeout || this.defaultTimeout;
      const result = await executeCommand(tool, args, timeout);

      this.emit('progress', { tool, phase: 'parsing', progress: 50 });

      const vulnerabilities = parseSSLScanOutput(result.stdout, sanitizedTarget);

      vulnerabilities.forEach(vuln => {
        this.emit('finding', vuln);
      });

      const endTime = new Date();
      const scanResult: ScanResult = {
        status: result.exitCode === 0 ? 'success' : 'error',
        tool,
        target: sanitizedTarget,
        startTime,
        endTime,
        duration: endTime.getTime() - startTime.getTime(),
        vulnerabilities,
        metadata: {
          toolVersion: version,
          exitCode: result.exitCode,
          stdout: options?.verbose ? result.stdout : undefined,
          stderr: result.stderr
        }
      };

      this.emit('complete', scanResult);
      this.emit('progress', { tool, phase: 'complete', progress: 100 });

      return scanResult;

    } catch (error: any) {
      const endTime = new Date();
      this.emit('error', { tool, error: error.message });

      return {
        status: error.message.includes('timeout') ? 'timeout' : 'error',
        tool,
        target,
        startTime,
        endTime,
        duration: endTime.getTime() - startTime.getTime(),
        vulnerabilities: [],
        metadata: {
          exitCode: -1,
          error: error.message
        }
      };
    }
  }

  /**
   * WhatWeb Scanner - Web technology fingerprinting
   * @param target - URL (e.g., 'http://example.com')
   * @param options - Scan options
   */
  async runWhatWebScan(target: string, options?: ScanOptions): Promise<ScanResult> {
    const startTime = new Date();
    const tool = 'whatweb';

    try {
      const installed = await checkToolInstalled(tool);
      if (!installed) {
        throw new Error(`WhatWeb is not installed. Install with: sudo apt-get install whatweb`);
      }

      const sanitizedTarget = sanitizeTarget(target);
      const version = await getToolVersion(tool);
      this.emit('output', `[WhatWeb] Version: ${version}`);

      const args = ['--log-json=-', '-a', '3', sanitizedTarget];

      this.emit('progress', { tool, phase: 'scanning', progress: 0 });
      this.emit('output', `[WhatWeb] Executing: whatweb ${args.join(' ')}`);

      const timeout = options?.timeout || this.defaultTimeout;
      const result = await executeCommand(tool, args, timeout);

      this.emit('progress', { tool, phase: 'parsing', progress: 50 });

      const vulnerabilities = parseWhatWebOutput(result.stdout, sanitizedTarget);

      vulnerabilities.forEach(vuln => {
        this.emit('finding', vuln);
      });

      const endTime = new Date();
      const scanResult: ScanResult = {
        status: result.exitCode === 0 ? 'success' : 'error',
        tool,
        target: sanitizedTarget,
        startTime,
        endTime,
        duration: endTime.getTime() - startTime.getTime(),
        vulnerabilities,
        metadata: {
          toolVersion: version,
          exitCode: result.exitCode,
          stdout: options?.verbose ? result.stdout : undefined,
          stderr: result.stderr
        }
      };

      this.emit('complete', scanResult);
      this.emit('progress', { tool, phase: 'complete', progress: 100 });

      return scanResult;

    } catch (error: any) {
      const endTime = new Date();
      this.emit('error', { tool, error: error.message });

      return {
        status: error.message.includes('timeout') ? 'timeout' : 'error',
        tool,
        target,
        startTime,
        endTime,
        duration: endTime.getTime() - startTime.getTime(),
        vulnerabilities: [],
        metadata: {
          exitCode: -1,
          error: error.message
        }
      };
    }
  }
}
