import { EventEmitter } from 'events';
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
    timeout?: number;
    verbose?: boolean;
    outputPath?: string;
}
export interface NmapOptions extends ScanOptions {
    flags?: string[];
    ports?: string;
    scanType?: 'tcp' | 'udp' | 'syn' | 'full';
}
export interface SqlmapOptions extends ScanOptions {
    params?: string[];
    level?: number;
    risk?: number;
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
export declare class ScannerAgent extends EventEmitter {
    private defaultTimeout;
    private verbose;
    constructor(options?: {
        defaultTimeout?: number;
        verbose?: boolean;
    });
    /**
     * Run ANY tool dynamically with AI-parsed output
     * This is the universal method that can execute any security tool on the system.
     * The output is returned raw - use AIToolSelector.parseToolOutput() for structured results.
     *
     * @param toolName - Binary name of the tool (e.g., 'nuclei', 'ffuf', 'burpsuite')
     * @param args - Command-line arguments
     * @param options - Scan options including timeout
     */
    runDynamicScan(toolName: string, args: string[], target: string, options?: ScanOptions & {
        requiresRoot?: boolean;
    }): Promise<ScanResult>;
    /**
     * Run a chain of tools sequentially, passing context between them
     * Each tool's output informs the next tool's arguments
     */
    runToolChain(tools: Array<{
        name: string;
        args: string[];
        requiresRoot?: boolean;
    }>, target: string, options?: ScanOptions): Promise<ScanResult[]>;
    /**
     * Nmap Scanner - Port scanning, OS detection, service enumeration
     * Parses XML output for structured results
     * @param target - IP address, hostname, or CIDR range (e.g., '192.168.1.0/24')
     * @param options - Scan options including flags and ports
     */
    runNmapScan(target: string, options?: NmapOptions): Promise<ScanResult>;
    /**
     * Nikto Scanner - Web server vulnerability scanner
     * Parses CSV output for findings
     * @param target - URL (e.g., 'http://example.com')
     * @param options - Scan options
     */
    runNiktoScan(target: string, options?: ScanOptions): Promise<ScanResult>;
    /**
     * SQLMap Scanner - SQL injection detection and exploitation
     * @param target - Target URL with parameter (e.g., 'http://example.com/page?id=1')
     * @param options - SQLMap specific options
     */
    runSqlmapScan(target: string, options?: SqlmapOptions): Promise<ScanResult>;
    /**
     * Gobuster Scanner - Directory and file brute forcing
     * @param target - Base URL (e.g., 'http://example.com')
     * @param options - Gobuster options including wordlist
     */
    runGobusterScan(target: string, options?: GobusterOptions): Promise<ScanResult>;
    /**
     * SSLScan - SSL/TLS configuration scanner
     * @param target - Host:port (e.g., 'example.com:443')
     * @param options - Scan options
     */
    runSSLScan(target: string, options?: ScanOptions): Promise<ScanResult>;
    /**
     * WhatWeb Scanner - Web technology fingerprinting
     * @param target - URL (e.g., 'http://example.com')
     * @param options - Scan options
     */
    runWhatWebScan(target: string, options?: ScanOptions): Promise<ScanResult>;
}
//# sourceMappingURL=scanner-agent.d.ts.map