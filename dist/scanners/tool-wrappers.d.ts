import { Vulnerability } from './scanner-agent';
/**
 * Command execution result
 */
export interface CommandResult {
    stdout: string;
    stderr: string;
    exitCode: number;
}
/**
 * Execute a command with timeout support
 * @param command - Command to execute
 * @param args - Command arguments
 * @param timeout - Timeout in milliseconds
 */
export declare function executeCommand(command: string, args: string[], timeout?: number): Promise<CommandResult>;
/**
 * Check if a tool is installed on the system
 * @param toolName - Name of the tool
 */
export declare function checkToolInstalled(toolName: string): Promise<boolean>;
/**
 * Get the version of an installed tool
 * @param toolName - Name of the tool
 */
export declare function getToolVersion(toolName: string): Promise<string>;
/**
 * Sanitize target to prevent command injection
 * @param target - Target string to sanitize
 */
export declare function sanitizeTarget(target: string): string;
/**
 * Parse Nmap XML output to structured vulnerabilities
 * @param xml - Nmap XML output
 */
export declare function parseNmapXML(xml: string): Vulnerability[];
/**
 * Parse Nikto CSV/text output
 * @param output - Nikto output
 * @param target - Target URL
 */
export declare function parseNiktoOutput(output: string, target: string): Vulnerability[];
/**
 * Parse SQLMap output
 * @param output - SQLMap output
 * @param target - Target URL
 */
export declare function parseSqlmapOutput(output: string, target: string): Vulnerability[];
/**
 * Parse Gobuster output
 * @param output - Gobuster output
 * @param target - Target URL
 */
export declare function parseGobusterOutput(output: string, target: string): Vulnerability[];
/**
 * Parse SSLScan output
 * @param output - SSLScan output
 * @param target - Target host:port
 */
export declare function parseSSLScanOutput(output: string, target: string): Vulnerability[];
/**
 * Parse WhatWeb JSON output
 * @param output - WhatWeb output
 * @param target - Target URL
 */
export declare function parseWhatWebOutput(output: string, target: string): Vulnerability[];
//# sourceMappingURL=tool-wrappers.d.ts.map