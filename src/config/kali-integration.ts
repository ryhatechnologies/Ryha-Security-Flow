import { execSync } from 'child_process';
import { existsSync, readFileSync } from 'fs';
import { join } from 'path';

/**
 * Tool detection result
 */
export interface ToolDetectionResult {
  id: string;
  name: string;
  path: string | null;
  installed: boolean;
  version?: string;
  category: string;
}

/**
 * Kali Linux integration configuration
 */
export interface KaliConfig {
  isKaliLinux: boolean;
  osInfo: {
    name: string;
    version?: string;
    codename?: string;
  };
  nodeVersion: string;
  npmVersion: string;
  pythonVersion: string;
  tools: {
    scanning: ToolDetectionResult[];
    web: ToolDetectionResult[];
    credentials: ToolDetectionResult[];
    exploitation: ToolDetectionResult[];
    utilities: ToolDetectionResult[];
  };
  directories: {
    appRoot: string;
    dataDir: string;
    reportsDir: string;
    toolsDir: string;
    configDir: string;
    logsDir: string;
  };
  sudoersConfigured: boolean;
  serviceInstalled: boolean;
  allToolsAvailable: boolean;
}

/**
 * Execute command and return output
 */
function executeCommand(command: string, silent: boolean = true): string {
  try {
    return execSync(command, { encoding: 'utf-8', stdio: silent ? 'pipe' : 'inherit' }).trim();
  } catch (error) {
    return '';
  }
}

/**
 * Get version of installed tool
 */
function getToolVersion(command: string): string {
  try {
    // Try common version flags
    for (const flag of ['--version', '-v', '-version']) {
      const result = executeCommand(`${command} ${flag} 2>&1`, true);
      if (result && !result.includes('not found')) {
        // Extract version number (first match of pattern like v1.2.3 or 1.2.3)
        const versionMatch = result.match(/(?:v?)?(\d+\.\d+(?:\.\d+)*)/);
        return versionMatch ? versionMatch[1] : result.split('\n')[0];
      }
    }
  } catch (error) {
    // Silently fail
  }
  return '';
}

/**
 * Check if command exists in system PATH
 */
function commandExists(command: string): boolean {
  try {
    const result = executeCommand(`command -v ${command} 2>&1`, true);
    return !!result && !result.includes('not found');
  } catch {
    return false;
  }
}

/**
 * Detect Kali Linux system
 */
function detectKaliLinux(): { isKali: boolean; osInfo: KaliConfig['osInfo'] } {
  const osInfo: KaliConfig['osInfo'] = {
    name: 'Unknown',
  };

  if (!existsSync('/etc/os-release')) {
    return { isKali: false, osInfo };
  }

  try {
    const osRelease = readFileSync('/etc/os-release', 'utf-8');
    const lines = osRelease.split('\n');
    const osData: Record<string, string> = {};

    lines.forEach((line) => {
      const [key, value] = line.split('=');
      if (key && value) {
        osData[key] = value.replace(/^["']|["']$/g, '');
      }
    });

    osInfo.name = osData.PRETTY_NAME || osData.NAME || 'Unknown';
    osInfo.version = osData.VERSION_ID || osData.VERSION;
    osInfo.codename = osData.VERSION_CODENAME;

    const isKali = (osData.ID || '').toLowerCase().includes('kali') ||
                  (osData.ID_LIKE || '').toLowerCase().includes('kali') ||
                  (osData.NAME || '').toLowerCase().includes('kali');

    return { isKali, osInfo };
  } catch (error) {
    return { isKali: false, osInfo };
  }
}

/**
 * Detect installed security tools
 */
function detectSecurityTools(): KaliConfig['tools'] {
  return {
    scanning: [
      { id: 'nmap', name: 'Nmap', path: null, installed: false, category: 'scanning' },
      { id: 'masscan', name: 'Masscan', path: null, installed: false, category: 'scanning' },
      { id: 'nessus', name: 'Nessus Agent', path: null, installed: false, category: 'scanning' },
      { id: 'nikto', name: 'Nikto', path: null, installed: false, category: 'scanning' },
      { id: 'wfuzz', name: 'Wfuzz', path: null, installed: false, category: 'scanning' },
      { id: 'dirb', name: 'Dirb', path: null, installed: false, category: 'scanning' },
    ].map((tool) => {
      const exists = commandExists(tool.id);
      return {
        ...tool,
        installed: exists,
        path: exists ? executeCommand(`command -v ${tool.id}`, true) : null,
        version: exists ? getToolVersion(tool.id) : undefined,
      };
    }),
    web: [
      { id: 'zaproxy', name: 'OWASP ZAP', path: null, installed: false, category: 'web' },
      { id: 'sqlmap', name: 'SQLMap', path: null, installed: false, category: 'web' },
      { id: 'burpsuite', name: 'Burp Suite', path: null, installed: false, category: 'web' },
    ].map((tool) => {
      const exists = commandExists(tool.id);
      return {
        ...tool,
        installed: exists,
        path: exists ? executeCommand(`command -v ${tool.id}`, true) : null,
        version: exists ? getToolVersion(tool.id) : undefined,
      };
    }),
    credentials: [
      { id: 'hashcat', name: 'Hashcat', path: null, installed: false, category: 'credentials' },
      { id: 'john', name: 'John the Ripper', path: null, installed: false, category: 'credentials' },
      { id: 'hydra', name: 'Hydra', path: null, installed: false, category: 'credentials' },
      { id: 'medusa', name: 'Medusa', path: null, installed: false, category: 'credentials' },
    ].map((tool) => {
      const exists = commandExists(tool.id);
      return {
        ...tool,
        installed: exists,
        path: exists ? executeCommand(`command -v ${tool.id}`, true) : null,
        version: exists ? getToolVersion(tool.id) : undefined,
      };
    }),
    exploitation: [
      { id: 'msfconsole', name: 'Metasploit Framework', path: null, installed: false, category: 'exploitation' },
      { id: 'aircrack-ng', name: 'Aircrack-ng', path: null, installed: false, category: 'exploitation' },
      { id: 'airmon-ng', name: 'Airmon-ng', path: null, installed: false, category: 'exploitation' },
    ].map((tool) => {
      const exists = commandExists(tool.id);
      return {
        ...tool,
        installed: exists,
        path: exists ? executeCommand(`command -v ${tool.id}`, true) : null,
        version: exists ? getToolVersion(tool.id) : undefined,
      };
    }),
    utilities: [
      { id: 'curl', name: 'curl', path: null, installed: false, category: 'utilities' },
      { id: 'wget', name: 'wget', path: null, installed: false, category: 'utilities' },
      { id: 'git', name: 'git', path: null, installed: false, category: 'utilities' },
      { id: 'python3', name: 'Python 3', path: null, installed: false, category: 'utilities' },
      { id: 'node', name: 'Node.js', path: null, installed: false, category: 'utilities' },
      { id: 'npm', name: 'npm', path: null, installed: false, category: 'utilities' },
    ].map((tool) => {
      const exists = commandExists(tool.id);
      return {
        ...tool,
        installed: exists,
        path: exists ? executeCommand(`command -v ${tool.id}`, true) : null,
        version: exists ? getToolVersion(tool.id) : undefined,
      };
    }),
  };
}

/**
 * Check if sudoers is properly configured
 */
function checkSudoersConfig(): boolean {
  try {
    if (!existsSync('/etc/sudoers.d/ryha')) {
      return false;
    }
    const sudoersContent = readFileSync('/etc/sudoers.d/ryha', 'utf-8');
    return sudoersContent.includes('RYHA_TOOLS') || sudoersContent.includes('ryha');
  } catch {
    return false;
  }
}

/**
 * Check if systemd service is installed
 */
function checkServiceInstalled(): boolean {
  return existsSync('/etc/systemd/system/ryha.service');
}

/**
 * Get Node.js version
 */
function getNodeVersion(): string {
  try {
    return executeCommand('node --version', true).replace(/^v/, '');
  } catch {
    return '';
  }
}

/**
 * Get npm version
 */
function getNpmVersion(): string {
  try {
    return executeCommand('npm --version', true);
  } catch {
    return '';
  }
}

/**
 * Get Python version
 */
function getPythonVersion(): string {
  try {
    return executeCommand('python3 --version', true).replace('Python ', '');
  } catch {
    return '';
  }
}

/**
 * Get Kali Linux integration configuration
 */
export function getKaliConfig(): KaliConfig {
  const { isKali, osInfo } = detectKaliLinux();
  const tools = detectSecurityTools();

  // Count available tools
  const allToolsList = [
    ...tools.scanning,
    ...tools.web,
    ...tools.credentials,
    ...tools.exploitation,
    ...tools.utilities,
  ];
  const installedCount = allToolsList.filter((t) => t.installed).length;
  const allToolsAvailable = installedCount === allToolsList.length;

  const config: KaliConfig = {
    isKaliLinux: isKali,
    osInfo,
    nodeVersion: getNodeVersion(),
    npmVersion: getNpmVersion(),
    pythonVersion: getPythonVersion(),
    tools,
    directories: {
      appRoot: '/opt/ryha-security-flow',
      dataDir: '/var/ryha/data',
      reportsDir: '/var/ryha/reports',
      toolsDir: '/var/ryha/tools',
      configDir: '/etc/ryha',
      logsDir: '/var/ryha/logs',
    },
    sudoersConfigured: checkSudoersConfig(),
    serviceInstalled: checkServiceInstalled(),
    allToolsAvailable,
  };

  return config;
}

/**
 * Get configuration summary as formatted string
 */
export function getConfigSummary(): string {
  const config = getKaliConfig();

  let summary = '\n========== RYHA KALI CONFIGURATION SUMMARY ==========\n\n';

  summary += `System:\n`;
  summary += `  OS:            ${config.osInfo.name}\n`;
  summary += `  Version:       ${config.osInfo.version || 'Unknown'}\n`;
  summary += `  Kali Linux:    ${config.isKaliLinux ? 'Yes' : 'No'}\n\n`;

  summary += `Runtime Versions:\n`;
  summary += `  Node.js:       ${config.nodeVersion || 'Not installed'}\n`;
  summary += `  npm:           ${config.npmVersion || 'Not installed'}\n`;
  summary += `  Python 3:      ${config.pythonVersion || 'Not installed'}\n\n`;

  summary += `Security Tools Summary:\n`;
  summary += `  Scanning:      ${config.tools.scanning.filter((t) => t.installed).length}/${config.tools.scanning.length} installed\n`;
  summary += `  Web Testing:   ${config.tools.web.filter((t) => t.installed).length}/${config.tools.web.length} installed\n`;
  summary += `  Credentials:   ${config.tools.credentials.filter((t) => t.installed).length}/${config.tools.credentials.length} installed\n`;
  summary += `  Exploitation:  ${config.tools.exploitation.filter((t) => t.installed).length}/${config.tools.exploitation.length} installed\n`;
  summary += `  Utilities:     ${config.tools.utilities.filter((t) => t.installed).length}/${config.tools.utilities.length} installed\n\n`;

  summary += `Configuration Status:\n`;
  summary += `  Sudoers Config: ${config.sudoersConfigured ? 'Configured' : 'Not configured'}\n`;
  summary += `  Systemd Service: ${config.serviceInstalled ? 'Installed' : 'Not installed'}\n`;
  summary += `  All Tools Ready: ${config.allToolsAvailable ? 'Yes' : 'No'}\n\n`;

  summary += `Application Directories:\n`;
  summary += `  App Root:      ${config.directories.appRoot}\n`;
  summary += `  Data:          ${config.directories.dataDir}\n`;
  summary += `  Reports:       ${config.directories.reportsDir}\n`;
  summary += `  Tools:         ${config.directories.toolsDir}\n`;
  summary += `  Config:        ${config.directories.configDir}\n`;
  summary += `  Logs:          ${config.directories.logsDir}\n\n`;

  summary += `=====================================================\n`;

  return summary;
}

/**
 * Get detailed tool information
 */
export function getToolInfo(category?: string): ToolDetectionResult[] {
  const config = getKaliConfig();
  const allTools = [
    ...config.tools.scanning,
    ...config.tools.web,
    ...config.tools.credentials,
    ...config.tools.exploitation,
    ...config.tools.utilities,
  ];

  if (category) {
    return allTools.filter((t) => t.category === category);
  }

  return allTools;
}

/**
 * Validate Kali configuration
 */
export function validateKaliConfig(): {
  isValid: boolean;
  errors: string[];
  warnings: string[];
} {
  const config = getKaliConfig();
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!config.isKaliLinux) {
    warnings.push('Not running on Kali Linux. Some features may not work correctly.');
  }

  if (!config.nodeVersion) {
    errors.push('Node.js is not installed.');
  } else if (parseInt(config.nodeVersion.split('.')[0]) < 20) {
    errors.push(`Node.js version ${config.nodeVersion} is less than required version 20.`);
  }

  if (!config.npmVersion) {
    errors.push('npm is not installed.');
  }

  const requiredTools = ['nmap', 'curl', 'wget', 'git'];
  const missingRequired = config.tools.utilities
    .filter((t) => requiredTools.includes(t.id) && !t.installed)
    .map((t) => t.name);

  if (missingRequired.length > 0) {
    errors.push(`Required tools not installed: ${missingRequired.join(', ')}`);
  }

  if (!config.sudoersConfigured) {
    warnings.push('Sudoers configuration not found. Some privileged operations may fail.');
  }

  return {
    isValid: errors.length === 0,
    errors,
    warnings,
  };
}

export default {
  getKaliConfig,
  getConfigSummary,
  getToolInfo,
  validateKaliConfig,
};
