/**
 * GitHub Tool Installer - Clone, build and install any security tool from GitHub
 * Ryha Security Flow - Enterprise Penetration Testing Platform
 *
 * Supports: Go, Python, Rust, Node.js, Ruby, Make-based, and script-based tools
 */

import { EventEmitter } from 'events';
import { spawn } from 'child_process';
import * as fs from 'fs/promises';
import * as path from 'path';
import { copilotAuth } from '../auth/copilot-auth';

/**
 * Build system type detection
 */
export type BuildSystem = 'go' | 'python' | 'rust' | 'node' | 'ruby' | 'make' | 'cmake' | 'script' | 'unknown';

/**
 * GitHub tool install request
 */
export interface GitHubToolRequest {
  repoUrl: string;
  name?: string;
  branch?: string;
  buildSystem?: BuildSystem;
  installPath?: string;
  buildArgs?: string[];
  postInstall?: string[];
}

/**
 * Install result
 */
export interface InstallResult {
  success: boolean;
  toolName: string;
  repoUrl: string;
  installPath: string;
  buildSystem: BuildSystem;
  version: string;
  duration: number;
  error?: string;
}

/**
 * Known GitHub security tool repos with build instructions
 */
export const KNOWN_GITHUB_TOOLS: Record<string, Partial<GitHubToolRequest> & { description: string }> = {
  // Go-based tools
  'projectdiscovery/nuclei':    { buildSystem: 'go', description: 'Fast vulnerability scanner with templates' },
  'projectdiscovery/httpx':     { buildSystem: 'go', description: 'Fast HTTP probing tool' },
  'projectdiscovery/subfinder': { buildSystem: 'go', description: 'Passive subdomain discovery' },
  'projectdiscovery/katana':    { buildSystem: 'go', description: 'Next-gen web crawling framework' },
  'projectdiscovery/naabu':     { buildSystem: 'go', description: 'Fast port scanner' },
  'projectdiscovery/dnsx':      { buildSystem: 'go', description: 'Fast DNS toolkit' },
  'projectdiscovery/uncover':   { buildSystem: 'go', description: 'API-based host discovery' },
  'projectdiscovery/interactsh':{ buildSystem: 'go', description: 'OOB interaction server' },
  'projectdiscovery/notify':    { buildSystem: 'go', description: 'Notification helper' },
  'projectdiscovery/chaos-client': { buildSystem: 'go', description: 'Chaos bug bounty recon' },
  'ffuf/ffuf':                  { buildSystem: 'go', description: 'Fast web fuzzer' },
  'tomnomnom/gf':               { buildSystem: 'go', description: 'Grep for pentesters' },
  'tomnomnom/waybackurls':      { buildSystem: 'go', description: 'Fetch all URLs cached by Wayback Machine' },
  'tomnomnom/assetfinder':      { buildSystem: 'go', description: 'Find domains and subdomains' },
  'tomnomnom/httprobe':         { buildSystem: 'go', description: 'Probe HTTP/HTTPS servers' },
  'tomnomnom/meg':              { buildSystem: 'go', description: 'Fetch many paths for many hosts' },
  'tomnomnom/unfurl':           { buildSystem: 'go', description: 'Pull out bits of URLs' },
  'tomnomnom/qsreplace':        { buildSystem: 'go', description: 'Replace query string values' },
  'lc/gau':                     { buildSystem: 'go', description: 'Fetch known URLs from multiple sources' },
  'hakluke/hakrawler':          { buildSystem: 'go', description: 'Web crawler for gathering URLs' },
  'hahwul/dalfox':              { buildSystem: 'go', description: 'XSS scanning and parameter analysis' },
  'OJ/gobuster':                { buildSystem: 'go', description: 'Directory/DNS brute-forcing' },
  'sensepost/gowitness':        { buildSystem: 'go', description: 'Web screenshot utility' },
  'dwisiswant0/crlfuzz':        { buildSystem: 'go', description: 'CRLF vulnerability scanner' },
  'Edgars/feroxbuster':         { buildSystem: 'rust', description: 'Fast content discovery tool' },
  'RustScan/RustScan':          { buildSystem: 'rust', description: 'Fast port scanner' },

  // Python-based tools
  'sqlmapproject/sqlmap':       { buildSystem: 'python', description: 'SQL injection detection' },
  'commixproject/commix':       { buildSystem: 'python', description: 'Command injection exploitation' },
  's0md3v/Arjun':               { buildSystem: 'python', description: 'HTTP parameter discovery' },
  'devanshbatham/ParamSpider':  { buildSystem: 'python', description: 'Parameter URL mining' },
  'aboul3la/Sublist3r':         { buildSystem: 'python', description: 'Fast subdomain enumeration' },
  'laramies/theHarvester':      { buildSystem: 'python', description: 'OSINT gathering' },
  'wpscanteam/wpscan':          { buildSystem: 'ruby', description: 'WordPress vulnerability scanner' },
  'EnableSecurity/wafw00f':     { buildSystem: 'python', description: 'WAF detection tool' },
  'lanmaster53/recon-ng':       { buildSystem: 'python', description: 'Recon framework' },
  'sherlock-project/sherlock':  { buildSystem: 'python', description: 'Social media username finder' },
  'threat9/routersploit':       { buildSystem: 'python', description: 'Router exploitation framework' },
  'urbanadventurer/WhatWeb':    { buildSystem: 'ruby', description: 'Web technology fingerprinter' },
  'httpie/cli':                 { buildSystem: 'python', description: 'Modern HTTP client' },
  'mpgn/CrackMapExec':          { buildSystem: 'python', description: 'Post-exploitation for AD' },
  'lgandx/Responder':           { buildSystem: 'python', description: 'LLMNR/NBT-NS poisoner' },
  'SecureAuthCorp/impacket':    { buildSystem: 'python', description: 'Network protocol tools' },
  'volatilityfoundation/volatility3': { buildSystem: 'python', description: 'Memory forensics' },
  'AlessandroZ/LaZagne':        { buildSystem: 'python', description: 'Credential recovery' },
  'Hackmanit/TIDoS-Framework':  { buildSystem: 'python', description: 'Web app pentest framework' },
  'OWASP/Amass':                { buildSystem: 'go', description: 'Attack surface mapping' },

  // Rust-based tools
  'epi052/feroxbuster':         { buildSystem: 'rust', description: 'Fast recursive content discovery' },

  // Make/C-based tools
  'vanhauser-thc/thc-hydra':   { buildSystem: 'make', description: 'Network logon cracker' },
  'openwall/john':              { buildSystem: 'make', description: 'Password cracker' },
  'aircrack-ng/aircrack-ng':   { buildSystem: 'make', description: 'WiFi security auditing' },
  'wireshark/wireshark':       { buildSystem: 'cmake', description: 'Network protocol analyzer' },
  'scanmem/scanmem':           { buildSystem: 'make', description: 'Memory scanner and editor' },
};

/**
 * GitHubInstaller - Clone, build, install any security tool from GitHub
 */
export class GitHubInstaller extends EventEmitter {
  private installBase: string;
  private clonePath: string;

  constructor(installBase: string = '/opt/ryha-tools') {
    super();
    this.installBase = installBase;
    this.clonePath = path.join(installBase, '.repos');
  }

  /**
   * Install a tool from GitHub repository URL
   */
  async installFromGitHub(request: GitHubToolRequest): Promise<InstallResult> {
    const startTime = Date.now();
    const repoUrl = this.normalizeRepoUrl(request.repoUrl);
    const toolName = request.name || this.extractToolName(repoUrl);
    const branch = request.branch || 'main';

    this.emit('install:start', toolName, repoUrl);

    try {
      // Ensure directories exist
      await fs.mkdir(this.clonePath, { recursive: true });
      await fs.mkdir(path.join(this.installBase, 'bin'), { recursive: true });

      const repoPath = path.join(this.clonePath, toolName);

      // Clone or update repo
      await this.cloneOrUpdate(repoUrl, repoPath, branch);
      this.emit('install:cloned', toolName);

      // Detect build system
      const buildSystem = request.buildSystem || await this.detectBuildSystem(repoPath);
      this.emit('install:detected', toolName, buildSystem);

      // Build and install
      const installPath = request.installPath || path.join(this.installBase, 'bin', toolName);
      await this.buildAndInstall(repoPath, buildSystem, toolName, installPath, request.buildArgs);
      this.emit('install:built', toolName);

      // Run post-install commands
      if (request.postInstall) {
        for (const cmd of request.postInstall) {
          await this.runCommand('bash', ['-c', cmd], repoPath);
        }
      }

      // Verify installation
      const version = await this.getVersion(installPath, toolName);

      // Add to PATH symlink
      await this.createSymlink(installPath, toolName);

      const result: InstallResult = {
        success: true,
        toolName,
        repoUrl,
        installPath,
        buildSystem,
        version,
        duration: Date.now() - startTime,
      };

      this.emit('install:complete', result);
      return result;

    } catch (error) {
      const result: InstallResult = {
        success: false,
        toolName,
        repoUrl,
        installPath: '',
        buildSystem: 'unknown',
        version: '',
        duration: Date.now() - startTime,
        error: (error as Error).message,
      };
      this.emit('install:error', result);
      return result;
    }
  }

  /**
   * Install from a known tool shortcut (e.g., "projectdiscovery/nuclei")
   */
  async installKnownTool(repoSlug: string): Promise<InstallResult> {
    const known = KNOWN_GITHUB_TOOLS[repoSlug];
    if (!known) {
      return this.installFromGitHub({
        repoUrl: `https://github.com/${repoSlug}`,
      });
    }

    return this.installFromGitHub({
      repoUrl: `https://github.com/${repoSlug}`,
      buildSystem: known.buildSystem,
      name: repoSlug.split('/')[1],
    });
  }

  /**
   * Ask AI to find the best GitHub repo for a tool need
   */
  async findToolOnGitHub(need: string): Promise<Array<{repo: string; description: string; stars: string}>> {
    try {
      const prompt = `You are a security researcher. I need a tool for: "${need}"

Find the BEST GitHub repositories for this purpose. Return ONLY valid JSON:
{
  "tools": [
    {
      "repo": "owner/repo-name",
      "description": "what it does",
      "stars": "approximate star count",
      "buildSystem": "go|python|rust|node|ruby|make",
      "installCommand": "how to install it"
    }
  ]
}

Prioritize actively maintained, well-known security tools.`;

      const response = await copilotAuth.sendChatMessage(prompt, 'gpt-4o');
      const parsed = this.parseJSON(response);
      return parsed.tools || [];
    } catch {
      return [];
    }
  }

  /**
   * List all known installable tools
   */
  listKnownTools(): Array<{repo: string; description: string; buildSystem: string}> {
    return Object.entries(KNOWN_GITHUB_TOOLS).map(([repo, info]) => ({
      repo,
      description: info.description,
      buildSystem: info.buildSystem || 'unknown',
    }));
  }

  /**
   * List currently installed GitHub tools
   */
  async listInstalledTools(): Promise<string[]> {
    try {
      const binDir = path.join(this.installBase, 'bin');
      const files = await fs.readdir(binDir);
      return files;
    } catch {
      return [];
    }
  }

  /**
   * Uninstall a GitHub-installed tool
   */
  async uninstallTool(toolName: string): Promise<boolean> {
    try {
      const binPath = path.join(this.installBase, 'bin', toolName);
      const repoPath = path.join(this.clonePath, toolName);
      const symlink = path.join('/usr/local/bin', toolName);

      await fs.rm(binPath, { force: true });
      await fs.rm(repoPath, { recursive: true, force: true });
      await fs.unlink(symlink).catch(() => {});

      this.emit('uninstall:complete', toolName);
      return true;
    } catch {
      return false;
    }
  }

  // -- Private methods --

  private normalizeRepoUrl(url: string): string {
    if (url.startsWith('https://') || url.startsWith('git@')) return url;
    // Assume owner/repo format
    return `https://github.com/${url}.git`;
  }

  private extractToolName(url: string): string {
    const match = url.match(/\/([^/]+?)(?:\.git)?$/);
    return match ? match[1] : 'unknown-tool';
  }

  private async cloneOrUpdate(repoUrl: string, repoPath: string, branch: string): Promise<void> {
    try {
      await fs.access(repoPath);
      // Repo exists, pull latest
      await this.runCommand('git', ['-C', repoPath, 'pull', '--ff-only'], repoPath);
    } catch {
      // Clone fresh
      await this.runCommand('git', ['clone', '--depth', '1', '-b', branch, repoUrl, repoPath]);
    }
  }

  private async detectBuildSystem(repoPath: string): Promise<BuildSystem> {
    const files = await fs.readdir(repoPath);
    const fileSet = new Set(files.map(f => f.toLowerCase()));

    if (fileSet.has('go.mod') || fileSet.has('go.sum'))           return 'go';
    if (fileSet.has('cargo.toml'))                                 return 'rust';
    if (fileSet.has('setup.py') || fileSet.has('pyproject.toml') || fileSet.has('requirements.txt')) return 'python';
    if (fileSet.has('package.json'))                                return 'node';
    if (fileSet.has('gemfile') || fileSet.has('gemspec'))           return 'ruby';
    if (fileSet.has('cmakelists.txt'))                              return 'cmake';
    if (fileSet.has('makefile') || fileSet.has('configure') || fileSet.has('configure.ac')) return 'make';

    // Check for scripts
    for (const f of files) {
      if (f.endsWith('.sh') || f.endsWith('.py') || f.endsWith('.rb') || f.endsWith('.pl')) {
        return 'script';
      }
    }

    return 'unknown';
  }

  private async buildAndInstall(
    repoPath: string,
    buildSystem: BuildSystem,
    toolName: string,
    installPath: string,
    buildArgs?: string[]
  ): Promise<void> {
    switch (buildSystem) {
      case 'go':
        await this.buildGo(repoPath, toolName, installPath, buildArgs);
        break;
      case 'python':
        await this.buildPython(repoPath, toolName, installPath);
        break;
      case 'rust':
        await this.buildRust(repoPath, toolName, installPath);
        break;
      case 'node':
        await this.buildNode(repoPath, toolName, installPath);
        break;
      case 'ruby':
        await this.buildRuby(repoPath, toolName, installPath);
        break;
      case 'make':
        await this.buildMake(repoPath, toolName, installPath);
        break;
      case 'cmake':
        await this.buildCMake(repoPath, toolName, installPath);
        break;
      case 'script':
        await this.installScript(repoPath, toolName, installPath);
        break;
      default:
        throw new Error(`Cannot determine how to build ${toolName} (build system: ${buildSystem})`);
    }
  }

  private async buildGo(repoPath: string, toolName: string, installPath: string, buildArgs?: string[]): Promise<void> {
    // Try go install first (most Go tools support this)
    const goPath = path.join(this.installBase, 'go');
    const env = { GOPATH: goPath, GOBIN: path.dirname(installPath) };

    try {
      // Read go.mod to find the module path
      const goMod = await fs.readFile(path.join(repoPath, 'go.mod'), 'utf8');
      const moduleMatch = goMod.match(/^module\s+(.+)$/m);
      const modulePath = moduleMatch ? moduleMatch[1].trim() : '';

      // Look for cmd/ directory pattern (common in Go projects)
      const cmdDir = path.join(repoPath, 'cmd', toolName);
      let buildTarget = './...';
      try {
        await fs.access(cmdDir);
        buildTarget = `./cmd/${toolName}`;
      } catch {
        // Try just cmd/ with any subfolder
        try {
          const cmdFiles = await fs.readdir(path.join(repoPath, 'cmd'));
          if (cmdFiles.length > 0) {
            buildTarget = `./cmd/${cmdFiles[0]}`;
          }
        } catch {
          // Use default
        }
      }

      await this.runCommand('go', ['build', '-o', installPath, ...(buildArgs || []), buildTarget], repoPath, env);
    } catch {
      // Fallback: try go install with the module path
      await this.runCommand('go', ['build', '-o', installPath, ...(buildArgs || []), '.'], repoPath, env);
    }
  }

  private async buildPython(repoPath: string, toolName: string, installPath: string): Promise<void> {
    // Check for setup.py or pyproject.toml
    const files = await fs.readdir(repoPath);

    if (files.includes('setup.py') || files.includes('pyproject.toml')) {
      await this.runCommand('pip3', ['install', '--break-system-packages', '-e', repoPath]);
    } else if (files.includes('requirements.txt')) {
      await this.runCommand('pip3', ['install', '--break-system-packages', '-r', path.join(repoPath, 'requirements.txt')]);
    }

    // Create wrapper script
    const mainScript = await this.findPythonEntry(repoPath, toolName);
    const wrapper = `#!/bin/bash\npython3 ${mainScript} "$@"\n`;
    await fs.writeFile(installPath, wrapper, { mode: 0o755 });
  }

  private async buildRust(repoPath: string, toolName: string, installPath: string): Promise<void> {
    await this.runCommand('cargo', ['build', '--release'], repoPath);

    // Find the built binary
    const targetDir = path.join(repoPath, 'target', 'release');
    const files = await fs.readdir(targetDir);
    const binary = files.find(f => f === toolName || f === toolName.replace(/-/g, '_'));

    if (binary) {
      await fs.copyFile(path.join(targetDir, binary), installPath);
      await fs.chmod(installPath, 0o755);
    } else {
      throw new Error(`Could not find built binary for ${toolName}`);
    }
  }

  private async buildNode(repoPath: string, toolName: string, installPath: string): Promise<void> {
    await this.runCommand('npm', ['install'], repoPath);

    // Check for bin entry in package.json
    const pkgJson = JSON.parse(await fs.readFile(path.join(repoPath, 'package.json'), 'utf8'));
    const binEntry = pkgJson.bin?.[toolName] || pkgJson.bin || pkgJson.main || 'index.js';
    const entryPoint = typeof binEntry === 'string' ? binEntry : Object.values(binEntry)[0];

    const wrapper = `#!/bin/bash\nnode ${path.join(repoPath, entryPoint as string)} "$@"\n`;
    await fs.writeFile(installPath, wrapper, { mode: 0o755 });
  }

  private async buildRuby(repoPath: string, toolName: string, installPath: string): Promise<void> {
    const files = await fs.readdir(repoPath);

    if (files.includes('Gemfile')) {
      await this.runCommand('bundle', ['install'], repoPath);
    }

    // Find the main executable
    const binDir = path.join(repoPath, 'bin');
    try {
      const binFiles = await fs.readdir(binDir);
      const mainBin = binFiles.find(f => f === toolName) || binFiles[0];
      if (mainBin) {
        const wrapper = `#!/bin/bash\nruby ${path.join(binDir, mainBin)} "$@"\n`;
        await fs.writeFile(installPath, wrapper, { mode: 0o755 });
        return;
      }
    } catch { /* no bin dir */ }

    // Fallback: gem install
    const gemspecFiles = files.filter(f => f.endsWith('.gemspec'));
    if (gemspecFiles.length > 0) {
      await this.runCommand('gem', ['build', gemspecFiles[0]], repoPath);
      const gemFile = (await fs.readdir(repoPath)).find(f => f.endsWith('.gem'));
      if (gemFile) {
        await this.runCommand('gem', ['install', path.join(repoPath, gemFile)]);
      }
    }
  }

  private async buildMake(repoPath: string, toolName: string, installPath: string): Promise<void> {
    const files = await fs.readdir(repoPath);

    // Run configure if present
    if (files.includes('configure')) {
      await this.runCommand('./configure', [], repoPath);
    } else if (files.includes('configure.ac') || files.includes('configure.in')) {
      if (files.includes('autogen.sh')) {
        await this.runCommand('bash', ['autogen.sh'], repoPath);
      } else {
        await this.runCommand('autoreconf', ['-fiv'], repoPath);
      }
      await this.runCommand('./configure', [], repoPath);
    }

    await this.runCommand('make', ['-j', String(Math.max(1, require('os').cpus().length - 1))], repoPath);

    // Try to find the built binary
    const possibleBinaries = [
      path.join(repoPath, toolName),
      path.join(repoPath, 'src', toolName),
      path.join(repoPath, 'build', toolName),
    ];

    for (const bin of possibleBinaries) {
      try {
        await fs.access(bin, fs.constants.X_OK);
        await fs.copyFile(bin, installPath);
        await fs.chmod(installPath, 0o755);
        return;
      } catch { /* try next */ }
    }

    // Fallback: make install
    await this.runCommand('make', ['install', `PREFIX=${this.installBase}`], repoPath);
  }

  private async buildCMake(repoPath: string, toolName: string, installPath: string): Promise<void> {
    const buildDir = path.join(repoPath, 'build');
    await fs.mkdir(buildDir, { recursive: true });

    await this.runCommand('cmake', ['..', `-DCMAKE_INSTALL_PREFIX=${this.installBase}`], buildDir);
    await this.runCommand('make', ['-j', String(Math.max(1, require('os').cpus().length - 1))], buildDir);
    await this.runCommand('make', ['install'], buildDir);
  }

  private async installScript(repoPath: string, toolName: string, installPath: string): Promise<void> {
    // Find main script
    const files = await fs.readdir(repoPath);
    const script = files.find(f =>
      f === `${toolName}.py` || f === `${toolName}.sh` || f === `${toolName}.rb` ||
      f === 'main.py' || f === 'main.sh' || f === toolName
    ) || files.find(f => f.endsWith('.py') || f.endsWith('.sh') || f.endsWith('.rb'));

    if (!script) {
      throw new Error(`No executable script found for ${toolName}`);
    }

    const scriptPath = path.join(repoPath, script);
    await fs.copyFile(scriptPath, installPath);
    await fs.chmod(installPath, 0o755);
  }

  private async findPythonEntry(repoPath: string, toolName: string): Promise<string> {
    const candidates = [
      path.join(repoPath, `${toolName}.py`),
      path.join(repoPath, toolName, '__main__.py'),
      path.join(repoPath, 'src', `${toolName}.py`),
      path.join(repoPath, 'main.py'),
      path.join(repoPath, `${toolName}`, `${toolName}.py`),
    ];

    for (const candidate of candidates) {
      try {
        await fs.access(candidate);
        return candidate;
      } catch { /* try next */ }
    }

    // Fallback: use -m module
    return `-m ${toolName}`;
  }

  private async getVersion(installPath: string, toolName: string): Promise<string> {
    try {
      const result = await this.runCommand(installPath, ['--version']);
      return result.trim().split('\n')[0] || 'installed';
    } catch {
      try {
        const result = await this.runCommand(installPath, ['-V']);
        return result.trim().split('\n')[0] || 'installed';
      } catch {
        return 'installed';
      }
    }
  }

  private async createSymlink(installPath: string, toolName: string): Promise<void> {
    const symlinkPath = path.join('/usr/local/bin', toolName);
    try {
      await fs.unlink(symlinkPath).catch(() => {});
      await fs.symlink(installPath, symlinkPath);
    } catch {
      // Might not have permission, tool still usable from installBase/bin
    }
  }

  private runCommand(
    cmd: string,
    args: string[],
    cwd?: string,
    env?: Record<string, string>
  ): Promise<string> {
    return new Promise((resolve, reject) => {
      const proc = spawn(cmd, args, {
        cwd,
        env: { ...process.env, ...env },
        shell: cmd.startsWith('./'),
      });

      let stdout = '';
      let stderr = '';

      proc.stdout?.on('data', (data) => {
        stdout += data.toString();
        this.emit('output', data.toString());
      });

      proc.stderr?.on('data', (data) => {
        stderr += data.toString();
        this.emit('output', data.toString());
      });

      proc.on('error', reject);

      proc.on('close', (code) => {
        if (code === 0) {
          resolve(stdout);
        } else {
          reject(new Error(`Command "${cmd} ${args.join(' ')}" failed (exit ${code}): ${stderr}`));
        }
      });

      // Timeout after 15 minutes
      setTimeout(() => {
        proc.kill('SIGTERM');
        reject(new Error(`Command timed out: ${cmd} ${args.join(' ')}`));
      }, 900000);
    });
  }

  private parseJSON(response: string): any {
    try {
      return JSON.parse(response);
    } catch {
      const match = response.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
      if (match) return JSON.parse(match[1]);
      const rawMatch = response.match(/\{[\s\S]*\}/);
      if (rawMatch) return JSON.parse(rawMatch[0]);
      return { tools: [] };
    }
  }
}
