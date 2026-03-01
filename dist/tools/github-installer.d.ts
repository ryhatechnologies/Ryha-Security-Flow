/**
 * GitHub Tool Installer - Clone, build and install any security tool from GitHub
 * Ryha Security Flow - Enterprise Penetration Testing Platform
 *
 * Supports: Go, Python, Rust, Node.js, Ruby, Make-based, and script-based tools
 */
import { EventEmitter } from 'events';
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
export declare const KNOWN_GITHUB_TOOLS: Record<string, Partial<GitHubToolRequest> & {
    description: string;
}>;
/**
 * GitHubInstaller - Clone, build, install any security tool from GitHub
 */
export declare class GitHubInstaller extends EventEmitter {
    private installBase;
    private clonePath;
    constructor(installBase?: string);
    /**
     * Install a tool from GitHub repository URL
     */
    installFromGitHub(request: GitHubToolRequest): Promise<InstallResult>;
    /**
     * Install from a known tool shortcut (e.g., "projectdiscovery/nuclei")
     */
    installKnownTool(repoSlug: string): Promise<InstallResult>;
    /**
     * Ask AI to find the best GitHub repo for a tool need
     */
    findToolOnGitHub(need: string): Promise<Array<{
        repo: string;
        description: string;
        stars: string;
    }>>;
    /**
     * List all known installable tools
     */
    listKnownTools(): Array<{
        repo: string;
        description: string;
        buildSystem: string;
    }>;
    /**
     * List currently installed GitHub tools
     */
    listInstalledTools(): Promise<string[]>;
    /**
     * Uninstall a GitHub-installed tool
     */
    uninstallTool(toolName: string): Promise<boolean>;
    private normalizeRepoUrl;
    private extractToolName;
    private cloneOrUpdate;
    private detectBuildSystem;
    private buildAndInstall;
    private buildGo;
    private buildPython;
    private buildRust;
    private buildNode;
    private buildRuby;
    private buildMake;
    private buildCMake;
    private installScript;
    private findPythonEntry;
    private getVersion;
    private createSymlink;
    private runCommand;
    private parseJSON;
}
//# sourceMappingURL=github-installer.d.ts.map