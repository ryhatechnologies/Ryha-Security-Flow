import { GitHubInstaller } from './github-installer';
/**
 * Tool category enumeration
 */
export declare enum ToolCategory {
    RECON = "recon",
    SCANNER = "scanner",
    EXPLOIT = "exploit",
    WIRELESS = "wireless",
    WEB = "web",
    PASSWORD = "password",
    FORENSICS = "forensics",
    SNIFFING = "sniffing",
    REVERSE_ENGINEERING = "reverse-engineering",
    CLOUD = "cloud",
    MOBILE = "mobile",
    API = "api",
    POST_EXPLOITATION = "post-exploitation",
    SOCIAL_ENGINEERING = "social-engineering",
    REPORTING = "reporting",
    VOIP = "voip",
    HARDWARE = "hardware",
    CUSTOM = "custom"
}
/**
 * Tool information interface
 */
export interface ToolInfo {
    name: string;
    displayName: string;
    version: string;
    description: string;
    category: ToolCategory;
    capabilities: string[];
    installed: boolean;
    path?: string;
    requiresRoot: boolean;
    defaultArgs?: string[];
}
/**
 * Custom tool definition
 */
export interface CustomTool {
    name: string;
    script: string;
    description: string;
    category: ToolCategory;
    requiresRoot: boolean;
    createdAt: Date;
}
/**
 * Tool command generation options
 */
export interface CommandOptions {
    target: string;
    port?: number;
    protocol?: string;
    output?: string;
    verbose?: boolean;
    additionalArgs?: string[];
}
/**
 * ToolManager - Manages available tools and custom tool creation
 */
export declare class ToolManager {
    private toolsPath;
    private customToolsPath;
    private installedTools;
    private toolDatabase;
    githubInstaller: GitHubInstaller;
    constructor(toolsPath?: string);
    /**
     * Initialize the built-in tool database
     */
    private initializeToolDatabase;
    /**
     * Discover installed tools on Kali Linux
     */
    discoverTools(): Promise<ToolInfo[]>;
    /**
     * Discover security tools not in the database by scanning system paths
     */
    private discoverUnknownTools;
    /**
     * Register a dynamically discovered tool
     */
    registerTool(name: string, info: Partial<ToolInfo>): void;
    /**
     * Guess tool category based on name
     */
    private guessCategory;
    /**
     * Get information about a specific tool
     */
    getToolInfo(name: string): Promise<ToolInfo | null>;
    /**
     * Install a tool using apt-get
     */
    installTool(name: string): Promise<boolean>;
    /**
     * Create a custom security tool
     */
    createCustomTool(name: string, script: string, description: string, category?: ToolCategory): Promise<CustomTool>;
    /**
     * List all available tools
     */
    listAvailableTools(category?: ToolCategory): ToolInfo[];
    /**
     * Generate command line for a tool
     */
    getToolCommand(toolName: string, options: CommandOptions): {
        command: string;
        args: string[];
    };
    /**
     * Get tools by category
     */
    getToolsByCategory(category: ToolCategory): ToolInfo[];
    /**
     * Search tools by capability
     */
    searchByCapability(capability: string): ToolInfo[];
    private checkToolInstalled;
    private getToolVersion;
    private discoverCustomTools;
    private executeCommand;
}
//# sourceMappingURL=tool-manager.d.ts.map