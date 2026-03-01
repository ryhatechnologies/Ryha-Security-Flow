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
 * Get Kali Linux integration configuration
 */
export declare function getKaliConfig(): KaliConfig;
/**
 * Get configuration summary as formatted string
 */
export declare function getConfigSummary(): string;
/**
 * Get detailed tool information
 */
export declare function getToolInfo(category?: string): ToolDetectionResult[];
/**
 * Validate Kali configuration
 */
export declare function validateKaliConfig(): {
    isValid: boolean;
    errors: string[];
    warnings: string[];
};
declare const _default: {
    getKaliConfig: typeof getKaliConfig;
    getConfigSummary: typeof getConfigSummary;
    getToolInfo: typeof getToolInfo;
    validateKaliConfig: typeof validateKaliConfig;
};
export default _default;
//# sourceMappingURL=kali-integration.d.ts.map