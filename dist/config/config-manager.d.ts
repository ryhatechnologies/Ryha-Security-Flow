import { z } from 'zod';
import { EventEmitter } from 'events';
export interface ConfigChangeEvent {
    type: 'change' | 'save' | 'reload' | 'error';
    section?: keyof RyhaConfig;
    timestamp: Date;
    details?: string;
}
declare const CopilotConfigSchema: z.ZodObject<{
    proxyUrl: z.ZodDefault<z.ZodString>;
    models: z.ZodDefault<z.ZodArray<z.ZodString>>;
    defaultModel: z.ZodDefault<z.ZodString>;
    apiKey: z.ZodOptional<z.ZodString>;
    apiKeyEncrypted: z.ZodDefault<z.ZodBoolean>;
}, z.core.$strip>;
declare const AgentsConfigSchema: z.ZodObject<{
    maxParallel: z.ZodDefault<z.ZodNumber>;
    retryAttempts: z.ZodDefault<z.ZodNumber>;
    defaultTypes: z.ZodOptional<z.ZodArray<z.ZodString>>;
}, z.core.$strip>;
declare const ToolsConfigSchema: z.ZodObject<{
    nmap: z.ZodOptional<z.ZodString>;
    burpsuite: z.ZodOptional<z.ZodString>;
    zaproxy: z.ZodOptional<z.ZodString>;
    metasploit: z.ZodOptional<z.ZodString>;
    sqlmap: z.ZodOptional<z.ZodString>;
}, z.core.$strip>;
declare const KaliConfigSchema: z.ZodObject<{
    baseDir: z.ZodDefault<z.ZodString>;
    dataDir: z.ZodDefault<z.ZodString>;
    reportsDir: z.ZodDefault<z.ZodString>;
    enabled: z.ZodDefault<z.ZodBoolean>;
}, z.core.$strip>;
declare const LoggingConfigSchema: z.ZodObject<{
    level: z.ZodDefault<z.ZodEnum<{
        info: "info";
        error: "error";
        warn: "warn";
        debug: "debug";
    }>>;
    retention: z.ZodDefault<z.ZodString>;
    logDir: z.ZodOptional<z.ZodString>;
}, z.core.$strip>;
declare const ServerConfigSchema: z.ZodObject<{
    port: z.ZodDefault<z.ZodNumber>;
    host: z.ZodDefault<z.ZodString>;
    enableCors: z.ZodDefault<z.ZodBoolean>;
    corsOrigins: z.ZodOptional<z.ZodArray<z.ZodString>>;
}, z.core.$strip>;
declare const RyhaConfigSchema: z.ZodObject<{
    copilot: z.ZodOptional<z.ZodObject<{
        proxyUrl: z.ZodDefault<z.ZodString>;
        models: z.ZodDefault<z.ZodArray<z.ZodString>>;
        defaultModel: z.ZodDefault<z.ZodString>;
        apiKey: z.ZodOptional<z.ZodString>;
        apiKeyEncrypted: z.ZodDefault<z.ZodBoolean>;
    }, z.core.$strip>>;
    agents: z.ZodOptional<z.ZodObject<{
        maxParallel: z.ZodDefault<z.ZodNumber>;
        retryAttempts: z.ZodDefault<z.ZodNumber>;
        defaultTypes: z.ZodOptional<z.ZodArray<z.ZodString>>;
    }, z.core.$strip>>;
    tools: z.ZodOptional<z.ZodObject<{
        nmap: z.ZodOptional<z.ZodString>;
        burpsuite: z.ZodOptional<z.ZodString>;
        zaproxy: z.ZodOptional<z.ZodString>;
        metasploit: z.ZodOptional<z.ZodString>;
        sqlmap: z.ZodOptional<z.ZodString>;
    }, z.core.$strip>>;
    kali: z.ZodOptional<z.ZodObject<{
        baseDir: z.ZodDefault<z.ZodString>;
        dataDir: z.ZodDefault<z.ZodString>;
        reportsDir: z.ZodDefault<z.ZodString>;
        enabled: z.ZodDefault<z.ZodBoolean>;
    }, z.core.$strip>>;
    logging: z.ZodOptional<z.ZodObject<{
        level: z.ZodDefault<z.ZodEnum<{
            info: "info";
            error: "error";
            warn: "warn";
            debug: "debug";
        }>>;
        retention: z.ZodDefault<z.ZodString>;
        logDir: z.ZodOptional<z.ZodString>;
    }, z.core.$strip>>;
    server: z.ZodOptional<z.ZodObject<{
        port: z.ZodDefault<z.ZodNumber>;
        host: z.ZodDefault<z.ZodString>;
        enableCors: z.ZodDefault<z.ZodBoolean>;
        corsOrigins: z.ZodOptional<z.ZodArray<z.ZodString>>;
    }, z.core.$strip>>;
}, z.core.$strip>;
type RyhaConfig = z.infer<typeof RyhaConfigSchema>;
type CopilotConfig = z.infer<typeof CopilotConfigSchema>;
type AgentsConfig = z.infer<typeof AgentsConfigSchema>;
type ToolsConfig = z.infer<typeof ToolsConfigSchema>;
type KaliConfig = z.infer<typeof KaliConfigSchema>;
type LoggingConfig = z.infer<typeof LoggingConfigSchema>;
type ServerConfig = z.infer<typeof ServerConfigSchema>;
interface ConfigManagerOptions {
    configPath?: string;
    validateOnInit?: boolean;
    enableHotReload?: boolean;
    encryptionPassword?: string;
}
declare class ConfigManager extends EventEmitter {
    private config;
    private configPath;
    private watchers;
    private fileWatcher;
    private encryptionPassword;
    private readonly ENCRYPTION_ALGORITHM;
    private readonly SALT_LENGTH;
    private static instance;
    private static readonly instanceLock;
    constructor(options?: ConfigManagerOptions);
    static getInstance(options?: ConfigManagerOptions): ConfigManager;
    static resetInstance(): void;
    private getDefaultConfigPath;
    private generateDefaultPassword;
    private loadConfig;
    private loadEnvVariables;
    private mergeConfigs;
    validateConfig(): boolean;
    getConfig(): RyhaConfig;
    getSection<K extends keyof RyhaConfig>(section: K): RyhaConfig[K] | undefined;
    setSection<K extends keyof RyhaConfig>(section: K, value: Partial<RyhaConfig[K]>): void;
    set(path: string, value: any): void;
    get(path: string, defaultValue?: any): any;
    saveConfig(): void;
    encryptValue(value: string): string;
    decryptValue(encrypted: string): string;
    setApiKey(apiKey: string, service?: string): void;
    getApiKey(service?: string): string | undefined;
    watch(id: string, callback: (config: RyhaConfig) => void): void;
    unwatch(id: string): void;
    private enableHotReload;
    disableHotReload(): void;
    private notifyWatchers;
    private emitEvent;
    exportConfig(): string;
    reset(): void;
    destroy(): void;
}
export { ConfigManager, RyhaConfig, CopilotConfig, AgentsConfig, ToolsConfig, KaliConfig, LoggingConfig, ServerConfig, RyhaConfigSchema, };
//# sourceMappingURL=config-manager.d.ts.map