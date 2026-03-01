import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import { z } from 'zod';
import * as dotenv from 'dotenv';
import { EventEmitter } from 'events';

const logger = console;

export interface ConfigChangeEvent {
  type: 'change' | 'save' | 'reload' | 'error';
  section?: keyof RyhaConfig;
  timestamp: Date;
  details?: string;
}

const CopilotConfigSchema = z.object({
  proxyUrl: z.string().url().default('https://api.githubcopilot.com'),
  models: z.array(z.string()).default(['claude-opus-4-6', 'claude-3-5-sonnet', 'claude-3-haiku']),
  defaultModel: z.string().default('claude-opus-4-6'),
  apiKey: z.string().optional(),
  apiKeyEncrypted: z.boolean().default(false),
});

const AgentsConfigSchema = z.object({
  maxParallel: z.number().int().min(1).default(10),
  retryAttempts: z.number().int().min(0).default(3),
  defaultTypes: z.array(z.string()).optional(),
});

const ToolsConfigSchema = z.object({
  nmap: z.string().optional(),
  burpsuite: z.string().optional(),
  zaproxy: z.string().optional(),
  metasploit: z.string().optional(),
  sqlmap: z.string().optional(),
});

const KaliConfigSchema = z.object({
  baseDir: z.string().default('/opt/ryha-security-flow'),
  dataDir: z.string().default('/var/ryha/data'),
  reportsDir: z.string().default('/var/ryha/reports'),
  enabled: z.boolean().default(true),
});

const LoggingConfigSchema = z.object({
  level: z.enum(['error', 'warn', 'info', 'debug']).default('info'),
  retention: z.string().default('30d'),
  logDir: z.string().optional(),
});

const ServerConfigSchema = z.object({
  port: z.number().int().min(1).max(65535).default(3000),
  host: z.string().default('localhost'),
  enableCors: z.boolean().default(true),
  corsOrigins: z.array(z.string()).optional(),
});

const RyhaConfigSchema = z.object({
  copilot: CopilotConfigSchema.optional(),
  agents: AgentsConfigSchema.optional(),
  tools: ToolsConfigSchema.optional(),
  kali: KaliConfigSchema.optional(),
  logging: LoggingConfigSchema.optional(),
  server: ServerConfigSchema.optional(),
});

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

class ConfigManager extends EventEmitter {
  private config: RyhaConfig;
  private configPath: string;
  private watchers: Map<string, (config: RyhaConfig) => void> = new Map();
  private fileWatcher: fs.FSWatcher | null = null;
  private encryptionPassword: string;
  private readonly ENCRYPTION_ALGORITHM = 'aes-256-cbc';
  private readonly SALT_LENGTH = 32;
  private static instance: ConfigManager | null = null;
  private static readonly instanceLock = { locked: false };

  constructor(options: ConfigManagerOptions = {}) {
    super();

    if (ConfigManager.instanceLock.locked) {
      throw new Error(
        'ConfigManager is a singleton. Use ConfigManager.getInstance() instead.'
      );
    }

    this.configPath = options.configPath || this.getDefaultConfigPath();
    this.encryptionPassword = options.encryptionPassword || this.generateDefaultPassword();
    this.config = this.loadConfig();

    if (options.validateOnInit !== false) {
      this.validateConfig();
    }

    if (options.enableHotReload !== false) {
      this.enableHotReload();
    }

    this.setMaxListeners(20);
  }

  static getInstance(options?: ConfigManagerOptions): ConfigManager {
    if (!ConfigManager.instance) {
      ConfigManager.instanceLock.locked = true;
      try {
        ConfigManager.instance = new ConfigManager(options);
      } finally {
        ConfigManager.instanceLock.locked = false;
      }
    }
    return ConfigManager.instance;
  }

  static resetInstance(): void {
    if (ConfigManager.instance) {
      ConfigManager.instance.destroy();
      ConfigManager.instance = null;
    }
  }

  private getDefaultConfigPath(): string {
    const homeDir = os.homedir();
    const ryhaDir = path.join(homeDir, '.ryha');

    if (!fs.existsSync(ryhaDir)) {
      fs.mkdirSync(ryhaDir, { recursive: true });
    }

    return path.join(ryhaDir, 'config.yaml');
  }

  private generateDefaultPassword(): string {
    const hostName = os.hostname();
    const platform = os.platform();
    return `${hostName}-${platform}-ryha-secured`;
  }

  private loadConfig(): RyhaConfig {
    let fileConfig: Partial<RyhaConfig> = {};

    if (fs.existsSync(this.configPath)) {
      try {
        const content = fs.readFileSync(this.configPath, 'utf-8');
        fileConfig = parseYaml(content) || {};
      } catch (error) {
        logger.warn(`Failed to load config from ${this.configPath}:`, error);
        this.emitEvent('error', undefined, `Failed to load config: ${error}`);
      }
    }

    dotenv.config();
    const envConfig = this.loadEnvVariables();

    const merged = this.mergeConfigs(fileConfig, envConfig);

    return merged as RyhaConfig;
  }

  private loadEnvVariables(): any {
    const envConfig: any = {};

    if (process.env.RYHA_COPILOT_PROXY_URL) {
      envConfig.copilot = {
        ...(envConfig.copilot || {}),
        proxyUrl: process.env.RYHA_COPILOT_PROXY_URL,
      };
    }
    if (process.env.RYHA_COPILOT_API_KEY) {
      envConfig.copilot = {
        ...(envConfig.copilot || {}),
        apiKey: process.env.RYHA_COPILOT_API_KEY,
        apiKeyEncrypted: false,
      };
    }
    if (process.env.RYHA_COPILOT_DEFAULT_MODEL) {
      envConfig.copilot = {
        ...(envConfig.copilot || {}),
        defaultModel: process.env.RYHA_COPILOT_DEFAULT_MODEL,
      };
    }

    if (process.env.RYHA_AGENTS_MAX_PARALLEL) {
      envConfig.agents = {
        ...(envConfig.agents || {}),
        maxParallel: parseInt(process.env.RYHA_AGENTS_MAX_PARALLEL, 10),
      };
    }
    if (process.env.RYHA_AGENTS_RETRY_ATTEMPTS) {
      envConfig.agents = {
        ...(envConfig.agents || {}),
        retryAttempts: parseInt(process.env.RYHA_AGENTS_RETRY_ATTEMPTS, 10),
      };
    }

    if (process.env.RYHA_SERVER_PORT) {
      envConfig.server = {
        ...(envConfig.server || {}),
        port: parseInt(process.env.RYHA_SERVER_PORT, 10),
      };
    }
    if (process.env.RYHA_SERVER_HOST) {
      envConfig.server = {
        ...(envConfig.server || {}),
        host: process.env.RYHA_SERVER_HOST,
      };
    }

    if (process.env.RYHA_LOG_LEVEL) {
      envConfig.logging = {
        ...(envConfig.logging || {}),
        level: process.env.RYHA_LOG_LEVEL as any,
      };
    }

    if (process.env.RYHA_NMAP_PATH) {
      envConfig.tools = {
        ...(envConfig.tools || {}),
        nmap: process.env.RYHA_NMAP_PATH,
      };
    }

    return envConfig;
  }

  private mergeConfigs(...configs: any[]): any {
    return configs.reduce((acc, config) => ({
      ...acc,
      copilot: { ...acc.copilot, ...config.copilot },
      agents: { ...acc.agents, ...config.agents },
      tools: { ...acc.tools, ...config.tools },
      kali: { ...acc.kali, ...config.kali },
      logging: { ...acc.logging, ...config.logging },
      server: { ...acc.server, ...config.server },
    }), {});
  }

  validateConfig(): boolean {
    try {
      const validated = RyhaConfigSchema.parse(this.config);
      this.config = validated;
      logger.log('Configuration validation passed');
      return true;
    } catch (error) {
      if (error instanceof z.ZodError) {
        logger.error('Configuration validation failed:');
        error.issues.forEach((err: any) => {
          logger.error(`  ${err.path.join('.')}: ${err.message}`);
        });
      }
      return false;
    }
  }

  getConfig(): RyhaConfig {
    return JSON.parse(JSON.stringify(this.config));
  }

  getSection<K extends keyof RyhaConfig>(section: K): RyhaConfig[K] | undefined {
    return this.config[section];
  }

  setSection<K extends keyof RyhaConfig>(section: K, value: Partial<RyhaConfig[K]>): void {
    this.config = {
      ...this.config,
      [section]: { ...this.config[section], ...value },
    };
    this.emitEvent('change', section);
    this.notifyWatchers();
  }

  set(path: string, value: any): void {
    const keys = path.split('.');
    let current: any = this.config;

    for (let i = 0; i < keys.length - 1; i++) {
      if (!(keys[i] in current)) {
        current[keys[i]] = {};
      }
      current = current[keys[i]];
    }

    current[keys[keys.length - 1]] = value;
    this.emitEvent('change', undefined, `Updated path: ${path}`);
    this.notifyWatchers();
  }

  get(path: string, defaultValue?: any): any {
    const keys = path.split('.');
    let current: any = this.config;

    for (const key of keys) {
      if (current && typeof current === 'object' && key in current) {
        current = current[key];
      } else {
        return defaultValue;
      }
    }

    return current;
  }

  saveConfig(): void {
    try {
      const validated = RyhaConfigSchema.parse(this.config);
      const content = stringifyYaml(validated);
      fs.writeFileSync(this.configPath, content, 'utf-8');
      logger.log(`Configuration saved to ${this.configPath}`);
      this.emitEvent('save', undefined, `Config saved to ${this.configPath}`);
    } catch (error) {
      logger.error('Failed to save configuration:', error);
      this.emitEvent('error', undefined, `Failed to save config: ${error}`);
      throw error;
    }
  }

  encryptValue(value: string): string {
    const salt = randomBytes(this.SALT_LENGTH);
    const derivedKey = scryptSync(this.encryptionPassword, salt, 32);
    const iv = randomBytes(16);
    const cipher = createCipheriv(this.ENCRYPTION_ALGORITHM, derivedKey, iv);

    let encrypted = cipher.update(value, 'utf-8', 'hex');
    encrypted += cipher.final('hex');

    const combined = salt.toString('hex') + ':' + iv.toString('hex') + ':' + encrypted;
    return combined;
  }

  decryptValue(encrypted: string): string {
    const parts = encrypted.split(':');
    if (parts.length !== 3) {
      throw new Error('Invalid encrypted value format');
    }

    const salt = Buffer.from(parts[0], 'hex');
    const iv = Buffer.from(parts[1], 'hex');
    const encryptedData = parts[2];

    const derivedKey = scryptSync(this.encryptionPassword, salt, 32);
    const decipher = createDecipheriv(this.ENCRYPTION_ALGORITHM, derivedKey, iv);

    let decrypted = decipher.update(encryptedData, 'hex', 'utf-8');
    decrypted += decipher.final('utf-8');

    return decrypted;
  }

  setApiKey(apiKey: string, service: string = 'copilot'): void {
    const encrypted = this.encryptValue(apiKey);
    this.set(`${service}.apiKey`, encrypted);
    this.set(`${service}.apiKeyEncrypted`, true);
  }

  getApiKey(service: string = 'copilot'): string | undefined {
    const apiKey = this.get(`${service}.apiKey`);
    const isEncrypted = this.get(`${service}.apiKeyEncrypted`, false);

    if (!apiKey) {
      return undefined;
    }

    if (isEncrypted) {
      try {
        return this.decryptValue(apiKey);
      } catch (error) {
        logger.error(`Failed to decrypt API key for ${service}:`, error);
        this.emitEvent('error', undefined, `Failed to decrypt API key: ${error}`);
        return undefined;
      }
    }

    return apiKey;
  }

  watch(id: string, callback: (config: RyhaConfig) => void): void {
    this.watchers.set(id, callback);
  }

  unwatch(id: string): void {
    this.watchers.delete(id);
  }

  private enableHotReload(): void {
    const configDir = path.dirname(this.configPath);

    try {
      this.fileWatcher = fs.watch(configDir, (eventType, filename) => {
        if (filename === path.basename(this.configPath) && eventType === 'change') {
          logger.log('Configuration file changed, reloading...');
          setTimeout(() => {
            this.config = this.loadConfig();
            this.validateConfig();
            this.emitEvent('reload', undefined, 'Config reloaded from file');
            this.notifyWatchers();
          }, 300);
        }
      });
    } catch (error) {
      logger.warn('Failed to enable hot reload:', error);
    }
  }

  disableHotReload(): void {
    if (this.fileWatcher) {
      this.fileWatcher.close();
      this.fileWatcher = null;
    }
  }

  private notifyWatchers(): void {
    const config = this.getConfig();
    this.watchers.forEach((callback) => {
      try {
        callback(config);
      } catch (error) {
        logger.error('Error in config watcher callback:', error);
      }
    });
  }

  private emitEvent(
    type: ConfigChangeEvent['type'],
    section?: keyof RyhaConfig,
    details?: string
  ): void {
    const event: ConfigChangeEvent = {
      type,
      section,
      timestamp: new Date(),
      details,
    };
    this.emit('change', event);
  }

  exportConfig(): string {
    return stringifyYaml(this.getConfig());
  }

  reset(): void {
    this.config = {};
    this.loadConfig();
    this.validateConfig();
    this.emitEvent('reload', undefined, 'Config reset to defaults');
  }

  destroy(): void {
    this.disableHotReload();
    this.watchers.clear();
    this.removeAllListeners();
  }
}

export {
  ConfigManager,
  RyhaConfig,
  CopilotConfig,
  AgentsConfig,
  ToolsConfig,
  KaliConfig,
  LoggingConfig,
  ServerConfig,
  RyhaConfigSchema,
};
