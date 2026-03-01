"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.RyhaConfigSchema = exports.ConfigManager = void 0;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const os = __importStar(require("os"));
const crypto_1 = require("crypto");
const yaml_1 = require("yaml");
const zod_1 = require("zod");
const dotenv = __importStar(require("dotenv"));
const events_1 = require("events");
const logger = console;
const CopilotConfigSchema = zod_1.z.object({
    proxyUrl: zod_1.z.string().url().default('https://api.githubcopilot.com'),
    models: zod_1.z.array(zod_1.z.string()).default(['claude-opus-4-6', 'claude-3-5-sonnet', 'claude-3-haiku']),
    defaultModel: zod_1.z.string().default('claude-opus-4-6'),
    apiKey: zod_1.z.string().optional(),
    apiKeyEncrypted: zod_1.z.boolean().default(false),
});
const AgentsConfigSchema = zod_1.z.object({
    maxParallel: zod_1.z.number().int().min(1).default(10),
    retryAttempts: zod_1.z.number().int().min(0).default(3),
    defaultTypes: zod_1.z.array(zod_1.z.string()).optional(),
});
const ToolsConfigSchema = zod_1.z.object({
    nmap: zod_1.z.string().optional(),
    burpsuite: zod_1.z.string().optional(),
    zaproxy: zod_1.z.string().optional(),
    metasploit: zod_1.z.string().optional(),
    sqlmap: zod_1.z.string().optional(),
});
const KaliConfigSchema = zod_1.z.object({
    baseDir: zod_1.z.string().default('/opt/ryha-security-flow'),
    dataDir: zod_1.z.string().default('/var/ryha/data'),
    reportsDir: zod_1.z.string().default('/var/ryha/reports'),
    enabled: zod_1.z.boolean().default(true),
});
const LoggingConfigSchema = zod_1.z.object({
    level: zod_1.z.enum(['error', 'warn', 'info', 'debug']).default('info'),
    retention: zod_1.z.string().default('30d'),
    logDir: zod_1.z.string().optional(),
});
const ServerConfigSchema = zod_1.z.object({
    port: zod_1.z.number().int().min(1).max(65535).default(3000),
    host: zod_1.z.string().default('localhost'),
    enableCors: zod_1.z.boolean().default(true),
    corsOrigins: zod_1.z.array(zod_1.z.string()).optional(),
});
const RyhaConfigSchema = zod_1.z.object({
    copilot: CopilotConfigSchema.optional(),
    agents: AgentsConfigSchema.optional(),
    tools: ToolsConfigSchema.optional(),
    kali: KaliConfigSchema.optional(),
    logging: LoggingConfigSchema.optional(),
    server: ServerConfigSchema.optional(),
});
exports.RyhaConfigSchema = RyhaConfigSchema;
class ConfigManager extends events_1.EventEmitter {
    constructor(options = {}) {
        super();
        this.watchers = new Map();
        this.fileWatcher = null;
        this.ENCRYPTION_ALGORITHM = 'aes-256-cbc';
        this.SALT_LENGTH = 32;
        if (ConfigManager.instanceLock.locked) {
            throw new Error('ConfigManager is a singleton. Use ConfigManager.getInstance() instead.');
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
    static getInstance(options) {
        if (!ConfigManager.instance) {
            ConfigManager.instanceLock.locked = true;
            try {
                ConfigManager.instance = new ConfigManager(options);
            }
            finally {
                ConfigManager.instanceLock.locked = false;
            }
        }
        return ConfigManager.instance;
    }
    static resetInstance() {
        if (ConfigManager.instance) {
            ConfigManager.instance.destroy();
            ConfigManager.instance = null;
        }
    }
    getDefaultConfigPath() {
        const homeDir = os.homedir();
        const ryhaDir = path.join(homeDir, '.ryha');
        if (!fs.existsSync(ryhaDir)) {
            fs.mkdirSync(ryhaDir, { recursive: true });
        }
        return path.join(ryhaDir, 'config.yaml');
    }
    generateDefaultPassword() {
        const hostName = os.hostname();
        const platform = os.platform();
        return `${hostName}-${platform}-ryha-secured`;
    }
    loadConfig() {
        let fileConfig = {};
        if (fs.existsSync(this.configPath)) {
            try {
                const content = fs.readFileSync(this.configPath, 'utf-8');
                fileConfig = (0, yaml_1.parse)(content) || {};
            }
            catch (error) {
                logger.warn(`Failed to load config from ${this.configPath}:`, error);
                this.emitEvent('error', undefined, `Failed to load config: ${error}`);
            }
        }
        dotenv.config();
        const envConfig = this.loadEnvVariables();
        const merged = this.mergeConfigs(fileConfig, envConfig);
        return merged;
    }
    loadEnvVariables() {
        const envConfig = {};
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
                level: process.env.RYHA_LOG_LEVEL,
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
    mergeConfigs(...configs) {
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
    validateConfig() {
        try {
            const validated = RyhaConfigSchema.parse(this.config);
            this.config = validated;
            logger.log('Configuration validation passed');
            return true;
        }
        catch (error) {
            if (error instanceof zod_1.z.ZodError) {
                logger.error('Configuration validation failed:');
                error.issues.forEach((err) => {
                    logger.error(`  ${err.path.join('.')}: ${err.message}`);
                });
            }
            return false;
        }
    }
    getConfig() {
        return JSON.parse(JSON.stringify(this.config));
    }
    getSection(section) {
        return this.config[section];
    }
    setSection(section, value) {
        this.config = {
            ...this.config,
            [section]: { ...this.config[section], ...value },
        };
        this.emitEvent('change', section);
        this.notifyWatchers();
    }
    set(path, value) {
        const keys = path.split('.');
        let current = this.config;
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
    get(path, defaultValue) {
        const keys = path.split('.');
        let current = this.config;
        for (const key of keys) {
            if (current && typeof current === 'object' && key in current) {
                current = current[key];
            }
            else {
                return defaultValue;
            }
        }
        return current;
    }
    saveConfig() {
        try {
            const validated = RyhaConfigSchema.parse(this.config);
            const content = (0, yaml_1.stringify)(validated);
            fs.writeFileSync(this.configPath, content, 'utf-8');
            logger.log(`Configuration saved to ${this.configPath}`);
            this.emitEvent('save', undefined, `Config saved to ${this.configPath}`);
        }
        catch (error) {
            logger.error('Failed to save configuration:', error);
            this.emitEvent('error', undefined, `Failed to save config: ${error}`);
            throw error;
        }
    }
    encryptValue(value) {
        const salt = (0, crypto_1.randomBytes)(this.SALT_LENGTH);
        const derivedKey = (0, crypto_1.scryptSync)(this.encryptionPassword, salt, 32);
        const iv = (0, crypto_1.randomBytes)(16);
        const cipher = (0, crypto_1.createCipheriv)(this.ENCRYPTION_ALGORITHM, derivedKey, iv);
        let encrypted = cipher.update(value, 'utf-8', 'hex');
        encrypted += cipher.final('hex');
        const combined = salt.toString('hex') + ':' + iv.toString('hex') + ':' + encrypted;
        return combined;
    }
    decryptValue(encrypted) {
        const parts = encrypted.split(':');
        if (parts.length !== 3) {
            throw new Error('Invalid encrypted value format');
        }
        const salt = Buffer.from(parts[0], 'hex');
        const iv = Buffer.from(parts[1], 'hex');
        const encryptedData = parts[2];
        const derivedKey = (0, crypto_1.scryptSync)(this.encryptionPassword, salt, 32);
        const decipher = (0, crypto_1.createDecipheriv)(this.ENCRYPTION_ALGORITHM, derivedKey, iv);
        let decrypted = decipher.update(encryptedData, 'hex', 'utf-8');
        decrypted += decipher.final('utf-8');
        return decrypted;
    }
    setApiKey(apiKey, service = 'copilot') {
        const encrypted = this.encryptValue(apiKey);
        this.set(`${service}.apiKey`, encrypted);
        this.set(`${service}.apiKeyEncrypted`, true);
    }
    getApiKey(service = 'copilot') {
        const apiKey = this.get(`${service}.apiKey`);
        const isEncrypted = this.get(`${service}.apiKeyEncrypted`, false);
        if (!apiKey) {
            return undefined;
        }
        if (isEncrypted) {
            try {
                return this.decryptValue(apiKey);
            }
            catch (error) {
                logger.error(`Failed to decrypt API key for ${service}:`, error);
                this.emitEvent('error', undefined, `Failed to decrypt API key: ${error}`);
                return undefined;
            }
        }
        return apiKey;
    }
    watch(id, callback) {
        this.watchers.set(id, callback);
    }
    unwatch(id) {
        this.watchers.delete(id);
    }
    enableHotReload() {
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
        }
        catch (error) {
            logger.warn('Failed to enable hot reload:', error);
        }
    }
    disableHotReload() {
        if (this.fileWatcher) {
            this.fileWatcher.close();
            this.fileWatcher = null;
        }
    }
    notifyWatchers() {
        const config = this.getConfig();
        this.watchers.forEach((callback) => {
            try {
                callback(config);
            }
            catch (error) {
                logger.error('Error in config watcher callback:', error);
            }
        });
    }
    emitEvent(type, section, details) {
        const event = {
            type,
            section,
            timestamp: new Date(),
            details,
        };
        this.emit('change', event);
    }
    exportConfig() {
        return (0, yaml_1.stringify)(this.getConfig());
    }
    reset() {
        this.config = {};
        this.loadConfig();
        this.validateConfig();
        this.emitEvent('reload', undefined, 'Config reset to defaults');
    }
    destroy() {
        this.disableHotReload();
        this.watchers.clear();
        this.removeAllListeners();
    }
}
exports.ConfigManager = ConfigManager;
ConfigManager.instance = null;
ConfigManager.instanceLock = { locked: false };
//# sourceMappingURL=config-manager.js.map