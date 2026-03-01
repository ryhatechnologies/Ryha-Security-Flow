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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerConfigCommands = registerConfigCommands;
exports.initializeConfig = initializeConfig;
const chalk_1 = __importDefault(require("chalk"));
const commander_1 = require("commander");
const os = __importStar(require("os"));
const path = __importStar(require("path"));
const fs = __importStar(require("fs"));
const config_1 = require("../config");
const setup_wizard_1 = require("./setup-wizard");
/**
 * Register configuration and setup commands with commander
 */
function registerConfigCommands(program) {
    // Setup Command
    program
        .command('setup')
        .description('Run interactive setup wizard')
        .option('--non-interactive', 'Skip interactive prompts (use defaults)')
        .action(async (options) => {
        if (options.nonInteractive) {
            console.log(chalk_1.default.yellow('Non-interactive mode not yet implemented'));
            process.exit(1);
        }
        else {
            const success = await (0, setup_wizard_1.runSetupWizard)();
            process.exit(success ? 0 : 1);
        }
    });
    // Config Command - Enhanced version
    program
        .command('config')
        .description('Manage configuration')
        .addCommand(new commander_1.Command('list')
        .description('List all configuration values')
        .action(() => {
        try {
            const config = new config_1.ConfigManager({ validateOnInit: false });
            const fullConfig = config.getConfig();
            console.log(chalk_1.default.bold.cyan('\n⚙️  Ryha Security Flow - Configuration\n'));
            console.log(chalk_1.default.bold('Server:'));
            console.log(`  Port: ${fullConfig.server?.port || '3000'}`);
            console.log(`  Host: ${fullConfig.server?.host || 'localhost'}`);
            console.log(chalk_1.default.bold('\nAgents:'));
            console.log(`  Max Parallel: ${fullConfig.agents?.maxParallel || '10'}`);
            console.log(`  Retry Attempts: ${fullConfig.agents?.retryAttempts || '3'}`);
            console.log(chalk_1.default.bold('\nLogging:'));
            console.log(`  Level: ${fullConfig.logging?.level || 'info'}`);
            console.log(`  Retention: ${fullConfig.logging?.retention || '30d'}`);
            console.log(chalk_1.default.bold('\nCopilot:'));
            console.log(`  Default Model: ${fullConfig.copilot?.defaultModel || 'claude-opus-4-6'}`);
            console.log(`  API Key: ${fullConfig.copilot?.apiKey ? '***ENCRYPTED***' : 'Not configured'}`);
            console.log(chalk_1.default.bold('\nKali Integration:'));
            console.log(`  Enabled: ${fullConfig.kali?.enabled !== false ? 'Yes' : 'No'}`);
            console.log(`  Base Dir: ${fullConfig.kali?.baseDir || '/opt/ryha-security-flow'}`);
            console.log(chalk_1.default.bold('\nConfiguration File:'));
            const homeDir = os.homedir();
            const configPath = path.join(homeDir, '.ryha', 'config.yaml');
            console.log(`  Location: ${configPath}`);
            console.log(`  Exists: ${fs.existsSync(configPath) ? 'Yes' : 'No'}`);
            console.log();
            config.destroy();
        }
        catch (error) {
            console.error(chalk_1.default.red('Error reading configuration:'), error);
            process.exit(1);
        }
    }))
        .addCommand(new commander_1.Command('show <section>')
        .description('Show configuration for a specific section')
        .action((section) => {
        try {
            const config = new config_1.ConfigManager({ validateOnInit: false });
            const value = config.getSection(section);
            if (!value) {
                console.log(chalk_1.default.yellow(`Section '${section}' not found`));
                process.exit(1);
            }
            console.log(chalk_1.default.bold.cyan(`\n⚙️  ${section} Configuration\n`));
            console.log(JSON.stringify(value, null, 2));
            console.log();
            config.destroy();
        }
        catch (error) {
            console.error(chalk_1.default.red('Error reading configuration:'), error);
            process.exit(1);
        }
    }))
        .addCommand(new commander_1.Command('get <key>')
        .description('Get a specific configuration value')
        .action((key) => {
        try {
            const config = new config_1.ConfigManager({ validateOnInit: false });
            const value = config.get(key);
            if (value === undefined) {
                console.log(chalk_1.default.yellow(`Key '${key}' not found`));
                process.exit(1);
            }
            if (typeof value === 'object') {
                console.log(JSON.stringify(value, null, 2));
            }
            else {
                console.log(value);
            }
            config.destroy();
        }
        catch (error) {
            console.error(chalk_1.default.red('Error reading configuration:'), error);
            process.exit(1);
        }
    }))
        .addCommand(new commander_1.Command('set <key> <value>')
        .description('Set a configuration value')
        .action((key, value) => {
        try {
            const config = new config_1.ConfigManager();
            // Try to parse value as JSON, otherwise treat as string
            let parsedValue = value;
            if (value === 'true')
                parsedValue = true;
            else if (value === 'false')
                parsedValue = false;
            else if (!isNaN(Number(value)))
                parsedValue = Number(value);
            config.set(key, parsedValue);
            config.saveConfig();
            console.log(chalk_1.default.green(`✓ Configuration updated: ${key} = ${value}`));
            config.destroy();
        }
        catch (error) {
            console.error(chalk_1.default.red('Error updating configuration:'), error);
            process.exit(1);
        }
    }))
        .addCommand(new commander_1.Command('validate')
        .description('Validate current configuration')
        .action(() => {
        try {
            const config = new config_1.ConfigManager({ validateOnInit: false });
            const isValid = config.validateConfig();
            if (isValid) {
                console.log(chalk_1.default.green('✓ Configuration is valid'));
            }
            else {
                console.log(chalk_1.default.red('✗ Configuration validation failed'));
            }
            config.destroy();
            process.exit(isValid ? 0 : 1);
        }
        catch (error) {
            console.error(chalk_1.default.red('Error validating configuration:'), error);
            process.exit(1);
        }
    }));
}
/**
 * Initialize configuration on CLI startup
 */
function initializeConfig() {
    try {
        const config = new config_1.ConfigManager({
            validateOnInit: true,
            enableHotReload: true,
        });
        if (process.env.RYHA_DEBUG) {
            console.log(chalk_1.default.gray('[DEBUG] Configuration initialized from ~/.ryha/config.yaml'));
        }
        return config;
    }
    catch (error) {
        console.error(chalk_1.default.red('Failed to initialize configuration:'), error);
        console.log(chalk_1.default.yellow('\nRun "ryha setup" to configure the application'));
        process.exit(1);
    }
}
//# sourceMappingURL=config-commands.js.map