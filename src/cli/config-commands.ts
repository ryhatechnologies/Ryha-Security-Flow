import chalk from 'chalk';
import { Command } from 'commander';
import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs';
import { ConfigManager } from '../config';
import { runSetupWizard } from './setup-wizard';

/**
 * Register configuration and setup commands with commander
 */
export function registerConfigCommands(program: Command): void {
  // Setup Command
  program
    .command('setup')
    .description('Run interactive setup wizard')
    .option('--non-interactive', 'Skip interactive prompts (use defaults)')
    .action(async (options) => {
      if (options.nonInteractive) {
        console.log(chalk.yellow('Non-interactive mode not yet implemented'));
        process.exit(1);
      } else {
        const success = await runSetupWizard();
        process.exit(success ? 0 : 1);
      }
    });

  // Config Command - Enhanced version
  program
    .command('config')
    .description('Manage configuration')
    .addCommand(
      new Command('list')
        .description('List all configuration values')
        .action(() => {
          try {
            const config = new ConfigManager({ validateOnInit: false });
            const fullConfig = config.getConfig();

            console.log(chalk.bold.cyan('\n⚙️  Ryha Security Flow - Configuration\n'));
            console.log(chalk.bold('Server:'));
            console.log(`  Port: ${fullConfig.server?.port || '3000'}`);
            console.log(`  Host: ${fullConfig.server?.host || 'localhost'}`);

            console.log(chalk.bold('\nAgents:'));
            console.log(`  Max Parallel: ${fullConfig.agents?.maxParallel || '10'}`);
            console.log(`  Retry Attempts: ${fullConfig.agents?.retryAttempts || '3'}`);

            console.log(chalk.bold('\nLogging:'));
            console.log(`  Level: ${fullConfig.logging?.level || 'info'}`);
            console.log(`  Retention: ${fullConfig.logging?.retention || '30d'}`);

            console.log(chalk.bold('\nCopilot:'));
            console.log(`  Default Model: ${fullConfig.copilot?.defaultModel || 'claude-opus-4-6'}`);
            console.log(`  API Key: ${fullConfig.copilot?.apiKey ? '***ENCRYPTED***' : 'Not configured'}`);

            console.log(chalk.bold('\nKali Integration:'));
            console.log(`  Enabled: ${fullConfig.kali?.enabled !== false ? 'Yes' : 'No'}`);
            console.log(`  Base Dir: ${fullConfig.kali?.baseDir || '/opt/ryha-security-flow'}`);

            console.log(chalk.bold('\nConfiguration File:'));
            const homeDir = os.homedir();
            const configPath = path.join(homeDir, '.ryha', 'config.yaml');
            console.log(`  Location: ${configPath}`);
            console.log(`  Exists: ${fs.existsSync(configPath) ? 'Yes' : 'No'}`);

            console.log();
            config.destroy();
          } catch (error) {
            console.error(chalk.red('Error reading configuration:'), error);
            process.exit(1);
          }
        })
    )
    .addCommand(
      new Command('show <section>')
        .description('Show configuration for a specific section')
        .action((section) => {
          try {
            const config = new ConfigManager({ validateOnInit: false });
            const value = config.getSection(section as any);

            if (!value) {
              console.log(chalk.yellow(`Section '${section}' not found`));
              process.exit(1);
            }

            console.log(chalk.bold.cyan(`\n⚙️  ${section} Configuration\n`));
            console.log(JSON.stringify(value, null, 2));
            console.log();

            config.destroy();
          } catch (error) {
            console.error(chalk.red('Error reading configuration:'), error);
            process.exit(1);
          }
        })
    )
    .addCommand(
      new Command('get <key>')
        .description('Get a specific configuration value')
        .action((key) => {
          try {
            const config = new ConfigManager({ validateOnInit: false });
            const value = config.get(key);

            if (value === undefined) {
              console.log(chalk.yellow(`Key '${key}' not found`));
              process.exit(1);
            }

            if (typeof value === 'object') {
              console.log(JSON.stringify(value, null, 2));
            } else {
              console.log(value);
            }

            config.destroy();
          } catch (error) {
            console.error(chalk.red('Error reading configuration:'), error);
            process.exit(1);
          }
        })
    )
    .addCommand(
      new Command('set <key> <value>')
        .description('Set a configuration value')
        .action((key, value) => {
          try {
            const config = new ConfigManager();

            // Try to parse value as JSON, otherwise treat as string
            let parsedValue: any = value;
            if (value === 'true') parsedValue = true;
            else if (value === 'false') parsedValue = false;
            else if (!isNaN(Number(value))) parsedValue = Number(value);

            config.set(key, parsedValue);
            config.saveConfig();

            console.log(chalk.green(`✓ Configuration updated: ${key} = ${value}`));
            config.destroy();
          } catch (error) {
            console.error(chalk.red('Error updating configuration:'), error);
            process.exit(1);
          }
        })
    )
    .addCommand(
      new Command('validate')
        .description('Validate current configuration')
        .action(() => {
          try {
            const config = new ConfigManager({ validateOnInit: false });
            const isValid = config.validateConfig();

            if (isValid) {
              console.log(chalk.green('✓ Configuration is valid'));
            } else {
              console.log(chalk.red('✗ Configuration validation failed'));
            }

            config.destroy();
            process.exit(isValid ? 0 : 1);
          } catch (error) {
            console.error(chalk.red('Error validating configuration:'), error);
            process.exit(1);
          }
        })
    );
}

/**
 * Initialize configuration on CLI startup
 */
export function initializeConfig(): ConfigManager {
  try {
    const config = new ConfigManager({
      validateOnInit: true,
      enableHotReload: true,
    });

    if (process.env.RYHA_DEBUG) {
      console.log(chalk.gray('[DEBUG] Configuration initialized from ~/.ryha/config.yaml'));
    }

    return config;
  } catch (error) {
    console.error(chalk.red('Failed to initialize configuration:'), error);
    console.log(chalk.yellow('\nRun "ryha setup" to configure the application'));
    process.exit(1);
  }
}
