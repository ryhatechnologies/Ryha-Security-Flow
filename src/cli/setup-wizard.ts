import inquirer from 'inquirer';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import chalk from 'chalk';
import { ConfigManager } from '../config/config-manager';

interface SetupWizardOptions {
  interactive?: boolean;
  validateTools?: boolean;
  skipApiKeyPrompt?: boolean;
}

class SetupWizard {
  private configManager: ConfigManager;
  private interactive: boolean;
  private validateTools: boolean;

  constructor(options: SetupWizardOptions = {}) {
    this.interactive = options.interactive !== false;
    this.validateTools = options.validateTools !== false;
    this.configManager = ConfigManager.getInstance({ validateOnInit: false });
  }

  /**
   * Run the complete setup wizard
   */
  async runSetup(): Promise<boolean> {
    try {
      console.log(chalk.bold.blue('\n╔════════════════════════════════════════╗'));
      console.log(chalk.bold.blue('║   Ryha Security Flow - Setup Wizard    ║'));
      console.log(chalk.bold.blue('╚════════════════════════════════════════╝\n'));

      // Step 1: Welcome and check existing config
      const shouldProceed = await this.promptWelcome();
      if (!shouldProceed) {
        console.log(chalk.yellow('Setup cancelled.'));
        return false;
      }

      // Step 2: Configure Copilot/Claude
      await this.setupCopilot();

      // Step 3: Configure Agents
      await this.setupAgents();

      // Step 4: Configure Tools
      await this.setupTools();

      // Step 5: Configure Kali Integration
      await this.setupKali();

      // Step 6: Configure Logging
      await this.setupLogging();

      // Step 7: Configure Server
      await this.setupServer();

      // Step 8: Validate and Save
      const success = await this.validateAndSave();

      if (success) {
        console.log(chalk.green.bold('\n✓ Configuration saved successfully!\n'));
        console.log(chalk.blue('Config location: ') + this.getConfigPath());
        console.log(chalk.blue('You can now run: ') + chalk.cyan('ryha pentest --target <url>\n'));
        return true;
      } else {
        console.log(chalk.red('\n✗ Configuration validation failed.'));
        return false;
      }
    } catch (error) {
      console.error(chalk.red('Setup wizard error:'), error);
      return false;
    }
  }

  /**
   * Welcome prompt and existing config check
   */
  private async promptWelcome(): Promise<boolean> {
    const configPath = this.getConfigPath();
    const configExists = fs.existsSync(configPath);

    if (configExists) {
      const answers = await inquirer.prompt([
        {
          type: 'confirm',
          name: 'overwrite',
          message: chalk.yellow('Configuration already exists. Do you want to reconfigure?'),
          default: false,
        },
      ]);

      return answers.overwrite;
    }

    console.log(chalk.green('Welcome to Ryha Security Flow!\n'));
    console.log('This wizard will help you configure:');
    console.log('  • Claude Copilot API authentication');
    console.log('  • AI agent settings');
    console.log('  • Penetration testing tools');
    console.log('  • Kali Linux integration');
    console.log('  • Server and logging');

    const answers = await inquirer.prompt([
      {
        type: 'confirm',
        name: 'proceed',
        message: '\nReady to begin setup?',
        default: true,
      },
    ]);

    return answers.proceed;
  }

  /**
   * Setup Copilot/Claude configuration
   */
  private async setupCopilot(): Promise<void> {
    console.log(chalk.bold.cyan('\n📡 GitHub Copilot / Claude API Configuration'));

    const answers = await inquirer.prompt([
      {
        type: 'password',
        name: 'apiKey',
        message: 'Enter your Claude API key (sk-ant-...)? (leave empty to skip)',
        mask: '*',
        default: '',
      },
      {
        type: 'input',
        name: 'proxyUrl',
        message: 'Proxy URL (optional):',
        default: 'https://api.githubcopilot.com',
      },
      {
        type: 'list',
        name: 'defaultModel',
        message: 'Default model for agents:',
        choices: ['claude-opus-4-6', 'claude-3-5-sonnet', 'claude-3-haiku'],
        default: 'claude-opus-4-6',
      },
    ]);

    const copilotConfig = {
      proxyUrl: answers.proxyUrl,
      defaultModel: answers.defaultModel,
    };

    if (answers.apiKey) {
      this.configManager.setApiKey(answers.apiKey, 'copilot');
      console.log(chalk.green('✓ API key saved (encrypted)'));
    }

    this.configManager.setSection('copilot', copilotConfig);
  }

  /**
   * Setup agent configuration
   */
  private async setupAgents(): Promise<void> {
    console.log(chalk.bold.cyan('\n🤖 Agent Configuration'));

    const answers = await inquirer.prompt([
      {
        type: 'number',
        name: 'maxParallel',
        message: 'Maximum parallel agents:',
        default: 10,
        validate: (value) => value > 0 && value <= 100 ? true : 'Must be between 1 and 100',
      },
      {
        type: 'number',
        name: 'retryAttempts',
        message: 'Retry attempts for failed tasks:',
        default: 3,
        validate: (value) => value >= 0 && value <= 10 ? true : 'Must be between 0 and 10',
      },
      {
        type: 'checkbox',
        name: 'defaultTypes',
        message: 'Default agent types to spawn:',
        choices: [
          new inquirer.Separator('--- Scanning ---'),
          { name: 'Vulnerability Scanner', value: 'vulnerability-scanner' },
          { name: 'Port Scanner', value: 'port-scanner' },
          { name: 'Web Scanner', value: 'web-scanner' },
          new inquirer.Separator('--- Exploitation ---'),
          { name: 'Exploitation Agent', value: 'exploitation-agent' },
          { name: 'Payload Generator', value: 'payload-generator' },
          new inquirer.Separator('--- Reporting ---'),
          { name: 'Report Generator', value: 'report-generator' },
          { name: 'Evidence Collector', value: 'evidence-collector' },
        ],
        default: ['vulnerability-scanner', 'exploitation-agent', 'report-generator'],
      },
    ]);

    this.configManager.setSection('agents', {
      maxParallel: answers.maxParallel,
      retryAttempts: answers.retryAttempts,
      defaultTypes: answers.defaultTypes,
    });

    console.log(chalk.green(`✓ Configured ${answers.defaultTypes.length} agent types`));
  }

  /**
   * Setup penetration testing tools
   */
  private async setupTools(): Promise<void> {
    console.log(chalk.bold.cyan('\n🔧 Penetration Testing Tools'));

    const tools = [
      { name: 'nmap', display: 'Nmap (Network Mapper)', default: '/usr/bin/nmap' },
      { name: 'burpsuite', display: 'Burp Suite Pro', default: '/opt/burpsuite/burpsuite_pro' },
      { name: 'zaproxy', display: 'OWASP ZAP', default: '/usr/bin/zaproxy' },
      { name: 'metasploit', display: 'Metasploit Framework', default: '/usr/bin/msfconsole' },
      { name: 'sqlmap', display: 'SQLMap', default: '/usr/bin/sqlmap' },
    ];

    const toolConfig: any = {};

    for (const tool of tools) {
      const answers = await inquirer.prompt([
        {
          type: 'input',
          name: 'path',
          message: `Path to ${tool.display}:`,
          default: tool.default,
          validate: (value) => {
            if (!value) return true; // Optional
            if (!this.validateTools) return true; // Skip validation if disabled
            return fs.existsSync(value) ? true : `File not found: ${value}`;
          },
        },
      ]);

      if (answers.path) {
        toolConfig[tool.name] = answers.path;
      }
    }

    this.configManager.setSection('tools', toolConfig);
    console.log(chalk.green(`✓ Configured ${Object.keys(toolConfig).length} tools`));
  }

  /**
   * Setup Kali Linux integration
   */
  private async setupKali(): Promise<void> {
    console.log(chalk.bold.cyan('\n🐉 Kali Linux Integration'));

    const answers = await inquirer.prompt([
      {
        type: 'confirm',
        name: 'enabled',
        message: 'Enable Kali Linux integration?',
        default: true,
      },
      {
        type: 'input',
        name: 'baseDir',
        message: 'Kali base directory:',
        default: '/opt/ryha-security-flow',
        when: (prev) => prev.enabled,
      },
      {
        type: 'input',
        name: 'dataDir',
        message: 'Data directory:',
        default: '/var/ryha/data',
        when: (prev) => prev.enabled,
      },
      {
        type: 'input',
        name: 'reportsDir',
        message: 'Reports directory:',
        default: '/var/ryha/reports',
        when: (prev) => prev.enabled,
      },
    ]);

    this.configManager.setSection('kali', {
      enabled: answers.enabled,
      baseDir: answers.baseDir || '/opt/ryha-security-flow',
      dataDir: answers.dataDir || '/var/ryha/data',
      reportsDir: answers.reportsDir || '/var/ryha/reports',
    });

    console.log(chalk.green(answers.enabled ? '✓ Kali integration enabled' : '✓ Kali integration disabled'));
  }

  /**
   * Setup logging configuration
   */
  private async setupLogging(): Promise<void> {
    console.log(chalk.bold.cyan('\n📋 Logging Configuration'));

    const answers = await inquirer.prompt([
      {
        type: 'list',
        name: 'level',
        message: 'Log level:',
        choices: ['error', 'warn', 'info', 'debug'],
        default: 'info',
      },
      {
        type: 'input',
        name: 'retention',
        message: 'Log retention period (e.g., "30d"):',
        default: '30d',
      },
    ]);

    this.configManager.setSection('logging', {
      level: answers.level,
      retention: answers.retention,
    });

    console.log(chalk.green(`✓ Logging configured (level: ${answers.level})`));
  }

  /**
   * Setup server configuration
   */
  private async setupServer(): Promise<void> {
    console.log(chalk.bold.cyan('\n🖥️  Server Configuration'));

    const answers = await inquirer.prompt([
      {
        type: 'number',
        name: 'port',
        message: 'API server port:',
        default: 3000,
        validate: (value) => (value >= 1 && value <= 65535) ? true : 'Must be between 1 and 65535',
      },
      {
        type: 'input',
        name: 'host',
        message: 'API server host:',
        default: 'localhost',
      },
      {
        type: 'confirm',
        name: 'enableCors',
        message: 'Enable CORS?',
        default: true,
      },
    ]);

    this.configManager.setSection('server', {
      port: answers.port,
      host: answers.host,
      enableCors: answers.enableCors,
    });

    console.log(chalk.green(`✓ Server configured (${answers.host}:${answers.port})`));
  }

  /**
   * Validate and save configuration
   */
  private async validateAndSave(): Promise<boolean> {
    console.log(chalk.bold.cyan('\n✔️  Validating configuration...\n'));

    if (!this.configManager.validateConfig()) {
      return false;
    }

    try {
      this.configManager.saveConfig();
      return true;
    } catch (error) {
      console.error(chalk.red('Failed to save configuration:', error));
      return false;
    }
  }

  /**
   * Get the configuration file path
   */
  private getConfigPath(): string {
    const homeDir = os.homedir();
    return path.join(homeDir, '.ryha', 'config.yaml');
  }
}

/**
 * Run setup wizard from CLI
 */
export async function runSetupWizard(): Promise<boolean> {
  const wizard = new SetupWizard({
    interactive: true,
    validateTools: false, // Don't validate tool paths for Linux-specific tools on other systems
  });

  return wizard.runSetup();
}

export { SetupWizard };
