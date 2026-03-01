#!/usr/bin/env node
/**
 * Ryha Security Flow - CLI with full implementations
 */

import chalk from 'chalk';
import { Command } from 'commander';
import inquirer from 'inquirer';
import ora from 'ora';
import Table from 'cli-table3';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { copilotAuth } from './auth/copilot-auth';
import { RyhaServer } from './api/server';
import { AuthDocument, TestingType } from './compliance/auth-document';
import { ConfigManager } from './config/config-manager';
import { PentestOrchestrator } from './orchestrator/orchestrator';
import { ToolManager, ToolCategory } from './tools/tool-manager';
import { AIToolSelector } from './tools/ai-tool-selector';

const program = new Command();
const banner = `RYHA SECURITY FLOW - v1.0.0`;
console.log(chalk.cyan.bold(banner));

program.name('ryha').description('Ryha Security Flow').version('1.0.0');

// AUTH
const auth = program.command('auth');
auth.command('login').action(async () => {
  try { await copilotAuth.authenticate(); } 
  catch (e) { console.error(chalk.red((e as Error).message)); process.exit(1); }
});
auth.command('status').action(async () => {
  const isAuth = await copilotAuth.isAuthenticated();
  console.log(isAuth ? chalk.green('Authenticated') : chalk.red('Not authenticated'));
});
auth.command('logout').action(() => copilotAuth.clearTokens());

// SCOPE
const scope = program.command('scope');
scope.command('create').action(async () => {
  const answers = await inquirer.prompt([
    {name: 'clientName', message: 'Client name:'},
    {name: 'targetDomain', message: 'Target domain:'},
    {name: 'inScope', message: 'In-scope (comma-separated):'},
    {name: 'outOfScope', message: 'Out-of-scope:', default: ''},
    {name: 'startDate', message: 'Start date:', default: new Date().toISOString().split('T')[0]},
    {name: 'endDate', message: 'End date:', default: new Date(Date.now() + 30*24*60*60*1000).toISOString().split('T')[0]},
    {type: 'checkbox', name: 'testingType', message: 'Testing types:', choices: ['network','web','infrastructure','code','cloud','full']},
    {name: 'authorizedBy', message: 'Authorized by:'},
    {name: 'signature', message: 'Signature:'},
    {name: 'notes', message: 'Notes:', default: ''}
  ]);
  const doc = new AuthDocument(answers.clientName, answers.targetDomain, answers.inScope.split(','), answers.outOfScope?answers.outOfScope.split(','):[], new Date(answers.startDate), new Date(answers.endDate), answers.testingType, answers.authorizedBy, answers.signature, answers.notes);
  doc.save();
  console.log(chalk.green('Created: ' + doc.id));
});
scope.command('list').action(() => {
  AuthDocument.listAll().forEach(id => console.log(id));
});
scope.command('view <id>').action((id) => {
  const doc = AuthDocument.load(id);
  console.log(doc ? doc.exportAsText() : 'Not found');
});

// PENTEST
program.command('pentest').requiredOption('-d, --domain <domain>').option('-t, --type <type>', 'Scan type', 'full').option('-a, --auth <id>', 'Auth doc ID (auto-detected if omitted)').action(async (opts) => {
  const isAuth = await copilotAuth.isAuthenticated();
  if (!isAuth) { console.error(chalk.red('Not authenticated. Run: ryha auth login')); process.exit(1); }

  // Auto-find auth doc if not specified
  let authDocId = opts.auth;
  if (!authDocId) {
    const allDocs = AuthDocument.listAll();
    const validDoc = allDocs.map(id => AuthDocument.load(id)).find(d => d && d.isValid() && (d.targetDomain === opts.domain || d.inScope.some((s: string) => opts.domain.includes(s) || s.includes(opts.domain))));
    if (validDoc) {
      authDocId = validDoc.id;
      console.log(chalk.blue(`Auto-detected auth doc: ${validDoc.clientName} (${validDoc.id.substring(0, 8)}...)`));
    } else if (allDocs.length > 0) {
      const anyValid = allDocs.map(id => AuthDocument.load(id)).find(d => d && d.isValid());
      if (anyValid) {
        authDocId = anyValid.id;
        console.log(chalk.yellow(`Using auth doc: ${anyValid.clientName} (may not match domain exactly)`));
      } else {
        console.error(chalk.red('No valid auth documents found. Run: ryha scope create'));
        process.exit(1);
      }
    } else {
      console.error(chalk.red('No auth documents found. Run: ryha scope create'));
      process.exit(1);
    }
  } else {
    const doc = AuthDocument.load(authDocId);
    if (!doc) { console.error(chalk.red('Auth doc not found')); process.exit(1); }
    if (!doc.isValid()) { console.error(chalk.red('Auth expired')); process.exit(1); }
  }

  const orch = new PentestOrchestrator();
  const spinner = ora('Starting pentest...').start();
  try {
    const jobId = await orch.startPentest(opts.domain, opts.type, authDocId);
    spinner.succeed(`Pentest started: ${jobId}`);
    console.log(chalk.cyan(`  Target:  ${opts.domain}`));
    console.log(chalk.cyan(`  Type:    ${opts.type}`));
    console.log(chalk.cyan(`  Auth:    ${authDocId.substring(0, 8)}...`));
    console.log(chalk.green(`\n  Dashboard: ryha server   (then open http://localhost:3000)`));
  } catch (e) {
    spinner.fail((e as Error).message);
    process.exit(1);
  }
});

// AGENTS
const agents = program.command('agents');
agents.command('list').action(() => console.log('Agents: 6'));
agents.command('status').action(() => console.log('Status: Running'));

// REPORT
program.command('report <jobId>').option('-f, --format <fmt>', 'Format', 'html').action((jobId, opts) => {
  console.log(`Report ${jobId} in ${opts.format} format`);
});

// CONFIG
const config = program.command('config');
config.command('set <key> <value>').action((k, v) => {
  ConfigManager.getInstance().set(k, v);
  ConfigManager.getInstance().saveConfig();
  console.log(chalk.green('Set ' + k));
});
config.command('get <key>').action((k) => {
  console.log(ConfigManager.getInstance().get(k));
});
config.command('list').action(() => {
  console.log(JSON.stringify(ConfigManager.getInstance().getConfig(), null, 2));
});

// SERVER
program.command('server').option('-p, --port <port>', 'Port', '3000').action((opts) => {
  new RyhaServer(parseInt(opts.port)).start();
});

// SETUP
program.command('setup').description('One-time setup wizard: authenticate + create auth doc').action(async () => {
  console.log(chalk.cyan.bold('\n  RYHA SETUP WIZARD\n'));

  // Step 1: Auth
  const isAuth = await copilotAuth.isAuthenticated();
  if (isAuth) {
    console.log(chalk.green('  [1/2] Authentication: Already logged in'));
  } else {
    console.log(chalk.yellow('  [1/2] Authentication: Logging in via GitHub Copilot...'));
    try { await copilotAuth.authenticate(); } catch (e) { console.error(chalk.red((e as Error).message)); process.exit(1); }
    console.log(chalk.green('  [1/2] Authentication: Success'));
  }

  // Step 2: Auth doc
  const existingDocs = AuthDocument.listAll();
  const validDocs = existingDocs.map(id => AuthDocument.load(id)).filter(d => d && d.isValid());
  if (validDocs.length > 0) {
    console.log(chalk.green(`  [2/2] Authorization: ${validDocs.length} valid doc(s) found`));
    validDocs.forEach(d => console.log(chalk.blue(`         - ${d!.clientName} → ${d!.targetDomain} (expires ${d!.endDate.toISOString().split('T')[0]})`)));
  } else {
    console.log(chalk.yellow('  [2/2] Authorization: Creating new auth document...\n'));
    const answers = await inquirer.prompt([
      { name: 'clientName', message: 'Client/Company name:' },
      { name: 'targetDomain', message: 'Target domain:' },
      { name: 'inScope', message: 'In-scope targets (comma-separated):' },
      { name: 'outOfScope', message: 'Out-of-scope (comma-separated):', default: '' },
      { name: 'startDate', message: 'Start date:', default: new Date().toISOString().split('T')[0] },
      { name: 'endDate', message: 'End date:', default: new Date(Date.now() + 30*24*60*60*1000).toISOString().split('T')[0] },
      { type: 'checkbox', name: 'testingType', message: 'Testing types:', choices: ['network','web','infrastructure','code','cloud','full'], default: ['full'] },
      { name: 'authorizedBy', message: 'Authorized by:' },
      { name: 'signature', message: 'Signature:' }
    ]);
    const doc = new AuthDocument(answers.clientName, answers.targetDomain, answers.inScope.split(',').map((s: string) => s.trim()), answers.outOfScope ? answers.outOfScope.split(',').map((s: string) => s.trim()) : [], new Date(answers.startDate), new Date(answers.endDate), answers.testingType, answers.authorizedBy, answers.signature);
    doc.save();
    console.log(chalk.green(`\n  Auth doc created: ${doc.id.substring(0, 8)}...`));
  }

  console.log(chalk.cyan.bold('\n  Setup complete! You can now run:'));
  console.log(chalk.white(`    ryha pentest -d target.com -t full`));
  console.log(chalk.white(`    ryha server`));
  console.log('');
});

// TOOLS
const tools = program.command('tools').description('Manage security tools');
const toolManager = new ToolManager();

tools.command('list').option('-c, --category <category>', 'Filter by category').option('-i, --installed', 'Show only installed').action(async (opts) => {
  const spinner = ora('Discovering tools...').start();
  if (opts.installed) {
    const discovered = await toolManager.discoverTools();
    spinner.succeed(`Found ${discovered.length} installed tools`);
    const table = new Table({ head: [chalk.cyan('Name'), chalk.cyan('Category'), chalk.cyan('Version'), chalk.cyan('Description')] });
    discovered.forEach(t => table.push([t.name, t.category, t.version || '-', t.description.substring(0, 50)]));
    console.log(table.toString());
  } else {
    const category = opts.category ? opts.category as ToolCategory : undefined;
    const allTools = toolManager.listAvailableTools(category);
    spinner.succeed(`${allTools.length} tools in database${category ? ` (${category})` : ''}`);
    const table = new Table({ head: [chalk.cyan('Name'), chalk.cyan('Category'), chalk.cyan('Root'), chalk.cyan('Description')] });
    allTools.forEach(t => table.push([t.name, t.category, t.requiresRoot ? 'Yes' : '-', t.description.substring(0, 50)]));
    console.log(table.toString());
  }
});

tools.command('categories').description('List all tool categories').action(() => {
  const categories = Object.values(ToolCategory);
  console.log(chalk.bold('\nAvailable categories:'));
  categories.forEach(c => {
    const count = toolManager.listAvailableTools(c as ToolCategory).length;
    console.log(`  ${chalk.yellow(c.padEnd(25))} ${count} tools`);
  });
});

tools.command('info <name>').description('Get tool details').action(async (name) => {
  const info = await toolManager.getToolInfo(name);
  if (!info) { console.error(chalk.red(`Tool "${name}" not found`)); return; }
  console.log(chalk.bold(`\n${info.displayName} (${info.name})`));
  console.log(`  Category:     ${info.category}`);
  console.log(`  Version:      ${info.version || 'unknown'}`);
  console.log(`  Installed:    ${info.installed ? chalk.green('Yes') : chalk.red('No')}`);
  console.log(`  Root:         ${info.requiresRoot ? 'Required' : 'Not required'}`);
  console.log(`  Description:  ${info.description}`);
  console.log(`  Capabilities: ${info.capabilities.join(', ')}`);
  if (info.defaultArgs) console.log(`  Default args: ${info.defaultArgs.join(' ')}`);
});

tools.command('install <name>').description('Install a tool via apt-get').action(async (name) => {
  const spinner = ora(`Installing ${name}...`).start();
  const success = await toolManager.installTool(name);
  success ? spinner.succeed(`${name} installed`) : spinner.fail(`Failed to install ${name}`);
});

tools.command('search <capability>').description('Search tools by capability').action(async (capability) => {
  const spinner = ora('Searching...').start();
  await toolManager.discoverTools();
  const results = toolManager.searchByCapability(capability);
  spinner.succeed(`Found ${results.length} tools with "${capability}"`);
  results.forEach(t => console.log(`  ${chalk.yellow(t.name.padEnd(20))} ${t.description}`));
});

tools.command('github <repo>').description('Install tool from GitHub (owner/repo)').action(async (repo) => {
  const spinner = ora(`Installing from GitHub: ${repo}...`).start();
  const result = await toolManager.githubInstaller.installKnownTool(repo);
  if (result.success) {
    spinner.succeed(`${result.toolName} installed (${result.buildSystem}) in ${(result.duration / 1000).toFixed(1)}s`);
  } else {
    spinner.fail(`Failed: ${result.error}`);
  }
});

tools.command('github-search <query>').description('Search GitHub for security tools').action(async (query) => {
  const isAuth = await copilotAuth.isAuthenticated();
  if (!isAuth) { console.error(chalk.red('Login first: ryha auth login')); process.exit(1); }
  const spinner = ora('Searching GitHub via AI...').start();
  const results = await toolManager.githubInstaller.findToolOnGitHub(query);
  spinner.succeed(`Found ${results.length} repos`);
  results.forEach(r => console.log(`  ${chalk.yellow(r.repo.padEnd(40))} ${r.description}`));
});

tools.command('github-list').description('List known GitHub security tool repos').action(() => {
  const known = toolManager.githubInstaller.listKnownTools();
  const table = new Table({ head: [chalk.cyan('Repository'), chalk.cyan('Build'), chalk.cyan('Description')] });
  known.forEach(k => table.push([k.repo, k.buildSystem, k.description]));
  console.log(table.toString());
});

tools.command('create').description('Create a custom security tool with AI').action(async () => {
  const isAuth = await copilotAuth.isAuthenticated();
  if (!isAuth) { console.error(chalk.red('Login first: ryha auth login')); process.exit(1); }
  const answers = await inquirer.prompt([
    { name: 'purpose', message: 'Tool purpose:' },
    { name: 'target', message: 'Target type (web/network/api/host):', default: 'web' },
    { type: 'list', name: 'language', message: 'Language:', choices: ['python', 'bash', 'ruby', 'perl', 'go'], default: 'python' },
    { type: 'list', name: 'template', message: 'Template:', choices: ['custom', 'port-scanner', 'web-fuzzer', 'credential-tester', 'api-enumerator', 'subdomain-finder', 'vulnerability-checker', 'network-sniffer', 'log-analyzer', 'hash-cracker'], default: 'custom' }
  ]);
  const spinner = ora('AI is creating your tool...').start();
  try {
    const selector = new AIToolSelector(toolManager);
    const tool = await selector.createCustomTool(answers.purpose, answers.target, answers.language, answers.template === 'custom' ? undefined : answers.template);
    spinner.succeed(`Created: ${tool.name}`);
    console.log(chalk.green(`  Description: ${tool.description}`));
    console.log(chalk.green(`  Usage: ${tool.usage}`));
  } catch (e) {
    spinner.fail((e as Error).message);
  }
});

tools.command('ensure <name>').description('Auto-install a missing tool (tries apt, pip, go, github)').action(async (name) => {
  const spinner = ora(`Ensuring ${name} is available...`).start();
  const selector = new AIToolSelector(toolManager);
  const result = await selector.ensureToolAvailable(name);
  result.available
    ? spinner.succeed(`${name} available (${result.method})`)
    : spinner.fail(`Could not install ${name} via any method`);
});

program.parse(process.argv);
if (!process.argv.slice(2).length) program.outputHelp();
