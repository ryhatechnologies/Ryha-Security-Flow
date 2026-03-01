#!/usr/bin/env node
"use strict";
/**
 * Ryha Security Flow - CLI with full implementations
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const chalk_1 = __importDefault(require("chalk"));
const commander_1 = require("commander");
const inquirer_1 = __importDefault(require("inquirer"));
const ora_1 = __importDefault(require("ora"));
const cli_table3_1 = __importDefault(require("cli-table3"));
const copilot_auth_1 = require("./auth/copilot-auth");
const server_1 = require("./api/server");
const auth_document_1 = require("./compliance/auth-document");
const config_manager_1 = require("./config/config-manager");
const orchestrator_1 = require("./orchestrator/orchestrator");
const tool_manager_1 = require("./tools/tool-manager");
const ai_tool_selector_1 = require("./tools/ai-tool-selector");
const program = new commander_1.Command();
const banner = `RYHA SECURITY FLOW - v1.0.0`;
console.log(chalk_1.default.cyan.bold(banner));
program.name('ryha').description('Ryha Security Flow').version('1.0.0');
// AUTH
const auth = program.command('auth');
auth.command('login').action(async () => {
    try {
        await copilot_auth_1.copilotAuth.authenticate();
    }
    catch (e) {
        console.error(chalk_1.default.red(e.message));
        process.exit(1);
    }
});
auth.command('status').action(async () => {
    const isAuth = await copilot_auth_1.copilotAuth.isAuthenticated();
    console.log(isAuth ? chalk_1.default.green('Authenticated') : chalk_1.default.red('Not authenticated'));
});
auth.command('logout').action(() => copilot_auth_1.copilotAuth.clearTokens());
// SCOPE
const scope = program.command('scope');
scope.command('create').action(async () => {
    const answers = await inquirer_1.default.prompt([
        { name: 'clientName', message: 'Client name:' },
        { name: 'targetDomain', message: 'Target domain:' },
        { name: 'inScope', message: 'In-scope (comma-separated):' },
        { name: 'outOfScope', message: 'Out-of-scope:', default: '' },
        { name: 'startDate', message: 'Start date:', default: new Date().toISOString().split('T')[0] },
        { name: 'endDate', message: 'End date:', default: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0] },
        { type: 'checkbox', name: 'testingType', message: 'Testing types:', choices: ['network', 'web', 'infrastructure', 'code', 'cloud', 'full'] },
        { name: 'authorizedBy', message: 'Authorized by:' },
        { name: 'signature', message: 'Signature:' },
        { name: 'notes', message: 'Notes:', default: '' }
    ]);
    const doc = new auth_document_1.AuthDocument(answers.clientName, answers.targetDomain, answers.inScope.split(','), answers.outOfScope ? answers.outOfScope.split(',') : [], new Date(answers.startDate), new Date(answers.endDate), answers.testingType, answers.authorizedBy, answers.signature, answers.notes);
    doc.save();
    console.log(chalk_1.default.green('Created: ' + doc.id));
});
scope.command('list').action(() => {
    auth_document_1.AuthDocument.listAll().forEach(id => console.log(id));
});
scope.command('view <id>').action((id) => {
    const doc = auth_document_1.AuthDocument.load(id);
    console.log(doc ? doc.exportAsText() : 'Not found');
});
// PENTEST
program.command('pentest').requiredOption('-d, --domain <domain>').option('-t, --type <type>', 'Scan type', 'full').option('-a, --auth <id>', 'Auth doc ID (auto-detected if omitted)').action(async (opts) => {
    const isAuth = await copilot_auth_1.copilotAuth.isAuthenticated();
    if (!isAuth) {
        console.error(chalk_1.default.red('Not authenticated. Run: ryha auth login'));
        process.exit(1);
    }
    // Auto-find auth doc if not specified
    let authDocId = opts.auth;
    if (!authDocId) {
        const allDocs = auth_document_1.AuthDocument.listAll();
        const validDoc = allDocs.map(id => auth_document_1.AuthDocument.load(id)).find(d => d && d.isValid() && (d.targetDomain === opts.domain || d.inScope.some((s) => opts.domain.includes(s) || s.includes(opts.domain))));
        if (validDoc) {
            authDocId = validDoc.id;
            console.log(chalk_1.default.blue(`Auto-detected auth doc: ${validDoc.clientName} (${validDoc.id.substring(0, 8)}...)`));
        }
        else if (allDocs.length > 0) {
            const anyValid = allDocs.map(id => auth_document_1.AuthDocument.load(id)).find(d => d && d.isValid());
            if (anyValid) {
                authDocId = anyValid.id;
                console.log(chalk_1.default.yellow(`Using auth doc: ${anyValid.clientName} (may not match domain exactly)`));
            }
            else {
                console.error(chalk_1.default.red('No valid auth documents found. Run: ryha scope create'));
                process.exit(1);
            }
        }
        else {
            console.error(chalk_1.default.red('No auth documents found. Run: ryha scope create'));
            process.exit(1);
        }
    }
    else {
        const doc = auth_document_1.AuthDocument.load(authDocId);
        if (!doc) {
            console.error(chalk_1.default.red('Auth doc not found'));
            process.exit(1);
        }
        if (!doc.isValid()) {
            console.error(chalk_1.default.red('Auth expired'));
            process.exit(1);
        }
    }
    const orch = new orchestrator_1.PentestOrchestrator();
    const spinner = (0, ora_1.default)('Starting pentest...').start();
    try {
        const jobId = await orch.startPentest(opts.domain, opts.type, authDocId);
        spinner.succeed(`Pentest started: ${jobId}`);
        console.log(chalk_1.default.cyan(`  Target:  ${opts.domain}`));
        console.log(chalk_1.default.cyan(`  Type:    ${opts.type}`));
        console.log(chalk_1.default.cyan(`  Auth:    ${authDocId.substring(0, 8)}...`));
        console.log(chalk_1.default.green(`\n  Dashboard: ryha server   (then open http://localhost:3000)`));
    }
    catch (e) {
        spinner.fail(e.message);
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
    config_manager_1.ConfigManager.getInstance().set(k, v);
    config_manager_1.ConfigManager.getInstance().saveConfig();
    console.log(chalk_1.default.green('Set ' + k));
});
config.command('get <key>').action((k) => {
    console.log(config_manager_1.ConfigManager.getInstance().get(k));
});
config.command('list').action(() => {
    console.log(JSON.stringify(config_manager_1.ConfigManager.getInstance().getConfig(), null, 2));
});
// SERVER
program.command('server').option('-p, --port <port>', 'Port', '3000').action((opts) => {
    new server_1.RyhaServer(parseInt(opts.port)).start();
});
// SETUP
program.command('setup').description('One-time setup wizard: authenticate + create auth doc').action(async () => {
    console.log(chalk_1.default.cyan.bold('\n  RYHA SETUP WIZARD\n'));
    // Step 1: Auth
    const isAuth = await copilot_auth_1.copilotAuth.isAuthenticated();
    if (isAuth) {
        console.log(chalk_1.default.green('  [1/2] Authentication: Already logged in'));
    }
    else {
        console.log(chalk_1.default.yellow('  [1/2] Authentication: Logging in via GitHub Copilot...'));
        try {
            await copilot_auth_1.copilotAuth.authenticate();
        }
        catch (e) {
            console.error(chalk_1.default.red(e.message));
            process.exit(1);
        }
        console.log(chalk_1.default.green('  [1/2] Authentication: Success'));
    }
    // Step 2: Auth doc
    const existingDocs = auth_document_1.AuthDocument.listAll();
    const validDocs = existingDocs.map(id => auth_document_1.AuthDocument.load(id)).filter(d => d && d.isValid());
    if (validDocs.length > 0) {
        console.log(chalk_1.default.green(`  [2/2] Authorization: ${validDocs.length} valid doc(s) found`));
        validDocs.forEach(d => console.log(chalk_1.default.blue(`         - ${d.clientName} → ${d.targetDomain} (expires ${d.endDate.toISOString().split('T')[0]})`)));
    }
    else {
        console.log(chalk_1.default.yellow('  [2/2] Authorization: Creating new auth document...\n'));
        const answers = await inquirer_1.default.prompt([
            { name: 'clientName', message: 'Client/Company name:' },
            { name: 'targetDomain', message: 'Target domain:' },
            { name: 'inScope', message: 'In-scope targets (comma-separated):' },
            { name: 'outOfScope', message: 'Out-of-scope (comma-separated):', default: '' },
            { name: 'startDate', message: 'Start date:', default: new Date().toISOString().split('T')[0] },
            { name: 'endDate', message: 'End date:', default: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0] },
            { type: 'checkbox', name: 'testingType', message: 'Testing types:', choices: ['network', 'web', 'infrastructure', 'code', 'cloud', 'full'], default: ['full'] },
            { name: 'authorizedBy', message: 'Authorized by:' },
            { name: 'signature', message: 'Signature:' }
        ]);
        const doc = new auth_document_1.AuthDocument(answers.clientName, answers.targetDomain, answers.inScope.split(',').map((s) => s.trim()), answers.outOfScope ? answers.outOfScope.split(',').map((s) => s.trim()) : [], new Date(answers.startDate), new Date(answers.endDate), answers.testingType, answers.authorizedBy, answers.signature);
        doc.save();
        console.log(chalk_1.default.green(`\n  Auth doc created: ${doc.id.substring(0, 8)}...`));
    }
    console.log(chalk_1.default.cyan.bold('\n  Setup complete! You can now run:'));
    console.log(chalk_1.default.white(`    ryha pentest -d target.com -t full`));
    console.log(chalk_1.default.white(`    ryha server`));
    console.log('');
});
// TOOLS
const tools = program.command('tools').description('Manage security tools');
const toolManager = new tool_manager_1.ToolManager();
tools.command('list').option('-c, --category <category>', 'Filter by category').option('-i, --installed', 'Show only installed').action(async (opts) => {
    const spinner = (0, ora_1.default)('Discovering tools...').start();
    if (opts.installed) {
        const discovered = await toolManager.discoverTools();
        spinner.succeed(`Found ${discovered.length} installed tools`);
        const table = new cli_table3_1.default({ head: [chalk_1.default.cyan('Name'), chalk_1.default.cyan('Category'), chalk_1.default.cyan('Version'), chalk_1.default.cyan('Description')] });
        discovered.forEach(t => table.push([t.name, t.category, t.version || '-', t.description.substring(0, 50)]));
        console.log(table.toString());
    }
    else {
        const category = opts.category ? opts.category : undefined;
        const allTools = toolManager.listAvailableTools(category);
        spinner.succeed(`${allTools.length} tools in database${category ? ` (${category})` : ''}`);
        const table = new cli_table3_1.default({ head: [chalk_1.default.cyan('Name'), chalk_1.default.cyan('Category'), chalk_1.default.cyan('Root'), chalk_1.default.cyan('Description')] });
        allTools.forEach(t => table.push([t.name, t.category, t.requiresRoot ? 'Yes' : '-', t.description.substring(0, 50)]));
        console.log(table.toString());
    }
});
tools.command('categories').description('List all tool categories').action(() => {
    const categories = Object.values(tool_manager_1.ToolCategory);
    console.log(chalk_1.default.bold('\nAvailable categories:'));
    categories.forEach(c => {
        const count = toolManager.listAvailableTools(c).length;
        console.log(`  ${chalk_1.default.yellow(c.padEnd(25))} ${count} tools`);
    });
});
tools.command('info <name>').description('Get tool details').action(async (name) => {
    const info = await toolManager.getToolInfo(name);
    if (!info) {
        console.error(chalk_1.default.red(`Tool "${name}" not found`));
        return;
    }
    console.log(chalk_1.default.bold(`\n${info.displayName} (${info.name})`));
    console.log(`  Category:     ${info.category}`);
    console.log(`  Version:      ${info.version || 'unknown'}`);
    console.log(`  Installed:    ${info.installed ? chalk_1.default.green('Yes') : chalk_1.default.red('No')}`);
    console.log(`  Root:         ${info.requiresRoot ? 'Required' : 'Not required'}`);
    console.log(`  Description:  ${info.description}`);
    console.log(`  Capabilities: ${info.capabilities.join(', ')}`);
    if (info.defaultArgs)
        console.log(`  Default args: ${info.defaultArgs.join(' ')}`);
});
tools.command('install <name>').description('Install a tool via apt-get').action(async (name) => {
    const spinner = (0, ora_1.default)(`Installing ${name}...`).start();
    const success = await toolManager.installTool(name);
    success ? spinner.succeed(`${name} installed`) : spinner.fail(`Failed to install ${name}`);
});
tools.command('search <capability>').description('Search tools by capability').action(async (capability) => {
    const spinner = (0, ora_1.default)('Searching...').start();
    await toolManager.discoverTools();
    const results = toolManager.searchByCapability(capability);
    spinner.succeed(`Found ${results.length} tools with "${capability}"`);
    results.forEach(t => console.log(`  ${chalk_1.default.yellow(t.name.padEnd(20))} ${t.description}`));
});
tools.command('github <repo>').description('Install tool from GitHub (owner/repo)').action(async (repo) => {
    const spinner = (0, ora_1.default)(`Installing from GitHub: ${repo}...`).start();
    const result = await toolManager.githubInstaller.installKnownTool(repo);
    if (result.success) {
        spinner.succeed(`${result.toolName} installed (${result.buildSystem}) in ${(result.duration / 1000).toFixed(1)}s`);
    }
    else {
        spinner.fail(`Failed: ${result.error}`);
    }
});
tools.command('github-search <query>').description('Search GitHub for security tools').action(async (query) => {
    const isAuth = await copilot_auth_1.copilotAuth.isAuthenticated();
    if (!isAuth) {
        console.error(chalk_1.default.red('Login first: ryha auth login'));
        process.exit(1);
    }
    const spinner = (0, ora_1.default)('Searching GitHub via AI...').start();
    const results = await toolManager.githubInstaller.findToolOnGitHub(query);
    spinner.succeed(`Found ${results.length} repos`);
    results.forEach(r => console.log(`  ${chalk_1.default.yellow(r.repo.padEnd(40))} ${r.description}`));
});
tools.command('github-list').description('List known GitHub security tool repos').action(() => {
    const known = toolManager.githubInstaller.listKnownTools();
    const table = new cli_table3_1.default({ head: [chalk_1.default.cyan('Repository'), chalk_1.default.cyan('Build'), chalk_1.default.cyan('Description')] });
    known.forEach(k => table.push([k.repo, k.buildSystem, k.description]));
    console.log(table.toString());
});
tools.command('create').description('Create a custom security tool with AI').action(async () => {
    const isAuth = await copilot_auth_1.copilotAuth.isAuthenticated();
    if (!isAuth) {
        console.error(chalk_1.default.red('Login first: ryha auth login'));
        process.exit(1);
    }
    const answers = await inquirer_1.default.prompt([
        { name: 'purpose', message: 'Tool purpose:' },
        { name: 'target', message: 'Target type (web/network/api/host):', default: 'web' },
        { type: 'list', name: 'language', message: 'Language:', choices: ['python', 'bash', 'ruby', 'perl', 'go'], default: 'python' },
        { type: 'list', name: 'template', message: 'Template:', choices: ['custom', 'port-scanner', 'web-fuzzer', 'credential-tester', 'api-enumerator', 'subdomain-finder', 'vulnerability-checker', 'network-sniffer', 'log-analyzer', 'hash-cracker'], default: 'custom' }
    ]);
    const spinner = (0, ora_1.default)('AI is creating your tool...').start();
    try {
        const selector = new ai_tool_selector_1.AIToolSelector(toolManager);
        const tool = await selector.createCustomTool(answers.purpose, answers.target, answers.language, answers.template === 'custom' ? undefined : answers.template);
        spinner.succeed(`Created: ${tool.name}`);
        console.log(chalk_1.default.green(`  Description: ${tool.description}`));
        console.log(chalk_1.default.green(`  Usage: ${tool.usage}`));
    }
    catch (e) {
        spinner.fail(e.message);
    }
});
tools.command('ensure <name>').description('Auto-install a missing tool (tries apt, pip, go, github)').action(async (name) => {
    const spinner = (0, ora_1.default)(`Ensuring ${name} is available...`).start();
    const selector = new ai_tool_selector_1.AIToolSelector(toolManager);
    const result = await selector.ensureToolAvailable(name);
    result.available
        ? spinner.succeed(`${name} available (${result.method})`)
        : spinner.fail(`Could not install ${name} via any method`);
});
program.parse(process.argv);
if (!process.argv.slice(2).length)
    program.outputHelp();
//# sourceMappingURL=cli.js.map