# Ryha Security Flow - Configuration System

## Overview

The configuration system provides centralized configuration management for Ryha Security Flow with:

- **File-based configuration** (YAML at `~/.ryha/config.yaml`)
- **Environment variable overrides** (prefix: `RYHA_*`)
- **Schema validation** using Zod
- **Hot reload capability** (detects file changes automatically)
- **Secure API key storage** (encrypted with AES-256-CBC)
- **Type-safe configuration** (TypeScript)

## Configuration Structure

### Sections

#### 1. **Copilot Configuration**
```yaml
copilot:
  proxyUrl: 'https://api.githubcopilot.com'
  models: ['claude-opus-4-6', 'claude-3-5-sonnet', 'claude-3-haiku']
  defaultModel: 'claude-opus-4-6'
  apiKey: 'sk-ant-...' # Encrypted
```

**Environment Variables:**
- `RYHA_COPILOT_PROXY_URL` - Proxy URL
- `RYHA_COPILOT_API_KEY` - API key
- `RYHA_COPILOT_DEFAULT_MODEL` - Default model

#### 2. **Agents Configuration**
```yaml
agents:
  maxParallel: 10  # Max concurrent agents
  retryAttempts: 3 # Retry failed tasks
  defaultTypes:
    - 'vulnerability-scanner'
    - 'exploitation-agent'
    - 'report-generator'
```

**Environment Variables:**
- `RYHA_AGENTS_MAX_PARALLEL` - Max parallel agents
- `RYHA_AGENTS_RETRY_ATTEMPTS` - Retry attempts

#### 3. **Tools Configuration**
Paths to penetration testing tools:
```yaml
tools:
  nmap: '/usr/bin/nmap'
  burpsuite: '/opt/burpsuite/burpsuite_pro'
  zaproxy: '/usr/bin/zaproxy'
  metasploit: '/usr/bin/msfconsole'
  sqlmap: '/usr/bin/sqlmap'
```

**Environment Variables:**
- `RYHA_NMAP_PATH` - Nmap path

#### 4. **Kali Linux Integration**
```yaml
kali:
  baseDir: '/opt/ryha-security-flow'
  dataDir: '/var/ryha/data'
  reportsDir: '/var/ryha/reports'
  enabled: true
```

#### 5. **Logging Configuration**
```yaml
logging:
  level: 'info'  # error, warn, info, debug
  retention: '30d'  # Keep logs for 30 days
  logDir: '~/.ryha/logs'
```

**Environment Variables:**
- `RYHA_LOG_LEVEL` - Log level

#### 6. **Server Configuration**
```yaml
server:
  port: 3000
  host: 'localhost'
  enableCors: true
  corsOrigins:
    - 'http://localhost:3000'
```

**Environment Variables:**
- `RYHA_SERVER_PORT` - Server port
- `RYHA_SERVER_HOST` - Server host

## Usage

### 1. Initialize Configuration Manager

```typescript
import { ConfigManager } from './src/config';

const config = new ConfigManager({
  validateOnInit: true,    // Validate schema on startup
  enableHotReload: true,   // Watch for file changes
});
```

### 2. Get Configuration Values

```typescript
// Get full configuration
const fullConfig = config.getConfig();

// Get specific section
const serverConfig = config.getSection('server');

// Get specific value
const port = config.get('server.port', 3000);
```

### 3. Update Configuration

```typescript
// Update a section
config.setSection('agents', {
  maxParallel: 20,
  retryAttempts: 5,
});

// Update a specific value
config.set('server.port', 4000);

// Save to file
config.saveConfig();
```

### 4. Secure API Key Storage

```typescript
// Store an API key (encrypted)
config.setApiKey('sk-ant-...', 'copilot');

// Retrieve API key (auto-decrypted)
const apiKey = config.getApiKey('copilot');
```

### 5. Watch for Configuration Changes

```typescript
// Set up a watcher
config.watch('my-id', (updatedConfig) => {
  console.log('Config changed:', updatedConfig);
});

// Remove watcher
config.unwatch('my-id');
```

### 6. Configuration Validation

```typescript
// Validate current configuration
const isValid = config.validateConfig();

if (!isValid) {
  console.log('Configuration has validation errors');
}
```

## Setup Wizard

Run the interactive setup wizard:

```bash
npx ts-node src/cli/setup-wizard.ts
```

Or programmatically:

```typescript
import { SetupWizard } from './src/cli/setup-wizard';

const wizard = new SetupWizard({ interactive: true });
const success = await wizard.runSetup();
```

The wizard will:
1. Check for existing configuration
2. Prompt for Copilot API key
3. Configure agent settings
4. Set tool paths
5. Enable Kali integration
6. Set logging level
7. Configure server settings
8. Validate and save configuration

## Environment Variable Precedence

Configuration loads in this order (later overrides earlier):
1. **Default values** (hardcoded in Zod schemas)
2. **YAML file** (`~/.ryha/config.yaml`)
3. **Environment variables** (`RYHA_*`)

Example:
```bash
export RYHA_SERVER_PORT=4000
export RYHA_LOG_LEVEL=debug

# These will override config.yaml values
npx ryha pentest --target example.com
```

## Security

### API Key Encryption

API keys are encrypted using:
- **Algorithm:** AES-256-CBC
- **Key derivation:** scrypt (32-byte key, 32-byte salt)
- **Storage format:** `salt:iv:encrypted_data` (hex-encoded)

The encryption password is derived from:
```
{hostname}-{platform}-ryha-secured
```

### Best Practices

1. **Never commit** `~/.ryha/config.yaml` to version control
2. **Encrypt sensitive data** using `config.setApiKey()`
3. **Use environment variables** for CI/CD pipelines
4. **Restrict file permissions:** `chmod 600 ~/.ryha/config.yaml`

## Configuration File Example

```yaml
# ~/.ryha/config.yaml

copilot:
  defaultModel: 'claude-opus-4-6'
  proxyUrl: 'https://api.githubcopilot.com'

agents:
  maxParallel: 10
  retryAttempts: 3

tools:
  nmap: '/usr/bin/nmap'
  burpsuite: '/opt/burpsuite/burpsuite_pro'

kali:
  baseDir: '/opt/ryha-security-flow'
  dataDir: '/var/ryha/data'
  reportsDir: '/var/ryha/reports'
  enabled: true

logging:
  level: 'info'
  retention: '30d'

server:
  port: 3000
  host: 'localhost'
  enableCors: true
```

## Development

### Testing Configuration

```bash
# Run examples
npm run dev examples/config-usage.ts

# Run tests
npm run test config
```

### Adding New Configuration Sections

1. Update Zod schema in `src/config/config-manager.ts`:
```typescript
const MyConfigSchema = z.object({
  // ... fields
});
```

2. Update `RyhaConfigSchema`:
```typescript
const RyhaConfigSchema = z.object({
  myConfig: MyConfigSchema.optional(),
  // ... other sections
});
```

3. Add environment variable handling in `loadEnvVariables()`:
```typescript
if (process.env.RYHA_MY_CONFIG_VALUE) {
  envConfig.myConfig = { value: process.env.RYHA_MY_CONFIG_VALUE };
}
```

## Troubleshooting

### Configuration file not found
- Check location: `~/.ryha/config.yaml`
- Run setup wizard: `npm run setup`

### API key decryption fails
- Export password: `export RYHA_ENCRYPTION_PASSWORD=...`
- Or re-encrypt: `config.setApiKey(newKey, 'service')`

### Hot reload not working
- Check file permissions on `~/.ryha/`
- Disable on network file systems (NFS, SMB)

### Validation errors
- Run `npm run doctor` to diagnose
- Check schema validation output
- Verify YAML syntax

## CLI Integration

The setup wizard is integrated into the main CLI:

```bash
# Interactive setup
ryha setup

# Non-interactive setup (uses defaults)
ryha setup --non-interactive

# Verify configuration
ryha config list

# Show specific section
ryha config show server
```

## Types

All configuration types are exported for TypeScript usage:

```typescript
import {
  RyhaConfig,
  CopilotConfig,
  AgentsConfig,
  ToolsConfig,
  KaliConfig,
  LoggingConfig,
  ServerConfig,
} from './src/config';

const config: RyhaConfig = { /* ... */ };
const copilot: CopilotConfig = config.copilot;
```
