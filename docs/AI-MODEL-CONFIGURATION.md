# AI Model Configuration Guide

## Overview

Ryha Security Flow supports multiple AI models for different tasks. Each task type can use its optimal model based on complexity, speed, and cost requirements.

---

## Available AI Models

| Model ID | Name | Provider | Cost | Speed | Reasoning | Best For |
|----------|------|----------|------|-------|-----------|----------|
| `claude-opus-4-6` | Claude Opus 4.6 | Anthropic | $$ | Slow | Excellent | Complex reasoning, tool selection, attack planning |
| `claude-3-5-sonnet-20241022` | Claude 3.5 Sonnet | Anthropic | $ | Medium | Very Good | Tool output analysis, report generation |
| `gpt-4o` | GPT-4o | OpenAI | $ | Fast | Good | Fast searches, simple analysis |
| `gpt-4` | GPT-4 | OpenAI | $$ | Slow | Excellent | Alternative to Opus |
| `o1-preview` | o1 Preview | OpenAI | $$$ | Very Slow | Outstanding | Complex problems, advanced reasoning |

---

## Model Selection Methods

### 1. **Global Default Model** (Easiest)

Set the default model for all AI operations:

```bash
ryha config set copilot.defaultModel claude-opus-4-6
```

Then verify:

```bash
ryha config get copilot.defaultModel
```

### 2. **Environment Variable**

Set the model via environment variable (takes precedence):

```bash
export RYHA_COPILOT_DEFAULT_MODEL=claude-opus-4-6
ryha server
```

Or in `.env` file:

```env
RYHA_COPILOT_DEFAULT_MODEL=claude-opus-4-6
RYHA_AGENTS_MAX_PARALLEL=10
RYHA_SERVER_PORT=3000
```

### 3. **Configuration File**

Edit `~/.ryha/config.yaml`:

```yaml
copilot:
  proxyUrl: https://api.githubcopilot.com
  defaultModel: claude-opus-4-6
  models:
    - claude-opus-4-6
    - claude-3-5-sonnet-20241022
    - gpt-4o
    - gpt-4
    - o1-preview
```

### 4. **Per-Task Model Selection** (Recommended for Production)

Different task types use optimal models automatically (once integrated):

```typescript
// Tool selection (complex reasoning) → Claude Opus
const toolSelectionModel = 'claude-opus-4-6';

// Tool output analysis (fast) → Sonnet
const outputAnalysisModel = 'claude-3-5-sonnet-20241022';

// GitHub search (speed) → GPT-4o
const gitHubSearchModel = 'gpt-4o';
```

---

## System Instructions by Agent

### Orchestrator

**Role**: Master coordinator of penetration tests.

**Instructions**:
- Validate all scans against authorization documents
- Extract vulnerabilities from tool output
- Maintain compliance audit trail
- Ensure targets stay in scope

**Example task**:
```
Analyze nmap output and extract all discovered services,
versions, and potential vulnerabilities.
```

### Recon Agent

**Role**: Information gathering specialist.

**Instructions**:
- Enumerate DNS, subdomains, WHOIS data
- Identify services and versions
- Perform OSINT
- Detect WAF/security controls

**Example task**:
```
Perform comprehensive reconnaissance on example.com:
- DNS enumeration
- Subdomain discovery
- WHOIS and registration data
- Technology fingerprinting
```

### Scanner Agent

**Role**: Vulnerability discovery specialist.

**Instructions**:
- Scan for known CVEs
- Test OWASP Top 10
- Assess SSL/TLS configuration
- Test authentication mechanisms

**Example task**:
```
Scan 192.168.1.100:8080 for web application vulnerabilities
including XSS, SQLi, CSRF, and authentication bypass.
```

### Analyzer Agent

**Role**: Deep analysis and risk assessment.

**Instructions**:
- Calculate CVSS scores
- Correlate findings into attack chains
- Assess exploitability
- Identify business impact

**Example task**:
```
Analyze these 15 vulnerabilities and prioritize by
real-world exploitability and business impact.
```

### Exploit Tester

**Role**: Safe proof-of-concept verification.

**Instructions**:
- Create non-destructive PoCs
- Verify exploitability
- Test privilege escalation
- Assess data exposure

**Example task**:
```
Verify the SQL injection in the login form is exploitable
without causing data modification.
```

### Reporter Agent

**Role**: Professional report generation.

**Instructions**:
- Write executive summaries
- Provide clear remediation steps
- Map to standards (OWASP, CWE)
- Consider multiple audiences

**Example task**:
```
Generate a professional pentest report for C-level executives
and technical teams covering all findings and remediation steps.
```

### AI Tool Selector

**Role**: Strategic planning and tool selection.

**Instructions**:
- Analyze targets and vulnerabilities
- Select optimal tools from 300+ available
- Plan comprehensive attack strategies
- Adapt based on findings

**Example task**:
```
Plan a comprehensive attack strategy for a web application
with the following services: Apache, MySQL, PHP 7.2.
```

---

## Recommended Model Combinations

### **Cost-Optimized (Minimum Spend)**

```yaml
toolSelection: claude-3-5-sonnet-20241022
outputAnalysis: claude-3-5-sonnet-20241022
githubSearch: gpt-4o
customToolCreation: gpt-4o
reportGeneration: claude-3-5-sonnet-20241022
```

**Cost**: ~\$2-5 per pentest

### **Balanced (Recommended)**

```yaml
toolSelection: claude-opus-4-6
outputAnalysis: claude-3-5-sonnet-20241022
githubSearch: gpt-4o
customToolCreation: claude-opus-4-6
reportGeneration: claude-3-5-sonnet-20241022
```

**Cost**: ~\$10-20 per pentest

### **Maximum Quality (Enterprise)**

```yaml
toolSelection: claude-opus-4-6
outputAnalysis: claude-opus-4-6
githubSearch: gpt-4o
customToolCreation: claude-opus-4-6
reportGeneration: claude-opus-4-6
```

**Cost**: ~\$30-50 per pentest

### **Speed-Optimized (Quick Scans)**

```yaml
toolSelection: claude-3-5-sonnet-20241022
outputAnalysis: gpt-4o
githubSearch: gpt-4o
customToolCreation: claude-3-5-sonnet-20241022
reportGeneration: gpt-4o
```

**Cost**: ~\$3-8 per pentest

---

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `RYHA_COPILOT_DEFAULT_MODEL` | `claude-opus-4-6` | Default model for all operations |
| `RYHA_COPILOT_PROXY_URL` | `https://api.githubcopilot.com` | GitHub Copilot API endpoint |
| `RYHA_COPILOT_API_KEY` | (unset) | Direct API key (optional, encrypted) |
| `RYHA_AGENTS_MAX_PARALLEL` | `10` | Maximum concurrent agents |

---

## CLI Commands for Model Management

### Set Default Model

```bash
ryha config set copilot.defaultModel claude-opus-4-6
```

### List Available Models

```bash
ryha auth              # Check current authentication
ryha config list       # Show all configuration
```

### Verify Model Access

```bash
# Check if authenticated (have access to models)
ryha auth status

# Test a specific model
npx ts-node -e "
  import { copilotAuth } from './src/auth/copilot-auth';
  copilotAuth.sendChatMessage('Hello', 'claude-opus-4-6')
    .then(r => console.log('✅ Model accessible'))
    .catch(e => console.error('❌ Error:', e.message));
"
```

---

## How System Instructions Are Used

### 1. **Agent Initialization**

When an agent starts, it receives system instructions:

```typescript
const systemPrompt = AgentSystemInstructions.orchestrator;
const response = await copilotAuth.sendChatMessage(
  userPrompt,           // e.g., "Analyze this nmap output"
  selectedModel,        // e.g., 'claude-opus-4-6'
  systemPrompt          // Agent-specific instructions
);
```

### 2. **Behavioral Control**

System instructions define:
- **Agent role** — What the agent specializes in
- **Approach** — How to analyze and respond
- **Standards** — What quality to maintain
- **Constraints** — What to avoid or be careful about

Example: The Exploit Tester's instruction includes `"Never cause system disruption"` to prevent destructive tests.

### 3. **Consistency Assurance**

Same system instructions → Consistent behavior across multiple calls.

This ensures that multiple vulnerability analyses produce compatible findings.

---

## Current State & Future Improvements

### Currently Implemented ✅

- ✅ 5 AI models available (Opus, Sonnet, GPT-4o, GPT-4, o1)
- ✅ Configurable default model via config/environment
- ✅ System prompts for key operations (tool analysis, strategy planning, tool creation)
- ✅ Model parameter support in `sendChatMessage()`

### Recommended Improvements 🔧

1. **Centralized System Instructions** ← Added in `src/agents/system-instructions.ts`
2. **Per-task model selection** — Route tool selection to Opus, output analysis to Sonnet
3. **Model cost tracking** — Track cost per operation
4. **Model fallback** — Use cheaper models if primary unavailable
5. **Token budgeting** — Limit tokens per pentest
6. **Model switching** — Change models mid-pentest if needed

---

## Configuration Examples

### Example 1: Use Claude Opus for Everything

```bash
ryha config set copilot.defaultModel claude-opus-4-6
ryha server
```

### Example 2: Environment Variable Override

```bash
export RYHA_COPILOT_DEFAULT_MODEL=gpt-4o
ryha pentest -d target.com -t full
```

### Example 3: Custom YAML Config

Create `~/.ryha/config.yaml`:

```yaml
copilot:
  proxyUrl: https://api.githubcopilot.com
  defaultModel: claude-opus-4-6
  models:
    - claude-opus-4-6
    - claude-3-5-sonnet-20241022
    - gpt-4o

agents:
  maxParallel: 10
  retryAttempts: 3

server:
  port: 3000
  host: localhost
```

Then run:

```bash
ryha server
```

---

## Troubleshooting

### "Model Not Available"

Ensure you have access:

```bash
ryha auth status
# Output: Authenticated ✅
```

### Test Model Access

```bash
ryha config get copilot.defaultModel
# Output: claude-opus-4-6 (or your chosen model)
```

### Check Configuration

```bash
ryha config list
# Shows all settings including active model
```

### Switch Models Quickly

```bash
# Test with Sonnet (faster, cheaper)
export RYHA_COPILOT_DEFAULT_MODEL=claude-3-5-sonnet-20241022
ryha pentest -d test.com -t quick

# Switch back to Opus (better reasoning)
export RYHA_COPILOT_DEFAULT_MODEL=claude-opus-4-6
ryha pentest -d test.com -t full
```

---

## Security Notes

- ✅ API keys are AES-256 encrypted if stored
- ✅ Tokens are auto-refreshed before expiry
- ✅ No secrets logged or printed
- ❌ Avoid putting API keys in command history
- ❌ Don't commit `.ryha/tokens.json` to git

---

## Performance Tips

| Goal | Setting |
|------|---------|
| **Fastest scans** | `gpt-4o` for all tasks |
| **Best analysis** | `claude-opus-4-6` for complex tasks |
| **Cost control** | `claude-3-5-sonnet-20241022` as default |
| **Hybrid** | Use Opus for strategy, Sonnet for analysis |

---

## References

- **Full Model Details**: See `src/auth/copilot-auth.ts` for all 5 models
- **System Instructions**: See `src/agents/system-instructions.ts`
- **Config Schema**: See `src/config/config-manager.ts`
- **Usage Examples**: See `docs/README.md` section "AI Models & Authentication"

---

**Last Updated**: March 1, 2026
**Status**: Production Ready ✅
