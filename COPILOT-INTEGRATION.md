# Ryha Security Flow - GitHub Copilot Integration

This integration enables Ryha Security Flow to use Claude and GPT models through GitHub Copilot, without requiring direct API keys from Anthropic or OpenAI.

## Features

- **GitHub Device Flow Authentication**: Login with your GitHub account (no API keys needed)
- **Multi-Model Support**: Access to Claude Opus 4.6, Claude 3.5 Sonnet, GPT-4o, and more
- **Real-Time Dashboard**: React-based UI with live agent status and vulnerability feed
- **RESTful API**: Complete API for chat, agents, jobs, and reports
- **Socket.IO Integration**: Real-time updates for agents, vulnerabilities, and job progress
- **Secure Token Storage**: Encrypted token storage in `~/.ryha/tokens.json`

## Setup

### 1. Install Dependencies

```bash
cd c:/Users/vellu/Downloads/ryha-security-flow
npm install
```

### 2. Authenticate with GitHub

Before using the API or UI, you need to authenticate with GitHub:

```bash
npm run build
node dist/auth-cli.js
```

This will:
1. Generate a device code
2. Display a URL and code for you to enter at github.com/login/device
3. Wait for you to authorize the application
4. Store encrypted tokens in `~/.ryha/tokens.json`

### 3. Start the Server

```bash
npm run build
node dist/api/server.js
```

The server will start on http://localhost:3000

## Usage

### CLI Authentication

Create a simple CLI script to handle authentication:

```bash
# Create auth CLI
cat > src/auth-cli.ts << 'EOF'
import { copilotAuth } from './auth/copilot-auth';

async function main() {
  try {
    const isAuth = await copilotAuth.isAuthenticated();

    if (isAuth) {
      console.log('✓ Already authenticated');
      console.log('\nAvailable models:');
      copilotAuth.getAvailableModels().forEach(model => {
        console.log(`  - ${model.name} (${model.id})`);
      });
    } else {
      console.log('Starting authentication...\n');
      await copilotAuth.authenticate();
    }
  } catch (error) {
    console.error('Authentication failed:', error.message);
    process.exit(1);
  }
}

main();
EOF
```

### API Endpoints

#### Chat with AI
```bash
POST /api/chat
Content-Type: application/json

{
  "prompt": "Explain SQL injection vulnerabilities",
  "model": "claude-3-5-sonnet-20241022",
  "systemPrompt": "You are a security expert"
}
```

#### Start Pentest
```bash
POST /api/pentest
Content-Type: application/json

{
  "target": "https://example.com",
  "authDoc": "Authorization document content..."
}
```

#### Get Agents
```bash
GET /api/agents?jobId=abc123
```

#### Get Job Status
```bash
GET /api/jobs/abc123
```

#### Download Report
```bash
GET /api/report/abc123
```

#### List Available Models
```bash
GET /api/models
```

### Web UI

Open http://localhost:3000 in your browser to access the dashboard:

- **Chat Window**: Ask questions or give commands to Claude/GPT
- **Agent Status**: Real-time view of all active agents and their progress
- **Vulnerability Feed**: Live feed of discovered vulnerabilities
- **Job Progress**: Current pentest job progress and statistics
- **New Pentest**: Start a new penetration test with target validation

### Socket.IO Events

The server emits the following real-time events:

- `agent:update` - Agent status changed
- `vulnerability:new` - New vulnerability discovered
- `job:update` - Job status changed
- `job:progress` - Job progress updated
- `jobs:update` - All jobs list updated

## Architecture

### File Structure

```
src/
├── auth/
│   └── copilot-auth.ts       # GitHub OAuth + Copilot token management
├── api/
│   └── server.ts             # Express API + Socket.IO server
└── ui/
    └── index.html            # React dashboard (CDN-based)
```

### Authentication Flow

1. **Device Flow**: Request device code from GitHub
2. **User Authorization**: User visits URL and enters code
3. **Token Poll**: Poll GitHub for access token
4. **Copilot Token**: Exchange GitHub token for Copilot session token
5. **Secure Storage**: Encrypt and store tokens in ~/.ryha/tokens.json
6. **Auto Refresh**: Automatically refresh tokens before expiration

### Security Features

- **Encrypted Token Storage**: AES-256-CBC encryption with random key
- **Authorization Document Validation**: AI-powered validation of pentest authorization
- **Token Auto-Refresh**: Tokens refreshed 5 minutes before expiration
- **Secure File Permissions**: Token files created with 0600 permissions

## Available Models

| Model ID | Name | Provider |
|----------|------|----------|
| `claude-opus-4-6` | Claude Opus 4.6 | Anthropic |
| `claude-3-5-sonnet-20241022` | Claude 3.5 Sonnet | Anthropic |
| `gpt-4o` | GPT-4o | OpenAI |
| `gpt-4` | GPT-4 | OpenAI |
| `o1-preview` | o1 Preview | OpenAI |

## Environment Variables

No environment variables required! Authentication is handled through GitHub device flow.

Optional configuration:
- `RYHA_PORT` - Server port (default: 3000)
- `RYHA_TOKENS_PATH` - Custom tokens storage path

## Troubleshooting

### "Not authenticated" Error

Run the authentication CLI:
```bash
node dist/auth-cli.js
```

### "GitHub Copilot access is not available"

Ensure your GitHub account has Copilot access. GitHub Copilot requires:
- GitHub Pro, Team, or Enterprise subscription
- Or GitHub Copilot Individual subscription

### Token Expired

Tokens are automatically refreshed, but you can manually re-authenticate:
```bash
node dist/auth-cli.js
```

### Port Already in Use

Change the port:
```javascript
// In src/api/server.ts
const server = new RyhaServer(3001); // Change port here
```

## Example Usage

### 1. Authentication
```bash
npm run build
node dist/auth-cli.js
```

### 2. Start Server
```bash
node dist/api/server.js
```

### 3. Open UI
Navigate to http://localhost:3000

### 4. Chat with AI
Type in the chat: "How do I test for CSRF vulnerabilities?"

### 5. Start Pentest
Click "New Pentest" button, enter target URL, and start

### 6. Monitor Progress
Watch real-time agent updates and vulnerability discoveries

## Development

### Build
```bash
npm run build
```

### Development Mode
```bash
npm run dev
```

### Run Tests
```bash
npm test
```

## Notes

- GitHub Copilot authentication is required
- Tokens are stored encrypted in `~/.ryha/tokens.json`
- Token refresh happens automatically
- All AI requests go through GitHub Copilot API (no direct API keys needed)
- Dark mode is enabled by default in the UI

## License

MIT
