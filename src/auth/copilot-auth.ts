import axios, { AxiosError } from 'axios';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as os from 'os';

// GitHub OAuth Device Flow endpoints
const GITHUB_DEVICE_CODE_URL = 'https://github.com/login/device/code';
const GITHUB_TOKEN_URL = 'https://github.com/login/oauth/access_token';
const GITHUB_CLIENT_ID = 'Iv1.b507a08c87ecfe98'; // GitHub Copilot public client ID

// Copilot API endpoints
const COPILOT_TOKEN_URL = 'https://api.github.com/copilot_internal/v2/token';
const COPILOT_CHAT_URL = 'https://api.githubcopilot.com/chat/completions';

interface DeviceCodeResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  expires_in: number;
  interval: number;
}

interface TokenResponse {
  access_token: string;
  token_type: string;
  scope: string;
  expires_in?: number;
}

interface CopilotToken {
  token: string;
  expires_at: number;
}

interface StoredTokens {
  github_access_token: string;
  copilot_token: string;
  copilot_token_expires_at: number;
  created_at: number;
}

export interface CopilotModel {
  id: string;
  name: string;
  provider: string;
}

export const AVAILABLE_MODELS: CopilotModel[] = [
  { id: 'claude-opus-4-6', name: 'Claude Opus 4.6', provider: 'anthropic' },
  { id: 'claude-3-5-sonnet-20241022', name: 'Claude 3.5 Sonnet', provider: 'anthropic' },
  { id: 'gpt-4o', name: 'GPT-4o', provider: 'openai' },
  { id: 'gpt-4', name: 'GPT-4', provider: 'openai' },
  { id: 'o1-preview', name: 'o1 Preview', provider: 'openai' },
];

export class CopilotAuth {
  private tokensPath: string;
  private encryptionKey: Buffer;

  constructor() {
    const homeDir = os.homedir();
    const ryhaDir = path.join(homeDir, '.ryha');

    // Create .ryha directory if it doesn't exist
    if (!fs.existsSync(ryhaDir)) {
      fs.mkdirSync(ryhaDir, { recursive: true });
    }

    this.tokensPath = path.join(ryhaDir, 'tokens.json');

    // Generate or load encryption key
    const keyPath = path.join(ryhaDir, '.key');
    if (fs.existsSync(keyPath)) {
      this.encryptionKey = fs.readFileSync(keyPath);
    } else {
      this.encryptionKey = crypto.randomBytes(32);
      fs.writeFileSync(keyPath, this.encryptionKey, { mode: 0o600 });
    }
  }

  /**
   * Start GitHub device flow authentication
   */
  async startDeviceFlow(): Promise<DeviceCodeResponse> {
    try {
      const response = await axios.post(
        GITHUB_DEVICE_CODE_URL,
        {
          client_id: GITHUB_CLIENT_ID,
          scope: 'read:user',
        },
        {
          headers: {
            Accept: 'application/json',
          },
        }
      );

      return response.data;
    } catch (error) {
      const axiosError = error as AxiosError;
      throw new Error(`Failed to start device flow: ${axiosError.message}`);
    }
  }

  /**
   * Poll for access token after user authorizes
   */
  async pollForToken(deviceCode: string, interval: number = 5): Promise<string> {
    const maxAttempts = 120; // 10 minutes max
    let attempts = 0;

    while (attempts < maxAttempts) {
      await this.sleep(interval * 1000);
      attempts++;

      try {
        const response = await axios.post(
          GITHUB_TOKEN_URL,
          {
            client_id: GITHUB_CLIENT_ID,
            device_code: deviceCode,
            grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          },
          {
            headers: {
              Accept: 'application/json',
            },
          }
        );

        const data: TokenResponse = response.data;

        if (data.access_token) {
          return data.access_token;
        }
      } catch (error) {
        const axiosError = error as AxiosError;
        const data = axiosError.response?.data as any;

        if (data?.error === 'authorization_pending') {
          // Continue polling
          continue;
        } else if (data?.error === 'slow_down') {
          // Increase interval
          interval += 5;
          continue;
        } else if (data?.error === 'expired_token') {
          throw new Error('Device code expired. Please start authentication again.');
        } else if (data?.error === 'access_denied') {
          throw new Error('Access denied by user.');
        } else {
          throw new Error(`Token polling failed: ${axiosError.message}`);
        }
      }
    }

    throw new Error('Authentication timeout. Please try again.');
  }

  /**
   * Get Copilot session token from GitHub access token
   */
  async getCopilotToken(githubAccessToken: string): Promise<CopilotToken> {
    try {
      const response = await axios.get(COPILOT_TOKEN_URL, {
        headers: {
          Authorization: `token ${githubAccessToken}`,
          Accept: 'application/json',
        },
      });

      return response.data;
    } catch (error) {
      const axiosError = error as AxiosError;

      if (axiosError.response?.status === 401) {
        throw new Error('GitHub access token is invalid or expired.');
      } else if (axiosError.response?.status === 403) {
        throw new Error('GitHub Copilot access is not available for this account.');
      }

      throw new Error(`Failed to get Copilot token: ${axiosError.message}`);
    }
  }

  /**
   * Encrypt data before storing
   */
  private encrypt(text: string): string {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', this.encryptionKey, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
  }

  /**
   * Decrypt stored data
   */
  private decrypt(text: string): string {
    const parts = text.split(':');
    const iv = Buffer.from(parts.shift()!, 'hex');
    const encryptedText = parts.join(':');
    const decipher = crypto.createDecipheriv('aes-256-cbc', this.encryptionKey, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }

  /**
   * Store tokens securely
   */
  private storeTokens(tokens: StoredTokens): void {
    const encrypted = this.encrypt(JSON.stringify(tokens));
    fs.writeFileSync(this.tokensPath, encrypted, { mode: 0o600 });
  }

  /**
   * Load stored tokens
   */
  private loadTokens(): StoredTokens | null {
    if (!fs.existsSync(this.tokensPath)) {
      return null;
    }

    try {
      const encrypted = fs.readFileSync(this.tokensPath, 'utf8');
      const decrypted = this.decrypt(encrypted);
      return JSON.parse(decrypted);
    } catch (error) {
      console.error('Failed to load tokens:', error);
      return null;
    }
  }

  /**
   * Complete authentication flow
   */
  async authenticate(): Promise<void> {
    console.log('Starting GitHub authentication...\n');

    // Step 1: Start device flow
    const deviceFlow = await this.startDeviceFlow();

    console.log('Please visit:', deviceFlow.verification_uri);
    console.log('And enter code:', deviceFlow.user_code);
    console.log('\nWaiting for authorization...\n');

    // Step 2: Poll for access token
    const githubAccessToken = await this.pollForToken(
      deviceFlow.device_code,
      deviceFlow.interval
    );

    console.log('GitHub authentication successful!');

    // Step 3: Get Copilot token
    console.log('Getting Copilot access...');
    const copilotToken = await this.getCopilotToken(githubAccessToken);

    console.log('Copilot access granted!');

    // Step 4: Store tokens
    const tokens: StoredTokens = {
      github_access_token: githubAccessToken,
      copilot_token: copilotToken.token,
      copilot_token_expires_at: copilotToken.expires_at,
      created_at: Date.now(),
    };

    this.storeTokens(tokens);
    console.log('\nTokens stored securely in:', this.tokensPath);
  }

  /**
   * Check if tokens are valid
   */
  async isAuthenticated(): Promise<boolean> {
    const tokens = this.loadTokens();

    if (!tokens) {
      return false;
    }

    // Check if Copilot token is expired
    if (Date.now() >= tokens.copilot_token_expires_at * 1000) {
      return false;
    }

    return true;
  }

  /**
   * Get valid Copilot token (refresh if needed)
   */
  async getValidToken(): Promise<string> {
    const tokens = this.loadTokens();

    if (!tokens) {
      throw new Error('Not authenticated. Please run authentication first.');
    }

    // Check if token needs refresh (refresh 5 minutes before expiry)
    const expiresAt = tokens.copilot_token_expires_at * 1000;
    const now = Date.now();
    const fiveMinutes = 5 * 60 * 1000;

    if (now >= expiresAt - fiveMinutes) {
      console.log('Refreshing Copilot token...');

      try {
        const copilotToken = await this.getCopilotToken(tokens.github_access_token);

        tokens.copilot_token = copilotToken.token;
        tokens.copilot_token_expires_at = copilotToken.expires_at;

        this.storeTokens(tokens);
        console.log('Token refreshed successfully');
      } catch (error) {
        throw new Error('Token refresh failed. Please re-authenticate.');
      }
    }

    return tokens.copilot_token;
  }

  /**
   * Send chat message to Claude via Copilot
   */
  async sendChatMessage(
    prompt: string,
    model: string = 'claude-3-5-sonnet-20241022',
    systemPrompt?: string
  ): Promise<string> {
    const token = await this.getValidToken();

    const messages = [
      {
        role: 'user',
        content: prompt,
      },
    ];

    const requestBody: any = {
      messages,
      model,
      temperature: 0.7,
      max_tokens: 4096,
      stream: false,
    };

    if (systemPrompt) {
      requestBody.messages.unshift({
        role: 'system',
        content: systemPrompt,
      });
    }

    try {
      const response = await axios.post(COPILOT_CHAT_URL, requestBody, {
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
          'Copilot-Integration-Id': 'vscode-chat',
          'Editor-Version': 'vscode/1.85.0',
        },
      });

      return response.data.choices[0].message.content;
    } catch (error) {
      const axiosError = error as AxiosError;

      if (axiosError.response?.status === 401) {
        throw new Error('Authentication failed. Please re-authenticate.');
      }

      throw new Error(`Chat request failed: ${axiosError.message}`);
    }
  }

  /**
   * List available models
   */
  getAvailableModels(): CopilotModel[] {
    return AVAILABLE_MODELS;
  }

  /**
   * Clear stored tokens
   */
  clearTokens(): void {
    if (fs.existsSync(this.tokensPath)) {
      fs.unlinkSync(this.tokensPath);
      console.log('Tokens cleared successfully');
    }
  }

  /**
   * Helper to sleep
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Export singleton instance
export const copilotAuth = new CopilotAuth();
