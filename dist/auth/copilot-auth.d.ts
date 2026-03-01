interface DeviceCodeResponse {
    device_code: string;
    user_code: string;
    verification_uri: string;
    expires_in: number;
    interval: number;
}
interface CopilotToken {
    token: string;
    expires_at: number;
}
export interface CopilotModel {
    id: string;
    name: string;
    provider: string;
}
export declare const AVAILABLE_MODELS: CopilotModel[];
export declare class CopilotAuth {
    private tokensPath;
    private encryptionKey;
    constructor();
    /**
     * Start GitHub device flow authentication
     */
    startDeviceFlow(): Promise<DeviceCodeResponse>;
    /**
     * Poll for access token after user authorizes
     */
    pollForToken(deviceCode: string, interval?: number): Promise<string>;
    /**
     * Get Copilot session token from GitHub access token
     */
    getCopilotToken(githubAccessToken: string): Promise<CopilotToken>;
    /**
     * Encrypt data before storing
     */
    private encrypt;
    /**
     * Decrypt stored data
     */
    private decrypt;
    /**
     * Store tokens securely
     */
    private storeTokens;
    /**
     * Load stored tokens
     */
    private loadTokens;
    /**
     * Complete authentication flow
     */
    authenticate(): Promise<void>;
    /**
     * Check if tokens are valid
     */
    isAuthenticated(): Promise<boolean>;
    /**
     * Get valid Copilot token (refresh if needed)
     */
    getValidToken(): Promise<string>;
    /**
     * Send chat message to Claude via Copilot
     */
    sendChatMessage(prompt: string, model?: string, systemPrompt?: string): Promise<string>;
    /**
     * List available models
     */
    getAvailableModels(): CopilotModel[];
    /**
     * Clear stored tokens
     */
    clearTokens(): void;
    /**
     * Helper to sleep
     */
    private sleep;
}
export declare const copilotAuth: CopilotAuth;
export {};
//# sourceMappingURL=copilot-auth.d.ts.map