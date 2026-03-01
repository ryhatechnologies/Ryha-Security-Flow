interface SetupWizardOptions {
    interactive?: boolean;
    validateTools?: boolean;
    skipApiKeyPrompt?: boolean;
}
declare class SetupWizard {
    private configManager;
    private interactive;
    private validateTools;
    constructor(options?: SetupWizardOptions);
    /**
     * Run the complete setup wizard
     */
    runSetup(): Promise<boolean>;
    /**
     * Welcome prompt and existing config check
     */
    private promptWelcome;
    /**
     * Setup Copilot/Claude configuration
     */
    private setupCopilot;
    /**
     * Setup agent configuration
     */
    private setupAgents;
    /**
     * Setup penetration testing tools
     */
    private setupTools;
    /**
     * Setup Kali Linux integration
     */
    private setupKali;
    /**
     * Setup logging configuration
     */
    private setupLogging;
    /**
     * Setup server configuration
     */
    private setupServer;
    /**
     * Validate and save configuration
     */
    private validateAndSave;
    /**
     * Get the configuration file path
     */
    private getConfigPath;
}
/**
 * Run setup wizard from CLI
 */
export declare function runSetupWizard(): Promise<boolean>;
export { SetupWizard };
//# sourceMappingURL=setup-wizard.d.ts.map