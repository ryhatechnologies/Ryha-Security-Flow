/**
 * AI Tool Selector - Autonomous tool selection and strategy planning
 * Ryha Security Flow - Enterprise Penetration Testing Platform
 *
 * Uses GitHub Copilot AI to analyze targets and autonomously decide
 * which tools to run, with what arguments, in what order.
 */
import { ToolManager } from './tool-manager';
import { EventEmitter } from 'events';
/**
 * Tool recommendation from AI
 */
export interface ToolRecommendation {
    toolName: string;
    command: string;
    args: string[];
    priority: number;
    reason: string;
    expectedOutput: string;
    timeout: number;
    requiresRoot: boolean;
    category: string;
}
/**
 * Attack strategy planned by AI
 */
export interface AttackStrategy {
    phases: StrategyPhase[];
    estimatedDuration: string;
    targetAnalysis: string;
    approachRationale: string;
    fallbackStrategies: string[];
}
/**
 * Phase in the attack strategy
 */
export interface StrategyPhase {
    name: string;
    description: string;
    tools: ToolRecommendation[];
    dependsOn: string[];
    successCriteria: string;
    nextPhaseCondition: string;
}
/**
 * Custom tool created by AI
 */
export interface AIGeneratedTool {
    name: string;
    description: string;
    script: string;
    language: 'bash' | 'python' | 'ruby' | 'perl' | 'go';
    purpose: string;
    usage: string;
}
/**
 * Tool template for common security patterns
 */
export type ToolTemplate = 'port-scanner' | 'web-fuzzer' | 'credential-tester' | 'api-enumerator' | 'subdomain-finder' | 'vulnerability-checker' | 'network-sniffer' | 'log-analyzer' | 'hash-cracker' | 'custom';
/**
 * AIToolSelector - The autonomous brain for tool selection
 */
export declare class AIToolSelector extends EventEmitter {
    private toolManager;
    private discoveredTools;
    private systemTools;
    private githubInstaller;
    constructor(toolManager?: ToolManager);
    /**
     * Discover ALL security tools on the system (not just hardcoded)
     */
    discoverSystemTools(): Promise<Map<string, string>>;
    /**
     * Get all installed security tools as a formatted list
     */
    getInstalledToolsList(): string[];
    /**
     * Ask AI to plan a complete attack strategy for a target
     */
    planAttackStrategy(target: string, scanType: string, scope: string[], previousFindings?: any[]): Promise<AttackStrategy>;
    /**
     * Ask AI to select the best tools for a specific task
     */
    selectToolsForTask(task: string, target: string, context?: any): Promise<ToolRecommendation[]>;
    /**
     * Ask AI to generate arguments for a specific tool
     */
    generateToolArguments(toolName: string, target: string, objective: string): Promise<string[]>;
    /**
     * Ask AI to create a custom security tool when no existing tool fits
     * Supports bash, python, ruby, perl, and go
     */
    createCustomTool(purpose: string, target: string, language?: 'bash' | 'python' | 'ruby' | 'perl' | 'go', template?: ToolTemplate): Promise<AIGeneratedTool>;
    /**
     * Create a tool from a predefined template without AI (fast, offline)
     */
    createToolFromTemplate(name: string, template: ToolTemplate, target: string, language?: 'bash' | 'python'): Promise<AIGeneratedTool>;
    /**
     * Ensure a tool is available - auto-install if missing
     * Tries: apt-get → GitHub known tools → pip/go install → AI creation
     */
    ensureToolAvailable(toolName: string): Promise<{
        available: boolean;
        method?: string;
    }>;
    /**
     * Ask AI to analyze tool output and decide next steps
     */
    analyzeAndDecideNextSteps(toolName: string, output: string, target: string, currentPhase: string, completedTools: string[]): Promise<ToolRecommendation[]>;
    /**
     * Parse AI output to extract tool output as vulnerabilities
     */
    parseToolOutput(toolName: string, rawOutput: string, target: string): Promise<any[]>;
    /**
     * Build a default strategy when AI is unavailable
     */
    private buildDefaultStrategy;
    private parseJSONResponse;
}
//# sourceMappingURL=ai-tool-selector.d.ts.map