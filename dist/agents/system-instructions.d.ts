/**
 * Centralized System Instructions for All AI Agents
 * Ryha Security Flow - Enterprise Penetration Testing Platform
 *
 * This file defines the system prompts/instructions for each agent type
 * to ensure consistent behavior, role clarity, and specific expertise.
 */
export declare const AgentSystemInstructions: {
    orchestrator: string;
    reconAgent: string;
    scannerAgent: string;
    analyzerAgent: string;
    exploitTester: string;
    reporterAgent: string;
    aiToolSelector: string;
    githubInstaller: string;
    customToolCreator: string;
    codeGeneration: string;
};
export declare const ModelRecommendations: {
    toolSelection: string;
    vulnerabilityAnalysis: string;
    attackStrategyPlanning: string;
    toolOutputAnalysis: string;
    reportGeneration: string;
    customToolCreation: string;
    githubSearch: string;
    simpleAnalysis: string;
};
export declare const AgentPromptTemplates: {
    vulnerabilityExtraction: (toolName: string, scanType: string, target: string, phase: string) => string;
    toolSelection: (installedTools: string[], target: string, objective: string) => string;
    strategyPlanning: (target: string, scanType: string, scope: string[]) => string;
    customToolCreation: (language: string, purpose: string, target: string) => string;
};
declare const _default: {
    AgentSystemInstructions: {
        orchestrator: string;
        reconAgent: string;
        scannerAgent: string;
        analyzerAgent: string;
        exploitTester: string;
        reporterAgent: string;
        aiToolSelector: string;
        githubInstaller: string;
        customToolCreator: string;
        codeGeneration: string;
    };
    ModelRecommendations: {
        toolSelection: string;
        vulnerabilityAnalysis: string;
        attackStrategyPlanning: string;
        toolOutputAnalysis: string;
        reportGeneration: string;
        customToolCreation: string;
        githubSearch: string;
        simpleAnalysis: string;
    };
    AgentPromptTemplates: {
        vulnerabilityExtraction: (toolName: string, scanType: string, target: string, phase: string) => string;
        toolSelection: (installedTools: string[], target: string, objective: string) => string;
        strategyPlanning: (target: string, scanType: string, scope: string[]) => string;
        customToolCreation: (language: string, purpose: string, target: string) => string;
    };
};
export default _default;
//# sourceMappingURL=system-instructions.d.ts.map