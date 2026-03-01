/**
 * Core types for Ryha Security Flow
 */
export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ScanType = 'network' | 'web' | 'infrastructure' | 'code' | 'cloud' | 'full';
export type VulnerabilityType = 'cve' | 'cwe' | 'zero-day' | 'misconfig' | 'weak-auth' | 'injection' | 'exposure' | 'custom';
export type AgentState = 'idle' | 'scanning' | 'analyzing' | 'reporting' | 'error' | 'complete';
export type AuthorizationStatus = 'pending' | 'approved' | 'rejected' | 'expired';
export interface AuthorizationDocument {
    id: string;
    clientName: string;
    targetDomain: string;
    inScope: string[];
    outOfScope: string[];
    startDate: Date;
    endDate: Date;
    scope: string;
    testingType: ScanType[];
    authorizedBy: string;
    status: AuthorizationStatus;
    createdAt: Date;
    signature: string;
    notes: string;
}
export interface Vulnerability {
    id: string;
    title: string;
    description: string;
    type: VulnerabilityType;
    severity: SeverityLevel;
    cvss: number;
    cveId?: string;
    cwePrimary?: string;
    affectedAsset: string;
    discoveredAt: Date;
    evidence: string[];
    remediationAdvice: string;
    toolSource: string;
    isZeroDay: boolean;
}
export interface ScanJob {
    id: string;
    authDocId: string;
    targetDomain: string;
    scanType: ScanType;
    status: 'pending' | 'running' | 'completed' | 'failed';
    startedAt: Date;
    completedAt?: Date;
    vulnerabilities: Vulnerability[];
    agentsAssigned: string[];
    progressPercent: number;
    totalVulnerabilitiesFound: number;
    criticalCount: number;
    highCount: number;
}
export interface Agent {
    id: string;
    name: string;
    type: 'scanner' | 'analyzer' | 'executor' | 'reporter' | 'orchestrator';
    state: AgentState;
    currentTask?: string;
    tasksCompleted: number;
    lastActiveAt: Date;
    model: string;
    tools: string[];
}
export interface PentestReport {
    id: string;
    jobId: string;
    clientName: string;
    targetDomain: string;
    executiveSummary: string;
    vulnerabilities: Vulnerability[];
    riskScore: number;
    recommendations: string[];
    tools_used: string[];
    testedAt: Date;
    reportedAt: Date;
}
export interface Config {
    copilotApiKey?: string;
    copilotProxyUrl: string;
    kaliLinuxPath: string;
    maxParallelAgents: number;
    logLevel: 'debug' | 'info' | 'warn' | 'error';
    dataDir: string;
    reportsDir: string;
    toolsDir: string;
    enableAutoScan: boolean;
    autoScanInterval: number;
}
//# sourceMappingURL=types.d.ts.map