import { EventEmitter } from 'events';
import { spawn, ChildProcess, execSync } from 'child_process';
import { randomUUID } from 'crypto';

export type AgentType =
  | 'recon'
  | 'network-scanner'
  | 'web-scanner'
  | 'vuln-analyzer'
  | 'exploit-tester'
  | 'reporter';

export type AgentStatus = 'idle' | 'running' | 'completed' | 'failed' | 'stopped';

export interface Agent {
  id: string;
  name: string;
  type: AgentType;
  status: AgentStatus;
  currentTask: AgentTask | null;
  progress: number;
  findings: AgentFinding[];
  process?: ChildProcess;
  startedAt: Date;
  completedAt: Date | null;
  error?: string;
}

export interface AgentTask {
  name: string;
  target: string;
  phase: string;
  scanType: string;
  prompt: string;
}

export interface AgentFinding {
  timestamp: Date;
  type: 'info' | 'warning' | 'vulnerability';
  data: string;
}

export interface AgentMetrics {
  totalAgents: number;
  activeAgents: number;
  completedAgents: number;
  failedAgents: number;
  totalTasksCompleted: number;
  totalVulnerabilitiesFound: number;
  averageTaskDuration: number;
  uptime: number;
  agentsByType: Record<AgentType, number>;
}

interface ToolConfig {
  command: string;
  args: string[];
  timeout: number;
}

export class AgentPool extends EventEmitter {
  private agents: Map<string, Agent> = new Map();
  private startTime: Date = new Date();
  private taskCompletionTimes: number[] = [];
  private readonly maxAgents = 50;

  constructor() {
    super();
  }

  /**
   * Spawn a new agent to execute a task
   */
  public async spawn(
    agentType: AgentType,
    task: AgentTask,
    target: string
  ): Promise<Agent> {
    // Check agent limit
    if (this.agents.size >= this.maxAgents) {
      throw new Error(`Agent pool limit reached (${this.maxAgents})`);
    }

    // Create agent
    const agent: Agent = {
      id: randomUUID(),
      name: task.name,
      type: agentType,
      status: 'running',
      currentTask: task,
      progress: 0,
      findings: [],
      startedAt: new Date(),
      completedAt: null,
    };

    this.agents.set(agent.id, agent);
    this.emit('agent:spawned', agent.id, agentType);

    // Execute agent task asynchronously
    this.executeAgent(agent, target).catch((error) => {
      this.handleAgentError(agent.id, error);
    });

    return agent;
  }

  /**
   * Execute agent task by running appropriate security tools
   */
  private async executeAgent(agent: Agent, target: string): Promise<void> {
    try {
      const toolConfig = this.getToolConfig(agent.type, target, agent.currentTask!);

      // Spawn process
      const process = spawn(toolConfig.command, toolConfig.args, {
        shell: true,
        stdio: ['pipe', 'pipe', 'pipe'],
      });

      agent.process = process;

      // Handle stdout
      process.stdout?.on('data', (data: Buffer) => {
        const output = data.toString();
        this.handleAgentOutput(agent.id, output);
      });

      // Handle stderr
      process.stderr?.on('data', (data: Buffer) => {
        const error = data.toString();
        this.handleAgentOutput(agent.id, error);
      });

      // Handle process completion
      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          process.kill('SIGTERM');
          reject(new Error(`Agent ${agent.id} timed out after ${toolConfig.timeout}ms`));
        }, toolConfig.timeout);

        process.on('close', (code) => {
          clearTimeout(timeout);
          if (code === 0) {
            resolve();
          } else {
            reject(new Error(`Process exited with code ${code}`));
          }
        });

        process.on('error', (error) => {
          clearTimeout(timeout);
          reject(error);
        });
      });

      // Mark agent as completed
      agent.status = 'completed';
      agent.completedAt = new Date();
      agent.progress = 100;

      const duration = agent.completedAt.getTime() - agent.startedAt.getTime();
      this.taskCompletionTimes.push(duration);

      this.emit('agent:completed', agent.id);
    } catch (error) {
      this.handleAgentError(agent.id, error as Error);
      throw error;
    }
  }

  /**
   * Get tool configuration based on agent type
   */
  private getToolConfig(
    agentType: AgentType,
    target: string,
    task: AgentTask
  ): ToolConfig {
    const sanitizedTarget = this.sanitizeTarget(target);

    switch (agentType) {
      case 'recon':
        if (task.name.includes('DNS')) {
          return {
            command: 'nslookup',
            args: [sanitizedTarget],
            timeout: 30000,
          };
        } else if (task.name.includes('WHOIS')) {
          return {
            command: 'whois',
            args: [sanitizedTarget],
            timeout: 30000,
          };
        } else {
          // Service discovery with nmap
          return {
            command: 'nmap',
            args: ['-sV', '-p', '80,443,22,21,25,3306,5432', sanitizedTarget],
            timeout: 120000,
          };
        }

      case 'network-scanner':
        return {
          command: 'nmap',
          args: ['-sS', '-sV', '-O', '-p-', '--max-retries', '2', sanitizedTarget],
          timeout: 300000,
        };

      case 'web-scanner':
        return {
          command: 'nikto',
          args: ['-h', sanitizedTarget, '-Format', 'json', '-o', '/tmp/nikto-output.json'],
          timeout: 600000,
        };

      case 'vuln-analyzer':
        return {
          command: 'nmap',
          args: ['--script', 'vuln', '-p', '1-10000', sanitizedTarget],
          timeout: 600000,
        };

      case 'exploit-tester':
        // Use Metasploit framework (safe mode)
        return {
          command: 'msfconsole',
          args: [
            '-q',
            '-x',
            `use auxiliary/scanner/http/http_version; set RHOSTS ${sanitizedTarget}; run; exit`,
          ],
          timeout: 300000,
        };

      case 'reporter':
        return {
          command: 'echo',
          args: [`Generating report for ${sanitizedTarget}`],
          timeout: 10000,
        };

      default:
        throw new Error(`Unknown agent type: ${agentType}`);
    }
  }

  /**
   * Sanitize target to prevent command injection
   */
  private sanitizeTarget(target: string): string {
    // Remove dangerous characters
    const sanitized = target.replace(/[;&|`$(){}[\]<>]/g, '');

    // Validate format (IP or domain)
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    const domainPattern = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

    if (!ipPattern.test(sanitized) && !domainPattern.test(sanitized)) {
      throw new Error(`Invalid target format: ${target}`);
    }

    return sanitized;
  }

  /**
   * Handle agent output
   */
  private handleAgentOutput(agentId: string, output: string): void {
    const agent = this.agents.get(agentId);
    if (!agent) return;

    // Parse output for findings
    const finding: AgentFinding = {
      timestamp: new Date(),
      type: this.classifyOutput(output),
      data: output.trim(),
    };

    agent.findings.push(finding);

    // Update progress based on output patterns
    if (output.includes('completed') || output.includes('finished')) {
      agent.progress = 100;
    } else if (output.includes('processing') || output.includes('scanning')) {
      agent.progress = Math.min(agent.progress + 10, 90);
    }

    this.emit('agent:output', agentId, output);
  }

  /**
   * Classify output type
   */
  private classifyOutput(output: string): 'info' | 'warning' | 'vulnerability' {
    const lowerOutput = output.toLowerCase();

    if (
      lowerOutput.includes('vulnerability') ||
      lowerOutput.includes('exploit') ||
      lowerOutput.includes('cve-')
    ) {
      return 'vulnerability';
    } else if (
      lowerOutput.includes('warning') ||
      lowerOutput.includes('deprecated') ||
      lowerOutput.includes('weak')
    ) {
      return 'warning';
    }

    return 'info';
  }

  /**
   * Handle agent error
   */
  private handleAgentError(agentId: string, error: Error): void {
    const agent = this.agents.get(agentId);
    if (!agent) return;

    agent.status = 'failed';
    agent.error = error.message;
    agent.completedAt = new Date();

    if (agent.process) {
      agent.process.kill('SIGTERM');
    }

    this.emit('agent:error', agentId, error);
  }

  /**
   * Get all active agents
   */
  public getActive(): Agent[] {
    return Array.from(this.agents.values()).filter(
      (agent) => agent.status === 'running'
    );
  }

  /**
   * Get agent by ID
   */
  public getAgent(agentId: string): Agent | null {
    return this.agents.get(agentId) || null;
  }

  /**
   * Kill a specific agent
   */
  public async kill(agentId: string): Promise<boolean> {
    const agent = this.agents.get(agentId);
    if (!agent) return false;

    if (agent.process) {
      agent.process.kill('SIGTERM');

      // Force kill after 5 seconds if still running
      setTimeout(() => {
        if (agent.process && !agent.process.killed) {
          agent.process.kill('SIGKILL');
        }
      }, 5000);
    }

    agent.status = 'stopped';
    agent.completedAt = new Date();

    this.emit('agent:killed', agentId);
    return true;
  }

  /**
   * Kill all agents
   */
  public async killAll(): Promise<number> {
    const activeAgents = this.getActive();
    let killed = 0;

    for (const agent of activeAgents) {
      const success = await this.kill(agent.id);
      if (success) killed++;
    }

    this.emit('pool:cleared', killed);
    return killed;
  }

  /**
   * Get pool metrics
   */
  public getMetrics(): AgentMetrics {
    const agents = Array.from(this.agents.values());

    const agentsByType: Record<AgentType, number> = {
      recon: 0,
      'network-scanner': 0,
      'web-scanner': 0,
      'vuln-analyzer': 0,
      'exploit-tester': 0,
      reporter: 0,
    };

    let totalVulns = 0;

    for (const agent of agents) {
      agentsByType[agent.type]++;
      totalVulns += agent.findings.filter((f) => f.type === 'vulnerability').length;
    }

    const completedAgents = agents.filter((a) => a.status === 'completed');
    const averageTaskDuration =
      this.taskCompletionTimes.length > 0
        ? this.taskCompletionTimes.reduce((a, b) => a + b, 0) / this.taskCompletionTimes.length
        : 0;

    return {
      totalAgents: this.agents.size,
      activeAgents: this.getActive().length,
      completedAgents: completedAgents.length,
      failedAgents: agents.filter((a) => a.status === 'failed').length,
      totalTasksCompleted: completedAgents.length,
      totalVulnerabilitiesFound: totalVulns,
      averageTaskDuration: Math.round(averageTaskDuration),
      uptime: Date.now() - this.startTime.getTime(),
      agentsByType,
    };
  }

  /**
   * Get agent pool size
   */
  public getSize(): number {
    return this.agents.size;
  }

  /**
   * Clean up completed agents
   */
  public cleanup(): number {
    let cleaned = 0;

    for (const [agentId, agent] of this.agents) {
      if (agent.status === 'completed' || agent.status === 'failed') {
        this.agents.delete(agentId);
        cleaned++;
      }
    }

    return cleaned;
  }

  /**
   * Check if specific tool is available
   */
  public checkToolAvailability(tool: string): boolean {
    try {
      execSync(`which ${tool}`, { stdio: 'ignore' });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Get all required tools for agent types
   */
  public getRequiredTools(): Record<AgentType, string[]> {
    return {
      recon: ['nslookup', 'whois', 'nmap'],
      'network-scanner': ['nmap'],
      'web-scanner': ['nikto'],
      'vuln-analyzer': ['nmap'],
      'exploit-tester': ['msfconsole'],
      reporter: ['echo'],
    };
  }

  /**
   * Validate all required tools are installed
   */
  public validateTools(): { valid: boolean; missing: string[] } {
    const missing: string[] = [];
    const requiredTools = this.getRequiredTools();

    const uniqueTools = new Set<string>();
    Object.values(requiredTools).forEach((tools) => {
      tools.forEach((tool) => uniqueTools.add(tool));
    });

    for (const tool of uniqueTools) {
      if (!this.checkToolAvailability(tool)) {
        missing.push(tool);
      }
    }

    return {
      valid: missing.length === 0,
      missing,
    };
  }
}
