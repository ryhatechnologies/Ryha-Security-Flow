/**
 * Executors module - Execute security tools with elevated permissions
 * @module executors
 */

export {
  ExecutorAgent,
  ExecutionResult,
  ToolOptions,
  AuthorizationDocument,
  MetasploitOptions,
  BurpScanType
} from './executor-agent';

export {
  ToolManager,
  ToolCategory,
  ToolInfo,
  CustomTool,
  CommandOptions
} from '../tools/tool-manager';
