"use strict";
/**
 * Executors module - Execute security tools with elevated permissions
 * @module executors
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.ToolCategory = exports.ToolManager = exports.BurpScanType = exports.ExecutorAgent = void 0;
var executor_agent_1 = require("./executor-agent");
Object.defineProperty(exports, "ExecutorAgent", { enumerable: true, get: function () { return executor_agent_1.ExecutorAgent; } });
Object.defineProperty(exports, "BurpScanType", { enumerable: true, get: function () { return executor_agent_1.BurpScanType; } });
var tool_manager_1 = require("../tools/tool-manager");
Object.defineProperty(exports, "ToolManager", { enumerable: true, get: function () { return tool_manager_1.ToolManager; } });
Object.defineProperty(exports, "ToolCategory", { enumerable: true, get: function () { return tool_manager_1.ToolCategory; } });
//# sourceMappingURL=index.js.map