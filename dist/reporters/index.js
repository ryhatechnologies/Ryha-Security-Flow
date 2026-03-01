"use strict";
/**
 * Reporter Agent Module - Exports
 * Ryha Security Flow - Enterprise Penetration Testing Platform
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateHTMLReport = exports.createReporterAgent = exports.ReporterAgent = void 0;
var reporter_agent_1 = require("./reporter-agent");
Object.defineProperty(exports, "ReporterAgent", { enumerable: true, get: function () { return reporter_agent_1.ReporterAgent; } });
Object.defineProperty(exports, "createReporterAgent", { enumerable: true, get: function () { return reporter_agent_1.createReporterAgent; } });
var html_template_1 = require("./templates/html-template");
Object.defineProperty(exports, "generateHTMLReport", { enumerable: true, get: function () { return html_template_1.generateHTMLReport; } });
//# sourceMappingURL=index.js.map