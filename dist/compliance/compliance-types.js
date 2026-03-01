"use strict";
/**
 * Compliance and Audit Type Definitions
 * Ryha Security Flow - SOC 2 / ISO 27001 Aligned
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.RetentionPolicy = exports.LogCategory = exports.ComplianceFramework = exports.Severity = exports.EventType = void 0;
var EventType;
(function (EventType) {
    EventType["SCAN_START"] = "scan_start";
    EventType["SCAN_COMPLETE"] = "scan_complete";
    EventType["SCAN_FAILED"] = "scan_failed";
    EventType["VULNERABILITY_FOUND"] = "vulnerability_found";
    EventType["TOOL_EXECUTION"] = "tool_execution";
    EventType["AGENT_SPAWNED"] = "agent_spawned";
    EventType["AGENT_COMPLETED"] = "agent_completed";
    EventType["EVIDENCE_COLLECTED"] = "evidence_collected";
    EventType["AUTHORIZATION_VERIFIED"] = "authorization_verified";
    EventType["SCOPE_VIOLATION"] = "scope_violation";
    EventType["EXPORT_GENERATED"] = "export_generated";
    EventType["USER_ACTION"] = "user_action";
})(EventType || (exports.EventType = EventType = {}));
var Severity;
(function (Severity) {
    Severity["INFO"] = "info";
    Severity["WARNING"] = "warning";
    Severity["ERROR"] = "error";
    Severity["CRITICAL"] = "critical";
})(Severity || (exports.Severity = Severity = {}));
var ComplianceFramework;
(function (ComplianceFramework) {
    ComplianceFramework["SOC2"] = "SOC2";
    ComplianceFramework["ISO27001"] = "ISO27001";
    ComplianceFramework["GDPR"] = "GDPR";
    ComplianceFramework["HIPAA"] = "HIPAA";
    ComplianceFramework["PCI_DSS"] = "PCI_DSS";
})(ComplianceFramework || (exports.ComplianceFramework = ComplianceFramework = {}));
var LogCategory;
(function (LogCategory) {
    LogCategory["OPERATIONS"] = "operations";
    LogCategory["SECURITY"] = "security";
    LogCategory["ERRORS"] = "errors";
})(LogCategory || (exports.LogCategory = LogCategory = {}));
var RetentionPolicy;
(function (RetentionPolicy) {
    RetentionPolicy[RetentionPolicy["SHORT"] = 7] = "SHORT";
    RetentionPolicy[RetentionPolicy["MEDIUM"] = 30] = "MEDIUM";
    RetentionPolicy[RetentionPolicy["LONG"] = 90] = "LONG";
    RetentionPolicy[RetentionPolicy["EXTENDED"] = 365] = "EXTENDED"; // 1 year
})(RetentionPolicy || (exports.RetentionPolicy = RetentionPolicy = {}));
//# sourceMappingURL=compliance-types.js.map