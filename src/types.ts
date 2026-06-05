export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface Vulnerability {
  vulnerability_id: string;
  title: string;
  type: string;
  cwe?: string;
  owasp?: string;
  severity: Severity;
  cvss: number;
  method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
  endpoint: string;
  parameter?: string;
  url: string;
  payload?: string;
  requires_login: boolean;
  source: string;
  validation_strategy: string;
  description?: string;
}

export interface AgentRunLog {
  timestamp: string;
  agentName: string;
  level: "info" | "warning" | "error" | "success";
  message: string;
  payload?: any;
}

export interface LLMComparisonMetric {
  model: string;
  tokens: number;
  cost: number;
  latency_ms: number;
  confidence: number;
  accuracy: number;
}

export interface AgentState {
  id: string;
  name: string;
  status: "idle" | "running" | "completed" | "failed";
  toolUsed?: string;
  lastOutput?: any;
}

export interface Evidence {
  payload_rendered?: boolean;
  javascript_executed?: boolean;
  outbound_request_detected?: boolean;
  authenticated_as?: string | number;
  requested_resource?: string | number;
  ownership_check_failed?: boolean;
  confirmed: boolean;
  confidence: number;
  rawResponse?: string;
  requestTrace?: string;
}

export interface Recommendation {
  remediation_id: string;
  vulnerability_id: string;
  title: string;
  solution: string;
  code_before: string;
  code_after: string;
  priority: Severity;
}

export interface ScanRun {
  runId: string;
  vulnerability: Vulnerability;
  timestamp: string;
  status: "pending" | "running" | "completed" | "failed";
  currentStep: string;
  agentStates: Record<string, AgentState>;
  evidence?: Evidence;
  riskScore?: number;
  logs: AgentRunLog[];
  metrics?: LLMComparisonMetric;
  recommendation?: Recommendation;
}
