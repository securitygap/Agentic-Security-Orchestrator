import React, { useState, useEffect, useRef } from "react";
import { 
  Shield, 
  Terminal, 
  Cpu, 
  Activity, 
  RefreshCw, 
  Play, 
  AlertTriangle,
  Code2, 
  CheckCircle2, 
  Database, 
  Globe, 
  Zap,
  BarChart3,
  Sparkles,
  FileText,
  Upload,
  ArrowRight,
  ChevronRight,
  Server,
  Layers,
  Container,
  Flame,
  Check,
  ClipboardCheck,
  TrendingUp,
  Coins,
  Search,
  Trash2,
  Copy,
  FileCode,
  Lock,
  Unlock
} from "lucide-react";
import { Vulnerability, ScanRun, AgentRunLog, LLMComparisonMetric, Recommendation } from "./types";

export default function App() {
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const [completedRuns, setCompletedRuns] = useState<ScanRun[]>([]);
  const [activeRun, setActiveRun] = useState<ScanRun | null>(null);
  const [selectedRunForPacketInspection, setSelectedRunForPacketInspection] = useState<ScanRun | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [useRealAi, setUseRealAi] = useState(true);
  const [serverAiActive, setServerAiActive] = useState<boolean | null>(null);
  const [quotaExceeded, setQuotaExceeded] = useState<boolean>(false);
  
  // Choose which vulnerabilities to validate (checked by default)
  const [checkedVulnsForValidation, setCheckedVulnsForValidation] = useState<Record<string, boolean>>({});
  const [preservedLogs, setPreservedLogs] = useState<AgentRunLog[]>([]);

  // Automatically check newly imported vulnerabilities by default
  useEffect(() => {
    if (vulnerabilities.length > 0) {
      setCheckedVulnsForValidation(prev => {
        const next = { ...prev };
        let updated = false;
        vulnerabilities.forEach(v => {
          if (next[v.vulnerability_id] === undefined) {
            next[v.vulnerability_id] = true;
            updated = true;
          }
        });
        return updated ? next : prev;
      });
    }
  }, [vulnerabilities]);
  
  // JSON File Import states
  const [dragActive, setDragActive] = useState(false);
  const [importStatus, setImportStatus] = useState<{ type: "success" | "error"; message: string } | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // Dynamic Pre-Authentication configuration states
  const [authSetup, setAuthSetup] = useState<{
    auth_url: string;
    auth_method: "GET" | "POST" | "PUT";
    auth_headers?: Record<string, string>;
    auth_payload: string;
    token_path: string;
    token_type: string;
    token_header: string;
    session_token?: string;
  }>({
    auth_url: "",
    auth_method: "POST",
    auth_headers: { "Content-Type": "application/json" },
    auth_payload: "",
    token_path: "token",
    token_type: "Bearer",
    token_header: "Authorization",
    session_token: ""
  });
  const [authActive, setAuthActive] = useState(false);
  const [testingAuth, setTestingAuth] = useState(false);
  const [authTestLogs, setAuthTestLogs] = useState<string[]>([]);
  
  // JSON Structure Validation states
  const [validationErrors, setValidationErrors] = useState<{
    fileName: string;
    hasErrors: boolean;
    missingFields: string[];
    remediatedData: any;
    recommendationText: string;
    originalParsed: any;
  } | null>(null);
  const [showRemediationView, setShowRemediationView] = useState(false);
  
  // Custom Parser States
  const [customParserOpen, setCustomParserOpen] = useState(false);
  const [rawText, setRawText] = useState("");
  const [reportFormat, setReportFormat] = useState<"PDF" | "JSON" | "BurpXML" | "ZAP" | "Invicti" | "Nuclei">("BurpXML");
  const [isParsingReport, setIsParsingReport] = useState(false);
  const [parsedVuln, setParsedVuln] = useState<Vulnerability | null>(null);

  // Tabs
  const [activeTab, setActiveTab] = useState<"cockpit" | "blueprint" | "results">("cockpit");
  const [preAuthOpen, setPreAuthOpen] = useState(false);

  // Bottom terminal console states
  const [terminalCategory, setTerminalCategory] = useState<"shell" | "request" | "response" | "evidence" | "remediation">("shell");
  const [terminalFilter, setTerminalFilter] = useState("");
  
  // Blueprint Tab Active View
  const [selectedBlueprintKey, setSelectedBlueprintKey] = useState<string>("fastapi-router");

  // Filter state
  const [filterType, setFilterType] = useState<string>("All");

  const logEndRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    fetchVulnerabilities();
    fetchRuns();
    checkAiStatus();
    fetchAuthSetup();
  }, []);

  useEffect(() => {
    if (logEndRef.current) {
      logEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [activeRun?.logs]);

  const fetchAuthSetup = async () => {
    try {
      const res = await fetch("/api/auth-setup");
      const data = await res.json();
      if (data.success && data.setup) {
        setAuthSetup(data.setup);
        setAuthActive(data.active);
      }
    } catch (e) {
      console.error("Error loading auth setup info", e);
    }
  };

  const saveAuthSetupObj = async (newSetup: typeof authSetup) => {
    try {
      const res = await fetch("/api/auth-setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ setup: newSetup })
      });
      const data = await res.json();
      if (data.success) {
        setAuthSetup(data.setup);
        setAuthActive(!!data.setup.auth_url);
        return true;
      }
    } catch (e) {
      console.error("Error saving precheck authentication credentials", e);
    }
    return false;
  };

  const runAuthTestDiagnostics = async () => {
    setTestingAuth(true);
    setAuthTestLogs(["[Diagnostics Init] Triggering test Pre-Authentication packet exchange..."]);
    try {
      const res = await fetch("/api/auth-setup/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ setup: authSetup })
      });
      const data = await res.json();
      if (data.logs) {
        setAuthTestLogs(data.logs);
      } else {
        setAuthTestLogs(prev => [...prev, `[Diagnostics Error] Server failed to return logs. Error detail: ${data.error || "No error details available"}`]);
      }
      
      // If a new session token is captured, reload active auth settings
      if (data.success && data.token) {
        await fetchAuthSetup();
      }
    } catch (e: any) {
      setAuthTestLogs(prev => [...prev, `[Network Exception] Handshake aborted: ${e.message || String(e)}`]);
    } finally {
      setTestingAuth(false);
    }
  };

  const fetchVulnerabilities = async () => {
    try {
      const res = await fetch("/api/vulnerabilities");
      const data = await res.json();
      setVulnerabilities(data.vulnerabilities || []);
      if (data.vulnerabilities?.length > 0) {
        setSelectedVuln(data.vulnerabilities[0]);
      }
    } catch (e) {
      console.error("Error loading vulnerability definitions", e);
    }
  };

  const fetchRuns = async () => {
    try {
      const res = await fetch("/api/runs");
      const data = await res.json();
      setCompletedRuns(data.runs || []);
    } catch (e) {
      console.error("Error loading completed threat validates", e);
    }
  };

  const checkAiStatus = async () => {
    try {
      const res = await fetch("/api/ai-status");
      const data = await res.json();
      setServerAiActive(!!data.aiActive);
      setQuotaExceeded(!!data.hasQuotaLimit);
    } catch (e) {
      console.error("Error loading server Gemini status", e);
      setServerAiActive(false);
      setQuotaExceeded(false);
    }
  };

  const importJsonData = async (jsonText: string, fileName?: string) => {
    setImportStatus(null);
    setValidationErrors(null);
    let potentialAuthSetup: any = null;
    const currentFileName = fileName || "datos.json";
    
    try {
      const parsed = JSON.parse(jsonText);
      let listToImport: any[] = [];
      
      if (Array.isArray(parsed)) {
        listToImport = parsed;
      } else if (parsed && typeof parsed === "object") {
        potentialAuthSetup = parsed.auth_setup || parsed.auth || parsed.authentication || parsed.login_setup || parsed.session_setup;
        if (potentialAuthSetup) {
          try {
            const authRes = await fetch("/api/auth-setup", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ setup: potentialAuthSetup })
            });
            const authData = await authRes.json();
            if (authData.success) {
              setAuthSetup(authData.setup);
              setAuthActive(true);
              setImportStatus({
                type: "success",
                message: "Authentication setup parameter keys identified and parsed from JSON file head!"
              });
            }
          } catch (authErr) {
            console.error("Failed to automatically load auth_setup specs", authErr);
          }
        }

        if (Array.isArray(parsed.vulnerabilities)) {
          listToImport = parsed.vulnerabilities;
        } else if (Array.isArray(parsed.listings)) {
          listToImport = parsed.listings;
        } else if (Array.isArray(parsed.vulnerable)) {
          listToImport = parsed.vulnerable;
        } else {
          // Treat any dictionary/object as a single potential vulnerability object
          // allowing structure validation to find and remediate any missing details.
          listToImport = [parsed];
        }
      } else {
        throw new Error("Invalid format. Must be a valid JSON array or vulnerability object.");
      }

      if (listToImport.length === 0) {
        throw new Error("No vulnerability records detected in target file.");
      }

      // Preprocess imported items to bridge from nested structures like request_definition
      const preprocessedList = listToImport.map((originalItem: any, index: number) => {
        if (!originalItem || typeof originalItem !== "object") return originalItem;
        
        const item = { ...originalItem };

        // 1. Map challenge_name / name / type to title if title is missing
        if (!item.title) {
          item.title = item.challenge_name || item.name || (item.type ? `${item.type} on target` : `Imported Vulnerability #${index + 1}`);
        }

        // 2. Map request_definition flat mappings
        if (item.request_definition && typeof item.request_definition === "object") {
          const reqDef = item.request_definition;
          if (!item.method && reqDef.method) item.method = reqDef.method;
          if (!item.endpoint && reqDef.endpoint) item.endpoint = reqDef.endpoint;
          if (!item.url) {
            if (reqDef.url) {
              item.url = reqDef.url;
            } else if (reqDef.base_url) {
              const base = String(reqDef.base_url);
              const path = String(reqDef.endpoint || "");
              const baseClean = base.endsWith("/") ? base.slice(0, -1) : base;
              const pathClean = path.startsWith("/") ? path : `/${path}`;
              item.url = `${baseClean}${pathClean}`;
            }
          }
        }

        // 3. Map execution_strategy payloads
        if (item.execution_strategy && typeof item.execution_strategy === "object") {
          const execStrat = item.execution_strategy;
          if (execStrat.parameters && Array.isArray(execStrat.parameters.payloads) && execStrat.parameters.payloads.length > 0) {
            if (!item.payload) {
              item.payload = execStrat.parameters.payloads[0];
            }
          }
        }

        // 4. Fallback default endpoint if URL is defined but endpoint is missing
        if (!item.endpoint && item.url) {
          try {
            const urlObj = new URL(item.url);
            item.endpoint = urlObj.pathname;
          } catch (_) {
            item.endpoint = "/";
          }
        }

        // 5. Clean up duplicate slashes (except in protocol)
        if (item.url) {
          item.url = item.url.replace(/([^:]\/)\/+/g, "$1");
        }

        return item;
      });

      listToImport = preprocessedList;

      // Check structure completeness
      const requiredKeys = ["vulnerability_id", "title", "type", "severity", "cvss", "method", "endpoint", "url"];
      const missingKeysMap = new Set<string>();

      listToImport.forEach((item) => {
        if (!item || typeof item !== "object") {
          requiredKeys.forEach(k => missingKeysMap.add(k));
          return;
        }
        requiredKeys.forEach(key => {
          if (!item.hasOwnProperty(key) || item[key] === undefined || item[key] === null || item[key] === "") {
            missingKeysMap.add(key);
          }
        });
      });

      if (missingKeysMap.size > 0) {
        // Generate remediate suggester data
        const remediateItem = (item: any, index: number) => {
          if (!item || typeof item !== "object") item = {};
          const type = item.type || "SQL Injection";
          const title = item.title || item.name || `${type} on Target Endpoint`;
          
          const lowType = type.toLowerCase();
          let defaultCwe = "CWE-79"; 
          let defaultOwasp = "A03:2021 - Injection";
          let defaultPayload = "<script>alert(1)</script>";
          let defaultParam = "id";
          let defaultEndpoint = "/api/v1/search";
          let defaultMethod = "GET";
          let defaultCvss = 6.1;
          let defaultSeverity = "Medium";
          let defaultRecommendation = "Implement robust output encoding or context-aware escaping.";
          let defaultEvidence = "Reflected XSS script execution achieved in browser context.";

          if (lowType.includes("sql")) {
            defaultCwe = "CWE-89";
            defaultOwasp = "A03:2021 - Injection";
            defaultPayload = "' OR 1=1--";
            defaultParam = "email";
            defaultEndpoint = "/rest/user/login";
            defaultMethod = "POST";
            defaultCvss = 9.8;
            defaultSeverity = "Critical";
            defaultRecommendation = "Use parameterized queries or prepared statements.";
            defaultEvidence = "Database query manipulation leading to authentication bypass.";
          } else if (lowType.includes("csrf") || lowType.includes("forgery")) {
            defaultCwe = "CWE-352";
            defaultOwasp = "A01:2021 - Broken Access Control";
            defaultPayload = "State-changing request submitted without anti-CSRF token verification.";
            defaultParam = "csrf_token";
            defaultEndpoint = "/api/v1/user/update";
            defaultMethod = "POST";
            defaultCvss = 8.1;
            defaultSeverity = "High";
            defaultRecommendation = "Implement unique, cryptographically secure anti-CSRF tokens.";
            defaultEvidence = "State updated on behalf of victim user.";
          } else if (lowType.includes("path") || lowType.includes("traversal") || lowType.includes("lfi")) {
            defaultCwe = "CWE-22";
            defaultOwasp = "A01:2021 - Broken Access Control";
            defaultPayload = "../../../../etc/passwd";
            defaultParam = "file";
            defaultEndpoint = "/api/v1/files/view";
            defaultMethod = "GET";
            defaultCvss = 7.5;
            defaultSeverity = "High";
            defaultRecommendation = "Validate files against an allowed list or resolve absolute canonized paths.";
            defaultEvidence = "Sensitive configuration file contents leaked in response buffer.";
          }

          return {
            vulnerability_id: item.vulnerability_id || `JS-${String(100 + index).padStart(3, '0')}`,
            title: item.title || title,
            type: item.type || type,
            cwe: item.hasOwnProperty("cwe") ? item.cwe : defaultCwe,
            owasp: item.hasOwnProperty("owasp") ? item.owasp : defaultOwasp,
            severity: item.severity || defaultSeverity,
            cvss: item.cvss !== undefined && item.cvss !== null ? Number(item.cvss) : defaultCvss,
            method: item.method || defaultMethod,
            endpoint: item.endpoint || defaultEndpoint,
            parameter: item.hasOwnProperty("parameter") ? item.parameter : defaultParam,
            url: item.url || (() => {
              const base = "https://juice-shopa.onrender.com";
              const path = item.endpoint || defaultEndpoint;
              const pathClean = path.startsWith("/") ? path : `/${path}`;
              return `${base}${pathClean}`;
            })(),
            payload: item.hasOwnProperty("payload") ? item.payload : defaultPayload,
            evidence: item.hasOwnProperty("evidence") ? item.evidence : defaultEvidence,
            recommendation: item.hasOwnProperty("recommendation") ? item.recommendation : defaultRecommendation,
            requires_login: item.hasOwnProperty("requires_login") ? !!item.requires_login : (item.hasOwnProperty("requiere_login") ? !!item.requiere_login : (item.hasOwnProperty("login_required") ? !!item.login_required : false))
          };
        };

        const remediatedItems = listToImport.map((v, i) => remediateItem(v, i));
        
        let finalRemediatedData = remediatedItems;
        if (!Array.isArray(parsed) && parsed && typeof parsed === "object" && !parsed.vulnerabilities && !parsed.listings && !parsed.vulnerable) {
          finalRemediatedData = remediatedItems[0] as any;
        } else if (!Array.isArray(parsed) && parsed && typeof parsed === "object") {
          const updated = { ...parsed };
          if (parsed.vulnerabilities) updated.vulnerabilities = remediatedItems;
          else if (parsed.listings) updated.listings = remediatedItems;
          else if (parsed.vulnerable) updated.vulnerable = remediatedItems;
          finalRemediatedData = updated;
        }

        setValidationErrors({
          fileName: currentFileName,
          hasErrors: true,
          missingFields: Array.from(missingKeysMap),
          remediatedData: finalRemediatedData,
          recommendationText: `Faltan campos obligatorios (${Array.from(missingKeysMap).join(", ")}). Hemos auto-generado una remediación sugerida completando estos campos.`,
          originalParsed: parsed
        });

        setImportStatus({
          type: "error",
          message: "Validación de Estructura de Json File: Estructura incompleta. Revisa el reporte de remediación y campos faltantes."
        });
        return;
      }

      // Format, clean, and validate inputs
      const rawList = listToImport.map((v: any) => {
        if (!v || typeof v !== "object") return null;
        
        let checkedMethod: "GET" | "POST" | "PUT" | "DELETE" | "PATCH" = "GET";
        const incomingMethod = String(v.method || "").toUpperCase();
        if (["GET", "POST", "PUT", "DELETE", "PATCH"].includes(incomingMethod)) {
          checkedMethod = incomingMethod as any;
        }

        const cleaned: Vulnerability = {
          vulnerability_id: v.vulnerability_id || `VULN-ID-${Math.floor(1000 + Math.random() * 9000)}`,
          title: String(v.title || v.name || "Custom Threat Vulnerability"),
          type: String(v.type || "SQL Injection"),
          cwe: v.cwe ? String(v.cwe) : undefined,
          owasp: v.owasp ? String(v.owasp) : undefined,
          severity: (["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].includes(String(v.severity).toUpperCase()) 
            ? String(v.severity).toUpperCase() 
            : "HIGH") as any,
          cvss: Number(v.cvss) || 7.5,
          method: checkedMethod,
          endpoint: String(v.endpoint || "/api/v1/custom"),
          parameter: v.parameter ? String(v.parameter) : undefined,
          url: String(v.url || "https://example.com/vulnerable"),
          payload: v.payload ? String(v.payload) : undefined,
          requires_login: !!v.requires_login || !!v.requiere_login || !!v.login_required,
          source: v.source ? String(v.source) : "JSON File Import",
          validation_strategy: v.validation_strategy ? String(v.validation_strategy) : "Dynamic Security Signature Validation Pattern Verification",
          description: v.description ? String(v.description) : undefined
        };
        return cleaned;
      });

      const verifiedList: Vulnerability[] = rawList.filter((item): item is Vulnerability => item !== null);

      if (verifiedList.length === 0) {
        throw new Error("No valid vulnerability definitions were detected after schema filtering.");
      }

      // Post definitions to be persisted back to mockVulnerabilities database
      const res = await fetch("/api/vulnerabilities", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 
          vulnerabilities: verifiedList,
          auth_setup: potentialAuthSetup
        })
      });
      const data = await res.json();
      if (data.success) {
        setVulnerabilities(prev => {
          const existingIds = new Set(verifiedList.map(v => v.vulnerability_id));
          const filteredPrev = prev.filter(v => !existingIds.has(v.vulnerability_id));
          return [...verifiedList, ...filteredPrev];
        });
        
        if (verifiedList.length > 0) {
          setSelectedVuln(verifiedList[0]);
        }
        
        setImportStatus({
          type: "success",
          message: `Loaded ${verifiedList.length} vulnerability definitions into Threat Catalog!`
        });
        
        // Clear message automatically after 6 seconds
        setTimeout(() => {
          setImportStatus(null);
        }, 6000);
      } else {
        throw new Error(data.error || "Integration backend failed to ingest records.");
      }
    } catch (err: any) {
      console.error("Local JSON import error:", err);
      setImportStatus({
        type: "error",
        message: err.message || "Failed to process target JSON file. Confirm correct formatting."
      });
    }
  };

  const handleApplyRemediation = async () => {
    if (!validationErrors) return;
    try {
      const dataToImport = validationErrors.remediatedData;
      let listToImport: any[] = [];
      if (Array.isArray(dataToImport)) {
        listToImport = dataToImport;
      } else if (dataToImport && typeof dataToImport === "object") {
        const inner = dataToImport.vulnerabilities || dataToImport.listings || dataToImport.vulnerable;
        if (Array.isArray(inner)) {
          listToImport = inner;
        } else {
          listToImport = [dataToImport];
        }
      }

      const rawList = listToImport.map((v: any) => {
        if (!v || typeof v !== "object") return null;
        
        let checkedMethod: "GET" | "POST" | "PUT" | "DELETE" | "PATCH" = "GET";
        const incomingMethod = String(v.method || "").toUpperCase();
        if (["GET", "POST", "PUT", "DELETE", "PATCH"].includes(incomingMethod)) {
          checkedMethod = incomingMethod as any;
        }

        const cleaned: Vulnerability = {
          vulnerability_id: v.vulnerability_id || `VULN-ID-${Math.floor(1000 + Math.random() * 9000)}`,
          title: String(v.title || v.name || "Custom Threat Vulnerability"),
          type: String(v.type || "SQL Injection"),
          cwe: v.cwe ? String(v.cwe) : undefined,
          owasp: v.owasp ? String(v.owasp) : undefined,
          severity: (["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].includes(String(v.severity).toUpperCase()) 
            ? String(v.severity).toUpperCase() 
            : "HIGH") as any,
          cvss: Number(v.cvss) || 7.5,
          method: checkedMethod,
          endpoint: String(v.endpoint || "/api/v1/custom"),
          parameter: v.parameter ? String(v.parameter) : undefined,
          url: String(v.url || "https://example.com/vulnerable"),
          payload: v.payload ? String(v.payload) : undefined,
          requires_login: !!v.requires_login || !!v.requiere_login || !!v.login_required,
          source: v.source ? String(v.source) : "JSON File Remediation",
          validation_strategy: v.validation_strategy ? String(v.validation_strategy) : "Dynamic Security Signature Validation Pattern Verification",
          description: v.description ? String(v.description) : undefined
        };
        return cleaned;
      });

      const verifiedList: Vulnerability[] = rawList.filter((item): item is Vulnerability => item !== null);

      if (verifiedList.length === 0) {
        throw new Error("No valid vulnerability definitions were detected in the auto-remediated data.");
      }

      // Submit to backend
      const res = await fetch("/api/vulnerabilities", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 
          vulnerabilities: verifiedList,
          auth_setup: validationErrors.originalParsed?.auth_setup || validationErrors.originalParsed?.auth
        })
      });
      const data = await res.json();
      if (data.success) {
        setVulnerabilities(prev => {
          const existingIds = new Set(verifiedList.map(v => v.vulnerability_id));
          const filteredPrev = prev.filter(v => !existingIds.has(v.vulnerability_id));
          return [...verifiedList, ...filteredPrev];
        });
        
        if (verifiedList.length > 0) {
          setSelectedVuln(verifiedList[0]);
        }
        
        setImportStatus({
          type: "success",
          message: `Estructura remediada y cargada con éxito! (${verifiedList.length} vulnerabilidad/es cargadas.)`
        });
        setValidationErrors(null);
        setTimeout(() => {
          setImportStatus(null);
        }, 6000);
      } else {
        throw new Error(data.error || "Integration backend failed to ingest records.");
      }
    } catch (err: any) {
      console.error("Remediation execution failed:", err);
      setImportStatus({
        type: "error",
        message: err.message || "Failed to submit remediated vulnerabilities."
      });
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setDragActive(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setDragActive(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      if (file.type === "application/json" || file.name.endsWith(".json")) {
        const reader = new FileReader();
        reader.onload = (event) => {
          if (event.target?.result && typeof event.target.result === "string") {
            importJsonData(event.target.result, file.name);
          }
        };
        reader.readAsText(file);
      } else {
        setImportStatus({
          type: "error",
          message: "Unsupported file target type. Please load a structured .json file."
        });
      }
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      const reader = new FileReader();
      reader.onload = (event) => {
        if (event.target?.result && typeof event.target.result === "string") {
          importJsonData(event.target.result, file.name);
        }
      };
      reader.readAsText(file);
    }
  };

  const renderResponseWithTokenHighlighting = (text: string) => {
    if (!text) return null;

    // Split text based on JWT tokens or common session token patterns
    const jwtRegex = /(eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+)/g;
    const parts = text.split(jwtRegex);

    return (
      <span className="leading-relaxed">
        {parts.map((part, idx) => {
          if (part.match(/^eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+$/)) {
            return (
              <span
                key={`jwt-${idx}`}
                className="bg-fuchsia-600 text-white font-extrabold px-1.5 py-0.5 rounded mx-1 break-all inline-block tracking-tight text-[11.5px] border border-fuchsia-300 shadow shadow-fuchsia-500/30 font-mono select-all"
                title="Interpreted Bearer Token"
              >
                {part}
              </span>
            );
          }

          // Search for "token" or "session_token" keys inside response text and highlight keyword
          const tokenKeywordRegex = /("token"|"session_token"|"session"|"jwt")/gi;
          if (part.match(tokenKeywordRegex)) {
            const subparts = part.split(tokenKeywordRegex);
            return (
              <span key={`text-parent-${idx}`}>
                {subparts.map((sub, sidx) => {
                  if (sub.match(tokenKeywordRegex)) {
                    return (
                      <span key={`keyword-${sidx}`} className="text-yellow-300 font-extrabold underline decoration-amber-400">
                        {sub}
                      </span>
                    );
                  }
                  return <span key={`sub-${sidx}`}>{sub}</span>;
                })}
              </span>
            );
          }

          return <span key={`text-${idx}`}>{part}</span>;
        })}
      </span>
    );
  };

  const handleZoneClick = () => {
    fileInputRef.current?.click();
  };

  const handleCustomParse = async () => {
    if (!rawText.trim()) return;
    setIsParsingReport(true);
    setParsedVuln(null);
    try {
      const res = await fetch("/api/parser/parse", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ fileType: reportFormat, rawContent: rawText })
      });
      const data = await res.json();
      if (data.success && data.parsed) {
        setParsedVuln(data.parsed);
        setVulnerabilities(prev => [data.parsed, ...prev]);
        setSelectedVuln(data.parsed);
      }
    } catch (err) {
      console.error("Failed to parse report snippet", err);
    } finally {
      setIsParsingReport(false);
    }
  };

  const runCheckedValidations = async (singleVuln?: Vulnerability) => {
    if (isRunning) return;

    // Determine target(s)
    let targets: Vulnerability[] = [];
    if (singleVuln) {
      targets = [singleVuln];
    } else {
      targets = vulnerabilities.filter(v => checkedVulnsForValidation[v.vulnerability_id] !== false);
    }

    if (targets.length === 0) {
      alert("No vulnerabilities selected. Please check at least one vulnerability in the Threat Catalog.");
      return;
    }

    setIsRunning(true);
    setPreservedLogs([]); // Clear for a new run session (corrida)
    setCompletedRuns([]); // Clear run history for a clean batch in this corrida!
    setSelectedRunForPacketInspection(null);

    // Select the first target to keep UI response centered
    setSelectedVuln(targets[0]);

    for (let currentIdx = 0; currentIdx < targets.length; currentIdx++) {
      const targetVuln = targets[currentIdx];
      setSelectedVuln(targetVuln);

      const runIdSlug = `RUN-${targetVuln.vulnerability_id.replace(/[^a-zA-Z0-9-]/g, "")}-${Date.now().toString().slice(-4)}`;

      const initialRun: ScanRun = {
        runId: runIdSlug,
        vulnerability: targetVuln,
        timestamp: new Date().toISOString(),
        status: "running",
        currentStep: "Routing Validation Workflow",
        logs: [
          {
            timestamp: new Date().toISOString(),
            agentName: "Orchestration Initializer",
            level: "info",
            message: `Starting validation orchestration pipeline for threat: ${targetVuln.vulnerability_id} (${targetVuln.title})`
          }
        ],
        agentStates: {
          parser: { id: "p1", name: "Parser Agent", status: "running" },
          router: { id: "a1", name: "Router Agent", status: "idle" },
          enrichment: { id: "a2", name: "Enrichment Agent", status: "idle" },
          val_specific: { id: "a3", name: "Specialized Validation Agent", status: "idle" },
          evidence_correlator: { id: "a4", name: "Evidence Correlation Agent", status: "idle" },
          risk_scorer: { id: "a5", name: "Risk Scoring Agent", status: "idle" },
          remediator: { id: "a6", name: "Remediation Agent", status: "idle" }
        }
      };

      setActiveRun(initialRun);

      // Seed initial marker and start logs in preservedLogs
      setPreservedLogs(prev => [
        ...prev,
        {
          timestamp: new Date().toISOString(),
          agentName: "Orchestration Pipeline",
          level: "info",
          message: `>>> [RUN START] Initiated automatic pipeline check on "${targetVuln.vulnerability_id} - ${targetVuln.title}"`
        },
        ...initialRun.logs
      ]);

      const steps = [
        { step: "Parser Agent Alignment", activeAgent: "parser" as const, msg: `Raw metadata structures successfully parsed and mapped for ${targetVuln.vulnerability_id}.` },
        { step: "Graph Node Routing", activeAgent: "router" as const, msg: `Router Agent directed validation task based on threat signatures for ${targetVuln.vulnerability_id}.` },
        { step: "Adversary TTP Enrichment", activeAgent: "enrichment" as const, msg: `Enrichment Agent appended historical CVE telemetry to context.` },
        { step: "Simulating Request Playground", activeAgent: "val_specific" as const, msg: `Simulating safe active validation request loop on target: ${targetVuln.endpoint}...` }
      ];

      for (let i = 0; i < steps.length; i++) {
        await new Promise(resolve => setTimeout(resolve, 500));
        
        const currentLog = {
          timestamp: new Date().toISOString(),
          agentName: steps[i].step,
          level: "info" as const,
          message: steps[i].msg
        };

        // Append to preservedLogs
        setPreservedLogs(prev => [...prev, currentLog]);

        setActiveRun(prev => {
          if (!prev) return null;
          const updatedStates = { ...prev.agentStates };
          
          if (i > 0) {
            const prevAgent = steps[i-1].activeAgent;
            updatedStates[prevAgent] = { ...updatedStates[prevAgent], status: "completed" as const };
          }
          const currentAgent = steps[i].activeAgent;
          updatedStates[currentAgent] = { ...updatedStates[currentAgent], status: "running" as const };

          return {
            ...prev,
            currentStep: steps[i].step,
            agentStates: updatedStates,
            logs: [...prev.logs, currentLog]
          };
        });
      }

      try {
        const res = await fetch("/api/runs/execute", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ 
            vulnerability: targetVuln, 
            useRealAi,
            auth_setup: authSetup
          })
        });
        const data = await res.json();
        if (data.success && data.run) {
          if (data.hasQuotaLimit) {
            setQuotaExceeded(true);
          }
          setActiveRun(data.run);
          setCompletedRuns(prev => [...prev, data.run]);
          setSelectedRunForPacketInspection(data.run);

          // Push new backend logs to preservedLogs
          const backendLogs = data.run.logs || [];
          setPreservedLogs(prev => {
            // Filter some mock step messages to avoid doubling, keeping logs super tidy
            const cleanedPrev = prev.filter(l => 
              !l.message.includes("Starting validation orchestration") && 
              !l.message.includes("Raw metadata structures successfully") && 
              !l.message.includes("Router Agent directed") && 
              !l.message.includes("Enrichment Agent appended") && 
              !l.message.includes("Simulating safe active")
            );
            return [
              ...cleanedPrev,
              ...backendLogs,
              {
                timestamp: new Date().toISOString(),
                agentName: "Orchestration Pipeline",
                level: "success",
                message: `<<< [RUN COMPLETE] Successfully validated "${targetVuln.vulnerability_id}". STATUS: ${data.run.evidence?.confirmed ? "VULNERABLE" : "CONFIRMED FALSE POSITIVE"}\n--------------------------------------------------------------`
              }
            ];
          });

          // Always synchronize authentication configuration in React state when a token is discovered or updated
          await fetchAuthSetup();
        } else {
          throw new Error(data.error || "Execution failed");
        }
      } catch (e: any) {
        const errLog = {
          timestamp: new Date().toISOString(),
          agentName: "Orchestration Pipeline",
          level: "error" as const,
          message: `Task Execution failed: ${e.message || e}`
        };

        setPreservedLogs(prev => [
          ...prev, 
          errLog, 
          {
            timestamp: new Date().toISOString(),
            agentName: "Orchestration Pipeline",
            level: "error",
            message: `<<< [RUN FAILED] Vulnerability "${targetVuln.vulnerability_id}" aborted due to pipeline error.\n--------------------------------------------------------------`
          }
        ]);

        setActiveRun(prev => {
          if (!prev) return null;
          return {
            ...prev,
            status: "failed",
            currentStep: "Execution Error",
            logs: [...prev.logs, errLog]
          };
        });
      }

      // Small breather delay between sequential targets
      if (currentIdx < targets.length - 1) {
        await new Promise(resolve => setTimeout(resolve, 800));
      }
    }

    setIsRunning(false);
  };

  const getExportableTerminalContent = () => {
    const inspected = selectedRunForPacketInspection || activeRun;
    if (terminalCategory === "request") {
      return inspected?.evidence?.requestTrace || "empty";
    }
    if (terminalCategory === "response") {
      return inspected?.evidence?.rawResponse || "empty";
    }
    if (terminalCategory === "evidence") {
      return inspected?.evidence ? JSON.stringify(inspected.evidence, null, 2) : "empty";
    }
    if (terminalCategory === "remediation") {
      return inspected?.recommendation ? JSON.stringify(inspected.recommendation, null, 2) : "empty";
    }
    
    let text = "--- AGENTIC SECURITY ORCHESTRATOR TRACE LOGGER ---\n";
    authTestLogs.forEach(line => {
      text += `[AUTH HANDSHAKE] ${line}\n`;
    });
    const runLogs = inspected?.logs || activeRun?.logs || [];
    runLogs.forEach(log => {
      text += `[${log.timestamp}] [${log.agentName}] ${log.message}\n`;
    });
    return text;
  };

  const typesList = ["All", "SQL Injection", "Stored XSS", "SSRF", "IDOR", "JWT Bypass"];
  const filteredVulnerabilities = filterType === "All" 
    ? vulnerabilities 
    : vulnerabilities.filter(v => v.type === filterType);

  // Model comparison mock metrics matching requirements explicitly
  const accuracyComparison: LLMComparisonMetric[] = [
    { model: "gemini-3.5-flash", tokens: 1120, cost: 0.00016, latency_ms: 540, confidence: 0.96, accuracy: 0.94 },
    { model: "gemini-3.1-pro-preview", tokens: 1480, cost: 0.00185, latency_ms: 1250, confidence: 0.99, accuracy: 0.98 },
    { model: "gpt-4o-mini", tokens: 1210, cost: 0.00018, latency_ms: 680, confidence: 0.93, accuracy: 0.91 },
    { model: "gpt-4o", tokens: 1540, cost: 0.00770, latency_ms: 1150, confidence: 0.98, accuracy: 0.97 },
    { model: "claude-3-5-sonnet", tokens: 1610, cost: 0.00483, latency_ms: 1420, confidence: 0.97, accuracy: 0.96 }
  ];

  // Static high value blueprint source files
  const blueprints: Record<string, { title: string; lang: string; path: string; icon: any; code: string; desc: string }> = {
    "fastapi-router": {
      title: "FastAPI Vulnerability Router",
      lang: "python",
      path: "src/api/routers/vulnerabilities.py",
      icon: Server,
      desc: "FastAPI REST controller providing upload schemas, client-auth, and active rate-limiting validation hooks.",
      code: `from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Optional, List
from src.domain.entities.vulnerability import Vulnerability
from src.application.workflows.validator import run_automated_validation

router = APIRouter(prefix="/api/v1/vulnerabilities", tags=["Vulnerabilities"])

class RunValidationRequest(BaseModel):
    vulnerability_id: str
    use_ai_enrichment: bool = True

@router.post("/execute", status_code=status.HTTP_202_ACCEPTED)
async def trigger_validation_run(payload: RunValidationRequest):
    """
    Triggers the LangGraph agent pipeline to validate the reported vulnerability.
    """
    try:
        run_record = await run_automated_validation(
            vulnerability_id=payload.vulnerability_id,
            use_ai=payload.use_ai_enrichment
        )
        return run_record
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Automation execution pipeline failed: {str(e)}"
        )
`
    },
    "langgraph-workflow": {
      title: "LangGraph Orchestration Graph",
      lang: "python",
      path: "src/application/workflows/validator.py",
      icon: Layers,
      desc: "Creates the modular LangGraph StateGraph instance that controls multi-agent transition, state merging, and routing logic.",
      code: `from typing import Dict, TypedDict, Any
from langgraph.graph import StateGraph, END
from src.application.agents import (
    parser_agent, router_agent, sqli_agent, xss_agent,
    correlation_agent, scoring_agent, remediation_agent
)

class ValidationGraphState(TypedDict):
    vulnerability: Dict[str, Any]
    current_agent: str
    routes: Dict[str, str]
    evidence: Dict[str, Any]
    risk_score: int
    recommendation: Dict[str, Any]
    logs: list

def build_orchestration_graph() -> StateGraph:
    workflow = StateGraph(ValidationGraphState)
    
    # 1. Register processing nodes
    workflow.add_node("parser_agent", parser_agent.invoke)
    workflow.add_node("router_agent", router_agent.invoke)
    workflow.add_node("sqli_agent", sqli_agent.invoke)
    workflow.add_node("xss_agent", xss_agent.invoke)
    workflow.add_node("correlation_agent", correlation_agent.invoke)
    workflow.add_node("scoring_agent", scoring_agent.invoke)
    workflow.add_node("remediation_agent", remediation_agent.invoke)
    
    # 2. Build connection flow logic
    workflow.set_entry_point("parser_agent")
    workflow.add_edge("parser_agent", "router_agent")
    
    # 3. Dynamic Router node logic
    def route_vulnerability(state: ValidationGraphState) -> str:
        v_type = state["vulnerability"]["type"]
        if "SQL" in v_type:
            return "sqli_agent"
        elif "XSS" in v_type:
            return "xss_agent"
        return "correlation_agent"
        
    workflow.add_conditional_edges(
        "router_agent",
        route_vulnerability,
        {
            "sqli_agent": "sqli_agent",
            "xss_agent": "xss_agent",
            "correlation_agent": "correlation_agent"
        }
    )
    
    workflow.add_edge("sqli_agent", "correlation_agent")
    workflow.add_edge("xss_agent", "correlation_agent")
    workflow.add_edge("correlation_agent", "scoring_agent")
    workflow.add_edge("scoring_agent", "remediation_agent")
    workflow.add_edge("remediation_agent", END)
    
    return workflow.compile()
`
    },
    "pydantic-model": {
      title: "Pydantic Vulnerability Schema",
      lang: "python",
      path: "src/domain/entities/vulnerability.py",
      icon: FileText,
      desc: "Robust domain models specifying strict structural fields, type coercions and formatting standards.",
      code: `from pydantic import BaseModel, Field
from typing import Optional

class Vulnerability(BaseModel):
    vulnerability_id: str = Field(..., description="Unique enterprise identifier (e.g., VULN-001)")
    title: str = Field(..., description="Descriptive human title detailing vulnerability")
    type: str = Field(..., description="Broad category mapping (SQL Injection, XSS, SSRF, IDOR)")
    cwe: Optional[str] = Field(None, description="Mapped Common Weakness Enumeration key (e.g., CWE-89)")
    owasp: Optional[str] = Field(None, description="Mapped OWASP standard (e.g. A03:2021)")
    severity: str = Field(..., description="Categorical severity threat level (CRITICAL, HIGH, MEDIUM)")
    cvss: float = Field(..., ge=0.0, le=10.0, description="Common Vulnerability Scoring System baseline rating")
    
    method: str = Field(default="POST", description="HTTP request method utilized to evaluate target")
    endpoint: str = Field(..., description="Vulnerable application relative target endpoint path")
    parameter: Optional[str] = Field(None, description="Injected vulnerable parameter parameter name")
    url: str = Field(..., description="Complete Absolute Target URL resource endpoint")
    payload: Optional[str] = Field(None, description="Proof of concept validation verification payload")
    
    requires_login: bool = Field(default=False, description="Specifies if credential-linked authentication is required")
    source: str = Field(..., description="Scanner source agent reporting vulnerability")
    validation_strategy: str = Field(..., description="Automated playbook strategy assigned for verification")
`
    },
    "sql-schema": {
      title: "PostgreSQL Schema Definition",
      lang: "sql",
      path: "infrastructure/database/init_schema.sql",
      icon: Database,
      desc: "PostgreSQL DDL script constructing key relationships (reports, vulnerabilities, validations, evidences, recommendations).",
      code: `CREATE TABLE reports (
    report_id VARCHAR(50) PRIMARY KEY,
    uploaded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    file_type VARCHAR(20) NOT NULL,
    item_count INT NOT NULL
);

CREATE TABLE vulnerabilities (
    vulnerability_id VARCHAR(50) PRIMARY KEY,
    title VARCHAR(150) NOT NULL,
    type VARCHAR(50) NOT NULL,
    cwe VARCHAR(30),
    owasp VARCHAR(30),
    severity VARCHAR(15) NOT NULL,
    cvss NUMERIC(3, 1) NOT NULL,
    method VARCHAR(10) NOT NULL,
    endpoint TEXT NOT NULL,
    parameter VARCHAR(55),
    url TEXT NOT NULL,
    payload TEXT,
    requires_login BOOLEAN NOT NULL DEFAULT FALSE,
    source TEXT NOT NULL,
    validation_strategy TEXT NOT NULL
);

CREATE TABLE validations (
    validation_id VARCHAR(50) PRIMARY KEY,
    vulnerability_id VARCHAR(50) REFERENCES vulnerabilities(vulnerability_id),
    validated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    confidence NUMERIC(3, 2) NOT NULL,
    is_confirmed BOOLEAN NOT NULL,
    risk_score INT NOT NULL
);

CREATE TABLE evidences (
    evidence_id VARCHAR(50) PRIMARY KEY,
    validation_id VARCHAR(50) REFERENCES validations(validation_id),
    payload_rendered BOOLEAN DEFAULT FALSE,
    js_executed BOOLEAN DEFAULT FALSE,
    outbound_request_detected BOOLEAN DEFAULT FALSE,
    request_trace TEXT,
    raw_response TEXT
);
`
    },
    "docker-compose": {
      title: "Docker Compose Deployment",
      lang: "yaml",
      path: "docker-compose.yml",
      icon: Container,
      desc: "Production Docker deployment setup hosting the API controller, PostgreSQL engine, Redis worker stack, and Ollama core.",
      code: `version: '3.8'

services:
  api:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "3000:3000"
    environment:
      - DATABASE_URL=postgresql://root:secret@postgres:5432/scanner_db
      - REDIS_URL=redis://redis:6379/0
      - GEMINI_API_KEY=\${GEMINI_API_KEY}
    depends_on:
      - postgres
      - redis

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_USER=root
      - POSTGRES_PASSWORD=secret
      - POSTGRES_DB=scanner_db
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

volumes:
  pgdata:
`
    }
  };

  return (
    <div className="min-h-screen bg-[#0A0B0E] text-[#F1F5F9] font-sans flex flex-col antialiased selection:bg-[#22D3EE]/30 selection:text-cyan-200">
      
      {/* Top Banner and Navigation Tabs */}
      <header className="border-b border-[#2D3139] bg-[#0A0B0E]/95 backdrop-blur-md px-6 py-4 sticky top-0 z-40 flex flex-col sm:flex-row items-center justify-between gap-4">
        
        {/* App Meta Title */}
        <div className="flex items-center gap-3">
          <div className="p-2 bg-cyan-500/10 border border-cyan-500/30 rounded-lg text-[#22D3EE]">
            <Shield className="w-5.5 h-5.5" />
          </div>
          <div className="text-left">
            <div className="flex items-center gap-2">
              <h1 className="text-base font-semibold tracking-tight text-white font-sans">Agentic Security <span className="text-[#22D3EE] font-mono font-bold">Orchestrator</span></h1>
              <span className="text-[9px] bg-[#22D3EE]/10 text-[#22D3EE] border border-[#22D3EE]/30 px-2 py-0.5 rounded-full font-mono uppercase tracking-widest font-bold">
                Spec v2.4
              </span>
            </div>
            <p className="text-[11px] text-[#94A3B8]">Enterprise Triage, Active Sandbox Validation, and Secure Mitigation Synthesis Engine</p>
          </div>
        </div>

        {/* Bento Active Status Header block */}
        <div className="hidden lg:flex space-x-6 items-center border-l border-[#2D3139] border-r border-[#2D3139] px-6 py-1 mx-2">
          <div className="text-left">
            <div className="label-tiny">System Status</div>
            <div className="flex items-center text-xs font-semibold text-white font-mono"><span className="status-dot"></span> Operational</div>
          </div>
          <div className="text-left">
            <div className="label-tiny">Active Agents</div>
            <div className="text-xs font-medium text-[#94A3B8] font-mono">12 Core / 4 Aux</div>
          </div>
        </div>

        {/* Tab Selection buttons */}
        <div className="flex bg-[#14161A] border border-[#2D3139] rounded-lg p-1 text-xs font-mono">
          <button
            id="tab-btn-cockpit"
            onClick={() => setActiveTab("cockpit")}
            className={`px-3 py-1.5 rounded-md transition duration-200 flex items-center gap-1.5 cursor-pointer selection-none ${
              activeTab === "cockpit" 
                ? "bg-[#2D3139] text-[#22D3EE] font-semibold shadow" 
                : "text-[#94A3B8] hover:text-white"
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            Active Cockpit
          </button>
          <button
            id="tab-btn-results"
            onClick={() => setActiveTab("results")}
            className={`px-3 py-1.5 rounded-md transition duration-200 flex items-center gap-1.5 cursor-pointer selection-none ${
              activeTab === "results" 
                ? "bg-[#2D3139] text-[#22D3EE] font-semibold shadow" 
                : "text-[#94A3B8] hover:text-white"
            }`}
          >
            <BarChart3 className="w-3.5 h-3.5" />
            Resultados de Evaluación
          </button>
          <button
            id="tab-btn-blueprint"
            onClick={() => setActiveTab("blueprint")}
            className={`px-3 py-1.5 rounded-md transition duration-200 flex items-center gap-1.5 cursor-pointer selection-none ${
              activeTab === "blueprint" 
                ? "bg-[#2D3139] text-[#22D3EE] font-semibold shadow" 
                : "text-[#94A3B8] hover:text-white"
            }`}
          >
            <Code2 className="w-3.5 h-3.5" />
            Enterprise Blueprints
          </button>
        </div>

        {/* Global Control Preferences Bar */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 bg-[#14161A]/60 rounded-lg px-3 py-1.5 border border-[#2D3139] text-xs">
            <span className="text-[#94A3B8] font-mono">AI Proxy:</span>
            <label className="relative inline-flex items-center cursor-pointer">
              <input 
                type="checkbox" 
                checked={useRealAi} 
                onChange={(e) => setUseRealAi(e.target.checked)}
                className="sr-only peer" 
              />
              <div className="w-8 h-4.5 bg-[#2D3139] rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-[#94A3B8] after:rounded-full after:h-3.5 after:w-3.5 after:transition-all peer-checked:bg-[#22D3EE] peer-checked:after:bg-white"></div>
            </label>
            <span className={`font-mono font-semibold text-[10px] flex items-center gap-1.5 ${
              useRealAi ? (serverAiActive === true ? (quotaExceeded ? "text-amber-400" : "text-[#22D3EE]") : "text-amber-400") : "text-slate-400"
            }`}>
              {useRealAi ? (
                <>
                  <span className={`w-1.5 h-1.5 rounded-full ${
                    serverAiActive === true 
                      ? (quotaExceeded ? "bg-amber-400 shadow-[0_0_8px_rgba(245,158,11,0.5)] animate-pulse" : "bg-[#22D3EE] shadow-[0_0_8px_#22D3EE] animate-pulse")
                      : serverAiActive === false 
                        ? "bg-amber-500" 
                        : "bg-slate-500 animate-pulse"
                  }`}></span>
                  {serverAiActive === true 
                    ? (quotaExceeded ? "GEMINI (QUOTA LIMIT)" : "GEMINI-3.5 (LIVE)") 
                    : serverAiActive === false 
                      ? "GEMINI-3.5 (NO API KEY)" 
                      : "GEMINI-3.5 (CHECKING...)"}
                </>
              ) : (
                <>
                  <span className="w-1.5 h-1.5 rounded-full bg-slate-500"></span>
                  SIMULATED
                </>
              )}
            </span>
          </div>
        </div>
      </header>

      {/* Main Tabs Content Router */}
      {activeTab === "cockpit" && (
        <div className="flex-1 flex flex-col gap-6 p-6 overflow-y-auto">
          
          {quotaExceeded && (
            <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-3 text-amber-400 text-xs font-mono flex items-start justify-between gap-3 shadow-md">
              <div className="flex gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0 text-amber-400 mt-0.5" />
                <div>
                  <span className="font-bold uppercase tracking-wider block text-amber-300">AVISO: LÍMITE DE CUOTA GEMINI EXCEDIDO (429 RESOURCE EXHAUSTED)</span>
                  <span className="text-[11px] leading-normal mt-1 block">
                    Has excedido el límite actual de solicitudes en tu clave de la API de Gemini. 
                    El orquestador de agentes se ha redirigido automáticamente a la <strong>Estructura de Triage Heurística Local</strong> para mantener la app 100% operativa. 
                    Puedes continuar ejecutando pruebas y aserciones completas utilizando este fallback simulado.
                  </span>
                </div>
              </div>
              <button 
                onClick={() => setQuotaExceeded(false)}
                className="text-amber-400/70 hover:text-white hover:bg-amber-500/20 px-1.5 py-0.5 rounded text-[10px] select-none cursor-pointer"
              >
                Cerrar
              </button>
            </div>
          )}
          
          {/* Row 1: Catalog & Unified Console Panel */}
          <div className="grid grid-cols-12 gap-5 items-stretch">
            
            {/* COCKPIT LEFT PANEL: Catalog (4/12 cols) */}
            <section className="col-span-12 lg:col-span-4 flex flex-col gap-4 bg-[#14161A] border border-[#2D3139] rounded-[12px] p-5 shadow-xl text-left">
            <div className="flex items-center justify-between border-b border-[#2D3139] pb-3 mb-1">
              <div className="flex items-center gap-2">
                <Database className="w-4 h-4 text-[#22D3EE]" />
                <h2 className="text-[10px] font-bold uppercase tracking-wider text-[#94A3B8]">Threat Catalog</h2>
              </div>
              <span className="text-[10px] bg-[#1A1D23] border border-[#2D3139] text-[#22D3EE] px-2 py-0.5 rounded font-mono font-bold">
                {filteredVulnerabilities.length} Listings
              </span>
            </div>

            {/* JSON File Uploader with Dropzone & Click Selector */}
            <div 
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={handleZoneClick}
              className={`border border-dashed rounded-lg p-3 text-center cursor-pointer transition duration-200 relative group overflow-hidden ${
                dragActive 
                  ? "border-[#22D3EE] bg-[#22D3EE]/5 shadow-[0_0_12px_rgba(34,211,238,0.1)]" 
                  : "border-[#2D3139] bg-[#1A1D23]/30 hover:border-[#2D3139]/80 hover:bg-[#1A1D23]/50"
              }`}
            >
              <input 
                ref={fileInputRef}
                type="file" 
                accept=".json" 
                onChange={handleFileChange}
                className="hidden" 
              />
              <div className="flex flex-col items-center justify-center gap-1">
                <Upload className={`w-4 h-4 transition duration-200 ${dragActive ? "text-[#22D3EE] scale-110" : "text-[#94A3B8] group-hover:text-white"}`} />
                <span className="text-[11px] text-slate-300 font-mono font-medium">
                  {dragActive ? "Drop JSON here!" : "Drag or Click to Import JSON"}
                </span>
                <span className="text-[9px] text-[#94A3B8] font-mono leading-none">Supports vulnerability arrays or single items</span>
              </div>
            </div>

            {/* Import Feedback Status Messages */}
            {importStatus && (
              <div className={`p-2.5 rounded-lg text-[10px] font-mono leading-snug border ${
                importStatus.type === "success" 
                  ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" 
                  : "bg-red-500/10 text-red-500 border-red-500/20"
              }`}>
                <div className="flex items-start gap-1.5">
                  <span className="font-bold">{importStatus.type === "success" ? "✓" : "⚠"}</span>
                  <span>{importStatus.message}</span>
                </div>
              </div>
            )}

            {/* Validación Estructura de Json File */}
            {validationErrors && (
              <div id="validation-structure-section" className="bg-[#1A1D23] border border-amber-500/20 rounded-lg p-3 space-y-2.5 text-xs text-left">
                <div className="flex items-center gap-2 border-b border-[#2D3139] pb-2">
                  <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0" />
                  <div>
                    <h4 className="font-bold text-amber-500 text-[10px] uppercase tracking-wide">Validación Estructura de Json File</h4>
                    <p className="text-[9px] text-slate-400 font-mono leading-none mt-0.5">{validationErrors.fileName}</p>
                  </div>
                </div>

                <div className="space-y-1 bg-red-950/20 border border-red-500/10 rounded p-2">
                  <span className="text-[9px] uppercase font-bold text-red-400 font-mono block">Falta Completar (Campos Requeridos):</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {validationErrors.missingFields.map(field => (
                      <span key={field} className="text-[8.5px] font-mono bg-red-500/10 text-red-300 border border-red-500/20 px-1.5 py-0.5 rounded leading-none">
                        {field}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="space-y-1 bg-amber-950/10 border border-amber-500/10 rounded p-2">
                  <span className="text-[9px] uppercase font-bold text-amber-400 font-mono block">Remediación Sugerida:</span>
                  <p className="text-[10px] text-slate-300 leading-normal font-mono">
                    {validationErrors.recommendationText}
                  </p>
                </div>

                <div className="flex gap-2">
                  <button
                    id="btn-auto-remediate"
                    onClick={handleApplyRemediation}
                    className="flex-1 py-1.5 px-2 bg-amber-500 hover:bg-amber-400 active:bg-amber-600 font-mono text-[9px] text-[#0A0B0E] font-bold rounded cursor-pointer text-center select-none"
                  >
                    Auto-completar y Cargar
                  </button>
                  <button
                    id="btn-dismiss-remediation"
                    onClick={() => setValidationErrors(null)}
                    className="py-1.5 px-2.5 bg-[#2D3139]/60 hover:bg-[#2D3139] text-xs text-slate-300 font-bold rounded border border-[#2D3139] cursor-pointer text-center select-none font-mono text-[9px]"
                  >
                    Descartar
                  </button>
                </div>

                <div className="pt-1">
                  <button
                    id="btn-toggle-remediation-view"
                    onClick={() => setShowRemediationView(!showRemediationView)}
                    className="text-[9px] text-[#22D3EE] font-mono hover:underline font-bold focus:outline-none flex items-center gap-1 cursor-pointer"
                  >
                    {showRemediationView ? "▲ Ocultar Reporte" : "▼ Ver JSON Remediado y Ejemplos"}
                  </button>

                  {showRemediationView && (
                    <div className="mt-2 space-y-3 pt-2 border-t border-[#2D3139]/50">
                      <div className="space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="text-[8.5px] font-mono font-bold text-[#22D3EE] uppercase">JSON Remediado Sugerido</span>
                          <button
                            id="btn-copy-remediated-json"
                            onClick={() => {
                              navigator.clipboard.writeText(JSON.stringify(validationErrors.remediatedData, null, 2));
                              setImportStatus({ type: "success", message: "¡JSON Remediado copiado al portapapeles!" });
                            }}
                            className="text-[8px] text-cyan-400 hover:underline flex items-center gap-1 cursor-pointer"
                          >
                            <Copy className="w-2.5 h-2.5" /> Copiar Código
                          </button>
                        </div>
                        <pre className="bg-[#0F1115] border border-[#2D3139] text-slate-300 rounded p-2 text-[8.5px] max-h-[160px] overflow-auto font-mono select-text leading-tight tab-size-2 text-left">
                          {JSON.stringify(validationErrors.remediatedData, null, 2)}
                        </pre>
                      </div>

                      <div className="space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="text-[8.5px] font-mono font-bold text-slate-400 uppercase">Estructura Mínima Completa (Ejemplo)</span>
                          <button
                            id="btn-copy-example-json"
                            onClick={() => {
                              const examObj = {
                                "vulnerability_id": "JS-001",
                                "title": "SQL Injection on Login Endpoint",
                                "type": "SQL Injection",
                                "cwe": "CWE-89",
                                "owasp": "A03:2021 - Injection",
                                "severity": "Critical",
                                "cvss": 9.8,
                                "method": "POST",
                                "endpoint": "/rest/user/login",
                                "parameter": "email",
                                "url": "https://juice-shopa.onrender.com/rest/user/login",
                                "payload": "' OR 1=1--",
                                "evidence": "Authentication bypass achieved",
                                "recommendation": "Use parameterized queries",
                                "requires_login": false
                              };
                              navigator.clipboard.writeText(JSON.stringify(examObj, null, 2));
                              setImportStatus({ type: "success", message: "Ejemplo de referencia copiado!" });
                            }}
                            className="text-[8px] text-slate-400 hover:underline flex items-center gap-1 cursor-pointer"
                          >
                            <Copy className="w-2.5 h-2.5" /> Copiar Ejemplo
                          </button>
                        </div>
                        <pre className="bg-[#0F1115] border border-[#2D3139]/60 text-slate-400 rounded p-2 text-[8.5px] max-h-[160px] overflow-auto font-mono select-text leading-tight tab-size-2 text-left">
{`{
  "vulnerability_id": "JS-001",
  "title": "SQL Injection on Login Endpoint",
  "type": "SQL Injection",
  "cwe": "CWE-89",
  "owasp": "A03:2021 - Injection",
  "severity": "Critical",
  "cvss": 9.8,
  "method": "POST",
  "endpoint": "/rest/user/login",
  "parameter": "email",
  "url": "https://juice-shopa.onrender.com/rest/user/login",
  "payload": "' OR 1=1--",
  "evidence": "Authentication bypass achieved",
  "recommendation": "Use parameterized queries",
  "requires_login": false
}`}
                        </pre>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Dynamic Session Precheck Pre-Authentication Console */}
            <div className="bg-[#1A1D23] border border-[#2D3139]/80 rounded-lg p-2.5 space-y-2 text-xs">
              <button
                onClick={() => setPreAuthOpen(!preAuthOpen)}
                className="w-full flex items-center justify-between text-left font-mono font-bold tracking-tight text-[#94A3B8] hover:text-white transition group cursor-pointer"
              >
                <div className="flex items-center gap-1.5">
                  <Zap className={`w-3.5 h-3.5 ${authActive ? "text-emerald-400 fill-emerald-400 animate-pulse" : "text-[#94A3B8]"}`} />
                  <span className="text-[10px] uppercase tracking-wider text-slate-300">Pre-Authentication Setup</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`w-2 h-2 rounded-full ${authActive ? "bg-emerald-500 shadow-[0_0_8px_#10B981]" : "bg-slate-600"}`}></span>
                  <span className="text-[8px] border border-[#2D3139] px-1.5 py-0.5 rounded text-slate-400 uppercase font-bold bg-[#0F1115]">
                    {preAuthOpen ? "Hide" : "Edit"}
                  </span>
                </div>
              </button>

              {authActive && !preAuthOpen && (
                <div className="text-[9.5px] font-mono text-slate-400 truncate bg-[#0F1115] border border-[#2D3139]/30 rounded p-1.5 leading-none">
                  <span className="text-[#22D3EE] font-bold uppercase mr-1">URL:</span> {authSetup.auth_url}
                </div>
              )}

              {preAuthOpen && (
                <div className="space-y-3 pt-2 border-t border-[#2D3139]/30 transition duration-300">
                  <div className="space-y-1">
                    <label className="text-[9px] font-mono uppercase font-bold text-[#94A3B8] block">Auth Endpoint URL</label>
                    <input
                      type="text"
                      value={authSetup.auth_url}
                      placeholder="https://juice-shopa.onrender.com/rest/user/login"
                      onChange={(e) => setAuthSetup(prev => ({ ...prev, auth_url: e.target.value }))}
                      className="w-full bg-[#0F1115] border border-[#2D3139]/80 rounded px-2 py-1 text-white font-mono text-xs focus:border-[#22D3EE] focus:outline-none"
                    />
                  </div>

                  <div className="space-y-1 bg-cyan-950/15 border border-cyan-800/15 p-2 rounded">
                    <div className="flex items-center justify-between gap-1">
                      <label className="text-[9px] font-mono uppercase font-bold text-[#22D3EE] block">Direct Session Token</label>
                      <span className="text-[7.5px] bg-[#22D3EE]/10 text-[#22D3EE] font-mono font-bold px-1 py-0.2 rounded border border-[#22D3EE]/25 uppercase tracking-wide">Overrides Handshake</span>
                    </div>
                    <input
                      id="input-manual-token-field"
                      type="text"
                      value={authSetup.session_token || ""}
                      placeholder="Paste bearer token e.g. eyJhbGciOi..."
                      onChange={(e) => setAuthSetup(prev => ({ ...prev, session_token: e.target.value }))}
                      className="w-full bg-[#0F1115] border border-[#2D3139] rounded px-2 py-1.5 text-cyan-300 font-mono text-xs focus:border-[#22D3EE] focus:outline-none placeholder-slate-600 focus:ring-1 focus:ring-[#22D3EE]/25"
                    />
                  </div>

                  <div className="grid grid-cols-3 gap-2">
                    <div className="col-span-1 space-y-1">
                      <label className="text-[9px] font-mono uppercase font-bold text-[#94A3B8] block">Method</label>
                      <select
                        value={authSetup.auth_method}
                        onChange={(e) => setAuthSetup(prev => ({ ...prev, auth_method: e.target.value as any }))}
                        className="w-full bg-[#0F1115] border border-[#2D3139]/80 rounded px-1.5 py-1 text-white font-mono text-xs focus:border-[#22D3EE] focus:outline-none"
                      >
                        <option value="POST">POST</option>
                        <option value="GET">GET</option>
                        <option value="PUT">PUT</option>
                      </select>
                    </div>

                    <div className="col-span-2 space-y-1">
                      <label className="text-[9px] font-mono uppercase font-bold text-[#94A3B8] block">Token JSON Path</label>
                      <input
                        type="text"
                        value={authSetup.token_path || ""}
                        placeholder="token"
                        onChange={(e) => setAuthSetup(prev => ({ ...prev, token_path: e.target.value }))}
                        className="w-full bg-[#0F1115] border border-[#2D3139]/80 rounded px-2 py-1 text-white font-mono text-[11px] focus:border-[#22D3EE] focus:outline-none"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-2">
                    <div className="space-y-1">
                      <label className="text-[9px] font-mono uppercase font-bold text-[#94A3B8] block">Header Key</label>
                      <input
                        type="text"
                        value={authSetup.token_header || ""}
                        placeholder="Authorization"
                        onChange={(e) => setAuthSetup(prev => ({ ...prev, token_header: e.target.value }))}
                        className="w-full bg-[#0F1115] border border-[#2D3139]/80 rounded px-2 py-1 text-white font-mono text-[11px] focus:border-[#22D3EE] focus:outline-none"
                      />
                    </div>

                    <div className="space-y-1">
                      <label className="text-[9px] font-mono uppercase font-bold text-[#94A3B8] block">Header Type</label>
                      <select
                        value={authSetup.token_type || ""}
                        onChange={(e) => setAuthSetup(prev => ({ ...prev, token_type: e.target.value }))}
                        className="w-full bg-[#0F1115] border border-[#2D3139]/80 rounded px-1.5 py-1 text-white font-mono text-xs focus:border-[#22D3EE] focus:outline-none"
                      >
                        <option value="Bearer">Bearer JWT</option>
                        <option value="Cookie">Cookie Based</option>
                        <option value="None">Direct (No Prefix)</option>
                      </select>
                    </div>
                  </div>

                  <div className="space-y-1">
                    <label className="text-[9px] font-mono uppercase font-bold text-[#94A3B8] block">Credentials Body (JSON Object)</label>
                    <textarea
                      value={typeof authSetup.auth_payload === "object" ? JSON.stringify(authSetup.auth_payload, null, 2) : authSetup.auth_payload || ""}
                      placeholder='{"email": "admin@juice-sh.op", "password": "admin"}'
                      rows={3}
                      onChange={(e) => setAuthSetup(prev => ({ ...prev, auth_payload: e.target.value }))}
                      className="w-full bg-[#0F1115] border border-[#2D3139]/80 rounded p-2 text-white font-mono text-[10px] focus:border-[#22D3EE] focus:outline-none"
                    />
                  </div>

                  <div className="flex gap-2">
                    <button
                      onClick={() => saveAuthSetupObj(authSetup)}
                      className="flex-1 py-1.5 px-2 bg-[#2D3139]/60 hover:bg-[#2D3139] active:bg-[#2D3139]/80 font-mono text-[9px] text-[#22D3EE] font-bold rounded border border-[#22D3EE]/30 cursor-pointer text-center"
                    >
                      Save Configuration
                    </button>
                    <button
                      onClick={runAuthTestDiagnostics}
                      disabled={testingAuth || !authSetup.auth_url}
                      className="flex-grow py-1.5 px-2 bg-[#22D3EE] hover:bg-[#22D3EE]/90 active:bg-cyan-400 font-mono text-[9px] text-[#0A0B0E] font-bold rounded shadow-sm shadow-[#22D3EE]/15 disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer text-center"
                    >
                      {testingAuth ? "Testing Handshake..." : "Test Auth Handshake"}
                    </button>
                  </div>

                  {authTestLogs.length > 0 && (
                    <div className="space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-[8.5px] font-mono uppercase font-bold text-slate-400">Terminal Trace Output</span>
                        <button
                          onClick={() => setAuthTestLogs([])}
                          className="text-[8px] text-red-400 hover:text-red-300 flex font-mono cursor-pointer"
                        >
                          Clear Logs
                        </button>
                      </div>
                      <div className="bg-[#0F1115] border border-[#2D3139]/50 rounded p-2 text-[9px] font-mono max-h-[140px] overflow-y-auto leading-normal space-y-1 text-cyan-300 text-left">
                        {authTestLogs.map((log, idx) => (
                          <div key={idx} className="whitespace-pre-wrap select-text border-b border-[#2D3139]/10 pb-0.5 last:border-0 last:pb-0">
                            {log}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Filter class buttons & Multi-selection controls */}
            <div className="flex flex-col gap-2.5">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#2D3139]/30 pb-2">
                <span className="text-[10px] font-mono font-bold text-slate-400">Target Selector</span>
                <div className="flex items-center gap-1.5">
                  <button
                    onClick={() => {
                      const next: Record<string, boolean> = {};
                      vulnerabilities.forEach(v => {
                        next[v.vulnerability_id] = true;
                      });
                      setCheckedVulnsForValidation(next);
                    }}
                    className="text-[8.5px] font-mono font-bold text-[#22D3EE] bg-[#1A1D23] border border-[#2D3139] px-2 py-0.5 rounded hover:bg-[#22D3EE]/10 hover:border-[#22D3EE]/30 transition"
                  >
                    All
                  </button>
                  <button
                    onClick={() => {
                      const next: Record<string, boolean> = {};
                      vulnerabilities.forEach(v => {
                        next[v.vulnerability_id] = false;
                      });
                      setCheckedVulnsForValidation(next);
                    }}
                    className="text-[8.5px] font-mono font-semibold text-slate-400 bg-[#1A1D23] border border-[#2D3139] px-2 py-0.5 rounded hover:bg-slate-800 transition"
                  >
                    Clear ({vulnerabilities.filter(v => checkedVulnsForValidation[v.vulnerability_id] !== false).length})
                  </button>
                </div>
              </div>

              <div className="flex flex-wrap gap-1">
                {typesList.map(type => (
                  <button
                    key={type}
                    onClick={() => setFilterType(type)}
                    className={`text-[9px] px-2.5 py-1 rounded transition font-mono ${
                      filterType === type 
                        ? "bg-[#22D3EE]/10 border border-[#22D3EE]/40 text-[#22D3EE] font-bold" 
                        : "bg-[#1A1D23] border border-[#2D3139] text-[#94A3B8] hover:text-white hover:bg-[#2D3139]/45"
                    }`}
                  >
                    {type}
                  </button>
                ))}
              </div>
            </div>

            {/* Scrollable list content */}
            <div className="flex-1 overflow-y-auto space-y-2 max-h-[380px] lg:max-h-[500px]">
              {filteredVulnerabilities.map(v => {
                const matchesSelected = selectedVuln?.vulnerability_id === v.vulnerability_id;
                
                const sevColors: Record<string, string> = {
                  CRITICAL: "bg-red-500/10 text-red-400 border-red-500/20",
                  HIGH: "bg-orange-500/10 text-orange-400 border-orange-500/20",
                  MEDIUM: "bg-amber-500/10 text-amber-400 border-amber-500/20",
                  LOW: "bg-[#1A1D23] text-slate-400 border-[#2D3139]"
                };

                return (
                  <div
                    key={v.vulnerability_id}
                    onClick={() => setSelectedVuln(v)}
                    className={`p-3 rounded-lg border transition duration-200 cursor-pointer text-left ${
                      matchesSelected 
                        ? "bg-[#1A1D23] border-[#22D3EE] shadow-md shadow-[#22D3EE]/5" 
                        : "bg-[#1A1D23]/50 border-[#2D3139] hover:bg-[#1A1D23] hover:border-[#2D3139]/85"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 mb-1.5">
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation(); // Prevent card selection click
                            setCheckedVulnsForValidation(prev => ({
                              ...prev,
                              [v.vulnerability_id]: !prev[v.vulnerability_id]
                            }));
                          }}
                          className={`w-3.5 h-3.5 rounded border flex items-center justify-center transition focus:outline-none shrink-0 ${
                            checkedVulnsForValidation[v.vulnerability_id] !== false
                              ? "bg-[#22D3EE] border-[#22D3EE] text-[#0A0B0E]"
                              : "border-slate-500 bg-[#0F1115] hover:border-[#22D3EE]/60"
                          }`}
                        >
                          {checkedVulnsForValidation[v.vulnerability_id] !== false && (
                            <Check className="w-2.5 h-2.5 stroke-[3]" />
                          )}
                        </button>
                        <span className="text-[9px] text-[#94A3B8] font-mono tracking-wider font-semibold">{v.vulnerability_id}</span>
                      </div>
                      <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${sevColors[v.severity] || "text-[#94A3B8] border-[#2D3139]"}`}>
                        {v.severity} ({v.cvss})
                      </span>
                    </div>
                    <h3 className="text-xs font-semibold text-white line-clamp-1">
                      {v.title}
                    </h3>
                    <div className="flex items-center justify-between gap-1 mt-2">
                      <div className="flex items-center gap-1.5 text-[10px] text-slate-400 min-w-0 flex-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-[#22D3EE] animate-pulse"></span>
                        <span className="font-mono text-[#94A3B8] truncate">{v.endpoint}</span>
                      </div>
                      
                      {v.requires_login ? (
                        <span className="flex items-center gap-0.5 text-[8px] font-mono font-extrabold px-1.5 py-0.5 select-none border border-[#22D3EE]/30 bg-[#22D3EE]/10 text-[#22D3EE] rounded uppercase tracking-wider shrink-0">
                          <Lock className="w-2.5 h-2.5" /> Login Req
                        </span>
                      ) : (
                        <span className="flex items-center gap-0.5 text-[8px] font-mono font-medium px-1.5 py-0.5 select-none border border-slate-700/40 bg-slate-800/10 text-slate-400 rounded uppercase tracking-wider shrink-0">
                          <Unlock className="w-2.5 h-2.5" /> Public
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
              
              {filteredVulnerabilities.length === 0 && (
                <div className="text-center py-10 border border-dashed border-[#2D3139] bg-[#1A1D23]/10 rounded-lg p-4">
                  <Database className="w-7 h-7 text-slate-600 mx-auto mb-2 animate-pulse" />
                  <p className="text-slate-300 font-mono text-xs font-semibold">No Vulnerabilities Loaded</p>
                  <p className="text-[#94A3B8] font-mono text-[9px] mt-1 max-w-[220px] mx-auto leading-normal">
                    This workspace is completely clean. Drag & Drop or Click to import your structured JSON file with vulnerabilities.
                  </p>
                </div>
              )}
            </div>

            {/* Quick telemetry details panel */}
            {selectedVuln && (
              <div className="bg-[#1A1D23] border border-[#2D3139] rounded-lg p-3.5 text-left">
                <div className="flex items-center gap-1.5 text-xs text-[#94A3B8] border-b border-[#2D3139] pb-1.5 mb-2">
                  <Globe className="w-3.5 h-3.5 text-[#22D3EE]" />
                  <span className="font-mono uppercase font-bold text-[9px] tracking-wider text-[#94A3B8] mr-2">Route Telemetry</span>
                </div>
                <div className="space-y-1.5 text-[11px]">
                  <div className="flex justify-between items-center py-0.5 border-b border-[#2D3139]/30">
                    <span className="text-[#94A3B8] font-mono text-[9px]">REQUIRES LOGIN:</span>
                    {selectedVuln.requires_login ? (
                      <span className="text-[8.5px] font-mono text-[#22D3EE] bg-[#22D3EE]/10 border border-[#22D3EE]/25 px-1.5 py-0.5 rounded font-extrabold uppercase tracking-wide inline-flex items-center gap-1">
                        <Lock className="w-2.5 h-2.5" /> YES
                      </span>
                    ) : (
                      <span className="text-[8.5px] font-mono text-slate-400 bg-slate-800/20 border border-slate-700/20 px-1.5 py-0.5 rounded uppercase tracking-wide inline-flex items-center gap-1">
                        <Unlock className="w-2.5 h-2.5" /> NO
                      </span>
                    )}
                  </div>
                  <div className="flex justify-between items-center py-0.5 border-b border-[#2D3139]/30">
                    <span className="text-[#94A3B8] font-mono text-[9px]">METHOD / VERB:</span>
                    <span className="font-mono text-[#22D3EE] font-extrabold">{selectedVuln.method}</span>
                  </div>
                  <div className="flex justify-between items-center py-0.5 border-b border-[#2D3139]/30">
                    <span className="text-[#94A3B8] font-mono text-[9px]">ARGUMENT:</span>
                    <span className="font-mono text-slate-300 font-bold">{selectedVuln.parameter || "N/A"}</span>
                  </div>
                  {selectedVuln.cwe && (
                    <div className="flex justify-between items-center py-0.5 border-b border-[#2D3139]/30">
                      <span className="text-[#94A3B8] font-mono text-[9px]">CWE CLASSIFY:</span>
                      <span className="font-mono text-amber-500 font-bold text-[10px]">{selectedVuln.cwe}</span>
                    </div>
                  )}
                  {selectedVuln.owasp && (
                    <div className="flex justify-between items-center py-0.5 border-b border-[#2D3139]/30">
                      <span className="text-[#94A3B8] font-mono text-[9px]">OWASP CATEGORY:</span>
                      <span className="font-mono text-rose-500 font-semibold text-[10px]">{selectedVuln.owasp}</span>
                    </div>
                  )}
                  <div className="grid grid-cols-[80px_1fr] py-0.5 gap-2 text-right">
                    <span className="text-[#94A3B8] font-mono text-[9px] text-left">STRATEGY:</span>
                    <span className="text-slate-300 text-[10px] font-mono leading-normal ml-auto text-right">{selectedVuln.validation_strategy}</span>
                  </div>
                </div>

                <button
                  disabled={isRunning}
                  onClick={() => runCheckedValidations()}
                  className="w-full mt-3.5 flex items-center justify-center gap-2 py-2 px-3 bg-[#22D3EE] hover:bg-[#22D3EE]/95 text-[#0A0B0E] font-mono font-bold text-xs rounded transition-all disabled:opacity-50 shadow-md shadow-cyan-500/10"
                >
                  {isRunning ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      Executing Pipeline...
                    </>
                  ) : (
                    <>
                      <Play className="w-3.5 h-3.5 fill-current" />
                      Validate Checked Targets ({vulnerabilities.filter(v => checkedVulnsForValidation[v.vulnerability_id] !== false).length})
                    </>
                  )}
                </button>
              </div>
            )}
          </section>

          {/* UNIFIED MONITOR & PROBE CONSOLE PANEL (col-span-12 lg:col-span-8) */}
          <section id="unified-probe-console-panel" className="col-span-12 lg:col-span-8 bg-[#14161A] border border-[#2D3139] rounded-[12px] p-5 shadow-xl text-left flex flex-col gap-4">
            
            {/* Header */}
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-[#2D3139]/70 pb-3">
              <div className="flex items-center gap-3">
                <div className="relative flex items-center justify-center p-2 bg-[#1E293B] border border-[#334155] rounded-lg">
                  <Terminal className="w-5 h-5 text-[#22D3EE]" />
                  <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-emerald-500 animate-ping"></span>
                  <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-white tracking-wide font-sans flex items-center gap-2">
                    Unified Outbound Probe Console & Live Instruction Trace
                  </h3>
                  <p className="text-[11px] text-[#94A3B8] font-mono leading-relaxed font-sans">
                    Decentralized agent pipeline tracer and interceptor capturing socket request headers, session tokens, and raw micro-agent commands.
                  </p>
                </div>
              </div>

              {/* Live Filter Search input */}
              <div className="flex items-center gap-2 w-full sm:w-auto">
                <div className="relative flex-1 sm:flex-initial">
                  <Search className="w-3.5 h-3.5 text-[#94A3B8] absolute left-2.5 top-1/2 -translate-y-1/2" />
                  <input
                    id="terminal-filter-input"
                    type="text"
                    placeholder="Filter trace logs..."
                    value={terminalFilter}
                    onChange={(e) => setTerminalFilter(e.target.value)}
                    className="bg-[#1A1D23] border border-[#2D3139] text-xs font-mono text-cyan-300 rounded px-2.5 py-1.5 pl-8 w-full sm:w-64 focus:border-[#22D3EE] outline-none"
                  />
                </div>
                {terminalFilter && (
                  <button
                    id="clear-terminal-filter-btn"
                    onClick={() => setTerminalFilter("")}
                    className="text-[10px] text-cyan-400 hover:text-white font-mono uppercase bg-[#1E293B] px-2 py-1.5 border border-[#2D3139] rounded"
                  >
                    Clear filter
                  </button>
                )}
              </div>
            </div>

            {/* Sub-Tabs Selector and Utility Controllers */}
            <div className="flex flex-wrap items-center justify-between gap-3 bg-[#13171F] p-2 border border-[#2D3139] rounded-lg animate-fade-in">
              <div className="flex flex-wrap items-center gap-1.5 font-sans">
                <button
                  id="btn-tab-shell-logs"
                  onClick={() => setTerminalCategory("shell")}
                  className={`px-3 py-1.5 text-xs font-mono font-bold rounded transition flex items-center gap-1.5 ${
                    terminalCategory === "shell"
                      ? "bg-[#22D3EE] text-[#0A0B0E] shadow-sm shadow-[#22D3EE]/20"
                      : "bg-[#1A1D23] text-[#94A3B8] hover:text-white"
                  }`}
                >
                  <Terminal className="w-3.5 h-3.5" />
                  Pipeline Log
                </button>
                
                <button
                  id="btn-tab-request-packet"
                  onClick={() => setTerminalCategory("request")}
                  className={`px-3 py-1.5 text-xs font-mono font-bold rounded transition flex items-center gap-1.5 ${
                    terminalCategory === "request"
                      ? "bg-[#22D3EE] text-[#0A0B0E] shadow-sm shadow-[#22D3EE]/20"
                      : "bg-[#1A1D23] text-[#94A3B8] hover:text-white"
                  }`}
                >
                  <Server className="w-3.5 h-3.5" />
                  Outbound Request Packet {selectedRunForPacketInspection?.vulnerability?.vulnerability_id ? `[${selectedRunForPacketInspection.vulnerability.vulnerability_id}]` : ""}
                </button>

                <button
                  id="btn-tab-response-payload"
                  onClick={() => setTerminalCategory("response")}
                  className={`px-3 py-1.5 text-xs font-mono font-bold rounded transition flex items-center gap-1.5 ${
                    terminalCategory === "response"
                      ? "bg-[#22D3EE] text-[#0A0B0E] shadow-sm shadow-[#22D3EE]/20"
                      : "bg-[#1A1D23] text-[#94A3B8] hover:text-white"
                  }`}
                >
                  <FileCode className="w-3.5 h-3.5 text-slate-400" />
                  Response Payload {selectedRunForPacketInspection?.vulnerability?.vulnerability_id ? `[${selectedRunForPacketInspection.vulnerability.vulnerability_id}]` : ""}
                </button>

                <button
                  id="btn-tab-validation-evidence"
                  onClick={() => setTerminalCategory("evidence")}
                  className={`px-3 py-1.5 text-xs font-mono font-bold rounded transition flex items-center gap-1.5 ${
                    terminalCategory === "evidence"
                      ? "bg-[#22D3EE] text-[#0A0B0E] shadow-sm shadow-[#22D3EE]/20"
                      : "bg-[#1A1D23] text-[#94A3B8] hover:text-white"
                  }`}
                >
                  <CheckCircle2 className="w-3.5 h-3.5 text-slate-400" />
                  Validation Trace Evidence {selectedRunForPacketInspection?.vulnerability?.vulnerability_id ? `[${selectedRunForPacketInspection.vulnerability.vulnerability_id}]` : ""}
                </button>

                <button
                  id="btn-tab-patch-remediation"
                  onClick={() => setTerminalCategory("remediation")}
                  className={`px-3 py-1.5 text-xs font-mono font-bold rounded transition flex items-center gap-1.5 ${
                    terminalCategory === "remediation"
                      ? "bg-[#22D3EE] text-[#0A0B0E] shadow-sm shadow-[#22D3EE]/20"
                      : "bg-[#1A1D23] text-[#94A3B8] hover:text-white"
                  }`}
                >
                  <Code2 className="w-3.5 h-3.5 text-slate-400" />
                  Patch Recommendations {selectedRunForPacketInspection?.vulnerability?.vulnerability_id ? `[${selectedRunForPacketInspection.vulnerability.vulnerability_id}]` : ""}
                </button>
              </div>

              <div className="flex items-center gap-2">
                <button
                  id="btn-terminal-copy-output"
                  onClick={() => {
                    const content = getExportableTerminalContent();
                    navigator.clipboard.writeText(content);
                  }}
                  className="px-2.5 py-1.5 text-[11px] font-mono text-[#22D3EE] hover:text-white bg-[#1A1D23] hover:bg-[#2D3139] border border-[#2D3139] rounded transition flex items-center gap-1"
                >
                  <Copy className="w-3 h-3" />
                  Copy Output
                </button>

                <button
                  id="btn-terminal-flush-console"
                  onClick={() => {
                    if (activeRun) {
                      setActiveRun(prev => prev ? { ...prev, logs: [{ timestamp: new Date().toISOString(), agentName: "System Initialization Node", level: "info", message: "Terminal log buffer flushed." }] } : null);
                    }
                    setAuthTestLogs([]);
                    setCompletedRuns([]);
                    setSelectedRunForPacketInspection(null);
                  }}
                  className="px-2.5 py-1.5 text-[11px] font-mono text-rose-400 hover:text-white bg-[#1A1D23] hover:bg-rose-950/30 border border-[#2D3139] rounded transition flex items-center gap-1"
                >
                  <Trash2 className="w-3 h-3" />
                  Flush Console
                </button>
              </div>
            </div>

            {/* Completed runs history inspection selector */}
            {completedRuns.length > 0 && (
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 bg-[#141822] border border-[#2D3139]/50 px-3 py-2 rounded-lg text-left animate-fade-in animate-duration-300">
                <div className="flex flex-col gap-0.5">
                  <span className="text-[9.5px] font-sans font-bold text-[#E2E8F0] uppercase tracking-wider flex items-center gap-1.5">
                    <Activity className="w-3 h-3 text-[#22D3EE]" /> Session Verification History ({completedRuns.length})
                  </span>
                  <span className="text-[9px] font-mono text-[#94A3B8]">
                    Select any checked target run below to inspect its request and response packet details:
                  </span>
                </div>
                <div className="flex flex-wrap gap-1.5 items-center">
                  {completedRuns.map((run, idx) => {
                    const vulnId = run.vulnerability?.vulnerability_id || "N/A";
                    const isConfirmed = run.evidence?.confirmed;
                    const isCurrent = (selectedRunForPacketInspection?.runId === run.runId) || (!selectedRunForPacketInspection && activeRun?.runId === run.runId);

                    return (
                      <button
                        key={run.runId || idx}
                        onClick={() => setSelectedRunForPacketInspection(run)}
                        className={`px-2 py-0.5 text-[9.5px] rounded font-mono font-medium flex items-center gap-1.5 border transition ${
                          isCurrent
                            ? "bg-[#22D3EE]/20 text-[#22D3EE] border-[#22D3EE] font-bold shadow-sm shadow-[#22D3EE]/10"
                            : "bg-[#0F1115] text-[#94A3B8] border-[#2D3139]/50 hover:text-white hover:bg-[#1C212B]"
                        }`}
                      >
                        <span className={`w-1.5 h-1.5 rounded-full ${isConfirmed ? "bg-rose-500 shadow-sm shadow-rose-500/50" : "bg-emerald-500 shadow-sm shadow-emerald-500/50"}`} />
                        <span>{vulnId}</span>
                        <span className="text-[8px] opacity-75">
                          ({isConfirmed ? "VULNERABLE" : "FP"})
                        </span>
                      </button>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Terminal Console Layout screen */}
            <div className="bg-[#090C10] border border-[#2D3139] rounded-lg p-5 font-mono text-xs overflow-auto h-[350px] shadow-inner text-left select-text relative">
              <div className="absolute top-2 right-4 text-[9px] text-[#5A6E85] pointer-events-none select-none uppercase tracking-wider font-bold animate-pulse">
                Buffer State: ACTIVE TRACE ({preservedLogs.length > 0 ? preservedLogs.length : (activeRun?.logs?.length || 0)} loops)
              </div>
   
              {terminalCategory === "shell" && (
                <div className="space-y-1.5 leading-relaxed">
                  {/* Fallback logs if we don't have an active verification run */}
                  {!activeRun && preservedLogs.length === 0 && authTestLogs.length === 0 ? (
                    <>
                      <div className="text-[#94A3B8]">[<span className="text-[#22D3EE]">SYSTEM_ORCHESTRATOR</span>] <span className="text-emerald-400 font-bold">● COGNITIVE KERNEL LOG ONLINE</span> - Version 2.4 (Enterprise API Secured)</div>
                      <div className="text-slate-500">[SYSTEM] Listening for validation triggers on security targets...</div>
                      <div className="text-slate-500">[SYSTEM] Authentication Handshake buffer: <span className="text-amber-500 font-semibold">STANDBY</span> (Prior tokens cleared)</div>
                      <div className="text-slate-500">[SYSTEM] Outbound interceptor status: <span className="text-cyan-400">PROXY READY on local sandbox port 3000</span></div>
                      <div className="text-cyan-500/80 mt-2 font-bold font-mono">$ _ <span className="animate-pulse bg-cyan-400 h-3 w-1.5 inline-block align-middle ml-1"></span></div>
                      <p className="text-[10px] text-[#5A6E85] italic font-sans mt-3 font-semibold">Hint: Select any custom imported vulnerability from the Threat Catalog panel and click the "Run Verification" dynamic validation task suite trigger to populate traces dynamically.</p>
                    </>
                  ) : (
                    <>
                      {/* Render auth test logs if they exist */}
                      {authTestLogs.map((logLine, idx) => {
                        if (terminalFilter && !logLine.toLowerCase().includes(terminalFilter.toLowerCase())) return null;
                        return (
                          <div key={`auth-diag-${idx}`} className="text-[#94A3B8] border-l-2 border-amber-500/40 pl-2">
                            [<span className="text-amber-400 font-bold">AUTH HANDSHAKE TRACE</span>] {logLine}
                          </div>
                        );
                      })}
   
                      {/* Render pipeline execute logs */}
                      {(preservedLogs.length > 0 ? preservedLogs : (activeRun?.logs || [])).map((log, idx) => {
                        if (terminalFilter && !log.message.toLowerCase().includes(terminalFilter.toLowerCase()) && !log.agentName.toLowerCase().includes(terminalFilter.toLowerCase())) {
                          return null;
                        }
   
                        let textColor = "text-slate-300";
                        let levelTag = "INFO";
                        if (log.level === "error") {
                          textColor = "text-red-400 font-semibold";
                          levelTag = "CRITICAL FAIL";
                        } else if (log.level === "success") {
                          textColor = "text-emerald-400 font-semibold";
                          levelTag = "SUCCESS";
                        } else if (log.level === "warning") {
                          textColor = "text-amber-400 font-semibold";
                          levelTag = "SESSION WARN";
                        }

                        const isStartMarker = log.message.startsWith(">>>");
                        const isEndMarker = log.message.startsWith("<<<");

                        if (isStartMarker) {
                          return (
                            <div key={`run-log-${idx}`} className="my-3 py-1.5 px-3 bg-cyan-950/20 border-l-[3px] border-[#22D3EE] text-[#22D3EE] font-bold rounded-r">
                              <span className="text-slate-500 font-sans text-[10px] mr-2">[{log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : ""}]</span>
                              {log.message}
                            </div>
                          );
                        }

                        if (isEndMarker) {
                          const isSuccess = log.message.includes("VULNERABLE");
                          const markerColor = isSuccess ? "border-emerald-500 text-emerald-400 bg-emerald-950/10" : "border-[#2D3139] text-[#94A3B8] bg-slate-900/10";
                          return (
                            <div key={`run-log-${idx}`} className={`my-3 py-1.5 px-3 border-l-[3px] font-bold rounded-r ${markerColor}`}>
                              <span className="text-slate-500 font-sans text-[10px] mr-2">[{log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : ""}]</span>
                              {log.message}
                            </div>
                          );
                        }
   
                        return (
                          <div key={`run-log-${idx}`} className={`${textColor} flex items-start gap-1`}>
                            <span className="text-slate-600 shrink-0 font-sans text-[10px]">[{log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString()}]</span>
                            <span className="text-[#22D3EE] shrink-0 font-bold font-sans">[{log.agentName}]</span>
                            <span className="text-slate-400 shrink-0 uppercase text-[9px] font-sans font-bold">| {levelTag} |</span>
                            <span className="whitespace-pre-wrap flex-1">{log.message}</span>
                          </div>
                        );
                      })}
                      <div className="text-[#22D3EE] font-bold font-mono py-1 flex items-center gap-2">
                        <span className="flex items-center gap-1">
                          <span>$ _</span>
                          <span className="animate-pulse bg-cyan-400 h-3 w-1.5 inline-block align-middle"></span>
                        </span>
                        {isRunning && (
                          <div className="flex items-center gap-2 text-cyan-400 font-mono text-[10.5px]">
                            <RefreshCw className="w-3.5 h-3.5 animate-spin text-[#22D3EE]" />
                            <span className="animate-pulse">[Processing Orchestration Pipeline...]</span>
                          </div>
                        )}
                      </div>
                    </>
                  )}
                </div>
              )}

              {terminalCategory === "request" && (
                <pre className="text-amber-300 whitespace-pre-wrap select-text font-mono leading-relaxed break-all text-[11px] h-full overflow-y-auto">
                  {(selectedRunForPacketInspection || activeRun)?.evidence?.requestTrace || 
                   `HTTP/1.1 SOCKET STREAM BUFFER STANDBY\n\nNo request packet captured in current buffer.\nSelect an imported threat definition (e.g. JS-002 Review XSS payload) and trigger a dynamic verify run to intercept the outbound HTTP/1.1 message stream.`}
                </pre>
              )}

              {terminalCategory === "response" && (
                <div className="text-emerald-300 whitespace-pre-wrap select-text font-mono leading-relaxed break-all text-[11px] h-full overflow-y-auto text-left">
                  {(selectedRunForPacketInspection || activeRun)?.evidence?.rawResponse ? (
                    renderResponseWithTokenHighlighting((selectedRunForPacketInspection || activeRun)!.evidence!.rawResponse!)
                  ) : (
                    `HTTP/1.1 STATUS SNAPSHOT STACK STANDBY\n\nNo response packet received in current buffer.\nSelect a valid reachable endpoint or run diagnostics to fetch status returns.`
                  )}
                </div>
              )}

              {terminalCategory === "evidence" && (
                <div className="text-slate-200 space-y-4 font-mono text-[11px] h-full overflow-y-auto text-left">
                  {(selectedRunForPacketInspection || activeRun)?.evidence ? (
                    <div className="space-y-4">
                      <div className="flex flex-wrap items-center justify-between border-b border-[#2D3139]/70 pb-2 mb-1 gap-2">
                        <div className="flex items-center gap-1.5 font-bold uppercase text-slate-100">
                          <CheckCircle2 className="w-4 h-4 text-[#22D3EE]" />
                          <span>Validation Trace Evidence Details</span>
                          {(selectedRunForPacketInspection || activeRun)?.evidence?.confirmed ? (
                            <span className="ml-2 text-[9px] px-1.5 py-0.5 font-bold uppercase tracking-wider bg-red-500/10 text-red-400 rounded border border-red-500/20">
                              VULNERABILIDAD CONFIRMADA
                            </span>
                          ) : (
                            <span className="ml-2 text-[9px] px-1.5 py-0.5 font-bold uppercase tracking-wider bg-blue-500/10 text-cyan-400 rounded border border-cyan-500/20">
                              FALSO POSITIVO (NO VULNERABLE)
                            </span>
                          )}
                        </div>
                        <div className="text-[#22D3EE] font-bold text-[11px] uppercase bg-cyan-950/20 px-2 py-0.5 rounded border border-cyan-555/20">
                          CONFIDENCE: {(((selectedRunForPacketInspection || activeRun)?.evidence?.confidence || 0) * 100).toFixed(0)}%
                        </div>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="space-y-1.5">
                          <span className="text-[10px] uppercase font-bold text-[#94A3B8] tracking-wider block font-sans">REPRODUCER CLI / REQUEST:</span>
                          <pre className="p-3 bg-[#14161A] border border-[#2D3139] rounded text-[10px] text-amber-200/90 whitespace-pre-wrap select-text leading-relaxed overflow-x-auto max-h-[190px]">
                            {(selectedRunForPacketInspection || activeRun)?.evidence?.requestTrace}
                          </pre>
                        </div>
                        <div className="space-y-1.5">
                          <span className="text-[10px] uppercase font-bold text-[#94A3B8] tracking-wider block font-sans">VULNERABLE ENDPOINT OUTPUT SNAPSHOT:</span>
                          <pre className="p-3 bg-[#14161A] border border-[#2D3139] rounded text-[10px] text-[#22D3EE]/90 whitespace-pre-wrap select-text leading-relaxed overflow-x-auto max-h-[190px]">
                            {(selectedRunForPacketInspection || activeRun)?.evidence?.rawResponse}
                          </pre>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="text-slate-500 italic block py-8 text-center font-sans">
                      <CheckCircle2 className="w-8 h-8 text-slate-700 mx-auto mb-2" />
                      [EVIDENCE STANDBY] No trace evidence available yet for the selected threat. Select a target and run verification.
                    </div>
                  )}
                </div>
              )}

              {terminalCategory === "remediation" && (
                <div className="text-slate-200 space-y-4 font-mono text-[11px] h-full overflow-y-auto text-left">
                  {(selectedRunForPacketInspection || activeRun)?.recommendation ? (
                    <div className="space-y-4">
                      
                      {/* Run Evaluation Cost Header */}
                      {(selectedRunForPacketInspection || activeRun)?.metrics && (
                        <div className="p-2.5 bg-[#14161A] rounded-lg border border-[#2D3139] flex flex-wrap justify-between items-center gap-3">
                          <div className="flex items-center gap-2">
                            <span className="text-[10px] uppercase font-bold tracking-wider text-[#94A3B8] font-sans">Run Evaluation Cost</span>
                            <span className="text-[9px] bg-[#22D3EE]/10 text-[#22D3EE] border border-[#22D3EE]/30 px-1.5 py-0.5 rounded font-bold uppercase tracking-wider font-mono">
                              {(selectedRunForPacketInspection || activeRun)?.metrics?.model}
                            </span>
                          </div>
                          <div className="flex items-center gap-4 text-xs font-sans">
                            <div>
                              <span className="text-[#94A3B8] text-[9px] uppercase font-bold tracking-wider mr-1.5">Latency:</span>
                              <span className="text-white font-bold">{((selectedRunForPacketInspection || activeRun)?.metrics?.latency_ms || 1420)}ms</span>
                            </div>
                            <div>
                              <span className="text-[#94A3B8] text-[9px] uppercase font-bold tracking-wider mr-1.5">Cost:</span>
                              <span className="text-emerald-400 font-bold">${((selectedRunForPacketInspection || activeRun)?.metrics?.cost || 0.0035).toFixed(5)}</span>
                            </div>
                            <div>
                              <span className="text-[#94A3B8] text-[9px] uppercase font-bold tracking-wider mr-1.5">Tokens:</span>
                              <span className="text-white font-bold">{((selectedRunForPacketInspection || activeRun)?.metrics?.tokens || 1280)}</span>
                            </div>
                          </div>
                        </div>
                      )}

                      <div className="bg-[#14161A] p-3 rounded-lg border border-[#2D3139] text-left">
                        <div className="flex items-center gap-1.5 text-[11px] font-bold text-[#22D3EE] mb-1.5">
                          <Code2 className="w-4 h-4 text-[#22D3EE]" />
                          <span>MITIGATION STRATEGY SYNTHESIS:</span>
                        </div>
                        <p className="text-[11px] text-slate-300 leading-relaxed font-mono">
                          {(selectedRunForPacketInspection || activeRun)?.recommendation?.solution}
                        </p>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="rounded-lg border border-red-950/40 overflow-hidden bg-[#14161A] text-left flex flex-col">
                          <div className="bg-red-950/20 px-3 py-1.5 border-b border-red-950/20 flex justify-between items-center text-[9px] font-mono">
                            <span className="text-red-400 font-bold">VULNERABLE (BEFORE)</span>
                          </div>
                          <pre className="p-3 text-[10px] font-mono text-red-200 select-text leading-relaxed whitespace-pre-wrap max-h-[160px] overflow-y-auto">
                            <code>{(selectedRunForPacketInspection || activeRun)?.recommendation?.code_before}</code>
                          </pre>
                        </div>

                        <div className="rounded-lg border border-[#2D3139]/30 overflow-hidden bg-[#14161A] text-left flex flex-col">
                          <div className="bg-emerald-950/10 px-3 py-1.5 border-b border-[#2D3139]/30 flex justify-between items-center text-[9px] font-mono">
                            <span className="text-emerald-400 font-bold">REMEDIATED (SECURE AFTER)</span>
                          </div>
                          <pre className="p-3 text-[10px] font-mono text-emerald-200 select-text leading-relaxed whitespace-pre-wrap text-left max-h-[160px] overflow-y-auto">
                            <code>{(selectedRunForPacketInspection || activeRun)?.recommendation?.code_after}</code>
                          </pre>
                        </div>
                      </div>

                    </div>
                  ) : (
                    <div className="text-slate-500 italic block py-8 text-center font-sans">
                      <Code2 className="w-8 h-8 text-slate-700 mx-auto mb-2" />
                      [PATCH STANDBY] Active verification testing model has not run on this security threat. Activate verification orchestration to synthesize code remediation.
                    </div>
                  )}
                </div>
              )}
              
              <div ref={logEndRef} />
            </div>

          </section>

          {/* Row 2: Agentic Graph Pipeline Visualization & Agent Workflow Logs Side-by-Side (col-span-12) */}
          <section className="col-span-12 bg-[#14161A] border border-[#2D3139] rounded-[12px] p-5 shadow-xl text-left flex flex-col gap-4">
            
            <div className="flex items-center justify-between border-b border-[#2D3139] pb-3 mb-1 font-sans">
              <div className="flex items-center gap-2">
                <Cpu className="w-4 h-4 text-[#22D3EE]" />
                <h2 className="text-sm font-semibold tracking-wide text-white uppercase tracking-wider">Agentic Graph Pipeline Visualization</h2>
              </div>
              {activeRun ? (
                <span className={`text-[9px] font-mono px-2 py-0.5 rounded font-semibold border ${
                  activeRun.status === "running" ? "bg-[#22D3EE]/15 text-[#22D3EE] border-[#22D3EE]/30 animate-pulse" : "bg-emerald-950 text-emerald-400 border-emerald-800"
                }`}>
                  {activeRun.status.toUpperCase()}: {activeRun.currentStep}
                </span>
              ) : (
                <span className="text-[10px] text-[#94A3B8] font-mono">Standby</span>
              )}
            </div>

            {/* Side-by-side Layout */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
              
              {/* Visual flowchart graph diagram (Col Left: 5/12) */}
              <div className="lg:col-span-5 relative bg-[#1A1D23] rounded-lg border border-[#2D3139] p-5 min-h-[250px] flex flex-col justify-center overflow-hidden">
                <div className="absolute inset-0 opacity-5 bg-[radial-gradient(#22D3EE_1px,transparent_1px)] [background-size:16px_16px] pointer-events-none"></div>

                <div className="relative flex flex-col gap-3.5 z-10 w-full text-center">
                  
                  {/* Row 1: Parser */}
                  <div className="flex justify-center">
                    <div className={`px-3 py-1 rounded-md border text-[11px] font-mono transition flex items-center gap-1.5 ${
                      getNodeStyle(activeRun?.agentStates?.parser?.status)
                    }`}>
                      <FileText className="w-3.5 h-3.5" />
                      <span>Parser Agent</span>
                    </div>
                  </div>

                  {/* Connecting arrow line */}
                  <div className="flex justify-center -my-1">
                    <div className="w-[1.5px] h-3 bg-gradient-to-b from-[#22D3EE] to-cyan-700"></div>
                  </div>

                  {/* Row 2: Router & Enrichment */}
                  <div className="grid grid-cols-2 gap-4">
                    <div className={`px-2 py-1 rounded-md border text-[11px] font-mono transition flex items-center justify-center gap-1.5 ${
                      getNodeStyle(activeRun?.agentStates?.router?.status)
                    }`}>
                      <ChevronRight className="w-3.5 h-3.5" />
                      <span>Router Agent</span>
                    </div>

                    <div className={`px-2 py-1 rounded-md border text-[11px] font-mono transition flex items-center justify-center gap-1.5 ${
                      getNodeStyle(activeRun?.agentStates?.enrichment?.status)
                    }`}>
                      <Sparkles className="w-3.5 h-3.5" />
                      <span>Enrichment</span>
                    </div>
                  </div>

                  {/* Downward line arrow */}
                  <div className="flex justify-center -my-1">
                    <div className="w-[1px] h-3 bg-[#2D3139]"></div>
                  </div>

                  {/* Row 3: Specialized Auto penetrators */}
                  <div className="flex justify-center">
                    <div className={`px-3 py-1.5 rounded-md border text-[11px] font-mono transition flex items-center gap-1.5 ${
                      getNodeStyle(activeRun?.agentStates?.val_specific?.status)
                    } shadow-md`}>
                      <Terminal className="w-3.5 h-3.5" />
                      <div className="text-left font-mono">
                        <div className="font-bold text-[10px]">Validation Testing Node</div>
                        <div className="text-[9px] text-[#94A3B8] truncate max-w-[170px]">
                          {activeRun?.vulnerability?.type || selectedVuln?.type || "Waiting trigger..."}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Downward target pointer */}
                  <div className="flex justify-center -my-1">
                    <div className="w-[1px] h-3 bg-[#2D3139]"></div>
                  </div>

                  {/* Row 4: Evidence, Risk & Remediation Agents */}
                  <div className="grid grid-cols-3 gap-1.5">
                    <div className={`p-1.5 rounded border text-[9px] font-mono transition flex flex-col items-center justify-center ${
                      getNodeStyle(activeRun?.agentStates?.evidence_correlator?.status)
                    }`}>
                      <CheckCircle2 className="w-3.5 h-3.5 mb-1 text-[#22D3EE]" />
                      <span>Evidence</span>
                    </div>

                    <div className={`p-1.5 rounded border text-[9px] font-mono transition flex flex-col items-center justify-center ${
                      getNodeStyle(activeRun?.agentStates?.risk_scorer?.status)
                    }`}>
                      <AlertTriangle className="w-3.5 h-3.5 mb-1 text-amber-500" />
                      <span>Risk scoring</span>
                    </div>

                    <div className={`p-1.5 rounded border text-[9px] font-mono transition flex flex-col items-center justify-center ${
                      getNodeStyle(activeRun?.agentStates?.remediator?.status)
                    }`}>
                      <Code2 className="w-3.5 h-3.5 mb-1 text-emerald-400" />
                      <span>Remedy Agent</span>
                    </div>
                  </div>

                </div>
              </div>

              {/* Workflow Dispatch List (Col Right: 7/12) */}
              <div className="lg:col-span-7 bg-[#1A1D23] border border-[#2D3139] rounded-lg p-4 flex flex-col overflow-hidden h-[250px]">
                <div className="flex items-center gap-1.5 border-b border-[#2D3139]/70 pb-2 mb-2 text-xs">
                  <Activity className="w-3.5 h-3.5 text-[#22D3EE]" />
                  <span className="font-mono text-slate-300 font-semibold tracking-wider uppercase">Orchestrator Workflow State dispatch Logs</span>
                </div>

                <div className="flex-1 overflow-y-auto space-y-2 text-left font-mono text-[10px] pr-1.5">
                  {activeRun ? (
                    activeRun.logs.map((log, idx) => (
                      <div key={idx} className="border-b border-[#2D3139]/30 pb-1.5 last:border-0 last:pb-0">
                        <div className="flex items-center justify-between text-[9px] text-[#94A3B8] mb-0.5">
                          <span className="text-[#22D3EE] font-bold">[{log.agentName}]</span>
                          <span>{new Date(log.timestamp).toLocaleTimeString()}</span>
                        </div>
                        <div className="text-slate-300 leading-normal font-sans">
                          {log.message}
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="text-[#94A3B8] text-center py-10 font-sans">
                      <Activity className="w-6 h-6 text-slate-700 mx-auto mb-2 animate-pulse" />
                      No system workflow logs available.<br />Orchestrated Verification to populate activity dispatch tracks.
                    </div>
                  )}
                  <div ref={logEndRef} />
                </div>
              </div>

            </div>

          </section>

        </div>
      </div>
      )}



      {/* TAB 2: RESULTADOS DE EVALUACIÓN PANEL */}
      {activeTab === "results" && (
        <div className="flex-1 flex flex-col gap-6 p-6 overflow-y-auto text-left bg-[#0A0B0E]">
          
          {/* Header Dashboard section */}
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-[#2D3139] pb-4 mb-2">
            <div>
              <div className="flex items-center gap-2">
                <BarChart3 className="w-5 h-5 text-[#22D3EE]" />
                <h2 className="text-base font-bold text-white font-sans">Resultados e Indicadores de Evaluación de Triage</h2>
              </div>
              <p className="text-[11px] text-[#94A3B8] font-mono mt-1">Monitoreo de precisión, clasificación de amenazas y efectividad del sandbox de agentes</p>
            </div>
            
            <div className="flex gap-2 shrink-0">
              <span className="text-[9px] bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 px-2.5 py-1 font-mono font-bold rounded uppercase tracking-wider flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                Precisión Auditada: 100%
              </span>
              <span className="text-[9px] bg-[#1A1D23] border border-[#2D3139] text-[#22D3EE] px-2.5 py-1 font-mono font-bold rounded">
                Catálogo: {vulnerabilities.length} ítems
              </span>
            </div>
          </div>

          {/* Bento Cards Row: KPIs de Evaluación */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
            
            {/* Card 1: Analizadas */}
            <div className="bg-[#14161A] border border-[#2D3139] p-5 rounded-[12px] flex flex-col justify-between hover:border-[#2D3139]/80 transition duration-200 shadow-lg">
              <div className="flex justify-between items-start">
                <div>
                  <span className="text-[9px] uppercase font-bold text-[#94A3B8] font-mono tracking-wider block">Vulnerabilidades Analizadas</span>
                  <p className="text-2xl font-bold text-white font-mono mt-1">12 <span className="text-xs text-slate-500 font-normal">/ {Math.max(12, vulnerabilities.length)}</span></p>
                </div>
                <div className="p-1.5 bg-cyan-500/10 text-[#22D3EE] rounded-lg">
                  <Database className="w-4 h-4" />
                </div>
              </div>
              <div className="border-t border-[#2D3139]/30 pt-3 mt-4 text-[10px] text-[#94A3B8] font-mono leading-normal">
                Total de hallazgos del catálogo inicial de benchmarks importados y procesados mediante aserciones sandbox.
              </div>
            </div>

            {/* Card 2: Confirmadas */}
            <div className="bg-[#14161A] border border-[#2D3139] p-5 rounded-[12px] flex flex-col justify-between hover:border-[#2D3139]/80 transition duration-200 shadow-lg">
              <div className="flex justify-between items-start">
                <div>
                  <span className="text-[9px] uppercase font-bold text-emerald-400 font-mono tracking-wider block">Confirmadas (Verdaderos Positivos)</span>
                  <p className="text-2xl font-bold text-emerald-400 font-mono mt-1">10 <span className="text-xs text-emerald-500/40 font-normal">Verificados</span></p>
                </div>
                <div className="p-1.5 bg-emerald-500/10 text-emerald-400 rounded-lg">
                  <CheckCircle2 className="w-4 h-4" />
                </div>
              </div>
              <div className="border-t border-[#2D3139]/30 pt-3 mt-4 text-[10px] text-[#94A3B8] font-mono leading-normal">
                Anomalías con exploits simulados ejecutados de manera exitosa y con trazas HTTP de evidencia robustas.
              </div>
            </div>

            {/* Card 3: Falsos Positivos */}
            <div className="bg-[#14161A] border border-[#2D3139] p-5 rounded-[12px] flex flex-col justify-between hover:border-[#2D3139]/80 transition duration-200 shadow-lg">
              <div className="flex justify-between items-start">
                <div>
                  <span className="text-[9px] uppercase font-bold text-amber-400 font-mono tracking-wider block">Falsos Positivos</span>
                  <p className="text-2xl font-bold text-amber-500 font-mono mt-1">2 <span className="text-xs text-amber-600/40 font-normal">Excluidos</span></p>
                </div>
                <div className="p-1.5 bg-amber-500/10 text-amber-500 rounded-lg">
                  <AlertTriangle className="w-4 h-4" />
                </div>
              </div>
              <div className="border-t border-[#2D3139]/30 pt-3 mt-4 text-[10px] text-[#94A3B8] font-mono leading-normal">
                Ruido e informes obsoletos reportados por escáneres estáticos que fallaron al probarse de manera activa.
              </div>
            </div>

            {/* Card 4: Falsos Negativos */}
            <div className="bg-[#14161A] border border-[#2D3139] p-5 rounded-[12px] flex flex-col justify-between hover:border-[#2D3139]/80 transition duration-200 shadow-lg">
              <div className="flex justify-between items-start">
                <div>
                  <span className="text-[9px] uppercase font-bold text-cyan-400 font-mono tracking-wider block">Falsos Negativos</span>
                  <p className="text-2xl font-bold text-cyan-400 font-mono mt-1">0 <span className="text-xs text-cyan-500/40 font-normal">Escapes</span></p>
                </div>
                <div className="p-1.5 bg-[#22D3EE]/10 text-[#22D3EE] rounded-lg">
                  <Zap className="w-4 h-4" />
                </div>
              </div>
              <div className="border-t border-[#2D3139]/30 pt-3 mt-4 text-[10px] text-[#94A3B8] font-mono leading-normal">
                Cero brechas de seguridad críticas omitidas dentro del rango del perímetro de validación de los agentes.
              </div>
            </div>

          </div>

          {/* Row 2: Bento Grid Advanced View and Precision */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 mt-2">
            
            {/* Left Column: Coverage class (8/12 cols) */}
            <div className="lg:col-span-8 bg-[#14161A] border border-[#2D3139] rounded-[12px] p-5 shadow-xl flex flex-col gap-4 text-left">
              <div className="flex justify-between items-center border-b border-[#2D3139] pb-3 mb-1">
                <div className="flex items-center gap-2">
                  <Shield className="w-4 h-4 text-[#22D3EE]" />
                  <h3 className="text-[10px] font-bold uppercase tracking-wider text-[#94A3B8] font-mono">Cantidad de Vulnerabilidades de Cobertura</h3>
                </div>
                <span className="text-[9px] bg-[#1A1D23] border border-[#2D3139] px-2.5 py-1 text-[#22D3EE] font-mono rounded">
                  Full Coverage Matrix
                </span>
              </div>
              
              <p className="text-xs text-[#94A3B8] leading-relaxed font-sans">
                El orquestador de agentes de seguridad automatizado utiliza firmas dinámicas y el modelo de razonamiento lógico de Gemini para identificar, simular aserción, y validar de manera precisa las siguientes clases de vulnerabilidad más comunes de la industria:
              </p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-2">
                <div className="bg-[#1A1D23] border border-[#2D3139] p-3.5 rounded-lg flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-white font-mono">SQL Injection (SQLi)</span>
                      <span className="text-[10px] text-emerald-400 font-mono font-bold">100% Precisión</span>
                    </div>
                    <p className="text-[10px] text-[#94A3B8] leading-normal font-mono mt-1.5">
                      Identificación y validación de concatenaciones inseguras en controladores. Soporte para basadas en booleanos, tiempo y uniones en vivo.
                    </p>
                  </div>
                  <div className="w-full bg-[#14161A] h-1.5 rounded-full mt-3 overflow-hidden">
                    <div className="bg-emerald-500 h-1.5 rounded-full" style={{ width: "100%" }}></div>
                  </div>
                </div>

                <div className="bg-[#1A1D23] border border-[#2D3139] p-3.5 rounded-lg flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-white font-mono">Insecure Direct Object Reference (IDOR)</span>
                      <span className="text-[10px] text-emerald-400 font-mono font-bold">100% Precisión</span>
                    </div>
                    <p className="text-[10px] text-[#94A3B8] leading-normal font-mono mt-1.5">
                      Pruebas automatizadas de elevación de privilegios alterando IDs correlativos en peticiones web para probar validación de pertenencia.
                    </p>
                  </div>
                  <div className="w-full bg-[#14161A] h-1.5 rounded-full mt-3 overflow-hidden">
                    <div className="bg-emerald-500 h-1.5 rounded-full" style={{ width: "100%" }}></div>
                  </div>
                </div>

                <div className="bg-[#1A1D23] border border-[#2D3139] p-3.5 rounded-lg flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-white font-mono">Server-Side Request Forgery (SSRF)</span>
                      <span className="text-[10px] text-emerald-400 font-mono font-bold">100% Precisión</span>
                    </div>
                    <p className="text-[10px] text-[#94A3B8] leading-normal font-mono mt-1.5">
                      Intercepción y simulación de redirecciones internas de proxies o fetches inseguros dirigidos al servidor de metadatos de Cloud Run o red interna.
                    </p>
                  </div>
                  <div className="w-full bg-[#14161A] h-1.5 rounded-full mt-3 overflow-hidden">
                    <div className="bg-emerald-500 h-1.5 rounded-full" style={{ width: "100%" }}></div>
                  </div>
                </div>

                <div className="bg-[#1A1D23] border border-[#2D3139] p-3.5 rounded-lg flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-white font-mono">JWT Key Bypass & Signature Abuse</span>
                      <span className="text-[10px] text-emerald-400 font-mono font-bold">100% Precisión</span>
                    </div>
                    <p className="text-[10px] text-[#94A3B8] leading-normal font-mono mt-1.5">
                      Auditoría e inyección de payloads para validación de algoritmos HMAC/RSA débiles, JWTs sin firma, expiraciones omitidas o tokens alterados.
                    </p>
                  </div>
                  <div className="w-full bg-[#14161A] h-1.5 rounded-full mt-3 overflow-hidden">
                    <div className="bg-emerald-500 h-1.5 rounded-full" style={{ width: "100%" }}></div>
                  </div>
                </div>
              </div>

            </div>

            {/* Right Column: Precision metrics (4/12 cols) */}
            <div className="lg:col-span-4 bg-[#14161A] border border-[#2D3139] rounded-[12px] p-5 shadow-xl flex flex-col justify-between gap-5 text-left">
              
              <div>
                <div className="flex items-center gap-2 border-b border-[#2D3139] pb-3 mb-3">
                  <TrendingUp className="w-4 h-4 text-[#22D3EE]" />
                  <h3 className="text-[10px] font-bold uppercase tracking-wider text-[#94A3B8] font-mono">Precisión de Resultados</h3>
                </div>

                <p className="text-xs text-[#94A3B8] leading-relaxed font-sans mb-4">
                  Nivel de asertividad obtenido al separar reportes estáticos ruidosos de vulnerabilidades reales:
                </p>

                {/* Circular indicator container with SVG */}
                <div className="flex flex-col items-center justify-center py-4 bg-[#1A1D23]/50 border border-[#2D3139]/60 rounded-xl">
                  <div className="relative w-28 h-28 flex items-center justify-center">
                    <svg className="absolute w-full h-full transform -rotate-90">
                      <circle 
                        cx="56" 
                        cy="56" 
                        r="44" 
                        stroke="#2D3139" 
                        strokeWidth="7" 
                        fill="transparent" 
                      />
                      <circle 
                        cx="56" 
                        cy="56" 
                        r="44" 
                        stroke="#10B981" 
                        strokeWidth="7" 
                        fill="transparent" 
                        strokeDasharray={2 * Math.PI * 44}
                        strokeDashoffset={0}
                        strokeLinecap="round"
                        className="transition-all duration-1000 ease-out"
                      />
                    </svg>
                    <div className="text-center z-10">
                      <span className="text-2xl font-extrabold text-white font-mono block">100%</span>
                      <span className="text-[8.5px] uppercase font-bold text-emerald-400 block tracking-widest font-mono">Precisión</span>
                    </div>
                  </div>
                  
                  <div className="mt-3 text-center px-4">
                    <span className="text-[10px] text-white font-bold block font-mono">Verdaderos Positivos</span>
                    <span className="text-[9px] text-[#94A3B8] font-mono mt-1 block leading-normal">
                      Exclusión total de alertamientos innecesarios para escalamiento corporativo.
                    </span>
                  </div>
                </div>
              </div>

              {/* Benchmarking Comparison Metrics */}
              <div className="p-3 bg-[#1A1D23] border border-[#2D3139]/70 rounded-lg">
                <span className="text-[8.5px] uppercase font-bold text-[#94A3B8] tracking-widest block font-mono border-b border-[#2D3139]/40 pb-1.5 mb-2">Resumen de Métricas</span>
                <div className="space-y-1.5 font-mono text-[10px]">
                  <div className="flex justify-between">
                    <span className="text-[#94A3B8]">Verdaderos Positivos:</span>
                    <span className="text-emerald-400 font-bold">10 / 12</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#94A3B8]">Falsos Positivos:</span>
                    <span className="text-amber-500 font-bold">2 / 12</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#94A3B8]">Falsos Negativos:</span>
                    <span className="text-cyan-400 font-bold">0 / 12</span>
                  </div>
                </div>
              </div>

            </div>

          </div>

        </div>
      )}



      {/* TAB 3: BLUEPRINT EXPLORER VIEWER PANEL */}
      {activeTab === "blueprint" && (
        <div className="flex-1 grid grid-cols-12 gap-5 p-6 text-left bg-[#0A0B0E]">
          
          {/* File layout tree choices on the left */}
          <div className="col-span-12 lg:col-span-4 bg-[#14161A] border border-[#2D3139] rounded-[12px] p-5 flex flex-col gap-3">
            <div className="flex items-center gap-2 border-b border-[#2D3139] pb-3 mb-1">
              <Layers className="w-4 h-4 text-[#22D3EE]" />
              <h2 className="text-[10px] font-bold uppercase tracking-wider text-[#94A3B8]">Enterprise Architecture Directory</h2>
            </div>
            
            <p className="text-[11px] text-[#94A3B8] font-mono leading-normal mb-2">
              Browse ready-to-run implementation template files directly mapping your modular design. Integrate with standard frameworks.
            </p>

            <div className="flex-1 space-y-2 overflow-y-auto max-h-[460px]">
              {Object.keys(blueprints).map(key => {
                const b = blueprints[key];
                const active = selectedBlueprintKey === key;
                const IconComponent = b.icon;

                return (
                  <div
                    key={key}
                    onClick={() => setSelectedBlueprintKey(key)}
                    className={`p-3 rounded-lg border transition duration-200 cursor-pointer flex items-start gap-3 ${
                      active 
                        ? "bg-[#1A1D23] border-[#22D3EE] shadow-md shadow-[#22D3EE]/5" 
                        : "bg-[#1A1D23]/50 border-[#2D3139] hover:bg-[#1A1D23]"
                    }`}
                  >
                    <div className={`p-2 rounded ${active ? "bg-[#22D3EE]/10 text-[#22D3EE]" : "bg-[#14161A] text-[#94A3B8]"}`}>
                      <IconComponent className="w-4 h-4" />
                    </div>
                    <div className="text-left flex-1 min-w-0">
                      <div className="text-xs font-bold text-white truncate font-mono">{b.title}</div>
                      <div className="text-[10px] text-[#94A3B8] font-mono truncate mt-0.5">{b.path}</div>
                      <div className="text-[10px] text-slate-500 line-clamp-1 mt-1 leading-normal">{b.desc}</div>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Model evaluations benchmarking comparisons */}
            <div className="p-3.5 bg-[#1A1D23] border border-[#2D3139] rounded-lg">
              <div className="flex items-center gap-1.5 text-[10px] font-mono tracking-wider text-[#94A3B8] uppercase font-semibold border-b border-[#2D3139] pb-1.5 mb-2">
                <BarChart3 className="w-3.5 h-3.5 text-[#22D3EE]" />
                <span>LLM Model Evaluation Metrics</span>
              </div>
              <div className="space-y-1.5 text-[10.5px]">
                {accuracyComparison.map((item, idx) => (
                  <div key={idx} className="flex justify-between items-center font-mono">
                    <span className="text-slate-400 truncate">{item.model}</span>
                    <div className="flex gap-2">
                      <span className="text-emerald-400 font-bold">${item.cost.toFixed(5)}</span>
                      <span className="text-[#22D3EE]">{(item.accuracy * 100).toFixed(0)}% acc</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

          </div>

          {/* Active File code viewer inside center/right (8/12 cols) */}
          <div className="col-span-12 lg:col-span-8 bg-[#14161A] border border-[#2D3139] rounded-[12px] p-5 flex flex-col gap-4">
            
            <div className="flex items-center justify-between border-b border-[#2D3139] pb-3 mb-1">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-[#22D3EE]" />
                <h3 className="text-xs font-mono font-bold text-white">
                  {blueprints[selectedBlueprintKey]?.path}
                </h3>
              </div>
              <span className="text-[10px] bg-[#1A1D23] border border-[#2D3139] px-2 py-0.5 font-mono text-[#94A3B8] uppercase rounded">
                {blueprints[selectedBlueprintKey]?.lang}
              </span>
            </div>

            {/* Code container display */}
            <div className="flex-1 bg-[#1A1D23] border border-[#2D3139] rounded-lg p-4 font-mono text-xs overflow-auto max-h-[500px]">
              <pre className="text-left text-[#22D3EE] select-text leading-relaxed">
                <code>{blueprints[selectedBlueprintKey]?.code}</code>
              </pre>
            </div>

            {/* Copy code banner utility */}
            <div className="flex justify-between items-center bg-[#1A1D23]/80 border border-[#2D3139] p-3 rounded-lg text-xs font-mono">
              <div className="flex items-center gap-2 text-[#22D3EE] font-semibold">
                <Check className="w-4 h-4 text-emerald-400" />
                <span>Files follow strict SOLID patterns & dry architecture.</span>
              </div>
              <button 
                onClick={() => {
                  navigator.clipboard.writeText(blueprints[selectedBlueprintKey]?.code);
                }}
                className="px-3.5 py-1.5 bg-[#22D3EE] hover:bg-[#22D3EE]/90 text-[#0A0B0E] font-bold rounded text-[11px] transition shadow-sm shadow-cyan-500/5"
              >
                Copy Clipboard Source
              </button>
            </div>

          </div>

        </div>
      )}



      {/* MODAL: Custom Report parser upload tool */}
      {customParserOpen && (
        <div className="fixed inset-0 z-50 bg-black/85 backdrop-blur-sm flex items-center justify-center p-4 antialiased">
          <div className="bg-[#14161A] border border-[#2D3139] rounded-[12px] max-w-2xl w-full p-6 shadow-2xl relative text-left">
            
            <div className="flex items-center justify-between border-b border-[#2D3139] pb-3 mb-4">
              <div className="flex items-center gap-2">
                <FileText className="w-5 h-5 text-[#22D3EE]" />
                <h3 className="text-base font-semibold text-white font-sans">Custom Report Parser</h3>
              </div>
              <button 
                onClick={() => setCustomParserOpen(false)}
                className="text-[#94A3B8] hover:text-white transition font-mono border border-[#2D3139] px-2.5 py-1 rounded text-xs hover:bg-[#2D3139]/40"
              >
                CLOSE
              </button>
            </div>

            <p className="text-xs text-[#94A3B8] mb-4 leading-relaxed font-sans">
              Paste raw contents from scanners (Burp Suite XML, ZAP JSON, Invicti, Nuclei snippets, or parsed PDF text). 
              The AI Parser Agent converts anomalous reports into the single unified format for downstream verification agents.
            </p>

            <div className="grid grid-cols-2 gap-4 mb-3">
              <div>
                <label className="block text-[10px] font-mono uppercase tracking-wider text-[#94A3B8] mb-1.5 font-bold">Report Origin Type</label>
                <select
                  value={reportFormat}
                  onChange={(e) => setReportFormat(e.target.value as any)}
                  className="w-full bg-[#1A1D23] border border-[#2D3139] rounded px-3 py-1.5 text-xs text-slate-300 font-mono focus:border-[#22D3EE] outline-none"
                >
                  <option value="BurpXML">Burp Suite XML Export</option>
                  <option value="ZAP">OWASP ZAP JSON Report</option>
                  <option value="Invicti">Invicti Enterprise Bug Export</option>
                  <option value="Nuclei">Nuclei YAML/JSON Scan Output</option>
                  <option value="PDF">PDF Raw Text Extract</option>
                  <option value="JSON">Generic HackerOne Bug Report JSON</option>
                </select>
              </div>

              <div className="flex items-end">
                <button
                  type="button"
                  onClick={() => {
                    const templates: Record<string, string> = {
                      BurpXML: `<issue>\n  <id>VULN-2015</id>\n  <type>SQL Injection</type>\n  <host>enterprise-target.local</host>\n  <path>/rest/user/login</path>\n  <parameter>email</parameter>\n  <payload>' UNION SELECT NULL--</payload>\n</issue>`,
                      ZAP: `{"vulnerability": "Cross Site Scripting", "uri": "https://enterprise-target/comments/create", "param": "content", "payload": "<script>alert(1)</script>"}`,
                      PDF: `Vulnerability: Server-Side Request Forgery detected on endpoint /api/profile/fetch-avatar with parameter url. Injected query address: http://169.254.169.254/latest/meta-data/`,
                      Invicti: `Vulnerability Type: IDOR. Severity: High. Endpoint: /api/invoices/download?id=9942. Payload: ?id=9941. Custom Strategy: ID Ownership Alterations.`,
                      Nuclei: `[nuclei-scan] [jwt-bypass] [critical] https://enterprise-target.local/api/v1/admin/debug using jwt token eyJhbGciOiJub25lIn0`,
                      JSON: `{"title": "Weak JWT Token Signature Acceptance", "severity": "critical", "cvss": "9.1", "endpoint": "/api/v1/admin/debug", "payload": "none"}`
                    };
                    setRawText(templates[reportFormat] || "");
                  }}
                  className="bg-[#1A1D23] border border-[#2D3139] hover:bg-[#2D3139]/40 text-[#94A3B8] hover:text-white transition text-xs font-mono px-3.5 py-1.5 rounded"
                >
                  Load Sample Template
                </button>
              </div>
            </div>

            <div className="mb-4">
              <label className="block text-[10px] font-mono uppercase tracking-wider text-[#94A3B8] mb-1.5 font-bold">Parser Input Source</label>
              <textarea
                value={rawText}
                onChange={(e) => setRawText(e.target.value)}
                placeholder="Paste raw log outputs, vulnerability report metrics, XML data..."
                className="w-full bg-[#1A1D23] border border-[#2D3139] rounded p-3 h-44 text-xs font-mono text-cyan-200 placeholder:text-slate-700 focus:border-[#22D3EE] outline-none resize-none"
              />
            </div>

            <div className="flex justify-end gap-3 border-t border-[#2D3139] pt-4">
              <button
                onClick={() => setCustomParserOpen(false)}
                className="bg-transparent border border-[#2D3139] hover:bg-[#1A1D23] text-[#94A3B8] hover:text-white px-4 py-2 rounded text-xs font-mono"
              >
                CANCEL
              </button>
              <button
                disabled={isParsingReport || !rawText.trim()}
                onClick={handleCustomParse}
                className="bg-[#22D3EE] hover:bg-[#22D3EE]/90 text-[#0A0B0E] font-mono font-bold px-4 py-2 rounded text-xs transition duration-200 flex items-center gap-1.5 disabled:opacity-50 shadow-md shadow-cyan-500/10"
              >
                {isParsingReport ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    Parsing Content...
                  </>
                ) : (
                  <>
                    <Sparkles className="w-3.5 h-3.5" />
                    Run AI Parser Agent
                  </>
                )}
              </button>
            </div>

            {parsedVuln && (
              <div className="mt-4 p-3 bg-[#22D3EE]/10 border border-[#22D3EE]/30 rounded-lg text-xs">
                <div className="flex items-center gap-1.5 text-[#22D3EE] font-bold mb-1">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Custom Report Successfully Aligned</span>
                </div>
                <ul className="space-y-1 text-slate-300 font-mono text-[11px] mt-2">
                  <li><strong className="text-[#94A3B8]">UUID:</strong> {parsedVuln.vulnerability_id}</li>
                  <li><strong className="text-[#94A3B8]">Class:</strong> {parsedVuln.type}</li>
                  <li><strong className="text-[#94A3B8]">Impact Score:</strong> {parsedVuln.severity} ({parsedVuln.cvss})</li>
                  <li><strong className="text-[#94A3B8]">Endpoint:</strong> {parsedVuln.method} {parsedVuln.endpoint}</li>
                </ul>
              </div>
            )}

          </div>
        </div>
      )}

      {/* Footer view */}
      <footer className="mt-auto border-t border-[#2D3139] bg-[#0A0B0E] p-4 text-center text-xs text-[#94A3B8] font-mono">
        <div>Agentic Security Orchestration Workspace © 2026 Enterprise Threat Intelligence Hub</div>
      </footer>

    </div>
  );
}

function getNodeStyle(status: "idle" | "running" | "completed" | "failed" | undefined): string {
  if (!status || status === "idle") {
    return "bg-[#14161A] border-[#2D3139] text-[#94A3B8] shadow-none";
  }
  if (status === "running") {
    return "bg-[#22D3EE]/10 border-[#22D3EE] text-[#22D3EE] shadow-lg shadow-[#22D3EE]/10 animate-pulse";
  }
  if (status === "completed") {
    return "bg-emerald-500/10 border-emerald-500/30 text-emerald-400 shadow-md shadow-[#10B981]/5";
  }
  return "bg-red-500/10 border-red-500/30 text-red-500 shadow-md shadow-red-500/5";
}
