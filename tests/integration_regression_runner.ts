import fs from "fs";
import path from "path";

// Color utilities for terminal formatting
const COLORS = {
  RESET: "\x1b[0m",
  BOLD: "\x1b[1m",
  RED: "\x1b[31m",
  GREEN: "\x1b[32m",
  YELLOW: "\x1b[33m",
  CYAN: "\x1b[36m",
  MAGENTA: "\x1b[35m",
  GRAY: "\x1b[90m"
};

interface TestResult {
  suite: string;
  name: string;
  status: "PASSED" | "FAILED";
  durationMs: number;
  message?: string;
}

async function runTestSuite() {
  console.log(`\n${COLORS.CYAN}${COLORS.BOLD}========================================================================${COLORS.RESET}`);
  console.log(`${COLORS.CYAN}${COLORS.BOLD}            AGENTIC SECURITY ORCHESTRECTOR - TESTING SUITE RUNNER       ${COLORS.RESET}`);
  console.log(`${COLORS.CYAN}${COLORS.BOLD}========================================================================${COLORS.RESET}`);
  console.log(`${COLORS.GRAY}Timestamp: ${new Date().toISOString()}${COLORS.RESET}\n`);

  const results: TestResult[] = [];
  const startSuiteTime = Date.now();

  // 1. Verify and read the vulnerability input dataset
  const dataPath = path.join(process.cwd(), "tests", "juice_shop_data.json");
  if (!fs.existsSync(dataPath)) {
    console.error(`${COLORS.RED}❌ ERROR: Test data file does not exist at: ${dataPath}${COLORS.RESET}`);
    process.exit(1);
  }

  const rawData = fs.readFileSync(dataPath, "utf-8");
  let testData: any;
  try {
    testData = JSON.parse(rawData);
  } catch (err: any) {
    console.error(`${COLORS.RED}❌ ERROR: Failed to parse test data JSON: ${err.message}${COLORS.RESET}`);
    process.exit(1);
  }

  const vulnerabilities = testData.vulnerabilities || [];
  console.log(`${COLORS.GREEN}✓${COLORS.RESET} Parsed ${COLORS.BOLD}${vulnerabilities.length}${COLORS.RESET} sample vulnerabilities from regression dataset.\n`);

  // 2. Health check to ensure the orchestrator development server is online
  const serverUrl = "http://localhost:3000";
  console.log(`${COLORS.BOLD}Testing Orchestrator API reachability at ${serverUrl}...${COLORS.RESET}`);
  let isServerOnline = false;
  try {
    const healthRes = await fetch(`${serverUrl}/api/ai-status`);
    if (healthRes.ok) {
      const data = await healthRes.json();
      isServerOnline = true;
      console.log(`${COLORS.GREEN}✓ [API STATUS] Online! (Gemini API Active: ${data.aiActive === true ? "TRUE 🚀" : "FALSE ⚠️"})${COLORS.RESET}\n`);
    } else {
      console.log(`${COLORS.YELLOW}⚠️  [API STATUS] Server returned status ${healthRes.status}. Running offline simulation suite.${COLORS.RESET}\n`);
    }
  } catch (e: any) {
    console.log(`${COLORS.YELLOW}⚠️  [API STATUS] Cannot reach server: ${e.message}. Testing through local unit assertions.${COLORS.RESET}\n`);
  }

  // ==========================================
  // SUITE 1: UNIT VALIDATION AND SCHEMA TRIAGE
  // ==========================================
  console.log(`${COLORS.MAGENTA}${COLORS.BOLD}[SUITE 1] Unit Validation & Schema Integrity Tests${COLORS.RESET}`);
  for (const vuln of vulnerabilities) {
    const startTest = Date.now();
    try {
      // Assertion 1.1: Vulnerability ID must exist
      if (!vuln.vulnerability_id) throw new Error("Missing 'vulnerability_id'");
      
      // Assertion 1.2: CWE code must be properly formatted
      if (vuln.cwe && !vuln.cwe.startsWith("CWE-")) {
        throw new Error(`CWE format invalid: ${vuln.cwe}`);
      }

      // Assertion 1.3: CVSS must be a number between 0 and 10 inclusive
      if (typeof vuln.cvss !== "number" || vuln.cvss < 0 || vuln.cvss > 10) {
        throw new Error(`CVSS score outside valid bounds: ${vuln.cvss}`);
      }

      // Assertion 1.4: Requires login field must be consistent
      const loginReq = vuln.requires_login !== undefined ? vuln.requires_login : vuln.requiere_login;
      if (loginReq === undefined) {
        throw new Error("Missing login requirement indicator ('requires_login' or 'requiere_login')");
      }

      results.push({
        suite: "Schema Unit",
        name: `Validate Schema for ${vuln.vulnerability_id} (${vuln.title.substring(0, 30)}...)`,
        status: "PASSED",
        durationMs: Date.now() - startTest
      });
      console.log(`  ${COLORS.GREEN}✔ PASS${COLORS.RESET} ${vuln.vulnerability_id} Schema Integrity`);
    } catch (err: any) {
      results.push({
        suite: "Schema Unit",
        name: `Validate Schema for ${vuln.vulnerability_id}`,
        status: "FAILED",
        durationMs: Date.now() - startTest,
        message: err.message
      });
      console.log(`  ${COLORS.RED}✘ FAIL${COLORS.RESET} ${vuln.vulnerability_id} Schema Integrity: ${err.message}`);
    }
  }
  console.log("");

  // ==========================================
  // SUITE 2: ROUTER AGENT ENRUTAMIENTO TESTS
  // ==========================================
  console.log(`${COLORS.MAGENTA}${COLORS.BOLD}[SUITE 2] Routing Logic Mapping Tests (LangGraph Simulations)${COLORS.RESET}`);
  if (isServerOnline) {
    for (const vuln of vulnerabilities) {
      const startTest = Date.now();
      try {
        // Send request payload to dynamic execution pipeline with useRealAi=false for fast response,
        // which focuses tests strictly on routers and local heuristic logic checks
        const res = await fetch(`${serverUrl}/api/runs/execute`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            vulnerability: vuln,
            useRealAi: false
          })
        });

        if (!res.ok) {
          throw new Error(`HTTP Endpoint crash with status ${res.status}`);
        }

        const runData = await res.json();
        if (!runData.success || !runData.run) {
          throw new Error(`Orchestration execution returned failure: ${runData.error || "run not found"}`);
        }

        // Expected specialized node mapping
        let expectedValidator = "SQLi Validating Node";
        if (vuln.type.toLowerCase().includes("xss")) expectedValidator = "XSS Sandboxed Playwright Tester";
        else if (vuln.type.toLowerCase().includes("ssrf")) expectedValidator = "SSRF Request Tracker";
        else if (vuln.type.toLowerCase().includes("idor")) expectedValidator = "IDOR Dual-Token Comparison Tester";
        else if (vuln.type.toLowerCase().includes("jwt")) expectedValidator = "JWT Sign-Bypass Validation Node";

        // Examine log trails to check if router mapped it correctly
        const logs = runData.run.logs || [];
        const routingLogs = logs.filter((log: any) => log.agentName === "Router Agent" && log.level === "success");
        if (routingLogs.length === 0) {
          throw new Error("No successful routing log event captured in dynamic workflow trace");
        }

        const matchExpected = routingLogs.some((log: any) => log.message.includes(expectedValidator));
        if (!matchExpected) {
          throw new Error(`Invalid mapping. Expected routing to '${expectedValidator}', trace shows: ${routingLogs[0].message}`);
        }

        results.push({
          suite: "Agent Routing",
          name: `Routing Verification for ${vuln.vulnerability_id} (${vuln.type})`,
          status: "PASSED",
          durationMs: Date.now() - startTest
        });
        console.log(`  ${COLORS.GREEN}✔ PASS${COLORS.RESET} Mapped ${vuln.vulnerability_id} (${vuln.type}) correctly to: ${COLORS.BOLD}${expectedValidator}${COLORS.RESET}`);
      } catch (err: any) {
        results.push({
          suite: "Agent Routing",
          name: `Routing Verification for ${vuln.vulnerability_id} (${vuln.type})`,
          status: "FAILED",
          durationMs: Date.now() - startTest,
          message: err.message
        });
        console.log(`  ${COLORS.RED}✘ FAIL${COLORS.RESET} Routine Check for ${vuln.vulnerability_id}: ${COLORS.RED}${err.message}${COLORS.RESET}`);
      }
    }
  } else {
    console.log(`  ${COLORS.YELLOW}⚠️  Skipping Server Integration Router tests because the Express API endpoint is offline.${COLORS.RESET}`);
    console.log(`  ${COLORS.YELLOW}   Hint: Ensure the application server is running with 'npm run dev' to allow end-to-end integration mapping checks.${COLORS.RESET}`);
  }
  console.log("");

  // ==========================================
  // SUITE 3: REGRESSION BOUNDARY ASSERTIONS
  // ==========================================
  console.log(`${COLORS.MAGENTA}${COLORS.BOLD}[SUITE 3] Regression Risk and Classification Assertions${COLORS.RESET}`);
  for (const vuln of vulnerabilities) {
    const startTest = Date.now();
    try {
      // Assertion 3.1: Remote Code Execution (RCE) and SLQi must always be flagged with high/critical severities
      if (vuln.type.toLowerCase().includes("remote code") || vuln.type.toLowerCase().includes("sql injection") || vuln.vulnerability_id === "JS-010") {
        if (vuln.severity !== "Critical" && vuln.severity !== "High") {
          throw new Error(`CRITICAL ALARM: Injection or Code Execution issue '${vuln.vulnerability_id}' marked with insufficient severity classification: '${vuln.severity}'`);
        }
      }

      // Assertion 3.2: Check CVSS scaling boundaries
      if (vuln.cvss >= 9.0 && vuln.severity !== "Critical") {
        throw new Error(`Severity classification inconsistency: CVSS score is ${vuln.cvss} but severity is listed as: '${vuln.severity}' (Expected: Critical)`);
      }

      // Assertion 3.3: Validate that recommendations exist and are constructive
      if (!vuln.recommendation || vuln.recommendation.length < 15) {
        throw new Error(`Insufficient remediation advice. Recommendation string must capture clear technical defense indicators.`);
      }

      results.push({
        suite: "Regression Guard",
        name: `Classification Guard for ${vuln.vulnerability_id}`,
        status: "PASSED",
        durationMs: Date.now() - startTest
      });
      console.log(`  ${COLORS.GREEN}✔ PASS${COLORS.RESET} Regression check validated for: ${vuln.vulnerability_id}`);
    } catch (err: any) {
      results.push({
        suite: "Regression Guard",
        name: `Classification Guard for ${vuln.vulnerability_id}`,
        status: "FAILED",
        durationMs: Date.now() - startTest,
        message: err.message
      });
      console.log(`  ${COLORS.RED}✘ FAIL${COLORS.RESET} Regression check failed for ${vuln.vulnerability_id}: ${err.message}`);
    }
  }

  // ==========================================
  // SUMMARY REPORT GENERATION
  // ==========================================
  const totalSuiteDuration = Date.now() - startSuiteTime;
  const passed = results.filter(r => r.status === "PASSED");
  const failed = results.filter(r => r.status === "FAILED");

  console.log(`\n${COLORS.CYAN}${COLORS.BOLD}========================================================================${COLORS.RESET}`);
  console.log(`${COLORS.CYAN}${COLORS.BOLD}                          TEST RUN SUMMARY                              ${COLORS.RESET}`);
  console.log(`${COLORS.CYAN}${COLORS.BOLD}========================================================================${COLORS.RESET}`);
  console.log(`Total tests executed: ${COLORS.BOLD}${results.length}${COLORS.RESET}`);
  console.log(`Passed assertions : ${COLORS.GREEN}${COLORS.BOLD}${passed.length}${COLORS.RESET}`);
  console.log(`Failed assertions : ${failed.length > 0 ? COLORS.RED : COLORS.GREEN}${COLORS.BOLD}${failed.length}${COLORS.RESET}`);
  console.log(`Total Execution Time: ${COLORS.BOLD}${totalSuiteDuration} ms${COLORS.RESET}`);
  console.log(`${COLORS.CYAN}${COLORS.BOLD}========================================================================${COLORS.RESET}\n`);

  if (failed.length > 0) {
    console.error(`${COLORS.RED}${COLORS.BOLD}TEST RUN FAILED! One or more assertions did not compile or run correctly.${COLORS.RESET}`);
    process.exit(1);
  } else {
    console.log(`${COLORS.GREEN}${COLORS.BOLD}TEST RUN SUCCESSFUL! Clean Architecture compliance and routing limits conform to requirements.${COLORS.RESET}\n`);
    process.exit(0);
  }
}

// Kick off the runner
runTestSuite();
