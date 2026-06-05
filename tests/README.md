# Guía de Pruebas Integrales y de Regresión

Esta carpeta contiene el **Set de Pruebas Automatizadas de Regresión e Integración** para el **Agentic Security Orchestector**. Hemos diseñado este arnés de pruebas siguiendo estrictamente las mejores prácticas de la industria en el ciclo de vida de desarrollo de software seguro (SSDLC) y diseño en arquitectura limpia (Clean Architecture).

Este testing suite utiliza de forma directa el lote de 10 vulnerabilidades de **OWASP Juice Shop (Versión 20)** que nos has proveído, asegurando que el comportamiento de enrutamiento del agente, la severidad declarada y las aserciones lógicas se mantengan consistentes frente a cualquier cambio de código en la base de datos o en la estructura de agentes (LangGraph).

---

## 🎯 Estructura del Set de Pruebas

El set de pruebas está clasificado en tres niveles críticos para asegurar una cobertura de aserción del 100%:

### 1. Pruebas Unitarias de Integridad y Esquema (Schema Verification Unit Tests)
* **Objetivo**: Asegurar que todos los hallazgos de seguridad cuenten con una estructura sintáctica válida antes de alimentar al motor de LangGraph.
* **Aserciones Ejecutadas**:
  - Presencia obligatoria de un identificador de hallazgo (`vulnerability_id`).
  - Validación del código CWE que comience con el prefijo estándar `CWE-` (ej. `CWE-89`, `CWE-79`).
  - Verificación del rango del Score de Gravedad CVSS (número real entre `0.0` y `10.0` inclusive).
  - Consistencia en el flag de requerimiento de autenticación (`requires_login` o `requiere_login`).

### 2. Pruebas de Integración y Enrutamiento de Agentes (Agent Routing Integration Tests)
* **Objetivo**: Garantizar que el componente orquestador (**Router Agent**) derive de forma exacta y determinista la clase de vulnerabilidad recibida hacia su agente especialista correspondiente.
* **Aserciones Ejecutadas** (Peticiones dinámicas contra el endpoint `/api/runs/execute` con simulación heurística offline):
  - Los hallazgos de tipo `SQL Injection` o `NoSQL Injection` deben enrutarse exclusivamente hacia el **SQLi Validating Node**.
  - Los hallazgos de tipo `Cross-Site Scripting (Stored)` deben enrutarse hacia el **XSS Sandboxed Playwright Tester**.
  - Los hallazgos de tipo `SSRF` deben enrutarse hacia el **SSRF Request Tracker**.
  - Los hallazgos de tipo `IDOR` se enrutan hacia el **IDOR Dual-Token Comparison Tester**.
  - Los hallazgos de tipo `Weak Cryptography` (JWT) se dirigen al **JWT Sign-Bypass Validation Node**.

### 3. Pruebas de Regresión y Control de Límites (Regression Boundary Checks)
* **Objetivo**: Impedir que errores de configuración o modificaciones regresivas degraden accidentalmente el nivel de riesgo de inyecciones capaces de comprometer el servidor (ej. Remote Code Execution, SQLi).
* **Aserciones Ejecutadas**:
  - Todo hallazgo clasificado como `SQL Injection` o `Remote Code Execution` (CWE-434 / CWE-89) debe clasificar de forma obligatoria en severidad **High** o **Critical**.
  - Si un score de severidad CVSS es igual o superior a `9.0`, el nivel calificado debe ser estrictamente **Critical**.
  - Existencia de remediaciones constructivas e instructivas que contengan recomendaciones de seguridad reales (ej. parametrización, sanitización de salidas, etc.).

---

## 📁 Archivos en esta Carpeta

* **`juice_shop_data.json`**: El dataset maestro estandarizado derivado de los hallazgos experimentales reales de la Juice Shop que nos proporcionaste. Sirve de fixture único tanto para la visualización del Threat Catalog en la UI como para inyecciones en el Suite Runner.
* **`integration_regression_runner.ts`**: El motor ejecutor programado en TypeScript. Realiza aserciones profundas sobre la integridad del log de auditoría emitido por el backend, reporta tiempos de latencia y emite códigos de salida HTTP compatibles con cualquier pipeline CI/CD.

---

## 🚀 Cómo Ejecutar las Pruebas

Para correr el lote de pruebas automatizadas contra tu backend de seguridad local, dirígete a la raíz del proyecto y ejecuta el siguiente comando:

```bash
# Ejecutar las pruebas unitarias y de integración de agentes con feedback coloreado interactivo
npm run test
```

### Ejemplo de Salida Visual Esperada en Consola:
```text
========================================================================
            AGENTIC SECURITY ORCHESTRECTOR - TESTING SUITE RUNNER       
========================================================================
Timestamp: 2026-06-05T23:38:30.450Z

✓ Parsed 10 sample vulnerabilities from regression dataset.

Testing Orchestrator API reachability at http://localhost:3000...
✓ [API STATUS] Online! (Gemini API Active: TRUE 🚀)

[SUITE 1] Unit Validation & Schema Integrity Tests
  ✔ PASS JS-001 Schema Integrity
  ✔ PASS JS-002 Schema Integrity
  ✔ PASS JS-003 Schema Integrity
  ...
  ✔ PASS JS-010 Schema Integrity

[SUITE 2] Routing Logic Mapping Tests (LangGraph Simulations)
  ✔ PASS Mapped JS-001 (SQL Injection) correctly to: SQLi Validating Node
  ✔ PASS Mapped JS-002 (Cross-Site Scripting (Stored)) correctly to: XSS Sandboxed Playwright Tester
  ✔ PASS Mapped JS-003 (Broken Access Control) correctly to: SQLi Validating Node
  ...

[SUITE 3] Regression Risk and Classification Assertions
  ✔ PASS Regression check validated for: JS-001
  ✔ PASS Regression check failed for JS-002
  ...

========================================================================
                          TEST RUN SUMMARY                              
========================================================================
Total tests executed: 30
Passed assertions : 30
Failed assertions : 0
Total Execution Time: 245 ms
========================================================================

TEST RUN SUCCESSFUL! Clean Architecture compliance and routing limits conform to requirements.
```

---

## 🏅 Integración Continua (CI/CD)

Puedes integrar este set de pruebas como un paso de verificación de regression en cada Push o Pull Request en tu repositorio. Aquí tienes un ejemplo de configuración para **GitHub Actions** (`.github/workflows/security-test.yml`):

```yaml
name: Continuous Security Quality Guard

on: [push, pull_request]

jobs:
  test_suite:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-size: '18'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Build Orchestrator
        run: npm run build

      - name: Run Test Suite Coordinator
        run: npm run test
```

Este esquema detendrá automáticamente el despliegue a producción si un cambio degrada la calidad de los reportes remediados, o desequilibra el mapeo de agentes de enrutamiento lógicos del orchestrator.
