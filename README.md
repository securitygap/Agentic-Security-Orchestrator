# Agentic Security Orchestrator: Manual de Arquitectura y Triage Automatizado

El **Agentic Security Orchestrator** es una solución de vanguardia diseñada para procesar, enriquecer, validar de manera activa y remediar de forma autónoma anomalías de seguridad y hallazgos provenientes de múltiples escáneres estáticos y dinámicos (DAST, SAST, e informes manuales). 

Esta plataforma transforma hallazgos estáticos crudos en resultados validados con evidencia real y código de reparación listo para producción mediante un flujo orquestado por agentes inteligentes autónomos alimentados con Google Gemini 3.5.

---

## 🧭 Flujo de Triage de Vulnerabilidades (Multi-Agent Graph)

La solución utiliza una arquitectura de agentes cooperativos basada en un grafo de estados lógico, estructurado de la siguiente manera:

```
[Reporte de Seguridad] ───► [Parser Agent]
                                   │
                                   ▼
                            [Router Agent] ───► (Analiza CWE/OWASP)
                                   │
         ┌─────────────────────────┼─────────────────────────┐
         ▼                         ▼                         ▼
   [SQLi Node]                [XSS Tester]             [SSRF Tracker] etc.
         │                         │                         │
         └─────────────────────────┬─────────────────────────┘
                                   ▼
                        [Pre-Auth Session Manager]
                                   │
                                   ▼
                        [Active Validation Probe]
                                   │
                                   ▼
                       [Scoring & Remediation Agent] ───► [Código Remedio / Parche]
```

El ciclo de triage y validación consta de 6 fases secuenciales totalmente automatizadas:

### 1. Ingesta y Estandarización (Parser Agent)
El **Parser Agent** recibe datos en formatos heterogéneos (como reportes XML de Burp Suite, JSON de OWASP ZAP, reportes de Invicti o Nuclei, o texto extraído de PDF) y los analiza en tiempo real empleando IA.
- **Función**: Neutraliza diferencias de formato, mapea correctamente campos críticos (método HTTP, endpoint, clases CWE) y genera un modelo de datos unificado estándar para el resto del motor de decisión.

### 2. Clasificación de Amenazas y Dependencias (Router Agent)
El **Router Agent** inspecciona las características del hallazgo (firmas de vectores, clases OWASP y severidad declarada) para direccionar el esfuerzo de análisis hacia el nodo de validación especializado.
- **Direccionamiento**:
  - `SQL Injection (SQLi)` ➔ **SQLi Validating Node**
  - `Cross-Site Scripting (XSS)` ➔ **XSS Sandboxed Playwright Tester**
  - `Server-Side Request Forgery` ➔ **SSRF Request Tracker**
  - `Insecure Direct Object Reference (IDOR)` ➔ **IDOR Dual-Token Comparison Tester**
  - `JSON Web Token (JWT) Issues` ➔ **JWT Sign-Bypass Validation Node**

### 3. Agregación Contextual (Enrichment Agent)
Antes de interactuar con el entorno objetivo, el **Enrichment Agent** correlaciona de manera heurística y mediante API los identificadores de vulnerabilidad con bases de datos públicas de telemetría de amenazas.
- **Función**: Junta información clave como exploits conocidos en la naturaleza (por ejemplo, firmas de Metasploit, plantillas Nuclei), historial de CVEs relacionados y estándares mundiales de remediación.

### 4. Gestión Inteligente de Sesiones (Pre-Auth Session Manager)
Para vulnerabilidades protegidas por perímetros de autenticación (`requires_login`), el sistema activa un subsistema dinámico de credenciales.
- **Función**: Ejecuta solicitudes de autenticación previas (handshake) en el endpoint configurado, gestiona y captura tokens de tipo *Bearer* o Cookies de sesión, e inyecta dichas cabeceras de autorización de forma segura en las consultas de explotación activa del paso subsecuente.

### 5. Validación Activa no Destructiva (Active Validation Probe)
Los agentes especializados ejecutan pruebas de concepto (*Proof-of-Concept* o PoC) controladas y parametrizadas directamente contra el endpoint objetivo indicado.
- **Función**: Envía cargas útiles adaptadas a las cabeceras/parámetros, capturando y registrando de manera aislada los bytes de respuesta, códigos HTTP, latencias y firmas visuales. Esto evita falsos positivos determinando si el puerto o endpoint reacciona verdaderamente de forma vulnerable.

### 6. Análisis de Evidencia, Puntaje y Parcheo (Remediation & Scoring Agent)
Una vez finalizada la consulta, el agente recopila los rastros de depuración ("traces"), respuestas de cabecera y el cuerpo del error obtenido de los servidores analizados.
- **Generación de Puntaje**: Calcula un impacto real correlacionando la explotabilidad detectada en vivo vs. la teórica.
- **Creación de Remedios con IA**: La IA genera propuestas analizando la sintaxis exacta del endpoint vulnerable y produce dos bloques de código en tiempo real:
  - **Vulnerable Snippet**: Fragmento que ilustra el error estructural (ej. falta de tipado, concatenación SQL directa).
  - **Remediated Snippet**: Código endurecido propuesto, listo para ser integrado, implementando saneamiento, sentencias preparadas o validación estricta de dominios según corresponda.

---

## 🛡️ Características Principales del Agentic Security Orchestrator

1. **Orquestación Basada en Grafos de Estado**: Flujos de trabajo secuenciales y deterministas dirigidos por agentes que comparten contexto mutuo, logrando decisiones sofisticadas paso a paso sin intervención humana.
2. **Eliminación Absoluta de Falsos Positivos**: Solo clasifica un fallo como "Verificado" si el agente de validación activa logra provocar un cambio de estado determinista, un rastro analizable o una respuesta de comportamiento anómalos pero seguros en el sistema destino.
3. **Mecanismo Dynamic Pre-Auth**: Capacidad para sortear inicios de sesión de aplicaciones modernas mediante un gestor de handshakes dinámico con soporte para JSON payloads y cabeceras personalizables.
4. **Motor de Remediación Hiper-Personalizado**: A diferencia de los escáneres estáticos tradicionales que proveen recomendaciones generales (de tipo "sanitice sus entradas"), genera código de producción corregido que encaja exactamente con el endpoint y la lógica inspeccionada.
5. **Panel Interactivo de Traces (Orchestrator Cockpit)**: Consola visual con hilos de ejecución en vivo separados por agente, lo que confiere transparencia y auditoría total (White Box) sobre las interacciones de seguridad realizadas.

---

> Nota sobre la configuración y ejecución local: Para arrancar esta aplicación con el entorno de orquestación en vivo (utilizando Gemini-3.5 Flash), consulte la guía en [README_DEPLOYMENT.md](README_DEPLOYMENT.md).
