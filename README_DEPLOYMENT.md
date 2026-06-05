# Enterprise Agentic Security Orchestrator — Local & Docker Runner Guide

This guide details how to set up, secure, and run the **Enterprise Agentic Security Orchestrator** on your local machine (macOS) natively or via Docker. By configuring your **Gemini 3.5 Flash API Key**, the system moves from simulated defaults to live, real-time security assessment generation and source-report dynamic parsing.

---

## 🚀 How the Real AI Core Operates
By default, the platform supports a dual evaluation mode:
1. **Simulation Mode (Fallback)**: When no API Key is set, the validation runs and parses uploaded reports using high-fidelity local templates. This ensures the app is responsive even without credentials.
2. **Live Gemini-3.5 Mode (Real)**: When you provide a valid `GEMINI_API_KEY`, the server initializes a secure `@google/genai` client. When validation workflows or report parsing are triggered with this mode active:
   * **Custom XML/PDF Report Parsing**: The uploaded report is parsed live using Gemini to align schemas and map out endpoints.
   * **Evidence Correlation Agent**: Raw server response traces are dynamically analyzed.
   * **Risk Scoring & Remediation**: Gemini scores risks and writes custom code patches (Vulnerable vs. Remediated) for the exact vulnerability on the fly rather than using generic mock constants.
   * **Visual Active Indicator**: A dynamic status light in the interface header will pulse green and show **`GEMINI-3.5 (LIVE)`** so you always know when your key is fully active.

---

## 🛠️ Option 1: Native Local Run (Mac or Linux)

Ensure you have **Node.js (v18 or higher)** and **npm** installed on your Mac.

### 1. Configure the Environment
Copy the example environment file and name it `.env`:
```bash
cp .env.example .env
```
Open the `.env` file and insert your Gemini API Key:
```env
GEMINI_API_KEY="your_actual_gemini_3.5_flash_key_here"
```

### 2. Install Dependencies
Install all package packages listed in `package.json`:
```bash
npm install
```

### 3. Run in Development Mode
To boot up the application in interactive development with real-time assets reloading, run:
```bash
npm run dev
```
Open your browser to `http://localhost:3000`.

### 4. Build and Run in Production Mode
For optimal performance, compile files and start the production application:
```bash
# Build Vite assets and compile TypeScript server CJS bundle
npm run build

# Start the optimized Node server
npm start
```

---

## 🐳 Option 2: Run with Docker (Recommended for macOS)

Docker isolates all environments and dependencies, making configuration effortless. This setup maps host port **3005** to container port **3000** automatically (so there's zero conflict with local Burp Suite installs listening on port 8080 or other local processes).

### 1. Build and Run via Docker Compose (Simplest)
This manages volume boundaries, host port bindings, and environment passing automatically.

1. Create a `.env` in the root folder containing:
   ```env
   GEMINI_API_KEY="your_actual_gemini_3.5_flash_key_here"
   ```
2. Build the image and spin up the container:
   ```bash
   docker compose up --build
   ```
   *The application will boot up on port 3005.*
3. Open your browser to `http://localhost:3005`.
4. To stop the container, press `Ctrl + C` or execute:
   ```bash
   docker compose down
   ```

### 2. Build and Run via Standard Docker Commands
If you prefer not to use Docker Compose, you can run normal docker directives.

1. **Build the Docker Image**:
   ```bash
   docker build -t threat-copilot .
   ```
2. **Run the Container** (directly passing the environment variable and mapping port 3005):
   ```bash
   docker run -d -p 3005:3000 -e GEMINI_API_KEY="your_actual_gemini_3.5_flash_key_here" --name threat-copilot-run threat-copilot
   ```
3. Open your browser to `http://localhost:3005`.
4. To view live server logs:
   ```bash
   docker logs -f threat-copilot-run
   ```
5. To stop the container:
   ```bash
   docker stop threat-copilot-run && docker rm threat-copilot-run
   ```

---

## 📁 Key File Structure Highlights
For local modifications, here are the main files you can explore:
* `server.ts`: Initialized the Express backend, processes `@google/genai` model requests, handles parsing endpoints, and hosts the static file server fallback.
* `src/App.tsx`: Main React UI dashboard, manages the visualization state, processes active log outputs, and implements custom report uploaded pipelines.
* `src/types.ts`: Holds data types for vulnerabilities, validation steps, and metrics.
* `Dockerfile` / `docker-compose.yml`: Local Docker environment configurations.
