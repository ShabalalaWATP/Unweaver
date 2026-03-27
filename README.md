# Unweaver

An agentic code deobfuscation workbench for malware analysts and security researchers. Unweaver combines 35+ deterministic transforms with an LLM-assisted orchestration loop to iteratively recover readable source from obfuscated JavaScript, TypeScript, Python, PowerShell, and C#/.NET scripts — including AES/RC4 decryption, rolling XOR recovery, Base32/Base85 decoding, reflection chain resolution, and multi-layer unwrapping (8+ nested encoding layers).

Paste or upload hostile code, hit Analyse, and watch the multi-pass engine strip away obfuscation layers — without ever executing the code.

![Python](https://img.shields.io/badge/Python-3.12-blue)
![React](https://img.shields.io/badge/React-18-61dafb)
![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-green)
![License](https://img.shields.io/badge/License-Proprietary-red)

---

## Table of Contents

- [What It Does](#what-it-does)
- [Architecture](#architecture)
- [Features](#features)
- [Setup on Ubuntu](#setup-on-ubuntu)
- [Setup on Windows](#setup-on-windows)
- [Setup with Docker](#setup-with-docker)
- [Configuration](#configuration)
- [Usage Guide](#usage-guide)
- [API Reference](#api-reference)
- [Demo Samples](#demo-samples)
- [Testing](#testing)
- [Air-Gapped Deployment](#air-gapped-deployment)
- [Security Notes](#security-notes)
- [Tech Stack](#tech-stack)

---

## What It Does

Unweaver is a web application that takes obfuscated code (malware scripts, packed JS, encoded PowerShell, etc.) and automatically deobfuscates it through multiple passes. The engine:

1. **Detects** the language and obfuscation techniques used — fingerprints 10+ known obfuscator tools (javascript-obfuscator, JSFuck, JJEncode, PyArmor, Invoke-Obfuscation, ConfuserEx, SmartAssembly, etc.)
2. **Decodes** multiple encoding layers — Base64 (8 nested layers, URL-safe), Base32, Base85/Ascii85, hex (5 formats), Unicode escapes, HTML entities, URL encoding, PowerShell EncodedCommand (UTF-16LE)
3. **Decrypts** encrypted payloads — AES-CBC/ECB (128/192/256-bit), RC4, XOR (single-byte, multi-byte Kasiski, rolling/rotating, CBC-like chaining, crib-dragging with 12+ default cribs)
4. **Simplifies** obfuscated code — constant folding, control flow unflattening (switch dispatcher + state machine tracing), junk code removal, JavaScript array resolver, .NET/PowerShell reflection chain resolution, Python pickle/marshal/zlib chain decoding
5. **Uses AI** (optional) to classify obfuscation type, plan transform strategy with multi-turn refinement, select transforms intelligently, reflect on failures, assess confidence, rename variables semantically, and auto-generate analysis summaries
6. **Scores** each result — blended heuristic + LLM confidence assessment (60/40), readability metrics, auto-rollback on regression, stall-resistant decode scheduling for multi-layer samples
7. **Extracts** IOCs (URLs, IPs, emails, file paths, registry keys, mutexes, hashes), strings, and severity-ranked security findings with evidence linking
8. **Presents** results in a dark/light analyst workbench — Monaco editor, per-file workspace browser with recovery summaries, per-file diffs, finding-to-code navigation, structured decision log, and auto-generated AI reports

Everything happens statically — **no code is ever executed**.

---

## Architecture

Unweaver has five runtime layers:

1. **Frontend workbench** — React 18 + Vite + Monaco on port `5173` in dev mode. It renders the original/recovered editors, per-file workspace browser, diff view, findings, notebook, and exports.
2. **FastAPI backend** — REST + WebSocket API on port `8000`. This owns uploads, projects, persistence, orchestration, exports, and report generation.
3. **Deterministic transform layer** — the main Python transform stack: decoders, crypto recovery, PowerShell/Python/C# analyzers, literal propagation, workspace profiling, and safe file-by-file workspace rewriting.
4. **Specialist workers** — a Node-backed JavaScript worker for modern JS/TS parsing and validation (`@babel/parser`), AST array resolution, and bundle unpacking/deobfuscation (`webcrack`), plus the optional .NET helper for assembly inspection.
5. **State + storage** — SQLite stores projects, samples, providers, transforms, strings, IOCs, findings, notes, and iteration state.

```
+-----------------------------------------------------------+
| React Frontend (Vite, TypeScript, Monaco)                 |
| Dev port 5173 - Summary, Original, Recovered, Diff, etc.  |
+---------------------------+-------------------------------+
                            |
                            | REST + WebSocket
                            v
+-----------------------------------------------------------+
| FastAPI Backend                                             |
| Uploads - API - Reports - Export - Provider Management      |
+--------------------+----------------------+----------------+
                     |                      |
                     v                      v
        +-------------------------+   +---------------------+
        | Orchestrator + Queue    |   | SQLite              |
        | Planner - Selector      |   | Projects, samples,  |
        | Execute - Verify - Stop |   | transforms, IOCs,   |
        | Workspace bundle aware   |   | findings, state     |
        +-----------+-------------+   +---------------------+
                    |
                    v
     +-----------------------------------------------+
     | Transform Layer                                |
     | Python deterministic transforms                |
     | Node JS worker: Babel parser + webcrack       |
     | Optional .NET worker                           |
     +-----------------------------------------------+
```

### Main Data Flow

1. **Ingest** — single scripts stay as plain text; archives are scanned and turned into a bounded `UNWEAVER_WORKSPACE_BUNDLE` that preserves file boundaries, priorities, and manifest metadata.
2. **Plan** — the orchestrator fingerprints the sample, builds a workspace context, and chooses the next deterministic or LLM-assisted action.
3. **Transform** — deterministic transforms run first where possible. JavaScript now takes an AST-first path for parsing/validation and can route bundle-heavy inputs through `webcrack`.
4. **Validate** — candidates are syntax-checked, scored, and rejected if they regress readability or structure.
5. **Reconcile** — strings, IOCs, findings, confidence, transform history, and workspace bundle state are merged back into the canonical analysis state.
6. **Present / Export** — the frontend shows the recovered source, per-file changes, bundle expansions, findings, and reports; exports can emit recovered text, ZIPs, Markdown, or JSON.

### 8-Stage Analysis Loop

Each iteration of the backend analysis engine runs through:

1. **Planner** — surveys the code, detects language and obfuscation techniques, and recommends prioritised actions. When an LLM is configured, the planner can refine strategy across stalled iterations.
2. **Action Selector** — feeds candidate actions into a priority queue and picks the best next transform. The selector is workspace-aware and can bias toward suspicious or entrypoint files.
3. **Pre-flight Validator** — checks language compatibility, size budgets, retry caps, workspace structure, and transform prerequisites.
4. **Executor** — runs deterministic transforms in-process or dispatches specialist workers / LLM transforms as needed.
5. **Post-processor** — normalises line endings, control characters, BOMs, and workspace bundle structure.
6. **Verifier** — measures readability change, syntax health, recovered strings, IOCs, and confidence delta.
7. **State Reconciler** — merges accepted changes, updates confidence, tracks failures, records transform history, and preserves rollback-safe state.
8. **Stop Decision** — exits on high confidence, readability plateau, exhausted actions, or repeated safe failures.

---

## Features

| Category | Capabilities |
|----------|-------------|
| **Languages** | JavaScript, TypeScript, Python, PowerShell, C#/.NET — extensible |
| **Encoding transforms** | Base64 (8 nested layers, URL-safe variant), Base32 (standard + hex), Base85/Ascii85, hex (5 formats), Unicode escapes, octal, HTML entities, URL percent-encoding |
| **Crypto transforms** | AES-CBC/ECB decryption (128/192/256-bit keys), RC4 decryption, XOR recovery (single-byte brute force, multi-byte Kasiski, rolling/rotating XOR, CBC-like chaining, crib-dragging), string decryption (ROT13, Caesar, reverse, charcode offset) |
| **Code transforms** | Constant folding (`String.fromCharCode`, `chr()`, `parseInt`, `Math.*`), junk code removal (opaque predicates, unreachable code, no-ops), control flow unflattening (switch dispatcher, string-split, state machine tracing), JavaScript array resolver, safe expression evaluation, deterministic variable renaming |
| **Language-specific** | PowerShell (`-EncodedCommand`, backtick/caret escapes, format strings, `-replace` chains), Python (`exec`/`codecs`/`chr()` sequences, pickle/marshal/zlib chain detection and safe string extraction), .NET/PowerShell reflection chain resolution (`GetMethod`+`Invoke`, `Activator.CreateInstance`, `Assembly.Load` chains, `[scriptblock]::Create`) |
| **LLM transforms** | LLM-powered deobfuscation, variable/function renaming, code summarisation, multi-layer unwrapping, obfuscation classification, transform selection, failure reflection, confidence assessment, multi-turn planning |
| **IOC extraction** | URLs, IPs (v4/v6), emails, file paths, registry keys, mutexes, hashes (MD5, SHA1, SHA256), defanged indicator support |
| **Analysis engine** | Priority queue with auto-approve, per-iteration state snapshots with rollback, LLM-assessed confidence (60% heuristic / 40% LLM blend), stall-resistant decode scheduling, multi-layer re-decode (up to 5 re-runs per decoder), readability scoring, typed WebSocket events for real-time progress |
| **LLM integration** | OpenAI-compatible (OpenAI, Azure, vLLM, Ollama, LM Studio), context-window-aware truncation (128K-200K), dynamic response token budgeting, `max_completion_tokens` default with `max_tokens` fallback, custom CA cert bundles, encrypted API key storage (Fernet AES-128-CBC + HMAC-SHA256) |
| **UI** | Dark and light themes, Monaco editor with syntax highlighting, per-file workspace browser with recovery summaries, per-file diff viewer for workspace bundles, finding-to-code navigation, severity-filtered findings, structured decision log (Notebook tab), confidence gauge, analyst notes |
| **AI Summary** | Auto-generated after analysis completes, few-shot calibrated prompts, structured sections (deobfuscation analysis, original intent, actual behavior, confidence assessment) |
| **Export** | Download individual recovered files, full workspace as ZIP, Markdown reports, JSON reports |

---

## Setup on Ubuntu

Tested on Ubuntu 22.04 and 24.04.

### Prerequisites

```bash
# Update packages
sudo apt update && sudo apt upgrade -y

# Install Python 3.12+ (Ubuntu 24.04 has it; on 22.04 use deadsnakes PPA)
sudo apt install -y python3 python3-pip python3-venv

# On Ubuntu 22.04, if Python < 3.12:
sudo add-apt-repository ppa:deadsnakes/ppa -y
sudo apt update
sudo apt install -y python3.12 python3.12-venv

# Install Node.js 20+ (via NodeSource)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# Install git
sudo apt install -y git
```

### Clone the Repository

```bash
git clone https://github.com/ShabalalaWATP/Unweaver.git
cd Unweaver
```

### Start the Backend

```bash
cd backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install the embedded JavaScript tooling used for
# JS/TS syntax validation, AST transforms, and webcrack
python -m app.services.transforms.js_tooling

# Start the server
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

The backend creates `unweaver.db` (SQLite) and an `uploads/` directory automatically on first start.

`UNWEAVER_JS_TOOLING_AUTO_INSTALL=true` can bootstrap the JS tooling on first use, but for CI, Docker, and production deployments the explicit bootstrap step above is the recommended path.

To run in the background:

```bash
nohup uvicorn app.main:app --host 0.0.0.0 --port 8000 &
```

### Start the Frontend

Open a new terminal:

```bash
cd frontend

# Install dependencies
npm ci

# Start the dev server (proxies /api to localhost:8000)
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser.

### Production Build (Optional)

```bash
cd frontend
npm run build    # outputs to frontend/dist/

# Serve the production build
npm run preview
```

For a production deployment, serve `frontend/dist/` with nginx and proxy `/api` to the backend:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    root /path/to/Unweaver/frontend/dist;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 300s;
    }
}
```

### Systemd Service (Optional)

Create `/etc/systemd/system/unweaver.service`:

```ini
[Unit]
Description=Unweaver Backend
After=network.target

[Service]
Type=simple
User=your-user
WorkingDirectory=/path/to/Unweaver/backend
ExecStart=/path/to/Unweaver/backend/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable unweaver
sudo systemctl start unweaver
sudo systemctl status unweaver
```

---

## Setup on Windows

### Prerequisites

- **Python 3.12+** — [python.org](https://www.python.org/downloads/)
- **Node.js 20+** — [nodejs.org](https://nodejs.org/)
- **Git** — [git-scm.com](https://git-scm.com/)

### Clone and Run

```powershell
git clone https://github.com/ShabalalaWATP/Unweaver.git
cd Unweaver
```

**Backend** (PowerShell):

```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate
pip install -r requirements.txt
python -m app.services.transforms.js_tooling
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**Frontend** (new terminal):

```powershell
cd frontend
npm ci
npm run dev
```

Open [http://localhost:5173](http://localhost:5173).

---

## Setup with Docker

The fastest way to get Unweaver running. Requires [Docker](https://www.docker.com/) and Docker Compose.

```bash
git clone https://github.com/ShabalalaWATP/Unweaver.git
cd Unweaver

# Build and start both services
docker compose up --build
```

The backend image now installs Node 20 and the embedded JS tooling during build, and the compose backend command re-checks that tooling at container start so bind-mounted development checkouts still retain the JS parser / `webcrack` path.

| Service | URL |
|---------|-----|
| Frontend | [http://localhost:5173](http://localhost:5173) |
| Backend API | [http://localhost:8000](http://localhost:8000) |
| Swagger docs | [http://localhost:8000/docs](http://localhost:8000/docs) |

```bash
# Stop
docker compose down

# Reset database and start fresh
docker compose down -v && docker compose up --build
```

---

## Configuration

All settings use the `UNWEAVER_` prefix. Place them in a `.env` file in the `backend/` directory or export as environment variables.

| Variable | Default | Description |
|----------|---------|-------------|
| `UNWEAVER_DATABASE_URL` | `sqlite+aiosqlite:///./unweaver.db` | Database connection string |
| `UNWEAVER_UPLOAD_DIR` | `backend/uploads` | Directory for uploaded files |
| `UNWEAVER_MAX_FILE_SIZE` | `5242880` (5 MB) | Maximum upload size in bytes |
| `UNWEAVER_MAX_ITERATIONS` | `20` | Maximum deobfuscation loop iterations |
| `UNWEAVER_AUTO_APPROVE_THRESHOLD` | `0.85` | Confidence threshold for auto-approving transforms |
| `UNWEAVER_MIN_CONFIDENCE_THRESHOLD` | `0.3` | Minimum confidence to enqueue an action |
| `UNWEAVER_STALL_THRESHOLD` | `3` | No-progress iterations before stopping |
| `UNWEAVER_DEBUG` | `false` | Enable debug mode |
| `UNWEAVER_LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |
| `UNWEAVER_DEFAULT_LLM_MAX_TOKENS` | `4096` | Default max tokens for LLM responses |
| `UNWEAVER_CORS_ORIGINS` | `""` | Comma-separated CORS origins; `*` for allow-all; empty = localhost defaults |
| `UNWEAVER_SECRET_KEY` | `""` | Fernet encryption key for API keys at rest; auto-generated if empty |

Example `.env`:

```env
UNWEAVER_MAX_ITERATIONS=30
UNWEAVER_LOG_LEVEL=DEBUG
```

---

## Usage Guide

### 1. Create a Project

Projects group related samples. Click the **"+"** button in the sidebar.

### 2. Add Samples

- **Upload** — drag-and-drop an obfuscated file (up to 5 MB)
- **Paste** — paste code directly into the text area

### 3. Configure an LLM Provider (Optional)

Click the **gear icon** in the sidebar. Add an OpenAI-compatible endpoint:

- **Base URL**: e.g. `https://api.openai.com`, `http://localhost:11434`
- **Model**: e.g. `gpt-4o`, `llama3`, `o3-mini`
- **API Key**: stored securely, masked in all responses
- **Max Tokens**: 128k or 200k preset

Click **"Test Connection"** to verify. The deterministic engine works fully without an LLM — the AI integration adds planning intelligence, variable naming, and summary generation.

### 4. Run Analysis

Click **"Analyse"**. The engine will:

1. Detect the language and obfuscation techniques
2. Apply deterministic transforms (base64, hex, constant folding, etc.)
3. Score each result and rollback if quality drops
4. Use LLM planning (if configured) to choose optimal next steps
5. Repeat until confidence is high enough or no more progress

Progress updates appear in real-time.

### 5. Review Results

Navigate the **9 workspace tabs**:

| Tab | What It Shows |
|-----|---------------|
| **Summary** | AI-generated analysis report, confidence metrics, detected techniques, transform statistics |
| **Original** | The original obfuscated code (Monaco editor) |
| **Recovered** | The deobfuscated result |
| **Diff** | Side-by-side diff between original and recovered |
| **Strings** | Extracted strings with encoding, offset, and context |
| **IOCs** | Indicators of compromise (URLs, IPs, hashes, etc.) with defanging |
| **Transforms** | Timeline of every transform applied with before/after metrics |
| **Findings** | Severity-ranked security findings |
| **Notebook** | Internal orchestrator state, LLM suggestions, and decision log |

### 6. Generate AI Summary

On the **Summary** tab, click **"Generate Summary"** to produce an LLM-written analysis report covering what the code does, what obfuscation was used, and what was recovered.

### 7. Export Reports

Use the export buttons to download:

- **Markdown** — full human-readable report
- **JSON** — structured report for tool integration
- **Deobfuscated code** — standalone recovered file

---

## API Reference

All endpoints are under `/api`. Interactive docs at `/docs` (Swagger) and `/redoc`.

### Projects

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/projects` | Create a new project |
| `GET` | `/api/projects` | List all projects |
| `GET` | `/api/projects/{id}` | Get project by ID |
| `DELETE` | `/api/projects/{id}` | Delete project and all samples |

### Samples

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/projects/{id}/samples/paste` | Create sample from pasted text |
| `POST` | `/api/projects/{id}/samples/upload` | Upload a file as a sample |
| `GET` | `/api/projects/{id}/samples` | List samples in a project |
| `GET` | `/api/samples/{id}` | Get full sample detail |
| `GET` | `/api/samples/{id}/original` | Get original text |
| `GET` | `/api/samples/{id}/recovered` | Get deobfuscated text |
| `GET` | `/api/samples/{id}/diff` | Get unified diff |
| `GET` | `/api/samples/{id}/strings` | Get extracted strings |
| `GET` | `/api/samples/{id}/iocs` | Get extracted IOCs |
| `GET` | `/api/samples/{id}/findings` | Get analysis findings |
| `GET` | `/api/samples/{id}/transforms` | Get transform history |
| `GET` | `/api/samples/{id}/iterations` | Get iteration state snapshots |
| `POST` | `/api/samples/{id}/summary` | Generate AI analysis summary |
| `PUT` | `/api/samples/{id}/notes` | Save analyst notes |
| `DELETE` | `/api/samples/{id}` | Delete a sample |

### Analysis Control

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/samples/{id}/analyze` | Start deobfuscation analysis |
| `GET` | `/api/samples/{id}/analysis/status` | Poll analysis progress |
| `POST` | `/api/samples/{id}/analysis/stop` | Request cancellation |

### LLM Providers

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/providers` | Create provider configuration |
| `GET` | `/api/providers` | List all providers |
| `GET` | `/api/providers/{id}` | Get provider detail |
| `PUT` | `/api/providers/{id}` | Update provider |
| `DELETE` | `/api/providers/{id}` | Delete provider |
| `POST` | `/api/providers/{id}/test` | Test provider connectivity |
| `POST` | `/api/providers/{id}/upload-cert` | Upload CA certificate bundle |

### Export

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/samples/{id}/export/deobfuscated` | Download deobfuscated code (text or ZIP for workspaces) |
| `GET` | `/api/samples/{id}/export/file?path=...&source=recovered` | Download a single file from a workspace bundle |
| `GET` | `/api/samples/{id}/export/markdown` | Download Markdown report |
| `GET` | `/api/samples/{id}/export/json` | Download JSON report |

### Health

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | Health check |

---

## Demo Samples

The `backend/demo_samples/` directory contains safe obfuscated code samples for testing:

| File | Language | Techniques |
|------|----------|------------|
| `js_obfuscated.js` | JavaScript | Array-based string table, base64, eval, `String.fromCharCode` |
| `ps_obfuscated.ps1` | PowerShell | Base64 `-EncodedCommand`, format strings, backtick insertion, IEX |
| `py_obfuscated.py` | Python | Nested base64, `exec`, `codecs.decode` (ROT13), `chr()` lists |
| `cs_obfuscated.cs` | C# | Reflection, base64, string construction, `Type.GetType` |

These decode to benign strings and exercise the full pipeline safely.

---

## Testing

```bash
cd backend
source venv/bin/activate

# Install test dependencies
pip install pytest pytest-asyncio httpx

# Ensure the JS parser / webcrack worker is present for JS-focused tests
python -m app.services.transforms.js_tooling

# Run all tests
pytest

# Verbose output
pytest -v

# Specific test file
pytest tests/test_transforms.py -v
```

Current backend suite: `282` passing tests covering API endpoints, transform correctness, workspace bundles, orchestrator logic, reports, WebSocket flows, and LLM provider handling.

---

## Air-Gapped Deployment

Unweaver is designed to work in isolated environments. All frontend assets are local, and the deterministic analysis path is fully offline once Python packages and the two npm dependency trees have been transferred.

### Offline Feature Matrix

Works fully offline once installed:

- deterministic transforms, workspace bundles, IOC extraction, findings, and exports
- JavaScript parsing / validation / AST cleanup through the embedded Node worker
- specialist bundled-JS deobfuscation through `webcrack`
- SQLite persistence, notes, diffs, and all UI tabs

Requires a **local** OpenAI-compatible endpoint on the isolated network:

- LLM-assisted deobfuscation / renaming / summaries
- LLM planning, transform selection, and reflection

### Recommended Air-Gapped Linux Install

Use a connected Linux machine with the same CPU architecture and a comparable libc / Node runtime as the target system.

**Step 1: Prepare transfer artifacts on a connected machine**

```bash
git clone https://github.com/ShabalalaWATP/Unweaver.git
cd Unweaver

# Python wheelhouse
python3 -m venv .prep-venv
source .prep-venv/bin/activate
pip download -r backend/requirements.txt -d airgap/python-wheels

# Frontend dependencies (deterministic because frontend/package-lock.json is committed)
cd frontend
npm ci
tar czf ../airgap/frontend-node_modules.tgz node_modules package.json package-lock.json
cd ..

# Embedded backend JS tooling (@babel/parser + webcrack)
cd backend/app/services/transforms/js_tooling
npm ci
tar czf ../../../../../airgap/js-tooling-node_modules.tgz node_modules package.json package-lock.json
cd ../../../../..
```

Transfer the repo checkout plus the `airgap/` directory to the isolated Linux machine via approved media.

**Step 2: Install system prerequisites on the air-gapped Linux machine**

Install these from your approved internal repo / mirror / package media:

- Python `3.12+`
- `python3-venv`
- Node.js `20+`
- `tar`
- optionally `git`, `nginx`, or a local static file server

**Step 3: Install the backend offline**

```bash
cd Unweaver/backend
python3 -m venv venv
source venv/bin/activate
pip install --no-index --find-links=../airgap/python-wheels -r requirements.txt
```

**Step 4: Install the frontend and embedded JS tooling offline**

```bash
# Frontend
cd ../frontend
tar xzf ../airgap/frontend-node_modules.tgz

# Backend JS tooling
cd ../backend/app/services/transforms/js_tooling
tar xzf ../../../../../airgap/js-tooling-node_modules.tgz
cd ../../../../..
```

At this point the backend already has the Babel parser + `webcrack` available with no network access. If you prefer transferring an npm cache instead of `node_modules`, run the embedded bootstrapper instead:

```bash
cd backend
source venv/bin/activate
UNWEAVER_JS_TOOLING_OFFLINE=true \
python -m app.services.transforms.js_tooling --cache-dir /path/to/transferred/npm-cache
```

**Step 5: Run the services**

```bash
# Backend
cd backend
source venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000

# Frontend (development server)
cd ../frontend
npm run dev -- --host
```

Or build the frontend once and serve static assets:

```bash
cd frontend
npm run build
npx serve dist -l 5173
```

### Air-Gapped Docker Deployment

If Docker is allowed in your environment, prebuild the images on a connected machine, then transfer the image tarball:

```bash
# Connected machine
docker compose build
docker save unweaver-backend unweaver-frontend | gzip > unweaver-images.tar.gz

# Air-gapped machine
docker load < unweaver-images.tar.gz
UNWEAVER_CORS_ORIGINS="*" docker compose up
```

The backend image now already contains Node 20 and the embedded JS tooling. The compose backend command also re-runs the local bootstrap check so a bind-mounted development checkout does not lose the JS worker path.

### Local LLM Options Inside an Isolated Network

**Ollama**

```bash
ollama serve
ollama run llama3.1:8b
```

**vLLM**

```bash
python -m vllm.entrypoints.openai.api_server \
  --model /path/to/model \
  --port 8001
```

**LM Studio**

1. Transfer the installer and GGUF model to the isolated workstation.
2. Start the local server.
3. Point Unweaver at that local OpenAI-compatible endpoint.

### Network, CORS, and Secrets

```bash
export UNWEAVER_CORS_ORIGINS="*"
export UNWEAVER_SECRET_KEY="your-persistent-secret-key"
```

If `UNWEAVER_SECRET_KEY` is omitted, Unweaver generates one locally and stores it in `.unweaver_secret`.

---

## Supported Obfuscation Techniques

| Category | Techniques | Max Layers |
|----------|-----------|------------|
| **Base64** | Standard, URL-safe (RFC 4648), nested, PowerShell UTF-16LE, wrapped (atob, b64decode, FromBase64String) | 8 per call, unlimited via re-decode |
| **Base32/Base85** | Standard Base32, Hex Base32, Ascii85 (`<~ ~>`), Python b85/a85 | 8 |
| **Hex** | `\x41`, `0x41,0x42`, `\u0041`, `%41`, hex streams, PS byte arrays | Unlimited |
| **XOR** | Single-byte brute force (256 keys), multi-byte Kasiski (up to 16-byte keys), rolling/rotating (position XOR, increment, CBC-like), crib dragging (12+ cribs) | Unlimited |
| **AES/RC4** | AES-CBC, AES-ECB (128/192/256-bit), RC4, CryptoJS patterns, .NET AesCryptoServiceProvider — keys extracted from hex literals, byte arrays, Base64 | 1 per call |
| **String tricks** | String.fromCharCode, chr() lists, [char] concatenation, ROT13, Caesar, reverse, replace chains, backtick/caret escapes, format strings | Unlimited |
| **Control flow** | Switch dispatcher (while+switch), string-split dispatch, state machine tracing (500 steps, 50 dispatchers), conditional branch resolution | 1 pass + re-run |
| **Junk code** | Opaque predicates (always-true/false), unreachable code, no-ops, variable overwrites, empty blocks | Multi-pass |
| **Reflection** | .NET GetMethod+Invoke, Assembly.Load chains, Activator.CreateInstance, PS GetType+Invoke, PS ScriptBlock.Create, Python getattr+__import__, globals() dict calls | 1 pass |
| **Serialization** | Python pickle (safe string extraction without execution), marshal (detection), zlib+base64 chains (full decompression) | 1 pass |
| **Tool signatures** | javascript-obfuscator, JJEncode, AAEncode, JSFuck, Dean Edwards Packer, PyArmor, Invoke-Obfuscation, ConfuserEx, SmartAssembly, Dotfuscator | Detection |

---

## Security Notes

- **No code execution** — all analysis is static pattern matching, string decoding, and LLM inference
- **API keys** are encrypted at rest using Fernet symmetric encryption and masked in all API responses
- **File uploads** are sanitised: filenames stripped of directory components, size capped at 5 MB
- **CORS** is configurable via `UNWEAVER_CORS_ORIGINS` environment variable; defaults to localhost origins
- **Custom CA certificates** supported for enterprise TLS inspection environments
- **No secrets in logs** — API keys are masked in all log output

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, TypeScript, Vite, Monaco Editor, react-diff-viewer-continued, Lucide icons |
| Backend | Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2.0 (async), cryptography (Fernet + AES) |
| Database | SQLite via aiosqlite (zero-config, single-file) |
| LLM Client | httpx (async), OpenAI-compatible chat/completions, context-window-aware, dynamic token budgeting |
| Crypto | Fernet AES-128-CBC (API key encryption), AES-CBC/ECB + RC4 (payload decryption), pure-Python RC4 |
| Styling | CSS custom properties with dark/light theme system |
| Testing | pytest, pytest-asyncio, httpx AsyncClient (198+ tests) |
| Containers | Docker, Docker Compose |

---

## License

This project is proprietary. All rights reserved.
