# Unweaver

An agentic code deobfuscation workbench for malware analysts and security researchers. Unweaver combines 28+ deterministic transforms with an LLM-assisted orchestration loop to iteratively recover readable source from obfuscated JavaScript, TypeScript, Python, PowerShell, and C#/.NET scripts.

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
- [Security Notes](#security-notes)
- [Tech Stack](#tech-stack)

---

## What It Does

Unweaver is a web application that takes obfuscated code (malware scripts, packed JS, encoded PowerShell, etc.) and automatically deobfuscates it through multiple passes. The engine:

1. **Detects** the language and obfuscation techniques used (base64 encoding, hex encoding, string array rotation, control flow flattening, eval/exec wrapping, XOR encryption, junk code insertion, etc.)
2. **Applies** deterministic transforms to decode, decrypt, and simplify the code — base64 decoding (up to 3 nested layers), hex decoding (5 formats), constant folding, control flow unflattening, junk code removal, XOR key recovery, variable renaming, and more
3. **Uses AI** (optional) to plan which transforms to apply next, suggest variable names, and generate analysis summaries via any OpenAI-compatible LLM endpoint
4. **Scores** each transform result — measuring readability, confidence, and string recovery — and automatically rolls back transforms that make the code worse
5. **Extracts** IOCs (URLs, IPs, email addresses, file paths, registry keys, mutexes, hashes), strings, and security findings from the recovered code
6. **Presents** results in a dark/light themed analyst workbench with a Monaco code editor, side-by-side diff viewer, AI-generated summary reports, and exportable Markdown/JSON reports

Everything happens statically — **no code is ever executed**.

---

## Architecture

```
+----------------------------------------------+
|               React Frontend                 |
|   Vite - TypeScript - Monaco Editor - Diff   |
|   Dark/Light themes - 9 workspace tabs       |
|              Port 3000 (dev)                 |
+------------------+---------------------------+
                   |  REST / JSON
                   |  (proxied via Vite)
+------------------v---------------------------+
|               FastAPI Backend                |
|            Port 8000 - async                 |
+----------+-----------+-----------------------+
| Transform|Orchestrator|   LLM Client         |
| Pipeline | (agentic   |   (OpenAI-compatible) |
| (28+     |  multi-    |   httpx async         |
|  actions)|  pass)     |   auto max_tokens     |
+----------+-----------+-----------------------+
|           SQLite (aiosqlite)                 |
|   projects - samples - transforms - IOCs     |
|   findings - strings - providers - state     |
+----------------------------------------------+
```

### 8-Stage Analysis Loop

Each iteration of the analysis engine runs through:

1. **Planner** — surveys the code, detects language and obfuscation techniques, recommends prioritised actions (LLM-assisted when available, deterministic fallback)
2. **Action Selector** — feeds recommendations into a priority queue, pops the best action (deterministic transforms get a priority bonus)
3. **Pre-flight Validator** — checks preconditions: language compatibility, input size, retry cap, conflict detection
4. **Executor** — runs the selected transform in a thread executor (non-blocking)
5. **Post-processor** — normalises output: strips BOM, removes control characters, normalises line endings, collapses blank lines
6. **Verifier** — measures improvement via readability heuristics, string recovery, IOC extraction, and confidence delta
7. **State Reconciler** — merges extracted data into canonical state; updates confidence, readability, and transform history; auto-rollback on regression
8. **Stop Decision** — checks 7 termination conditions (budget exhausted, stall, confidence regression, consecutive failures, queue empty, sufficiency, manual stop)

---

## Features

| Category | Capabilities |
|----------|-------------|
| **Languages** | JavaScript, TypeScript, Python, PowerShell, C#/.NET — extensible |
| **Deterministic transforms** | Base64 decoding (nested, 3 layers), hex decoding (5 formats), constant folding (`String.fromCharCode`, `chr()` lists), junk code removal, eval/exec detection, JavaScript array resolver, PowerShell `-EncodedCommand` decoder, Python `exec`/`codecs` decoder, XOR key recovery, control flow unflattening, string decryption, safe expression evaluation, deterministic variable renaming |
| **LLM transforms** | LLM-powered deobfuscation, variable/function renaming, code summarisation, multi-layer analysis planning |
| **IOC extraction** | URLs, IPs (v4/v6), emails, file paths, registry keys, mutexes, hashes (MD5, SHA1, SHA256), defanged indicator support |
| **Analysis engine** | Priority queue with auto-approve, per-iteration state snapshots with rollback, confidence tracking, stall detection, readability scoring, progress reporting |
| **LLM integration** | OpenAI-compatible (OpenAI, Azure, vLLM, Ollama, LM Studio), auto-detects `max_tokens` vs `max_completion_tokens`, custom CA cert bundles, 128k/200k token presets, connection testing |
| **UI** | Dark and light themes with smooth transitions, Monaco editor with syntax highlighting, side-by-side diff viewer, 9 workspace tabs, confidence gauge, transform timeline, analyst notes |
| **AI Summary** | LLM-generated analysis reports covering obfuscation techniques, transforms applied, findings, and IOCs |
| **Export** | Download deobfuscated code, Markdown reports, and JSON reports |

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

# Start the server
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

The backend creates `unweaver.db` (SQLite) and an `uploads/` directory automatically on first start.

To run in the background:

```bash
nohup uvicorn app.main:app --host 0.0.0.0 --port 8000 &
```

### Start the Frontend

Open a new terminal:

```bash
cd frontend

# Install dependencies
npm install

# Start the dev server (proxies /api to localhost:8000)
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

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
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**Frontend** (new terminal):

```powershell
cd frontend
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

---

## Setup with Docker

The fastest way to get Unweaver running. Requires [Docker](https://www.docker.com/) and Docker Compose.

```bash
git clone https://github.com/ShabalalaWATP/Unweaver.git
cd Unweaver

# Build and start both services
docker compose up --build
```

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
| `GET` | `/api/samples/{id}/export/deobfuscated` | Download deobfuscated code |
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

# Run all tests
pytest

# Verbose output
pytest -v

# Specific test file
pytest tests/test_transforms.py -v
```

The suite covers 160+ tests across API endpoints, transform correctness, orchestrator logic, and LLM provider handling.

---

## Security Notes

- **No code execution** — all analysis is static pattern matching, string decoding, and LLM inference
- **API keys** are masked in all API responses (only last 4 characters visible)
- **File uploads** are sanitised: filenames stripped of directory components, size capped at 5 MB
- **CORS** is configured for local dev origins; restrict `allow_origins` in production
- **Custom CA certificates** supported for enterprise TLS inspection environments
- **No secrets in logs** — API keys are masked in all log output

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, TypeScript, Vite, Monaco Editor, react-diff-viewer-continued, Lucide icons |
| Backend | Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2.0 (async) |
| Database | SQLite via aiosqlite (zero-config, single-file) |
| LLM Client | httpx (async), OpenAI-compatible chat/completions protocol |
| Styling | CSS custom properties with dark/light theme system |
| Testing | pytest, pytest-asyncio, httpx AsyncClient |
| Containers | Docker, Docker Compose |

---

## License

This project is proprietary. All rights reserved.
