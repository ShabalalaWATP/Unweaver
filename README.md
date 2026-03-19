# Unweaver

A dark-mode analyst workbench for automated, multi-pass code deobfuscation. Unweaver combines deterministic transforms with an LLM-assisted agentic orchestration loop to iteratively recover readable source from obfuscated JavaScript, TypeScript, Python, PowerShell, and C#/.NET scripts.

Built for malware analysts and security researchers who need to understand what hostile code actually does — without ever executing it.

![Python](https://img.shields.io/badge/Python-3.12-blue)
![React](https://img.shields.io/badge/React-18-61dafb)
![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-green)
![License](https://img.shields.io/badge/License-Proprietary-red)

---

## Table of Contents

- [Architecture](#architecture)
- [Features](#features)
- [Quick Start — Docker](#quick-start--docker)
- [Quick Start — Local Development](#quick-start--local-development)
- [Configuration](#configuration)
- [Usage Guide](#usage-guide)
- [API Reference](#api-reference)
- [Demo Samples](#demo-samples)
- [Testing](#testing)
- [Security Notes](#security-notes)
- [Tech Stack](#tech-stack)

---

## Architecture

```
┌──────────────────────────────────────────────┐
│               React Frontend                 │
│   Vite · TypeScript · Monaco Editor · Diff   │
│              Port 3000 (dev)                 │
└──────────────────┬───────────────────────────┘
                   │  REST / JSON
                   │  (proxied via Vite)
┌──────────────────▼───────────────────────────┐
│               FastAPI Backend                │
│            Port 8000 · async                 │
├──────────┬───────────┬───────────────────────┤
│ Transform│Orchestrator│   LLM Client         │
│ Pipeline │ (agentic   │   (OpenAI-compatible) │
│ (14+     │  multi-    │   httpx async         │
│  actions)│  pass)     │   custom CA support   │
├──────────┴───────────┴───────────────────────┤
│           SQLite (aiosqlite)                 │
│   projects · samples · transforms · IOCs     │
│   findings · strings · providers · state     │
└──────────────────────────────────────────────┘
```

The analysis engine runs a **5-stage loop** on every iteration:

1. **Planner** — surveys the code, detects the language and obfuscation techniques, recommends prioritised actions
2. **Action Selector** — feeds recommendations into a priority queue, pops the best action (deterministic transforms get a priority bonus)
3. **Executor** — runs the selected transform in a thread executor (non-blocking)
4. **Verifier / Scorer** — measures improvement via readability heuristics, string recovery count, IOC extraction, and confidence delta
5. **Stop Decision** — checks 7 termination conditions (budget exhausted, stall, confidence regression, consecutive failures, queue empty, sufficiency, manual stop)

High-confidence deterministic transforms are auto-approved; uncertain or LLM-dependent actions are queued as suggestions with human-in-the-loop approval.

---

## Features

| Category | Capabilities |
|----------|-------------|
| **Languages** | JavaScript, TypeScript, Python, PowerShell, C#/.NET — extensible |
| **Deterministic transforms** | Base64 decoding (nested, 3 layers), hex decoding (5 formats), constant folding (`String.fromCharCode`, `chr()` lists), junk code removal, eval/exec detection, JavaScript array resolver, PowerShell `-EncodedCommand` decoder, Python `exec`/`codecs` decoder |
| **IOC extraction** | URLs, IPs (v4/v6), emails, file paths, registry keys, mutexes, hashes (MD5, SHA1, SHA256), defanged indicator support |
| **Analysis engine** | Priority queue with auto-approve, per-iteration state snapshots with rollback, confidence tracking, stall detection, readability scoring |
| **LLM integration** | OpenAI-compatible (OpenAI, Azure, vLLM, Ollama, LM Studio), custom CA cert bundles, 128k/200k max-token presets, connection testing |
| **UI** | Dark-mode-only, Monaco editor, side-by-side diff viewer, 8 workspace tabs, confidence gauge, transform timeline, analyst notes |
| **Export** | Markdown and JSON reports with full findings, IOCs, transforms, and strings |

---

## Quick Start — Docker

The fastest way to get Unweaver running. Requires [Docker](https://www.docker.com/) and Docker Compose.

```bash
# Clone the repository
git clone https://github.com/AlexOleszler/unweaver.git
cd unweaver

# Build and start both services
docker compose up --build
```

Once both containers are healthy:

| Service | URL |
|---------|-----|
| Frontend | [http://localhost:5173](http://localhost:5173) |
| Backend API | [http://localhost:8000](http://localhost:8000) |
| Swagger docs | [http://localhost:8000/docs](http://localhost:8000/docs) |
| ReDoc | [http://localhost:8000/redoc](http://localhost:8000/redoc) |

To stop:

```bash
docker compose down
```

To reset the database and start fresh:

```bash
docker compose down -v
docker compose up --build
```

---

## Quick Start — Local Development

### Prerequisites

- **Python 3.12+**
- **Node.js 20+** and npm
- (Optional) An OpenAI-compatible LLM endpoint for LLM-assisted analysis — the deterministic transforms work without one

### Backend

```bash
cd backend

# Create and activate a virtual environment
python -m venv venv
# Linux / macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# (Optional) Install test dependencies
pip install pytest pytest-asyncio httpx

# Start the server (auto-reloads on file changes)
uvicorn app.main:app --reload --port 8000
```

The backend creates `unweaver.db` (SQLite) and an `uploads/` directory automatically on first start.

### Frontend

```bash
cd frontend

# Install dependencies
npm install

# Start the dev server (proxies /api → localhost:8000)
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser. The Vite dev server proxies all `/api` requests to the backend on port 8000.

To build for production:

```bash
npm run build    # outputs to frontend/dist/
npm run preview  # serve the production build locally
```

---

## Configuration

All settings are loaded from environment variables using the `UNWEAVER_` prefix. You can also place them in a `.env` file in the `backend/` directory.

| Variable | Default | Description |
|----------|---------|-------------|
| `UNWEAVER_DATABASE_URL` | `sqlite+aiosqlite:///./unweaver.db` | Database connection string |
| `UNWEAVER_UPLOAD_DIR` | `backend/uploads` | Directory for uploaded sample files |
| `UNWEAVER_MAX_FILE_SIZE` | `5242880` (5 MB) | Maximum upload size in bytes |
| `UNWEAVER_MAX_ITERATIONS` | `20` | Maximum deobfuscation loop iterations |
| `UNWEAVER_AUTO_APPROVE_THRESHOLD` | `0.85` | Confidence threshold for auto-approving deterministic transforms |
| `UNWEAVER_MIN_CONFIDENCE_THRESHOLD` | `0.3` | Minimum confidence to enqueue an action |
| `UNWEAVER_STALL_THRESHOLD` | `3` | Consecutive no-progress iterations before stopping |
| `UNWEAVER_DEBUG` | `false` | Enable debug mode |
| `UNWEAVER_LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |
| `UNWEAVER_DEFAULT_LLM_MAX_TOKENS` | `4096` | Default max tokens for LLM responses |

Example `.env` file:

```env
UNWEAVER_MAX_ITERATIONS=30
UNWEAVER_AUTO_APPROVE_THRESHOLD=0.9
UNWEAVER_LOG_LEVEL=DEBUG
```

---

## Usage Guide

### 1. Create a Project

Projects are top-level containers for grouping related samples. Click the **"+"** button in the left sidebar to create one.

### 2. Add Samples

You have two options:

- **Upload**: Click **"Upload"** and drag-and-drop an obfuscated file (up to 5 MB). Optionally select the language if auto-detection isn't sufficient.
- **Paste**: Click **"Paste"** and paste obfuscated code directly into the text area. Choose a filename and language.

### 3. Run Analysis

Click **"Analyse"** in the top bar. The orchestrator will:

1. Detect the language and obfuscation techniques
2. Run deterministic transforms (base64 decoding, hex decoding, string extraction, etc.)
3. Score each result and decide whether to accept, rollback, or try something else
4. Repeat until a stop condition is met (sufficient confidence, budget exhausted, or no more progress)

The progress bar and status indicator update in real-time via polling.

### 4. Review Results

Navigate the **8 workspace tabs**:

| Tab | What it shows |
|-----|---------------|
| **Original** | The original obfuscated code (Monaco editor with syntax highlighting) |
| **Recovered** | The deobfuscated result after all transforms |
| **Diff** | Side-by-side diff between original and recovered code |
| **Strings** | All extracted strings with encoding, offset, and context |
| **IOCs** | Extracted indicators of compromise (URLs, IPs, hashes, etc.) with defanging toggle |
| **Transform History** | Timeline of every transform applied, with confidence/readability before/after |
| **Findings** | Severity-ranked finding cards (suspicious APIs, techniques, behavioural patterns) |
| **Agent Notebook** | Internal orchestrator state, LLM suggestions, and decision log |

The **right panel** shows metadata: language, confidence gauge, readability bar, detected techniques, suspicious APIs, and analyst notes.

### 5. Configure LLM Provider (Optional)

Click the **gear icon** in the sidebar to open Provider Settings. Add an OpenAI-compatible endpoint:

- **Name**: A label for this provider (e.g., "Local Ollama", "GPT-4o")
- **Base URL**: The endpoint root (e.g., `http://localhost:11434`, `https://api.openai.com`)
- **Model**: The model name (e.g., `llama3`, `gpt-4o`)
- **API Key**: Your API key (stored encrypted, masked in all responses)
- **Max Tokens**: Choose 128k or 200k preset
- **CA Certificate**: Upload a custom cert bundle for enterprise TLS inspection

Click **"Test Connection"** to verify the endpoint is reachable before saving.

### 6. Export Reports

Use the **export buttons** in the top bar to download:

- **Markdown** — A full human-readable report with findings, IOCs, transforms, and strings
- **JSON** — Machine-readable structured report for integration with other tools

---

## API Reference

All endpoints are under `/api`. Interactive documentation is available at `/docs` (Swagger UI) and `/redoc` when the backend is running.

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
| `GET` | `/api/samples/{id}/original` | Get original obfuscated text |
| `GET` | `/api/samples/{id}/recovered` | Get deobfuscated text |
| `GET` | `/api/samples/{id}/diff` | Get unified diff |
| `GET` | `/api/samples/{id}/strings` | Get extracted strings |
| `GET` | `/api/samples/{id}/iocs` | Get extracted IOCs |
| `GET` | `/api/samples/{id}/findings` | Get analysis findings |
| `GET` | `/api/samples/{id}/transforms` | Get transform history |
| `GET` | `/api/samples/{id}/iterations` | Get iteration state snapshots |
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
| `GET` | `/api/samples/{id}/export/markdown` | Download Markdown report |
| `GET` | `/api/samples/{id}/export/json` | Download JSON report |

### Health

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | Health check |

---

## Demo Samples

The `backend/demo_samples/` directory contains obfuscated code samples for testing the full transform pipeline:

| File | Language | Techniques |
|------|----------|------------|
| `js_obfuscated.js` | JavaScript | Array-based string table, base64, eval, `String.fromCharCode` |
| `ps_obfuscated.ps1` | PowerShell | Base64 `-EncodedCommand`, format string obfuscation, backtick insertion, IEX |
| `py_obfuscated.py` | Python | Nested base64, `exec`, `codecs.decode` (ROT13), `chr()` lists |
| `cs_obfuscated.cs` | C# | Reflection, base64, string construction, `Type.GetType` |

These are **safe demonstration files** that decode to benign strings. They exercise the full pipeline without executing anything harmful.

To try them: create a project, upload one of these files, and click **Analyse**.

---

## Testing

### Backend Tests

```bash
cd backend

# Install test dependencies (if not already)
pip install pytest pytest-asyncio httpx

# Run all tests
pytest

# Run with verbose output
pytest -v

# Run a specific test file
pytest tests/test_transforms.py -v
```

The test suite covers:

- **160 tests** across 4 test modules
- **API endpoints** — project CRUD, sample paste/upload, analysis start/status, provider management, sub-resources (strings, IOCs, findings, transforms)
- **Transforms** — base64 decoding (nested layers, wrapper patterns), hex decoding (5 formats), string extraction (4 languages), constant folding, IOC extraction, language detection, readability scoring
- **Orchestrator** — action queue (priority ordering, deterministic bonus, failure caps, auto-approve), state manager (snapshots, rollback, confidence tracking, stall detection), stop conditions (7 termination criteria), verifier (improvement detection)
- **LLM providers** — schema validation, API key masking, max token presets, connection test mocking

### Frontend Build Verification

```bash
cd frontend
npm run build  # TypeScript compilation + Vite production build
```

---

## Security Notes

- **No code execution** — Unweaver never executes uploaded code. All analysis is pattern matching, string decoding, and LLM inference.
- **API keys** are stored in the database and **masked in all API responses** (only the last 4 characters are visible).
- **File uploads** are sanitised: filenames are stripped of directory components and dangerous characters, file size is capped at 5 MB.
- **Uploads treated as hostile** — no file paths from uploads are trusted, content is decoded as text only.
- **CORS** is configured for local development origins (`localhost:3000`, `localhost:5173`). For production, restrict `allow_origins` to your frontend domain in `app/main.py`.
- **Custom CA certificates** can be uploaded for LLM providers in enterprise environments with TLS inspection.
- **No secrets in logs** — API keys are masked in all log output via the LLM client.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, TypeScript, Vite, Monaco Editor, react-diff-viewer-continued, Lucide icons |
| Backend | Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2.0 (async) |
| Database | SQLite via aiosqlite (zero-config, single-file) |
| LLM Client | httpx (async), OpenAI-compatible chat/completions protocol |
| Testing | pytest, pytest-asyncio, httpx AsyncClient |
| Containers | Docker, Docker Compose |

---

## License

This project is proprietary. All rights reserved.
