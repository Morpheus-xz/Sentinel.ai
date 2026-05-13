# SENTINEL.AI

**On-Device AI-Based Code Security Analysis System**

`Python 3.10+` &nbsp;|&nbsp; `FastAPI` &nbsp;|&nbsp; `React` &nbsp;|&nbsp; `CodeBERT` &nbsp;|&nbsp; `ONNX Runtime` &nbsp;|&nbsp; `AMD Hardware Acceleration`

---

> SENTINEL.AI scans software projects entirely on your local machine — detecting vulnerabilities, flagging insecure dependencies, and generating secure code fixes using a locally-hosted AI model. No source code ever leaves your device.

---

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Core Analysis Modules](#core-analysis-modules)
- [Project Structure](#project-structure)
- [Technology Stack](#technology-stack)
- [Installation](#installation)
- [Output](#output)
- [Use Cases](#use-cases)
- [Team](#team)

---

## Overview

Most security scanning tools require you to send your source code to an external server. SENTINEL.AI takes a different approach — all analysis runs directly on your hardware, using a locally deployed AI model, with no network dependency required after setup.

SENTINEL.AI provides:

- Detection of unsafe code execution patterns
- Identification of vulnerable third-party dependencies
- Line-level vulnerability location across your entire codebase
- AI-generated secure code suggestions for every finding
- An overall security integrity score for the scanned project

The system is designed to be fast, private, and practical — usable during active development without disrupting your workflow.

---

## How It Works

Upload a `.zip` archive of your project through the dashboard and SENTINEL.AI handles the rest automatically.

**1. Local Extraction** — The backend extracts your source code entirely in local memory. Nothing is written to disk and nothing is transmitted externally.

**2. Parallel Analysis** — All analysis modules run simultaneously across the extracted codebase, covering structural patterns, semantic behavior, hardcoded secrets, and dependency vulnerabilities.

**3. AI Inference** — The locally-hosted CodeBERT model analyzes code behavior through ONNX Runtime, using AMD GPU or NPU acceleration where available, falling back to CPU automatically.

**4. Report Generation** — The engine controller aggregates results from every module into a single, structured security report.

**5. Dashboard Display** — Findings are rendered in the frontend with file names, line numbers, vulnerability descriptions, and suggested secure fixes.

---

## Core Analysis Modules

### AST Analysis Engine — `taint.py`

Parses Python source code into an Abstract Syntax Tree and traces execution paths to detect structurally dangerous patterns — including use of `eval`, `exec`, unsafe deserialization, and other high-risk operations. This engine catches vulnerabilities that exist in the code's structure before it ever runs.

---

### Semantic AI Analysis — `semantic.py`

Deploys a CodeBERT Transformer model locally through ONNX Runtime to understand code at a behavioral level. Rather than matching fixed patterns, it converts code into mathematical vectors and detects vulnerabilities that are only visible through semantic context — catching obfuscated and logic-level issues that traditional scanners miss entirely.

Runs on AMD GPU → AMD Ryzen AI NPU → CPU, in order of availability. No manual configuration required.

---

### Static Security Scanner — `static.py`

Pattern-based scanner that hunts for hardcoded secrets embedded directly in source code — API keys, passwords, authentication tokens, private keys, and other credentials that should never appear in a codebase. Includes deduplication to prevent repeat findings from generating duplicate alerts.

---

### Dependency Vulnerability Scanner — `sbom.py`

Reads dependency manifests such as `requirements.txt` and cross-references declared libraries against a database of known vulnerable versions. Flags outdated or compromised packages before they reach production.

---

### Privacy Guard — `privacy_guard.py`

Scans the AST for outbound network access — any use of `requests`, `socket`, `urllib`, or similar libraries. Identifies code that could be sending data to external servers, helping teams verify that no component of their application exfiltrates information unexpectedly.

---

### Engine Controller — `engine.py`

Coordinates all five analysis modules, runs them in parallel, and combines their individual results into a single unified security report. Acts as the central orchestrator for the entire analysis pipeline.

---

## Project Structure

```
sentinel-ai/
│
├── backend/
│   ├── app.py                  # FastAPI server and API endpoint routing
│   ├── download_model.py       # CodeBERT model download utility
│   ├── requirements.txt        # Python dependencies
│   ├── test_engine.py          # Engine test suite
│   │
│   ├── models/                 # Local CodeBERT ONNX model storage (~499 MB)
│   │
│   └── scanner/
│       ├── __init__.py
│       ├── engine.py           # Parallel engine coordinator
│       ├── taint.py            # AST data-flow and execution path analysis
│       ├── semantic.py         # CodeBERT / ONNX AI inference layer
│       ├── static.py           # Hardcoded secrets and credentials scanner
│       ├── sbom.py             # Dependency vulnerability scanner
│       └── privacy_guard.py    # Outbound network usage detection
│
└── frontend/
    ├── index.html
    ├── package.json
    ├── vite.config.js
    │
    ├── public/
    │   └── sentinel.png
    │
    └── src/
        ├── App.jsx             # Main application and routing
        ├── App.css
        ├── main.jsx
        └── index.css
```

---

## Technology Stack

**Frontend**
React, Vite, HTML, CSS

**Backend**
Python 3.10+, FastAPI

**AI & Code Analysis**
CodeBERT, ONNX Runtime, Python AST, Regex, Static Code Analysis

**Hardware Acceleration**
AMD Radeon GPU, AMD Ryzen AI NPU, CPU fallback

---

## Installation

### Requirements

Before starting, ensure you have the following installed:

- Python 3.10 or higher — [python.org](https://python.org)
- Node.js 18 or higher — [nodejs.org](https://nodejs.org)
- Git — [git-scm.com](https://git-scm.com)

An AMD Radeon GPU or AMD Ryzen AI NPU is recommended for faster AI inference but is entirely optional. The system falls back to CPU automatically.

---

### Step 1 — Clone the Repository

```bash
git clone https://github.com/your-org/sentinel-ai.git
cd sentinel-ai
```

---

### Step 2 — Set Up the Backend

```bash
cd backend
python -m venv .venv
```

Activate the virtual environment:

```bash
# macOS / Linux
source .venv/bin/activate

# Windows
.venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

### Step 3 — Download the AI Model

Run the provided model download script to fetch the CodeBERT ONNX model (~499 MB) into the `models/` directory:

```bash
python download_model.py
```

> The `models/` directory is excluded from version control. This step is required on first setup.

---

### Step 4 — Start the Backend Server

```bash
uvicorn app:app --reload
```

The API will be available at `http://localhost:8000`.

---

### Step 5 — Set Up the Frontend

Open a new terminal, then:

```bash
cd frontend
npm install
npm run dev
```

---

### Step 6 — Open SENTINEL.AI

Navigate to `http://localhost:5173` in your browser. Upload a `.zip` archive of any Python project to begin scanning.

---

## Output

For every vulnerability detected, SENTINEL.AI reports:

| Field | Description |
|---|---|
| **File** | The source file containing the vulnerability |
| **Line Number** | The exact line where the issue was found |
| **Description** | A plain-language explanation of the vulnerability |
| **Secure Fix** | An AI-generated code suggestion to resolve it |
| **Integrity Score** | An overall security score for the scanned project |

---

## Use Cases

**Security review during development** — Run SENTINEL.AI on your codebase at any point during development to catch vulnerabilities before they reach code review or production.

**Regulated and air-gapped environments** — Because all processing is local, SENTINEL.AI is suitable for environments where source code cannot leave the premises or be sent to cloud services.

**Learning secure coding practices** — Developers learning about application security can use SENTINEL.AI as a hands-on tool to understand what makes code vulnerable and how to write safer alternatives.

---

## Frequently Asked Questions

**Does SENTINEL.AI send my code anywhere?**
No. All analysis runs locally. No source code is transmitted to any external server at any point.

**What languages does it support?**
The current version is optimized for Python projects.

**What if I don't have an AMD GPU?**
SENTINEL.AI will automatically fall back to CPU inference. Analysis will still complete correctly, though it may take slightly longer.

**Where is the AI model stored?**
The ONNX-exported CodeBERT model is stored in `backend/models/` after running `download_model.py`. It never leaves your machine.

**Can I run this on Windows?**
Yes. All components support Windows, macOS, and Linux.

---

## Team

| Name | Role |
|---|---|
| **Vedansh Agarwal** | Team Lead — AI Architecture, Backend & Overall Technical Supervision |
| **Yash Bhatia** | Frontend Engineering — React Dashboard & UI Design |
| **Suryansh** | Tech Support |

---

*SENTINEL.AI — On-device code security. Zero cloud. Zero leaks. Zero compromise.*
