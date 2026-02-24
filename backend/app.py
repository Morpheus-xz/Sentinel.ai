import os
import io
import zipfile
import onnxruntime as ort
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Internal DevSecOps Engines
from scanner.engine import analyze_project, calculate_score
from scanner.semantic import initialize_semantic_scanner, scan_file_semantic
from scanner.static import scan_file_static
from scanner.taint import run_taint_analysis

# 1. Initialize FastAPI
app = FastAPI(title="SENTINEL-AI Enterprise Engine")

# 2. Configure CORS so our React frontend can talk to it safely
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variable to hold our AI model
onnx_session = None


# 3. Load the AI Model into Hardware NPU/CPU ONCE when the server starts
@app.on_event("startup")
async def startup_event():
    global onnx_session
    model_path = os.path.join("models", "model.onnx")

    if os.path.exists(model_path):
        print("Loading AI Model into Hardware Accelerator...")

        # 1. Silence the noisy ONNX C++ Backend Warnings
        ort.set_default_logger_severity(3)

        # 2. Dynamically check what hardware you actually have to avoid Python warnings
        available = ort.get_available_providers()
        providers = []

        if 'DmlExecutionProvider' in available:
            providers.append('DmlExecutionProvider')  # AMD/Windows
        if 'CoreMLExecutionProvider' in available:
            providers.append('CoreMLExecutionProvider')  # Apple Silicon (M1/M2/M3/M4)

        providers.append('CPUExecutionProvider')  # Universal Fallback

        # Initialize the session silently
        onnx_session = ort.InferenceSession(model_path, providers=providers)
        initialize_semantic_scanner(onnx_session)
        print("🟢 SENTINEL-AI Brain is Online!")
    else:
        print("⚠️ WARNING: ONNX model not found. Semantic scanning is disabled.")


# 4. Define the Data Model for the Live Editor
class CodeSnippet(BaseModel):
    code: str
    filename: str = "live_editor.py"


# 5. Create the Live Code Paste Endpoint
@app.post("/api/scan-live")
async def scan_live_code(snippet: CodeSnippet):
    """Real-time analysis route for live code pasting in the UI."""
    code_lines = snippet.code.split('\n')

    # 1. Run the new Taint Analysis Engine (Source-to-Sink Tracking)
    taint_results = run_taint_analysis(snippet.code)

    # 2. Run Static Scanner (RegEx & Secrets)
    static_results = scan_file_static(snippet.filename, code_lines)

    # 3. Run Semantic Scanner (AST + CodeBERT ONNX)
    semantic_results = {"issues": [], "telemetries": []}
    if onnx_session:
        semantic_results = scan_file_semantic(snippet.filename, code_lines, onnx_session)

    # 4. Combine all identified threats
    raw_issues = taint_results + static_results + semantic_results["issues"]

    # 5. DEDUPLICATION LOGIC: Prioritize Taint Engine's deep context over generic AI alerts
    seen_lines = set()
    all_issues = []

    # First pass: Lock in the Taint tracking exploits (they are the smartest and most accurate)
    for issue in raw_issues:
        if issue.get("type") == "DATA_FLOW_EXPLOIT":
            sig = f"{issue.get('file')}:{issue.get('line')}"
            all_issues.append(issue)
            seen_lines.add(sig)

    # Second pass: Add the remaining issues ONLY if that exact line wasn't already flagged
    for issue in raw_issues:
        if issue.get("type") != "DATA_FLOW_EXPLOIT":
            sig = f"{issue.get('file')}:{issue.get('line')}"
            if sig not in seen_lines:
                all_issues.append(issue)
                seen_lines.add(sig)

    # Calculate System Integrity Score
    final_score = calculate_score(all_issues)

    return {
        "security_score": final_score,
        "mode": "LIVE_INFERENCE",
        "issues": all_issues
    }


# 6. Create the main ZIP Project Scan Endpoint
@app.post("/api/scan")
async def scan_project(file: UploadFile = File(...)):
    if not file.filename.endswith('.zip'):
        raise HTTPException(status_code=400, detail="Only ZIP files are supported.")

    # Read the uploaded ZIP file directly into memory
    contents = await file.read()
    extracted_files = {}

    try:
        # Open the ZIP file from the memory buffer
        with zipfile.ZipFile(io.BytesIO(contents)) as zip_ref:
            for file_info in zip_ref.infolist():
                # Skip directories and hidden files (like macOS .DS_Store)
                if file_info.is_dir() or file_info.filename.startswith('.') or '__MACOSX' in file_info.filename:
                    continue

                # Only extract source code files to save compute time
                allowed_extensions = ('.py', '.js', '.ts', '.jsx', '.tsx', '.txt', '.json')
                if not file_info.filename.endswith(allowed_extensions):
                    continue

                with zip_ref.open(file_info) as f:
                    try:
                        # Decode the bytes into a string and split by line
                        content = f.read().decode('utf-8')
                        lines = content.split('\n')
                        extracted_files[file_info.filename] = lines
                    except UnicodeDecodeError:
                        # Skip binary files that accidentally slipped through
                        continue

    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid or corrupted ZIP file.")

    if not extracted_files:
        raise HTTPException(status_code=400, detail="No readable code files found in the ZIP.")

    # Hand the extracted files to our Risk Engine
    print(f"Scanning {len(extracted_files)} files...")
    results = analyze_project(extracted_files, onnx_session=onnx_session)

    return results