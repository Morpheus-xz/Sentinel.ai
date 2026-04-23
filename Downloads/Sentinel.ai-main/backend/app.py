import os
import io
import zipfile
import onnxruntime as ort
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from scanner.engine import analyze_project, calculate_score
from scanner.semantic import initialize_semantic_scanner, scan_file_semantic
from scanner.static import scan_file_static
from scanner.taint import run_taint_analysis

app = FastAPI(title="SENTINEL-AI Security Engine")

# CORS — restrict in production to your frontend domain
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # TODO: lock to your domain before production deploy
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

onnx_session = None

# Maximum ZIP size: 50MB — prevents memory exhaustion attacks
MAX_ZIP_SIZE_BYTES = 50 * 1024 * 1024

# Maximum individual file size: 1MB — prevents huge file DoS
MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024

ALLOWED_EXTENSIONS = ('.py', '.js', '.ts', '.jsx', '.tsx', '.txt', '.json')


@app.on_event("startup")
async def startup_event():
    global onnx_session
    model_path = os.path.join("models", "model.onnx")

    if os.path.exists(model_path):
        print("Loading AI Model into Hardware Accelerator...")
        ort.set_default_logger_severity(3)

        available = ort.get_available_providers()
        providers = []
        if 'DmlExecutionProvider' in available:
            providers.append('DmlExecutionProvider')
        if 'CoreMLExecutionProvider' in available:
            providers.append('CoreMLExecutionProvider')
        providers.append('CPUExecutionProvider')

        onnx_session = ort.InferenceSession(model_path, providers=providers)
        initialize_semantic_scanner(onnx_session)
        print("SENTINEL-AI Brain is Online!")
    else:
        print("WARNING: ONNX model not found. Semantic scanning is disabled.")
        print("Run: python download_model.py")


class CodeSnippet(BaseModel):
    code: str
    filename: str = "live_editor.py"


@app.post("/api/scan-live")
async def scan_live_code(snippet: CodeSnippet):
    """Real-time analysis for the live code editor."""

    # Guard: reject absurdly large pastes
    if len(snippet.code) > 100_000:
        raise HTTPException(status_code=413, detail="Code snippet too large (max 100KB).")

    code_lines = snippet.code.split('\n')

    taint_results = run_taint_analysis(snippet.code, filename=snippet.filename)
    static_results = scan_file_static(snippet.filename, code_lines)

    semantic_results = {"issues": [], "telemetries": []}
    if onnx_session:
        semantic_results = scan_file_semantic(snippet.filename, code_lines, onnx_session)

    raw_issues = taint_results + static_results + semantic_results["issues"]

    # Deduplication — taint results win over generic AI alerts on the same line
    seen_lines = {}
    all_issues = []

    for issue in raw_issues:
        sig = f"{issue.get('file')}:{issue.get('line')}"
        is_taint = issue.get("type") == "DATA_FLOW_EXPLOIT"
        if sig not in seen_lines:
            seen_lines[sig] = is_taint
            all_issues.append(issue)
        elif is_taint and not seen_lines[sig]:
            # Replace weaker finding with taint result
            seen_lines[sig] = True
            all_issues = [i for i in all_issues if f"{i.get('file')}:{i.get('line')}" != sig]
            all_issues.append(issue)

    final_score = calculate_score(all_issues)

    return {
        "security_score": final_score,
        "mode": "LIVE_INFERENCE",
        "issues": all_issues
    }


@app.post("/api/scan")
async def scan_project(file: UploadFile = File(...)):
    if not file.filename.endswith('.zip'):
        raise HTTPException(status_code=400, detail="Only ZIP files are supported.")

    contents = await file.read()

    # Guard: ZIP size limit
    if len(contents) > MAX_ZIP_SIZE_BYTES:
        raise HTTPException(status_code=413, detail=f"ZIP file too large (max {MAX_ZIP_SIZE_BYTES // (1024*1024)}MB).")

    extracted_files = {}

    try:
        with zipfile.ZipFile(io.BytesIO(contents)) as zip_ref:
            # Guard: ZIP bomb check — total uncompressed size
            total_size = sum(info.file_size for info in zip_ref.infolist())
            if total_size > MAX_ZIP_SIZE_BYTES * 10:
                raise HTTPException(status_code=413, detail="ZIP contents exceed safe extraction limit.")

            for file_info in zip_ref.infolist():
                # Skip directories, hidden files, and macOS artifacts
                if file_info.is_dir():
                    continue
                fname = file_info.filename
                if fname.startswith('.') or '__MACOSX' in fname or fname.startswith('/'):
                    continue

                # Only process known source code file types
                if not fname.endswith(ALLOWED_EXTENSIONS):
                    continue

                # Guard: individual file size
                if file_info.file_size > MAX_FILE_SIZE_BYTES:
                    continue

                with zip_ref.open(file_info) as f:
                    try:
                        content = f.read().decode('utf-8')
                        extracted_files[fname] = content.split('\n')
                    except UnicodeDecodeError:
                        continue

    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid or corrupted ZIP file.")

    if not extracted_files:
        raise HTTPException(status_code=400, detail="No readable source code files found in the ZIP.")

    print(f"Scanning {len(extracted_files)} files...")
    results = analyze_project(extracted_files, onnx_session=onnx_session)

    return results
