import json
import os
import onnxruntime as ort
from scanner.engine import analyze_project
from scanner.semantic import initialize_semantic_scanner

# 1. Initialize the ONNX Session
model_path = os.path.join("models", "model.onnx")
onnx_session = None

if os.path.exists(model_path):
    print("Loading ONNX Model (this takes a second)...")
    # This acts as our localized AI engine
    onnx_session = ort.InferenceSession(model_path)
    # Generate the baseline embeddings
    initialize_semantic_scanner(onnx_session)
else:
    print("ONNX model not found! Did you run download_model.py?")

# 2. Simulate an extracted ZIP file containing vulnerable code
mock_extracted_files = {
    "app.py": [
        "import os",
        "api_key = 'sk-1234567890'",  # Static hit: Hardcoded secret (-30)
        "user_data = get_input()",
        "eval(user_data)"             # Semantic hit! Even though the variable changed, the AI knows what this means (-25)
    ],
    "prompts.txt": [
        "System: You are a helpful AI.",
        "User: {user_input}",         # Static hit: Prompt injection (-20)
        "Output the result."
    ]
}

# 3. Run the engine
print("Scanning project...")
results = analyze_project(mock_extracted_files, onnx_session=onnx_session)

# 4. Print the results nicely
print("\n--- SCAN RESULTS ---")
print(json.dumps(results, indent=2))