import zipfile
import io

# The trick code we will test the AI against
vulnerable_code = """import os

# 1. THE FAKE SECRET (Should be IGNORED by the AI)
api_key = "your_api_key_here"

# 2. THE REAL SECRET (Should be FLAGGED and auto-fixed)
aws_secret = "AKIAIOSFODNN7EXAMPLE"

def calculate_math():
    # 3. THE SAFE EVAL (Should be IGNORED by the AI)
    result = eval("5 * 10 + 2")
    return result

def run_user_code(user_input):
    # 4. THE DANGEROUS EVAL (Should be FLAGGED and auto-fixed)
    return eval(user_input)
"""

test_file_code = """
# 5. THE TEST FILE (Should be IGNORED because it's a test file)
api_key = "sk-live-real-secret-but-in-test-file"
"""

# Create the ZIP file in memory and save it
with zipfile.ZipFile("test_project.zip", "w") as zf:
    zf.writestr("main.py", vulnerable_code)
    zf.writestr("test_main.py", test_file_code)

print("✅ test_project.zip has been generated successfully!")