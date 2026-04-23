import os
from optimum.onnxruntime import ORTModelForFeatureExtraction
from transformers import AutoTokenizer

print("Downloading CodeBERT and converting to ONNX...")

model_id = "microsoft/codebert-base"
save_dir = "models"

# Create the directory if it doesn't exist
os.makedirs(save_dir, exist_ok=True)

# 1. Load the model (export=True forces the ONNX conversion)
tokenizer = AutoTokenizer.from_pretrained(model_id)
model = ORTModelForFeatureExtraction.from_pretrained(model_id, export=True)

# 2. Save the converted ONNX model and tokenizer locally
tokenizer.save_pretrained(save_dir)
model.save_pretrained(save_dir)

print(f"\nSuccess! ONNX model saved to the '{save_dir}' directory.")