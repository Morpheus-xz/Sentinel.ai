import torch
from transformers import AutoTokenizer, AutoModel
import os

print("Downloading CodeBERT...")
model_id = "microsoft/codebert-base"
save_dir = "models"
os.makedirs(save_dir, exist_ok=True)

# Save tokenizer
tokenizer = AutoTokenizer.from_pretrained(model_id)
tokenizer.save_pretrained(save_dir)
print("Tokenizer saved.")

# Load model
model = AutoModel.from_pretrained(model_id)
model.eval()

# Create dummy inputs
dummy_input_ids = torch.ones(1, 128, dtype=torch.long)
dummy_attention_mask = torch.ones(1, 128, dtype=torch.long)

# Export to ONNX directly with opset 17
print("Exporting to ONNX...")
torch.onnx.export(
    model,
    (dummy_input_ids, dummy_attention_mask),
    f"{save_dir}/model.onnx",
    input_names=["input_ids", "attention_mask"],
    output_names=["last_hidden_state"],
    dynamic_axes={
        "input_ids": {0: "batch_size", 1: "sequence_length"},
        "attention_mask": {0: "batch_size", 1: "sequence_length"},
        "last_hidden_state": {0: "batch_size", 1: "sequence_length"},
    },
    opset_version=17,
)

print(f"\nSuccess! model.onnx saved to '{save_dir}/'")
