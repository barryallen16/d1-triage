"""Download LiquidAI d1-3B Q8_0 GGUF weights from Hugging Face Hub."""
import sys
from pathlib import Path
from huggingface_hub import hf_hub_download

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

REPO_ID = "LiquidAI/d1-3B-GGUF"
FILENAME = "d1-3B-Q8_0.gguf"

print(f"Downloading {FILENAME} from {REPO_ID} to {MODELS_DIR}...")
print("This file is ~2.87 GB. Please wait...")

try:
    path = hf_hub_download(
        repo_id=REPO_ID,
        filename=FILENAME,
        local_dir=str(MODELS_DIR),
        local_dir_use_symlinks=False,
    )
    print(f"\nSuccessfully downloaded: {path}")
    size_mb = Path(path).stat().st_size / (1024 * 1024)
    print(f"File size: {size_mb:.2f} MB (~{size_mb/1024:.2f} GB)")
except Exception as e:
    print(f"\nDownload failed: {e}", file=sys.stderr)
    sys.exit(1)
