"""Direct streaming downloader for LiquidAI d1-3B Q8_0 GGUF with progress tracking."""
import sys
import time
import urllib.request
from pathlib import Path

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)
TARGET_FILE = MODELS_DIR / "d1-3B-Q8_0.gguf"

URL = "https://huggingface.co/LiquidAI/d1-3B-GGUF/resolve/main/d1-3B-Q8_0.gguf"
CHUNK_SIZE = 8 * 1024 * 1024

print(f"Streaming from: {URL}")
print(f"Target file: {TARGET_FILE}")

req = urllib.request.Request(
    URL,
    headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) d1-triage/1.0",
    },
)

t0 = time.time()
try:
    with urllib.request.urlopen(req) as resp, open(TARGET_FILE, "wb") as out_f:
        total_size = int(resp.headers.get("Content-Length", 2874781280))
        downloaded = 0
        last_print = 0

        print(f"Total size: {total_size / (1024*1024):.1f} MB (~{total_size / (1024*1024*1024):.2f} GB)")

        while True:
            chunk = resp.read(CHUNK_SIZE)
            if not chunk:
                break
            out_f.write(chunk)
            downloaded += len(chunk)

            elapsed = time.time() - t0
            speed_mb = (downloaded / (1024 * 1024)) / max(0.1, elapsed)
            pct = (downloaded / total_size) * 100


            if downloaded - last_print >= 100 * 1024 * 1024 or downloaded >= total_size:
                last_print = downloaded
                rem_mb = (total_size - downloaded) / (1024 * 1024)
                eta_s = rem_mb / max(0.1, speed_mb)
                print(f"Progress: {downloaded / (1024*1024):.1f}/{total_size / (1024*1024):.1f} MB ({pct:.1f}%) | Speed: {speed_mb:.1f} MB/s | ETA: {eta_s:.0f}s")

    elapsed_total = time.time() - t0
    final_size = TARGET_FILE.stat().st_size
    print(f"\n[DONE] Successfully downloaded {final_size / (1024*1024):.1f} MB in {elapsed_total:.1f}s")

except Exception as ex:
    print(f"\n[ERROR] Download interrupted: {ex}", file=sys.stderr)
    sys.exit(1)
