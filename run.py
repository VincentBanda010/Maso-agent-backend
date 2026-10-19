"""Start Maso with local secrets; existing environment values take precedence."""
import argparse
import os
from pathlib import Path
import uvicorn

root = Path(__file__).resolve().parent
os.chdir(root)
env_file = root / ".env"
if env_file.exists():
    for line in env_file.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith("#") and "=" in line:
            name, value = line.split("=", 1)
            name = name.strip()
            if name.startswith("MASO_"):
                os.environ.setdefault(name, value.strip())
if not os.getenv("MASO_API_KEY", "").strip():
    raise SystemExit("Set MASO_API_KEY in .env before starting Maso.")
parser = argparse.ArgumentParser(description="Start the Maso API")
parser.add_argument("--port", type=int, default=8000)
args = parser.parse_args()
uvicorn.run("app.main:app", host="127.0.0.1", port=args.port, access_log=False)
