#!/usr/bin/env bash
set -e
echo "[*] Installing Python dependencies..."
python3 -m pip install -r requirements.txt
echo "[*] Training baseline model..."
python3 train_model.py
echo "[✓] Setup complete."
echo "Run: python3 main.py"
echo "API: uvicorn api.server:app --host 127.0.0.1 --port 8000"
