#!/usr/bin/env bash
set -euo pipefail

python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
cp -n .env.example backend/.env
echo "ARGUS backend setup complete. Edit backend/.env, then run: uvicorn backend.app.main:app --reload"

