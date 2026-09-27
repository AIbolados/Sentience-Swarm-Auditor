#!/bin/bash
# Sentience Swarm Launcher
# Uso: bash swarm.sh
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v uv &> /dev/null; then
    echo "uv no esta instalado. Instalalo: https://docs.astral.sh/uv/"
    exit 1
fi

if [ ! -f ".env" ] && [ -f ".env.example" ]; then
    echo "No existe .env. Copia .env.example a .env y completa los valores."
fi

uv sync --quiet
uv run python conductor.py
