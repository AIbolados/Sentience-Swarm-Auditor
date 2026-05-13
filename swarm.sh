#!/bin/bash
# Sentience Swarm Launcher
# Uso: bash swarm.sh

BASE_DIR="/home/jibol2/swarm_auditor"
PYTHON_EXE="$BASE_DIR/venv/bin/python3"

# Asegurar que el entorno existe
if [ ! -f "$PYTHON_EXE" ]; then
    echo "🔧 Inicializando entorno del Swarm..."
    python3 -m venv "$BASE_DIR/venv"
    "$BASE_DIR/venv/bin/pip" install -q ruff bandit radon requests
fi

# Ejecutar el conductor
"$PYTHON_EXE" "$BASE_DIR/conductor.py"
