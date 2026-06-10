#!/bin/bash

# ── A3 Security System — One-command startup ──────────────────────────────────

CYAN='\033[96m'
GREEN='\033[92m'
YELLOW='\033[93m'
RED='\033[91m'
RESET='\033[0m'

A3_DIR="$HOME/A3"
VENV="$A3_DIR/venv/bin/activate"

echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║       A3 SECURITY SYSTEM — STARTING UP        ║${RESET}"
echo -e "${CYAN}╚═══════════════════════════════════════════════╝${RESET}"
echo ""

# ── Check Docker is running ───────────────────────────────────────────────────
echo -e "${YELLOW}[1/5] Checking Docker...${RESET}"
if ! docker ps > /dev/null 2>&1; then
    echo -e "${RED}✗ Docker is not running. Open Docker Desktop first.${RESET}"
    exit 1
fi
echo -e "${GREEN}✓ Docker running${RESET}"

# ── Check Ollama ──────────────────────────────────────────────────────────────
echo -e "${YELLOW}[2/5] Starting Ollama...${RESET}"
if pgrep -x "ollama" > /dev/null; then
    echo -e "${GREEN}✓ Ollama already running${RESET}"
else
    ollama serve > /tmp/a3_ollama.log 2>&1 &
    sleep 3
    echo -e "${GREEN}✓ Ollama started${RESET}"
fi

# ── Activate venv ─────────────────────────────────────────────────────────────
echo -e "${YELLOW}[3/5] Activating virtual environment...${RESET}"
if [ ! -f "$VENV" ]; then
    echo -e "${RED}✗ Virtual environment not found at $VENV${RESET}"
    exit 1
fi
source "$VENV"
echo -e "${GREEN}✓ Virtual environment active${RESET}"

# ── Start API server ──────────────────────────────────────────────────────────
echo -e "${YELLOW}[4/5] Starting API server (port 8000)...${RESET}"
cd "$A3_DIR"
python3 -m uvicorn core.api:app --port 8000 > /tmp/a3_api.log 2>&1 &
API_PID=$!
sleep 2
if kill -0 $API_PID 2>/dev/null; then
    echo -e "${GREEN}✓ API server running (PID: $API_PID)${RESET}"
else
    echo -e "${RED}✗ API server failed to start — check /tmp/a3_api.log${RESET}"
fi

# ── Start dashboard ───────────────────────────────────────────────────────────
echo -e "${YELLOW}[5/5] Starting dashboard (port 5173)...${RESET}"
cd "$A3_DIR/dashboard"
npm run dev > /tmp/a3_dashboard.log 2>&1 &
DASH_PID=$!
sleep 3
echo -e "${GREEN}✓ Dashboard starting (PID: $DASH_PID)${RESET}"

# ── Start controller in foreground ───────────────────────────────────────────
cd "$A3_DIR"
echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║  All services started                         ║${RESET}"
echo -e "${CYAN}║  Dashboard  → http://localhost:5173           ║${RESET}"
echo -e "${CYAN}║  API        → http://localhost:8000           ║${RESET}"
echo -e "${CYAN}║                                               ║${RESET}"
echo -e "${CYAN}║  Press Ctrl+C to stop everything             ║${RESET}"
echo -e "${CYAN}╚═══════════════════════════════════════════════╝${RESET}"
echo ""

# Open dashboard in browser
sleep 2
open http://localhost:5173 2>/dev/null || true

# Run controller in foreground (this keeps the script alive)
python3 core/controller.py

# ── Cleanup on exit ───────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}Shutting down A3...${RESET}"
kill $API_PID 2>/dev/null
kill $DASH_PID 2>/dev/null
echo -e "${GREEN}A3 stopped.${RESET}"
