# A3 Security System

An autonomous, multi-layer endpoint security system with AI-powered threat analysis, Docker sandboxing, network detection, and a live React dashboard.

Built entirely in Python and React. Runs locally — no cloud, no subscriptions, no data leaves your machine.

---

## What it does

A3 monitors your system like an immune system — detecting threats, isolating them, analysing them with AI, and learning from every encounter.

| Layer | What it does |
|-------|-------------|
| Layer 2 — Monitor | Watches every process and file in real time. Scores suspicious behaviour. |
| Layer 3 — Sandbox | Locks flagged files in an isolated Docker container. No internet, no system access. |
| Layer 4 — AI Analysis | Sends sandbox reports to a local LLM (Llama3 via Ollama). Returns threat type, danger level, recommended action. |
| Layer 5 — Signal Detection | Maps every device on your network. Detects unknown or rogue devices. Scans open ports. |
| ML Layer | Trained classifier that predicts threats instantly without needing the AI — gets smarter over time. |
| Controller | Connects all layers. When a file is flagged → sandbox → AI → verdict. Fully automatic. |
| Dashboard | Live React UI showing alerts, sandbox results, AI assessments, network map, process monitor. |

---

## Architecture

```
File appears in Downloads / Desktop / tmp
        ↓
Layer 2 detects it (monitor.py)
        ↓
Controller picks it up (controller.py)
        ↓
Layer 3 locks it in Docker (sandbox.py)
        ↓
ML classifier gives instant verdict (ml_trainer.py)
        ↓
Layer 4 Llama3 gives deep analysis (ai_analyst.py)
        ↓
Verdict → ALLOW / MONITOR / QUARANTINE
        ↓
Live dashboard shows everything (React + FastAPI)

![A3 Dashboard](assets/dashboard.png)

```

---

## Tech stack

- **Python 3.11** — all backend layers
- **FastAPI + Uvicorn** — REST API for dashboard
- **React + Vite + Tailwind** — live dashboard
- **Docker** — sandbox isolation
- **SQLite + pgvector** — threat database
- **Ollama + Llama3** — local AI analysis (no internet required)
- **scikit-learn** — ML threat classifier
- **psutil + watchdog** — process and file monitoring
- **Scapy** — network signal detection

---

## Setup

### Requirements
- Mac or Linux
- Python 3.11+
- Docker Desktop
- Node.js 18+
- [Ollama](https://ollama.ai) with Llama3 installed

### Install

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/A3-Security-System.git
cd A3-Security-System

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Install dashboard dependencies
cd dashboard && npm install && cd ..
```

### Run

```bash
# Terminal 1 — start Ollama
ollama serve

# Terminal 2 — start A3 controller (all layers)
source venv/bin/activate
python3 core/controller.py

# Terminal 3 — start the API
python3 -m uvicorn core.api:app --reload --port 8000

# Terminal 4 — start the dashboard
cd dashboard && npm run dev
```

Open **http://localhost:5173** in your browser.

### Train the ML model

```bash
python3 core/ml_trainer.py
```

### Scan your network

```bash
python3 core/signal_detector.py --continuous
```

---

## Roadmap

- [x] Layer 2 — process and file monitor
- [x] Layer 3 — Docker sandbox with static + dynamic analysis
- [x] Layer 4 — local AI analysis via Ollama/Llama3
- [x] Layer 5 — network and signal detection
- [x] ML classifier — self-improving threat model
- [x] Live React dashboard
- [ ] Swarm agents — share threat intelligence across multiple machines
- [ ] Blockchain threat ledger — tamper-proof incident records
- [ ] Shannon integration — automated web app pentesting
- [ ] Financial monitoring module — correlate cyber events with business impact

---

## Important

This tool is for **defensive security purposes only** on systems you own or have explicit permission to monitor.

The network scanning and signal detection features must only be used on networks you own or administer.

---

## License

MIT License — free to use, modify, and distribute.
