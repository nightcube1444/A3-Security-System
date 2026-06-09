# A3 Security System — Layer 2

Your immune system for your Mac.
Watches processes and files. Scores threats. Learns over time.

---

## Setup (do this once)

Open Terminal and run these commands one by one:

```bash
# 1. Go into the A3 folder
cd ~/A3

# 2. Create a virtual environment (keeps your project clean)
python3 -m venv venv

# 3. Activate it
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt
```

---

## Run the monitor

```bash
# Make sure venv is active first
source venv/bin/activate

# Start the monitor (runs until you press Ctrl+C)
python3 core/monitor.py
```

You will see live output in your terminal.
Everything is also saved to: `data/a3_threats.db`

---

## See what was detected

Open a second terminal tab and run:

```bash
source venv/bin/activate
python3 core/viewer.py
```

This shows you a full threat report from the database.

---

## What it watches

| Layer | What |
|-------|------|
| Processes | Every new process that starts on your Mac |
| Files | New or modified files in Downloads, Desktop, /tmp |
| Scoring | Each suspicious signal adds points to a threat score |
| Threshold | Score >= 50 = FLAGGED as a threat |

## Threat score flags

| Flag | Points | Meaning |
|------|--------|---------|
| suspicious_name | +40 | Known hacking tool name |
| suspicious_path | +30 | Running from /tmp or Downloads |
| running_as_root | +20 | Unexpected root process |
| network_no_exe | +25 | Network connection with no known path |
| obfuscated_command | +35 | base64 or eval in command |
| hidden_process_name | +40 | Process name starts with a dot |
| suspicious_extension | +30 | .sh .py .exe etc in watched folder |
| executable_bit_set | +20 | New file is marked as executable |

---

## Folder structure

```
A3/
├── core/
│   ├── monitor.py      ← the main monitor (run this)
│   └── viewer.py       ← threat report viewer
├── data/
│   └── a3_threats.db   ← SQLite database (auto-created)
├── logs/
│   └── monitor.log     ← log file (auto-created)
├── config/             ← future: config files
└── requirements.txt
```

---

## Next steps (coming soon)

- Layer 3: Docker sandbox — lock threats in an isolated container
- Layer 4: AI analysis — Claude analyses sandboxed threats
- Layer 5: Signal detection — detect nearby WiFi/Bluetooth devices
- v2: Swarm agents — share intelligence across multiple machines
- v2: ML models — train your own threat classifier
- v3: Blockchain — tamper-proof threat ledger
