"""
A3 Security System — Blockchain Ledger
Tamper-proof threat records. Every confirmed threat gets written
to an immutable chain. Even if malware deletes your logs,
the blockchain record survives and tampering is detectable.

Simple private blockchain — no cryptocurrency, no internet needed.
Just cryptographic chaining of threat records.
"""

import sqlite3
import json
import hashlib
import time
from datetime import datetime
from pathlib import Path

BASE_DIR    = Path(__file__).parent.parent
DATA_DIR    = BASE_DIR / "data"
DB_PATH     = DATA_DIR / "a3_threats.db"
CHAIN_PATH  = DATA_DIR / "a3_chain.json"   # backup copy of the chain

def log(message, level="INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colours = {
        "INFO":  "\033[97m", "OK":    "\033[92m",
        "WARN":  "\033[93m", "ALERT": "\033[91m",
        "CHAIN": "\033[96m"
    }
    print(f"[{ts}] {colours.get(level,'')}[CHAIN][{level}]\033[0m {message}")

# ── Database ───────────────────────────────────────────────────────────────────

def init_chain_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS blockchain (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            block_index   INTEGER UNIQUE,
            timestamp     TEXT,
            block_hash    TEXT UNIQUE,
            prev_hash     TEXT,
            data          TEXT,
            nonce         INTEGER
        )
    """)
    conn.commit()

    # Create genesis block if chain is empty
    c.execute("SELECT COUNT(*) FROM blockchain")
    if c.fetchone()[0] == 0:
        genesis = {
            "block_index": 0,
            "timestamp":   datetime.now().isoformat(),
            "prev_hash":   "0" * 64,
            "data": {
                "type":    "genesis",
                "message": "A3 Security System — Threat Ledger Initialized",
                "version": "1.0"
            },
            "nonce": 0
        }
        genesis["block_hash"] = compute_hash(genesis)
        c.execute("""
            INSERT INTO blockchain
            (block_index, timestamp, block_hash, prev_hash, data, nonce)
            VALUES (?,?,?,?,?,?)
        """, (
            genesis["block_index"],
            genesis["timestamp"],
            genesis["block_hash"],
            genesis["prev_hash"],
            json.dumps(genesis["data"]),
            genesis["nonce"]
        ))
        conn.commit()
        log("Genesis block created", "CHAIN")

    conn.close()

# ── Hashing ────────────────────────────────────────────────────────────────────

def compute_hash(block):
    """Compute SHA256 hash of a block's contents."""
    block_string = json.dumps({
        "block_index": block["block_index"],
        "timestamp":   block["timestamp"],
        "prev_hash":   block["prev_hash"],
        "data":        block["data"],
        "nonce":       block["nonce"]
    }, sort_keys=True)
    return hashlib.sha256(block_string.encode()).hexdigest()

def proof_of_work(block, difficulty=2):
    """
    Simple proof of work — find a nonce so the hash starts
    with `difficulty` zeros. Keeps the chain tamper-evident
    without being computationally heavy.
    """
    target = "0" * difficulty
    nonce  = 0
    while True:
        block["nonce"] = nonce
        h = compute_hash(block)
        if h.startswith(target):
            return nonce, h
        nonce += 1

# ── Add a block ────────────────────────────────────────────────────────────────

def add_block(data: dict):
    """
    Add a new block to the chain.
    data: dict of threat information to record permanently.
    Returns the new block hash.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Get last block
    c.execute("""
        SELECT block_index, block_hash
        FROM blockchain
        ORDER BY block_index DESC LIMIT 1
    """)
    last = c.fetchone()
    last_index = last[0]
    last_hash  = last[1]

    # Build new block
    new_block = {
        "block_index": last_index + 1,
        "timestamp":   datetime.now().isoformat(),
        "prev_hash":   last_hash,
        "data":        data,
        "nonce":       0
    }

    # Find valid nonce
    nonce, block_hash = proof_of_work(new_block)
    new_block["nonce"]      = nonce
    new_block["block_hash"] = block_hash

    # Save to DB
    c.execute("""
        INSERT INTO blockchain
        (block_index, timestamp, block_hash, prev_hash, data, nonce)
        VALUES (?,?,?,?,?,?)
    """, (
        new_block["block_index"],
        new_block["timestamp"],
        block_hash,
        last_hash,
        json.dumps(data),
        nonce
    ))
    conn.commit()
    conn.close()

    log(
        f"Block #{new_block['block_index']} added — "
        f"hash:{block_hash[:16]}...",
        "CHAIN"
    )

    # Keep a JSON backup of the chain
    backup_chain()

    return block_hash

# ── Record threat ─────────────────────────────────────────────────────────────

def record_threat(file_path, file_hash, verdict, threat_type,
                  flags, score, source="local"):
    """
    Write a confirmed threat to the blockchain permanently.
    Call this after every MALICIOUS or SUSPICIOUS verdict.
    """
    data = {
        "type":        "threat",
        "source":      source,
        "file_path":   str(file_path),
        "file_hash":   file_hash,
        "verdict":     verdict,
        "threat_type": threat_type,
        "flags":       flags,
        "score":       score,
        "recorded_at": datetime.now().isoformat()
    }
    block_hash = add_block(data)
    log(f"Threat recorded on chain: {verdict} — {Path(file_path).name}", "ALERT")
    return block_hash

def record_network_threat(ip, mac, threat_score, flags, open_ports):
    """Record a high-risk network device on the blockchain."""
    data = {
        "type":        "network_threat",
        "ip":          ip,
        "mac":         mac,
        "score":       threat_score,
        "flags":       flags,
        "open_ports":  open_ports,
        "recorded_at": datetime.now().isoformat()
    }
    return add_block(data)

def record_system_event(event_type, details):
    """Record important system events — scans, startups, shutdowns."""
    data = {
        "type":        "system_event",
        "event_type":  event_type,
        "details":     details,
        "recorded_at": datetime.now().isoformat()
    }
    return add_block(data)

# ── Validate chain ────────────────────────────────────────────────────────────

def validate_chain():
    """
    Verify the entire chain is intact and untampered.
    Returns (is_valid, error_message)
    If any block has been modified, this will detect it.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT block_index, timestamp, block_hash,
               prev_hash, data, nonce
        FROM blockchain
        ORDER BY block_index ASC
    """)
    blocks = c.fetchall()
    conn.close()

    if not blocks:
        return False, "Chain is empty"

    prev_hash = "0" * 64

    for idx, ts, stored_hash, prev, data_json, nonce in blocks:
        # Skip genesis prev_hash check
        if idx > 0 and prev != prev_hash:
            return False, f"Block #{idx} has broken chain link"

        # Recompute hash
        block = {
            "block_index": idx,
            "timestamp":   ts,
            "prev_hash":   prev,
            "data":        json.loads(data_json),
            "nonce":       nonce
        }
        computed = compute_hash(block)

        if computed != stored_hash:
            return False, f"Block #{idx} has been TAMPERED — hash mismatch"

        prev_hash = stored_hash

    return True, f"Chain valid — {len(blocks)} block(s) verified"

# ── Backup chain ──────────────────────────────────────────────────────────────

def backup_chain():
    """Save entire chain as a JSON file — extra tamper evidence."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            SELECT block_index, timestamp, block_hash,
                   prev_hash, data, nonce
            FROM blockchain ORDER BY block_index ASC
        """)
        blocks = []
        for idx, ts, bh, prev, data_json, nonce in c.fetchall():
            blocks.append({
                "block_index": idx,
                "timestamp":   ts,
                "block_hash":  bh,
                "prev_hash":   prev,
                "data":        json.loads(data_json),
                "nonce":       nonce
            })
        conn.close()

        with open(CHAIN_PATH, "w") as f:
            json.dump(blocks, f, indent=2)
    except Exception as e:
        log(f"Backup error: {e}", "WARN")

# ── Print chain ────────────────────────────────────────────────────────────────

def print_chain(limit=10):
    """Print the most recent blocks in the chain."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT block_index, timestamp, block_hash, prev_hash, data
        FROM blockchain
        ORDER BY block_index DESC
        LIMIT ?
    """, (limit,))
    blocks = c.fetchall()
    conn.close()

    print(f"\n{'═'*55}")
    print(f"  A3 BLOCKCHAIN LEDGER — last {len(blocks)} blocks")
    print(f"{'═'*55}")

    for idx, ts, bh, prev, data_json in reversed(blocks):
        data = json.loads(data_json)
        dtype = data.get("type", "unknown")

        if dtype == "genesis":
            col = "\033[96m"
        elif dtype == "threat":
            verdict = data.get("verdict", "")
            col = "\033[91m" if verdict == "MALICIOUS" else "\033[93m"
        elif dtype == "network_threat":
            col = "\033[93m"
        else:
            col = "\033[97m"

        reset = "\033[0m"
        print(f"\n  {col}Block #{idx}{reset}")
        print(f"  Hash  : {bh[:32]}...")
        print(f"  Prev  : {prev[:32]}...")
        print(f"  Time  : {ts}")
        print(f"  Type  : {dtype}")

        if dtype == "threat":
            print(f"  File  : {Path(data.get('file_path','')).name}")
            print(f"  Result: {data.get('verdict','')} — {data.get('threat_type','')}")
            print(f"  Score : {data.get('score',0)}")
        elif dtype == "network_threat":
            print(f"  IP    : {data.get('ip','')}")
            print(f"  Score : {data.get('score',0)}")

    print(f"\n{'═'*55}\n")

# ── Auto-record from existing DB ──────────────────────────────────────────────

def sync_existing_threats():
    """
    On first run, record all existing confirmed threats
    from the sandbox database onto the blockchain.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Check which hashes are already on chain
    c.execute("SELECT data FROM blockchain WHERE data LIKE '%file_hash%'")
    chained = set()
    for (data_json,) in c.fetchall():
        try:
            d = json.loads(data_json)
            if "file_hash" in d:
                chained.add(d["file_hash"])
        except Exception:
            pass

    # Get unrecorded threats
    c.execute("""
        SELECT sr.file_path, sr.file_hash, sr.verdict,
               sr.behaviour_flags, sr.threat_score,
               COALESCE(aa.threat_type, 'unknown')
        FROM sandbox_reports sr
        LEFT JOIN ai_assessments aa ON sr.id = aa.sandbox_report_id
        WHERE sr.verdict IN ('MALICIOUS','SUSPICIOUS')
        AND sr.file_hash NOT IN ({})
    """.format(",".join(f"'{h}'" for h in chained) if chained else "'__none__'"))

    threats = c.fetchall()
    conn.close()

    if not threats:
        log("All existing threats already on chain")
        return

    log(f"Recording {len(threats)} existing threat(s) onto chain...")
    for fpath, fhash, verdict, flags_json, score, ttype in threats:
        flags = json.loads(flags_json) if flags_json else []
        record_threat(fpath, fhash, verdict, ttype, flags, score)

    log(f"Sync complete — {len(threats)} block(s) added", "OK")

# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    init_chain_db()

    if "--validate" in sys.argv:
        valid, msg = validate_chain()
        status = "\033[92m✓\033[0m" if valid else "\033[91m✗\033[0m"
        print(f"\n  {status} {msg}\n")

    elif "--sync" in sys.argv:
        sync_existing_threats()

    elif "--print" in sys.argv:
        limit = int(sys.argv[sys.argv.index("--print") + 1]) \
                if len(sys.argv) > sys.argv.index("--print") + 1 \
                else 10
        print_chain(limit)

    else:
        # Default: sync, validate, print
        sync_existing_threats()
        valid, msg = validate_chain()
        status = "\033[92m✓\033[0m" if valid else "\033[91m✗\033[0m"
        print(f"\n  {status} {msg}")
        print_chain()