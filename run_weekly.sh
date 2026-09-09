#!/bin/bash
# Weekly automated run for exposed-ai-radar. Installed via cron — see
# setup_cron.sh. Not meant to be edited to add more steps without also
# checking each step's credit/rate-limit budget (Shodan/Censys are both
# tightly capped — see README).

set -uo pipefail

PROJECT_DIR="/home/jason/exposed-ai-radar"
UV_BIN="/home/jason/.local/bin/uv"
LOG_DIR="$PROJECT_DIR/logs"
LOG_FILE="$LOG_DIR/run_$(date +%Y-%m-%d_%H%M%S).log"
REPORT_DIR="$PROJECT_DIR/reports"

mkdir -p "$LOG_DIR" "$REPORT_DIR"
cd "$PROJECT_DIR" || exit 1

{
    echo "===== exposed-ai-radar weekly run: $(date -Iseconds) ====="

    echo ""
    echo "--- collector.py (Shodan) ---"
    "$UV_BIN" run collector.py

    echo ""
    echo "--- leakix_collector.py (ComfyUI only, dedicated plugin) ---"
    "$UV_BIN" run leakix_collector.py --pages 15

    echo ""
    echo "--- enrich_abuse.py (RDAP, free) ---"
    "$UV_BIN" run enrich_abuse.py --delay 1.0

    echo ""
    echo "--- enrich_censys.py (limited — tight weekly credit budget) ---"
    "$UV_BIN" run enrich_censys.py --tiers Critical High --limit 20 --delay 1.0

    echo ""
    echo "--- generating dated report snapshot ---"
    "$UV_BIN" run python -c "
import sqlite3, pandas as pd
from report_generator import build_report_pdf
conn = sqlite3.connect('radar.db')
hosts = pd.read_sql_query('SELECT * FROM hosts', conn)
runs = pd.read_sql_query('SELECT * FROM snapshot_runs', conn)
out = f'reports/snapshot_{pd.Timestamp.now().strftime(\"%Y-%m-%d\")}.pdf'
open(out, 'wb').write(build_report_pdf(hosts, runs))
print('saved', out)
"

    echo ""
    echo "===== run complete: $(date -Iseconds) ====="
} >> "$LOG_FILE" 2>&1

# Keep only the 20 most recent logs and reports so this doesn't grow forever
ls -1t "$LOG_DIR"/run_*.log 2>/dev/null | tail -n +21 | xargs -r rm --
ls -1t "$REPORT_DIR"/snapshot_*.pdf 2>/dev/null | tail -n +21 | xargs -r rm --
