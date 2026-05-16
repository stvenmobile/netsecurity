#!/bin/sh
# OPNsense side - Rotation-Aware Line-based tracking
LOG_FILE="/var/log/suricata/eve.json"
STATE_FILE="/tmp/eve_line_position.state"
TARGET="steve@192.168.1.150:/home/steve/netsecurity/data/ingest/new_logs.json"

# 1. Check if the log file even has data yet
if [ ! -s "$LOG_FILE" ]; then
    echo "📭 Log file is empty (likely just rotated). Skipping."
    exit 0
fi

# 2. Get the current total number of lines in the log
CURRENT_LINE_COUNT=$(wc -l < "$LOG_FILE")

# 3. Read the last processed line
if [ ! -f "$STATE_FILE" ]; then
    LAST_LINE=0
else
    LAST_LINE=$(cat "$STATE_FILE")
fi

# 4. CRITICAL FIX: Detect log rotation/truncation
if [ "$CURRENT_LINE_COUNT" -lt "$LAST_LINE" ]; then
    echo "🧹 Log rotation detected! Resetting pointer to 0."
    LAST_LINE=0
fi

# 5. Calculate how many new lines there are
NEW_LINES=$((CURRENT_LINE_COUNT - LAST_LINE))

if [ "$NEW_LINES" -gt 0 ]; then
    # Grab all lines from LAST_LINE to the end
    tail -n "$NEW_LINES" "$LOG_FILE" > /tmp/current_batch.json
    
    # Push to WSL2
    scp -P 2222 -i /root/.ssh/id_rsa /tmp/current_batch.json "$TARGET"
    
    # Update the state file with the new line count
    echo "$CURRENT_LINE_COUNT" > "$STATE_FILE"
fi

# Cleanup
rm -f /tmp/current_batch.json
