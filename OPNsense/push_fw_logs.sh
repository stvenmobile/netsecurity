#!/bin/sh
# OPNsense Side - Standalone Firewall Log Tracker (Syslog-Stripped)
STATE_FILE="/tmp/fw_filter_line_position.state"
TARGET="steve@192.168.1.150:/home/steve/netsecurity/data/fw_ingest/new_fw_logs.json"

# 1. Capture the current active batch snapshot from the log utility directly
opnsense-log filter > /tmp/fw_current_dump.raw

if [ ! -s /tmp/fw_current_dump.raw ]; then
    rm -f /tmp/fw_current_dump.raw
    exit 0
fi

# 2. Get the current total number of lines in this execution snapshot
CURRENT_LINE_COUNT=$(wc -l < /tmp/fw_current_dump.raw)

if [ ! -f "$STATE_FILE" ]; then
    LAST_LINE=0
else
    LAST_LINE=$(cat "$STATE_FILE")
fi

# If the file shrank or was flushed out behind the scenes, reset our marker
if [ "$CURRENT_LINE_COUNT" -lt "$LAST_LINE" ]; then
    LAST_LINE=0
fi

NEW_LINES=$((CURRENT_LINE_COUNT - LAST_LINE))

if [ "$NEW_LINES" -gt 0 ]; then
    # Isolate explicitly BLOCKED packets from the fresh line delta
    tail -n "$NEW_LINES" /tmp/fw_current_dump.raw | grep ",block," > /tmp/fw_batch.raw
    
    if [ -s /tmp/fw_batch.raw ]; then
        # Package and strip syslog wrapper text down to clean pf tokens natively
        python3 -c '
import json, sys, re
out = []
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    # Strip the syslog header text by finding where the clean token block begins
    # It matches the format starting with a rule number followed by commas (e.g., 9,,,02f4...)
    match = re.search(r"(\d+,,,.*)$", line)
    if match:
        clean_csv = match.group(1)
        out.append({"event_type": "firewall", "raw": clean_csv})
print(json.dumps(out))
' < /tmp/fw_batch.raw > /tmp/fw_batch.json

        scp -P 2222 -i /root/.ssh/id_rsa /tmp/fw_batch.json "$TARGET"
    fi
    
    # Safely save our current position pointer match
    echo "$CURRENT_LINE_COUNT" > "$STATE_FILE"
fi

# Structural cleanup
rm -f /tmp/fw_current_dump.raw /tmp/fw_batch.raw /tmp/fw_batch.json
