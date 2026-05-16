# ==============================================================================
# MODULE: analyze_fw_logs.py
# DESCRIPTION: Standalone AI SOC Analyst for OPNsense Firewall Packet Filter Logs
# AUTHOR: Steve / AI Collaborator
# ==============================================================================
# CHANGE HISTORY:
# ------------------------------------------------------------------------------
# DATE        | VERSION | AUTHOR         | DESCRIPTION
# ------------------------------------------------------------------------------
# 2026-05-16  | 1.0.0   | Steve/AI       | Initial decoupled firewall analyzer.
# 2026-05-16  | 1.1.0   | Steve/AI       | Added ingestion & vector counts progress logs.
# 2026-05-16  | 1.1.1   | Steve/AI       | Implemented WAN perimeter noise grouping.
# 2026-05-16  | 1.2.0   | Steve/AI       | Expanded noise filter for LAN -> Internet egress.
# 2026-05-16  | 1.3.0   | Steve/AI       | Fixed Token Parsing with protocol anchoring.
# 2026-05-16  | 1.3.1   | Steve/AI       | Fixed Anchor Offsets relative column indexing.
# 2026-05-16  | 1.4.0   | Steve/AI       | Integrated passed traffic summary matrix.
# 2026-05-16  | 1.4.1   | Steve/AI       | Swapped specific pass rows for global totals.
# 2026-05-16  | 1.5.0   | Steve/AI       | CAPTURED ALLOWLIST METRICS: Added tracking counter 
#             |         |                | for bypassed allowlist filter rules and PDF matrix view.
# ==============================================================================

import json
import os
import re
import glob
from datetime import datetime
from langchain_chroma import Chroma
from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from weasyprint import HTML
from jinja2 import Template
from dotenv import load_dotenv

# --- CONFIGURATION ---
VERSION = "1.5.0"
load_dotenv()
INGEST_DIR = "./data/fw_ingest"
ARCHIVE_DIR = "./data/fw_archive"
DB_NAME = "./vector_db"
ALLOWLIST_FILE = "./knowledge-base/allowlist.json"
REPORT_NAME = f"Firewall_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
MODEL = "gpt-4.1-nano"

print(f"🚀 Initializing AI SOC Firewall Subsystem [v{VERSION}]...")

# Initialize LangChain components
embeddings = OpenAIEmbeddings(model="text-embedding-3-large")
vectorstore = Chroma(persist_directory=DB_NAME, embedding_function=embeddings)

llm = ChatOpenAI(
    model=MODEL,
    temperature=0,
    model_kwargs={"response_format": {"type": "json_object"}}
)

# --- HTML TEMPLATE ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f4f6f9; padding: 30px; color: #333; }
        .header { background: #2c3e50; color: white; padding: 30px; text-align: center; border-radius: 12px 12px 0 0; margin-bottom: 20px; }
        .card { background: white; margin-bottom: 25px; padding: 25px; border-radius: 12px; border-left: 12px solid #ccc; box-shadow: 0 4px 6px rgba(0,0,0,0.05); page-break-inside: avoid; }
        .risk-High { border-left-color: #c0392b; }
        .risk-Medium { border-left-color: #d35400; }
        .risk-Low { border-left-color: #27ae60; }
        .badge { float: right; padding: 6px 14px; border-radius: 20px; color: white; font-weight: bold; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }
        .badge-High { background: #c0392b; }
        .badge-Medium { background: #d35400; }
        .badge-Low { background: #27ae60; }
        h2 { margin-top: 0; color: #2c3e50; font-size: 18px; border-bottom: 1px solid #eee; padding-bottom: 10px; }
        .meta { font-size: 13px; color: #7f8c8d; margin: 12px 0; }
        .section-title { font-weight: bold; color: #34495e; margin-top: 15px; display: block; font-size: 13px; text-transform: uppercase; }
        .summary { font-style: italic; background: #fdfefe; padding: 15px; border-radius: 6px; border: 1px solid #e2e8f0; margin-top: 5px; line-height: 1.5; }
        .recommendation { margin-top: 5px; line-height: 1.5; font-size: 15px; }
        
        /* Summary Table Styling */
        table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px; }
        th { background: #f8f9fa; border-bottom: 2px solid #e2e8f0; text-align: left; padding: 12px; font-weight: bold; color: #2c3e50; }
        td { padding: 12px; border-bottom: 1px solid #eee; vertical-align: middle; }
        .action-block { background: #fce4d6; color: #c0392b; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }
        .action-pass { background: #e8f8f5; color: #117a65; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }
        .proto-badge { background: #eaf2f8; color: #2980b9; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: bold; }
        .filter-badge { background: #f2f4f4; color: #7f8c8d; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; border: 1px solid #d5dbdb; }
    </style>
</head>
<body>
    <div class="header">
        <h1>AI SOC Firewall Violations Report</h1>
        <p>Quantum-WSL2 Sentry Subsystem | Generated: {{ timestamp }}</p>
    </div>
    
    {% if events %}
        {% for event in events %}
        <div class="card risk-{{ event.risk }}">
            <span class="badge badge-{{ event.risk }}">{{ event.risk }} RISK</span>
            <h2>{{ event.signature }}</h2>
            <div class="meta">
                <strong>Timestamp:</strong> {{ event.log_time }} | 
                <strong>Source:</strong> {{ event.src_ip }} | 
                <strong>Target:</strong> {{ event.target }} ({{ event.dest_ip }})
            </div>
            
            <span class="section-title">Block Event Analysis</span>
            <div class="summary">{{ event.summary }}</div>
            
            <span class="section-title">Architectural Recommendation</span>
            <p class="recommendation">{{ event.recommendation }}</p>
        </div>
        {% endfor %}
    {% else %}
        <div class="card">
            <p>No unexpected firewall rule blocks detected in this tracking cycle.</p>
        </div>
    {% endif %}

    <hr style="border: 0; border-top: 2px dashed #bdc3c7; margin: 40px 0; page-break-before: always;">
    <div class="header" style="background: #27ae60;">
        <h1>Operational Posture Baseline Metrics</h1>
        <p>Volumetric Accounting of Filtered and Ingested Firewall Actions</p>
    </div>
    
    <div class="card" style="border-left: 12px solid #3498db;">
        <h2>Bypassed Noise Exceptions (Pre-Filter Allowlist Matching)</h2>
        <p class="meta">The following operational exceptions matched your custom allowlist profiles and were safely bypassed before AI processing:</p>
        
        <table>
            <thead>
                <tr>
                    <th>Matched Allowlist Rule Name</th>
                    <th style="text-align: right;">Bypassed Packet Volume</th>
                </tr>
            </thead>
            <tbody>
                {% if allowlist_metrics %}
                    {% for rule_name, count in allowlist_metrics.items() %}
                    <tr>
                        <td><span class="filter-badge">FILTER RULE</span> <strong>{{ rule_name }}</strong></td>
                        <td style="text-align: right; font-weight: bold; color: #2980b9;">{{ count }}</td>
                    </tr>
                    {% endfor %}
                {% else %}
                    <tr>
                        <td colspan="2" style="padding: 20px; text-align: center; color: #7f8c8d;">No log blocks matched your pre-filter allowlist metrics in this cycle.</td>
                    </tr>
                {% endif %}
            </tbody>
        </table>
    </div>

    <div class="card" style="border-left: 12px solid #27ae60;">
        <h2>Total Packet Volumetrics by Vector Classification</h2>
        <p class="meta">Global accounting breakdown of every raw packet processed in this ingestion frame:</p>
        
        <table>
            <thead>
                <tr>
                    <th>Enforced Action</th>
                    <th>Transport Protocol</th>
                    <th style="text-align: right;">Total Logged Packets</th>
                </tr>
            </thead>
            <tbody>
                {% if posture_metrics %}
                    {% for metric in posture_metrics %}
                    <tr>
                        <td>
                            {% if metric.action == 'block' %}
                                <span class="action-block">DROP / BLOCK</span>
                            {% else %}
                                <span class="action-pass">ALLOW / PASS</span>
                            {% endif %}
                        </td>
                        <td><span class="proto-badge">{{ metric.proto.upper() }}</span></td>
                        <td style="text-align: right; font-weight: bold; color: #2c3e50;">{{ metric.count }}</td>
                    </tr>
                    {% endfor %}
                {% else %}
                    <tr>
                        <td colspan="3" style="padding: 20px; text-align: center; color: #7f8c8d;">No volumetric logs processed in this cycle.</td>
                    </tr>
                {% endif %}
            </tbody>
        </table>
    </div>
</body>
</html>
"""

def load_topology_map():
    paths = ["./knowledge-base/topology.md", "./topology.md", "../knowledge-base/topology.md"]
    ip_map = {}
    for path in paths:
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("- "):
                            match = re.match(r'^-\s*([0-9a-fA-F.:]+):\s*([^.]+)', line)
                            if match:
                                ip = match.group(1).strip()
                                name = match.group(2).strip().replace("**", "")
                                ip_map[ip] = name
                break
            except Exception as e:
                print(f"⚠️ Error parsing topology map: {e}")
    return ip_map

def parse_firewall_line(raw_line):
    tokens = [t.strip() for t in raw_line.split(",")]
    if len(tokens) < 16:
        return None
        
    try:
        action = tokens[6]
        direction = tokens[7]
        
        proto_idx = -1
        for idx in [16, 15, 17, 14]:
            if idx < len(tokens) and tokens[idx] in ["tcp", "udp", "icmp"]:
                proto_idx = idx
                break
                
        if proto_idx == -1:
            return None
            
        proto = tokens[proto_idx]
        
        src_ip = tokens[proto_idx + 2]
        dest_ip = tokens[proto_idx + 3]
        src_port = tokens[proto_idx + 4]
        dest_port = tokens[proto_idx + 5]
        
        return {
            "event_type": "firewall",
            "action": action,
            "direction": direction,
            "proto": proto,
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "src_port": int(src_port) if src_port.isdigit() else src_port,
            "dest_port": int(dest_port) if dest_port.isdigit() else dest_port,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return None

def is_allowlisted(entry, allowlist):
    src = entry.get("src_ip", "")
    dest = entry.get("dest_ip", "")
    port = entry.get("dest_port")
    etype = entry.get("event_type")

    for rule in allowlist:
        if rule.get("event_type") != etype: continue
        src_match = (rule.get("src_ip") == src or any(src.startswith(p) for p in rule.get("src_ip_prefix", [])))
        dest_match = (rule.get("dest_ip") == dest)
        ports = rule.get("dest_port")
        port_match = port in ports if isinstance(ports, list) else port == ports if ports else True

        if src_match and dest_match and port_match:
            return True, rule.get("name")
            
    return False, None

def extract_json(text):
    json_match = re.search(r'```json\s*(\{.*?\})\s*```', text, re.DOTALL)
    if json_match: return json_match.group(1)
    brace_match = re.search(r'(\{.*\})', text, re.DOTALL)
    if brace_match: return brace_match.group(1)
    return text

def analyze_firewall_event(entry, ip_map):
    src_ip = entry.get("src_ip", "")
    dest_ip = entry.get("dest_ip", "")
    signature = f"Firewall Block: Explicit {entry.get('action').upper()} ({entry.get('proto').upper()})"

    def resolve_ip(ip):
        if not ip: return "Unknown"
        if ip in ip_map: return ip_map[ip]
        if any(ip.startswith(prefix) for prefix in ["192.168.", "10.", "172.16.", "172.20.", "172.31."]):
            return "Unknown LAN Device"
        return "Unknown External IP"

    src_host = resolve_ip(src_ip)
    dest_host = resolve_ip(dest_ip)

    query = f"Firewall threat analysis for {src_ip} hitting {dest_ip} on port {entry.get('dest_port')}."
    docs = vectorstore.similarity_search(query, k=5)
    context = "\n".join([d.page_content for d in docs])

    prompt = ChatPromptTemplate.from_template("""
    SYSTEM: You are Steve's AI SOC Firewall Analyst. Analyze the blocked packet metadata.
    
    DETERMINISTIC IDENTITIES (Source of Truth):
    - Packet Origin Host: {src_host} ({src_ip})
    - Packet Target Host: {dest_host} ({dest_ip})
    
    CORE FACTS:
    - 136.57.238.135 IS STEVE'S PUBLIC WAN IP boundary.
    - 172.20.227.5 is the internal WSL2 instance (Quantum PC).

    CRITICAL RULES:
    1. A packet dropped at the external Public WAN IP boundary from an 'Unknown External IP' is standard, routine internet exploration. Classify as LOW RISK.
    2. If a recognized internal local device (e.g., Bose, internal server) is being explicitly BLOCKED trying to reach another local segment or an unusual outbound internet port, this indicates a broken architectural path or potentially malicious movement. Classify as MEDIUM or HIGH RISK.
    3. Use the exact hostnames provided in the DETERMINISTIC IDENTITIES segment.

    KNOWLEDGE CONTEXT:
    {context}

    LOG ENTRY:
    {log_entry}

    Return ONLY a valid JSON object. Do not include any other text.
    {{
        "signature": "Clean title",
        "summary": "Detailed structural network summary specifying why this packet was blocked and what connection was attempted",
        "risk": "Low/Medium/High",
        "target": "Exact Target Hostname resolved above",
        "recommendation": "Suggested adjustment to OPNsense rules or device configuration"
    }}
    """)

    try:
        formatted_prompt = prompt.format(
            context=context, log_entry=json.dumps(entry),
            src_ip=src_ip, dest_ip=dest_ip,
            src_host=src_host, dest_host=dest_host
        )
        response = llm.invoke(formatted_prompt)
        content = extract_json(response.content.strip())
        out = json.loads(content)
        out["signature"] = signature
        return out
    except Exception as e:
        print(f"❌ Analysis failed for packet: {e}")
        return None

def main():
    ip_map = load_topology_map()
    print(f"🖥️  Loaded {len(ip_map)} host rules for mapping.")

    allowlist_data = []
    if os.path.exists(ALLOWLIST_FILE):
        try:
            with open(ALLOWLIST_FILE, "r") as f:
                allowlist_data = json.load(f).get("allowlist", [])
            print(f"✅ Loaded {len(allowlist_data)} rules into firewalls filter.")
        except Exception as e:
            print(f"⚠️ Error loading filter map: {e}")

    log_files = glob.glob(os.path.join(INGEST_DIR, "*.json"))
    if not log_files:
        print("📭 No new firewall log sets found.")
        return

    raw_events_count = 0
    unique_packets = {}
    posture_matrix = {}
    
    # v1.5.0 Allowlist metrics aggregator dictionary
    allowlist_counter = {}

    for log_path in log_files:
        print(f"🔍 Inspecting ingestion target: {log_path}...")
        with open(log_path, "r") as f:
            try:
                batch = json.load(f)
                if not isinstance(batch, list): batch = [batch]
            except:
                continue

            for raw_entry in batch:
                if raw_entry.get("event_type") == "firewall" and "raw" in raw_entry:
                    parsed = parse_firewall_line(raw_entry["raw"])
                    if not parsed: continue
                    
                    raw_events_count += 1
                    
                    if raw_events_count % 1000 == 0:
                        print(f"   ⏱️  Ingestion Progress: Read {raw_events_count} raw log entries...")

                    posture_key = (parsed["action"], parsed["proto"])
                    posture_matrix[posture_key] = posture_matrix.get(posture_key, 0) + 1

                    if parsed.get("action") == "pass":
                        continue

                    # v1.5.0 MATCH AND RECORD BYPASSED ALLOWLIST RULE VOLUMETRICS
                    matched, rule_name = is_allowlisted(parsed, allowlist_data)
                    if matched:
                        # Fallback to generic name string if not labeled
                        rule_label = rule_name if rule_name else "Unnamed Security Exception Filter"
                        allowlist_counter[rule_label] = allowlist_counter.get(rule_label, 0) + 1
                        continue
                    
                    agg_key = (parsed["src_ip"], parsed["dest_ip"], parsed["proto"], parsed["dest_port"])
                    
                    if agg_key not in unique_packets:
                        parsed["hit_count"] = 1
                        unique_packets[agg_key] = parsed
                    else:
                        unique_packets[agg_key]["hit_count"] += 1

    print(f"📊 Total Raw Scope: Read {raw_events_count} lines.")
    print(f"📉 Compression Optimization: Compressed down to {len(unique_packets)} unique block matrices.")

    report_events = []
    internet_noise_count = 0
    internet_noise_hits = 0
    filtered_packets = []

    for agg_key, parsed_event in unique_packets.items():
        src_ip, dest_ip, proto, dest_port = agg_key
        
        is_src_lan = any(src_ip.startswith(p) for p in ["192.168.", "10.", "172.16.", "172.20.", "172.31."])
        is_dest_lan = any(dest_ip.startswith(p) for p in ["192.168.", "10.", "172.16.", "172.20.", "172.31."])
        is_dest_wan = (dest_ip == "136.57.238.135")
        
        if not is_src_lan and is_dest_wan:
            internet_noise_count += 1
            internet_noise_hits += parsed_event["hit_count"]
            
        elif is_src_lan and not is_dest_lan and not is_dest_wan:
            internet_noise_count += 1
            internet_noise_hits += parsed_event["hit_count"]
            
        else:
            filtered_packets.append(parsed_event)

    print(f"🧹 Filtered out {internet_noise_count} unique internet scans/egress blocks ({internet_noise_hits} total packets) leaving or entering the network.")
    
    if internet_noise_hits > 0:
        report_events.append({
            "signature": f"Routine Network Isolation Boundary Blocks ({internet_noise_hits} Packets Blocked)",
            "risk": "Low",
            "target": "External Internet / WAN Boundary",
            "src_ip": "Distributed Local/External Traffic",
            "dest_ip": "Distributed Targets",
            "log_time": datetime.now().isoformat(),
            "summary": f"Firewall successfully dropped {internet_noise_hits} individual packets across {internet_noise_count} unique vectors involving public endpoints. This represents normal operational baseline enforcement.",
            "recommendation": "No action required. Perimeter isolation rules operating entirely as designed."
        })

    total_llm_tasks = len(filtered_packets)
    
    if total_llm_tasks > 0:
        print(f"🤖 Commencing AI Analysis processing loop for {total_llm_tasks} highly-relevant vectors...")

    current_llm_index = 0
    for parsed_event in filtered_packets:
        current_llm_index += 1
        analysis = analyze_firewall_event(parsed_event, ip_map)
        if analysis:
            analysis.update({
                'src_ip': parsed_event.get("src_ip"),
                'dest_ip': parsed_event.get("dest_ip"),
                'log_time': parsed_event.get("timestamp"),
                'signature': f"{analysis.get('signature', 'Firewall Block')} ({parsed_event['hit_count']} total hits)"
            })
            report_events.append(analysis)
            print(f"   Processed event vector {current_llm_index}/{total_llm_tasks} ({analysis.get('signature')})")

    # Format Volumetric Posture Matrix for the view context
    posture_metrics = []
    sorted_posture = sorted(posture_matrix.items(), key=lambda x: (x[0][0], x[0][1]))
    
    for (action, proto), count in sorted_posture:
        posture_metrics.append({
            "action": action,
            "proto": proto,
            "count": count
        })

    if report_events or posture_metrics or allowlist_counter:
        print(f"📄 Rendering Firewall PDF Report: {REPORT_NAME}")
        template = Template(HTML_TEMPLATE)
        html_out = template.render(
            events=report_events, 
            posture_metrics=posture_metrics,
            allowlist_metrics=allowlist_counter, # Pass the counter directly into Jinja
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        try:
            HTML(string=html_out).write_pdf(REPORT_NAME)
            print(f"✅ Generated standalone report: {REPORT_NAME}")
            
            if not os.path.exists(ARCHIVE_DIR): os.makedirs(ARCHIVE_DIR)
            for log_path in log_files:
                os.rename(log_path, os.path.join(ARCHIVE_DIR, f"proc_fw_{datetime.now().strftime('%Y%m%d_%H%M')}_{os.path.basename(log_path)}"))
        except Exception as e:
            print(f"❌ Generation error: {e}")
    else:
        print("✅ Clean run. No anomalous drops required attention.")

if __name__ == "__main__":
    main()
