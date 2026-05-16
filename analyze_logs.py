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
load_dotenv()
INGEST_DIR = "./data/ingest"
ARCHIVE_DIR = "./data/archive"
DB_NAME = "./vector_db"
ALLOWLIST_FILE = "./knowledge-base/allowlist.json"
REPORT_NAME = f"Security_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"

# Using your working model
MODEL = "gpt-4.1-nano" 

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
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f0f2f5; padding: 30px; color: #333; }
        .header { background: #1a2a6c; color: white; padding: 30px; text-align: center; border-radius: 12px 12px 0 0; margin-bottom: 20px; }
        .card { background: white; margin-bottom: 25px; padding: 25px; border-radius: 12px; border-left: 12px solid #ccc; box-shadow: 0 4px 6px rgba(0,0,0,0.05); page-break-inside: avoid; }
        .risk-High { border-left-color: #e74c3c; }
        .risk-Medium { border-left-color: #f39c12; }
        .risk-Low { border-left-color: #27ae60; }
        .badge { float: right; padding: 6px 14px; border-radius: 20px; color: white; font-weight: bold; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }
        .badge-High { background: #e74c3c; }
        .badge-Medium { background: #f39c12; }
        .badge-Low { background: #27ae60; }
        h2 { margin-top: 0; color: #1a2a6c; font-size: 20px; border-bottom: 1px solid #eee; padding-bottom: 10px; }
        .meta { font-size: 13px; color: #6b7280; margin: 12px 0; }
        .section-title { font-weight: bold; color: #4b5563; margin-top: 15px; display: block; font-size: 14px; text-transform: uppercase; }
        .summary { font-style: italic; background: #f9fafb; padding: 15px; border-radius: 6px; border: 1px solid #e5e7eb; margin-top: 5px; line-height: 1.5; }
        .recommendation { margin-top: 5px; line-height: 1.5; font-size: 15px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>AI SOC Security Analysis</h1>
        <p>Quantum-WSL2 Sentry | Generated: {{ timestamp }}</p>
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
            
            <span class="section-title">Analysis Summary</span>
            <div class="summary">{{ event.summary }}</div>
            
            <span class="section-title">Required Actions</span>
            <p class="recommendation">{{ event.recommendation }}</p>
        </div>
        {% endfor %}
    {% else %}
        <div class="card">
            <p>No security alerts or anomalies detected in this period requiring attention.</p>
        </div>
    {% endif %}
</body>
</html>
"""

def load_topology_map():
    """Parses topology.md to build a 100% deterministic lookup dictionary of IP to Hostname."""
    paths = [
        "./knowledge-base/topology.md",
        "./topology.md",
        "../knowledge-base/topology.md"
    ]
    ip_map = {}
    for path in paths:
        if os.path.exists(path):
            try:
                print(f"📖 Parsing {path} for deterministic device resolution...")
                with open(path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("- "):
                            # Match IPv4 patterns inside markdown lists
                            match = re.match(r'^-\s*([0-9a-fA-F.:]+):\s*([^.]+)', line)
                            if match:
                                ip = match.group(1).strip()
                                name = match.group(2).strip()
                                # Clean markdown formatting (e.g., bold markers)
                                name = name.replace("**", "").strip()
                                ip_map[ip] = name
                break
            except Exception as e:
                print(f"⚠️ Error parsing topology file {path}: {e}")
    return ip_map

def is_allowlisted(entry, allowlist):
    """Checks if a log entry matches any rule in the allowlist."""
    src = entry.get("src_ip", "")
    dest = entry.get("dest_ip", "")
    port = entry.get("dest_port") or entry.get("ssh", {}).get("port")
    etype = entry.get("event_type")

    for rule in allowlist:
        src_match = (rule.get("src_ip") == src or 
                     any(src.startswith(p) for p in rule.get("src_ip_prefix", [])))
        dest_match = (rule.get("dest_ip") == dest)
        type_match = rule.get("event_type") == etype if "event_type" in rule else True
        ports = rule.get("dest_port")
        port_match = True
        if ports:
            port_match = port in ports if isinstance(ports, list) else port == ports

        if src_match and dest_match and type_match and port_match:
            return True, rule.get("name")
            
    return False, None

def extract_json(text):
    """Deep extraction logic for JSON content from LLM responses."""
    json_match = re.search(r'```json\s*(\{.*?\})\s*```', text, re.DOTALL)
    if json_match: return json_match.group(1)
    brace_match = re.search(r'(\{.*\})', text, re.DOTALL)
    if brace_match: return brace_match.group(1)
    return text

def analyze_event(entry, ip_map):
    """Performs hybrid analysis utilizing a deterministic lookup map alongside RAG."""
    src_ip = entry.get("src_ip", "")
    dest_ip = entry.get("dest_ip", "")
    signature = entry.get("alert", {}).get("signature") or entry.get("event_type", "Network Anomaly")
    
    # Resolve hostnames using exact string matching
    def resolve_ip(ip):
        if not ip:
            return "Unknown"
        if ip in ip_map:
            return ip_map[ip]
        # Identify internal networks
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16.") or ip.startswith("172.20.") or ip.startswith("172.31."):
            return "Unknown LAN Device"
        return "Unknown External IP"

    src_host = resolve_ip(src_ip)
    dest_host = resolve_ip(dest_ip)

    # Conceptual RAG search for policy behavior matching
    query = f"Identify {src_ip} and {dest_ip}. Explain {signature}."
    docs = vectorstore.similarity_search(query, k=7)
    context = "\n".join([d.page_content for d in docs])

    prompt = ChatPromptTemplate.from_template("""
    SYSTEM: You are Steve's AI SOC Analyst.
    
    RESOLVED HOSTNAMES (100% Deterministic Source of Truth):
    - Source IP ({src_ip}) is: {src_host}
    - Destination IP ({dest_ip}) is: {dest_host}
    
    CORE NETWORK FACTS:
    - 136.57.238.135 IS STEVE'S PUBLIC WAN IP.
    - 172.20.227.5 is the internal WSL2 instance (Quantum PC).
    - 192.168.1.186 is the Bose Soundbar.
    - 192.168.1.150 is the Windows 11 host (Quantum PC).
    - 192.168.1.145 is the MacMini Linux Server.
    
    CRITICAL LOGIC:
    1. USE THE RESOLVED HOSTNAMES above for identifying devices. Under no circumstances should you match an IP to a hostname other than what is explicitly resolved in the 'RESOLVED HOSTNAMES' section.
    2. If a hostname is recognized (i.e., not 'Unknown External IP' or 'Unknown LAN Device'), that device is NOT a "Rogue Device".
    3. Traffic from Steve's WAN to Quantum PC on port 2222 or 22 is authorized management traffic (LOW RISK).
    4. Bose Soundbar anomalies on port 8883/443 with external IPs are typical cloud sync baselines (LOW RISK).

    CONTEXT FROM KNOWLEDGE BASE:
    {context}

    LOG ENTRY UNDER ANALYSIS:
    {log_entry}

    Return ONLY a valid JSON object. Do not include any other text.
    {{
        "signature": "Clean title",
        "summary": "Analysis of the event using the exact resolved hostnames provided",
        "risk": "Low/Medium/High",
        "target": "Exact Resolved Hostname for the destination IP",
        "recommendation": "Suggested action"
    }}
    """)

    try:
        formatted_prompt = prompt.format(
            context=context, 
            log_entry=json.dumps(entry),
            src_ip=src_ip,
            dest_ip=dest_ip,
            src_host=src_host,
            dest_host=dest_host
        )
        response = llm.invoke(formatted_prompt)
        content = extract_json(response.content.strip())
        return json.loads(content)
    except Exception as e:
        print(f"❌ Error analyzing {signature}: {e}")
        return None

def main():
    # Load Topology Map
    ip_map = load_topology_map()
    print(f"🖥️  Loaded {len(ip_map)} deterministic host mappings from topology.")

    # Load Allowlist
    allowlist_data = []
    if os.path.exists(ALLOWLIST_FILE):
        try:
            with open(ALLOWLIST_FILE, "r") as f:
                allowlist_data = json.load(f).get("allowlist", [])
            print(f"✅ Loaded {len(allowlist_data)} allowlist rules.")
        except Exception as e:
            print(f"⚠️ Failed to load allowlist: {e}")

    log_files = glob.glob(os.path.join(INGEST_DIR, "*.json"))
    if not log_files:
        print("📭 No new logs to process.")
        return

    report_events = []
    for log_path in log_files:
        print(f"🔍 Analyzing {log_path}...")
        with open(log_path, "r") as f:
            for line in f:
                if not line.strip(): continue
                try:
                    entry = json.loads(line)
                except:
                    continue
                
                if entry.get("event_type") in ["alert", "anomaly", "ssh"]:
                    # CHECK ALLOWLIST BEFORE LLM
                    matched, rule_name = is_allowlisted(entry, allowlist_data)
                    if matched:
                        print(f"   Skip filtered: {rule_name}")
                        continue
                        
                    analysis = analyze_event(entry, ip_map)
                    if analysis:
                        analysis.update({
                            'src_ip': entry.get("src_ip"), 
                            'dest_ip': entry.get("dest_ip"), 
                            'log_time': entry.get("timestamp")
                        })
                        report_events.append(analysis)

    if report_events:
        print(f"📄 Rendering {REPORT_NAME}")
        template = Template(HTML_TEMPLATE)
        html_out = template.render(events=report_events, timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        try:
            HTML(string=html_out).write_pdf(REPORT_NAME)
            print(f"✅ Successfully generated {REPORT_NAME}")

            if not os.path.exists(ARCHIVE_DIR):
                os.makedirs(ARCHIVE_DIR)
            
            for log_path in log_files:
                filename = os.path.basename(log_path)
                archive_path = os.path.join(ARCHIVE_DIR, f"proc_{datetime.now().strftime('%Y%m%d_%H%M')}_{filename}")
                os.rename(log_path, archive_path)
                print(f"🗄️  Archived: {filename}")
        except Exception as e:
            print(f"❌ Failed to generate PDF or archive logs: {e}")
    else:
        print("✅ No critical issues requiring AI analysis found.")

if __name__ == "__main__":
    main()
