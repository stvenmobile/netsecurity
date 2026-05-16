# AI-Driven SOC Firewall Analytics Subsystem

A decoupled, intelligent security operations center (SOC) pipeline that securely streams raw firewall events from a bare-metal OPNsense router, aggregates identical vectors, and uses an LLM-powered analytics processor to generate localized threat intelligence PDF reports.

## 🛠️ Architecture Overview

The system operates across a dual-node topology designed for minimal operational impact on the perimeter firewall:

1. **OPNsense Core Gateway Node:** Runs a lightweight shell utility that dynamically anchors and intercepts raw, variable-length `filterlog` outputs. It isolates explicitly blocked or high-consequence data packets, packages the raw tokens natively into JSON arrays, and ships the payload over an encrypted SSH link.
2. **Quantum Analytics Node (WSL2 / Ubuntu):** Ingests the raw JSON data batches, reads local network topology mappings, runs an aggressive in-memory de-duplication loop, processes noise through an exclusion allowlist matrix, and feeds remaining high-consequence vectors into an LLM analysis pipeline to render structured PDF violation cards.

## 📁 Repository Organization

* `/OPNsense`: Contains native FreeBSD shell utilities deployed to `/usr/local/bin/` on the router.
* `/WSL2`: Contains the LangChain-powered analytics processing core, Python dependencies, local orchestration scripts, and topological threat knowledge-bases.

## 🚀 Deployment & Installation

### 1. OPNsense Router Configuration
Deploy `push_fw_logs.sh` to your router at `/usr/local/bin/push_fw_logs.sh` and make it executable:
```bash
chmod +x /usr/local/bin/push_fw_logs.sh
```

Ensure you have configured SSH key-based authentication from root over to your target analytics environment.

### 2. Analytics Environment Setup (WSL2)
Step into your local Python project directory and establish your virtual environment:

```bash
cd WSL2
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Ensure your .env contains your API credentials and path setups:
```bash
OPENAI_API_KEY="your-api-key-here"
```
## 📈 Change History Log
v1.5.0
- Feature Expansion: Added comprehensive tracking metrics for bypassed noise exception filters (allowlist.json).
- Performance: Upgraded the volumetric accounting grid to dynamically parse and calculate global DROP/BLOCK and ALLOW/PASS packet flows with zero AI token overhead.
- Bug Fixes: Remapped packet extraction parsing arrays to use relative dynamic protocol anchoring (tcp, udp, icmp) to combat variable-length FreeBSD kernel header formatting.
