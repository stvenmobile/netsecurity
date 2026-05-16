# Steve's Home Lab Topology
- 192.168.1.1: OPNsense Router (Gateway). Primary firewall.
- 192.168.1.2: OpenWRT wireless access point.
- 192.168.2.2: Internet Service Provider (Google GFRG300 Router).
- 172.20.227.5: Internal WSL2 IP (Quantum PC).
- 192.168.1.40: Sentinel Linux Server. EExternally accessible via DDNS as stventech.com.
- 192.168.1.50: ProxMox Linux Server.
- 192.168.1.60: Orin NX Linux Server (Piper).
- 192.168.1.81: PI 5 Linux Server (WisePi).
- 192.168.1.100: Home Assistant Linux Server.
- 192.168.1.101: PIHole DNS Server.
- 192.168.1.110: SER5 Linux Server (Dev).
- 192.168.1.145: MacMini Linux Server (Ubuntu 22.04).
- 192.168.1.150: Quantum PC (Windows 11).
- 192.168.1.160: Pavilion PC (Windows 11).
- 192.168.1.201: PI 5 Linux Server (Piper). 
- 136.57.238.135: 136.57.238.135 is my Public WAN IP. It is used for internal NAT reflection and management. Alerts where this is the Source IP should be downgraded to 'Low' risk if the destination is a known management port (like 2222).
- 192.168.1.186: Bose Soundbar Receiver

# Known Behavioral Baselines
- **Bose Soundbar (192.168.1.186)**: Expected to communicate with AWS IPs (54.x.x.x, 44.x.x.x) on ports 8883 and 443. 
- **Suricata Anomalies**: 'WRONG_DIRECTION' on port 8883 for the Bose Soundbar is a known false positive caused by persistent MQTT sessions. Risk: Low.
