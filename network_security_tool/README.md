# 🛡️ Network Security Tool - Professional Edition

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

**A comprehensive network security scanner with a killer GUI**

Advanced network analysis, vulnerability scanning, and security testing toolkit

</div>

---

## ✨ Features

### 🔍 Port Scanner
- **Multiple Scan Types**: TCP, UDP, SYN, Comprehensive
- **Banner Grabbing**: Identify service versions
- **Service Detection**: Recognize 100+ common services
- **Multi-threaded**: Fast parallel scanning
- **Progress Tracking**: Real-time scan progress

### 🌐 Network Discovery
- **Host Detection**: Find active devices on network
- **Multiple Methods**: Ping sweep, ARP scan, TCP SYN
- **OS Detection**: Identify operating systems
- **MAC Address Resolution**: Hardware address discovery
- **Network Mapping**: Visual topology generation

### 📡 Packet Sniffer
- **Real-time Capture**: Live network traffic monitoring
- **Protocol Analysis**: TCP, UDP, ICMP, ARP, DNS
- **Packet Filtering**: BPF-style filter support
- **Detailed Analysis**: Deep packet inspection
- **Export Capability**: Save captures for analysis

### 🔐 Password Strength Checker
- **Comprehensive Analysis**: 10+ security metrics
- **Entropy Calculation**: Shannon entropy measurement
- **Pattern Detection**: Identify weak patterns
- **Crack Time Estimation**: Time-to-crack prediction
- **Common Password Detection**: Check against databases
- **Detailed Reports**: In-depth security assessment

### 🚨 Vulnerability Scanner
- **CVE Database**: Known vulnerability detection
- **Service Testing**: Version-based vulnerability checks
- **Configuration Audit**: Security misconfiguration detection
- **Web Application Testing**: OWASP Top 10 checks
- **Risk Scoring**: CVSS-based risk assessment
- **Remediation Advice**: Fix recommendations

### 📊 Reporting System
- **Multiple Formats**: PDF, HTML, JSON, CSV, XML
- **Comprehensive Reports**: Detailed findings
- **Executive Summaries**: High-level overviews
- **Risk Analysis**: Vulnerability prioritization
- **Export Capabilities**: Share findings easily

---

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Admin/root privileges (for packet sniffing)

### Quick Install

#### Windows
```powershell
# Clone or extract the project
cd network_security_tool

# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the tool
python main.py
```

#### Linux/macOS
```bash
# Clone or extract the project
cd network_security_tool

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the tool
python3 main.py

# For packet sniffing (requires root)
sudo python3 main.py
```

### Dependencies
```
- requests (HTTP library)
- cryptography (Encryption/Security)
- scapy (Packet manipulation - optional for sniffer)
- tkinter (GUI - usually included with Python)
```

---

## 📖 Usage Guide

### Starting the Application
```bash
python main.py
```

### 1. Port Scanner Tab

#### Basic Scan
1. Enter target IP or hostname (e.g., `192.168.1.1`)
2. Set port range (e.g., `1` to `1000`)
3. Select scan type: `TCP`, `UDP`, `SYN`, or `Comprehensive`
4. Click **🚀 Start Scan**

#### Interpreting Results
- **Port**: Port number
- **State**: Open/Closed/Filtered
- **Service**: Identified service name
- **Banner**: Service version information

#### Export Results
Click **💾 Export Results** to save scan data to JSON or CSV

### 2. Network Discovery Tab

#### Discover Network Hosts
1. Enter network range in CIDR notation (e.g., `192.168.1.0/24`)
2. Choose discovery method:
   - **Ping Sweep**: ICMP echo requests
   - **ARP Scan**: Layer 2 discovery (local network)
   - **TCP SYN**: SYN packet probe
   - **Full Scan**: Comprehensive detection
3. Click **🔎 Discover Network**

#### Results Information
- **IP Address**: Host IP
- **MAC Address**: Hardware address
- **Hostname**: DNS name
- **OS**: Operating system guess
- **Status**: Up/Down
- **Ports**: Open ports list

#### Generate Network Map
Click **🗺️ Generate Map** to create visual network topology

### 3. Packet Sniffer Tab

**⚠️ Requires Administrator/Root Privileges**

#### Start Sniffing
1. Select network interface (e.g., `eth0`, `wlan0`)
2. Enter packet filter (BPF syntax):
   - `tcp` - TCP packets only
   - `udp` - UDP packets only
   - `tcp or udp` - TCP and UDP
   - `host 192.168.1.1` - Specific host
   - `port 80` - Specific port
3. Click **▶️ Start Sniffing**

#### Packet Analysis
- Click on any packet to view detailed information
- Use **🗑️ Clear** to remove captured packets

#### Running with Root/Admin
```bash
# Linux/macOS
sudo python3 main.py

# Windows (Run as Administrator)
# Right-click main.py → Run as Administrator
```

### 4. Password Checker Tab

#### Check Password Strength
1. Enter password to analyze
2. Toggle "Show Password" if needed
3. Click **🔍 Check Strength**

#### Analysis Metrics
- **Length**: Character count
- **Character Types**: Lowercase, uppercase, digits, special
- **Entropy**: Randomness measurement (bits)
- **Common Password**: Check against known weak passwords
- **Patterns**: Sequential, repeated, keyboard patterns
- **Crack Time**: Estimated time to brute force

#### Strength Levels
- **Very Weak** (0-30): 😱 Critical - Change immediately
- **Weak** (30-50): 😟 Inadequate - Strengthen password
- **Medium** (50-70): 😐 Acceptable - Could be better
- **Strong** (70-90): 😊 Good - Well protected
- **Very Strong** (90-100): 🔥 Excellent - Maximum security

### 5. Vulnerability Scanner Tab

#### Perform Security Scan
1. Enter target (IP or hostname)
2. Choose scan profile:
   - **Quick Scan**: Basic vulnerability checks
   - **Deep Scan**: Comprehensive analysis
   - **Web Application**: Web-specific tests
   - **Network Services**: Service-focused scan
3. Click **🔎 Start Scan**

#### Vulnerability Information
- **Severity**: CRITICAL, HIGH, MEDIUM, LOW
- **CVE**: Common Vulnerabilities and Exposures ID
- **Service**: Affected service
- **Description**: Vulnerability details
- **Risk Score**: CVSS-based score (0-10)

#### Understanding Severity
- **CRITICAL**: Immediate action required
- **HIGH**: Address urgently
- **MEDIUM**: Plan remediation
- **LOW**: Monitor and address when possible

### 6. Reports Tab

#### Generate Security Reports
1. Select report type:
   - **Comprehensive**: All scan results
   - **Port Scan Only**: Port scanning results
   - **Network Map**: Network topology
   - **Vulnerabilities**: Security findings only
2. Choose format: PDF, HTML, JSON, CSV, XML
3. Click **📄 Generate Report**
4. Save report to file

#### Report Contents
- Executive Summary
- Scan Details
- Findings by Severity
- Risk Analysis
- Recommendations
- Remediation Steps

---

## 🛠️ Advanced Usage

### Command-Line Tools

#### Standalone Port Scanner
```bash
python network_scanner.py
# Follow prompts for interactive scanning
```

#### Password Checker
```bash
python password_checker.py
# Select mode: Interactive or Test
```

#### Vulnerability Scanner
```bash
python vulnerability_scanner.py
# Enter target when prompted
```

### Custom Scans

#### Port Scanner with Custom Options
```python
from network_scanner import PortScanner

scanner = PortScanner(
    target="example.com",
    start_port=1,
    end_port=65535,
    scan_type="TCP"
)

results = scanner.scan()
for result in results:
    print(f"{result['port']}: {result['state']}")
```

#### Network Discovery Script
```python
from network_scanner import NetworkDiscovery

discovery = NetworkDiscovery(
    network_range="192.168.1.0/24",
    method="Ping Sweep"
)

hosts = discovery.discover()
for host in hosts:
    print(f"{host['ip']}: {host['hostname']}")
```

---

## 🔒 Security Considerations

### Legal Notice
⚠️ **IMPORTANT**: Only use this tool on networks and systems you own or have explicit permission to test.

### Ethical Usage
- **Authorization Required**: Always obtain written permission
- **Responsible Disclosure**: Report vulnerabilities appropriately
- **No Harm**: Don't use for malicious purposes
- **Privacy**: Respect user data and privacy
- **Compliance**: Follow applicable laws and regulations

### Best Practices
1. Use in controlled environments
2. Document all testing activities
3. Implement proper access controls
4. Keep tool updated
5. Follow security guidelines

---

## 🐛 Troubleshooting

### Common Issues

#### "Permission Denied" Error
**Solution**: Run with administrator/root privileges
```bash
# Linux/macOS
sudo python3 main.py

# Windows
# Run as Administrator
```

#### Module Not Found
**Solution**: Install dependencies
```bash
pip install -r requirements.txt
```

#### Packet Sniffing Not Working
**Solution**: 
1. Install scapy: `pip install scapy`
2. Run with admin/root privileges
3. Check firewall settings

#### Slow Scanning
**Solution**:
- Reduce port range
- Decrease thread count in settings
- Check network connectivity
- Use faster scan types

#### GUI Not Displaying Correctly
**Solution**:
- Update tkinter
- Check Python version (3.8+)
- Try different theme settings

---

## 📝 Configuration

### Settings File
Settings are saved in `settings.json`:
```json
{
    "timeout": 5,
    "threads": 100,
    "interface": "eth0",
    "scan_delay": 0,
    "max_retries": 3
}
```

### Custom Configuration
Access via **⚙️ Settings** in the application menu

---

## 🎯 Use Cases

### Network Administration
- Inventory network devices
- Monitor open ports
- Track service versions
- Audit security configurations

### Security Testing
- Penetration testing
- Vulnerability assessments
- Security audits
- Compliance checking

### Educational Purposes
- Learn network security
- Understand protocols
- Practice ethical hacking
- Security research

### Development
- Test application security
- Verify firewall rules
- Debug network issues
- API security testing

---

## 🔧 Development

### Project Structure
```
network_security_tool/
├── main.py                    # Main GUI application
├── network_scanner.py         # Port & network scanning
├── password_checker.py        # Password analysis
├── vulnerability_scanner.py   # Vulnerability detection
├── requirements.txt           # Dependencies
├── README.md                  # Documentation
└── settings.json             # Configuration (created on first run)
```

### Adding Features
1. Create new module in project directory
2. Import in `main.py`
3. Add GUI tab if needed
4. Update documentation

### Contributing
Contributions welcome! Please:
1. Fork the repository
2. Create feature branch
3. Commit changes
4. Submit pull request

---

## 📊 Performance

### Scan Speed
- **Port Scan**: ~100 ports/second
- **Network Discovery**: ~50 hosts/second
- **Packet Capture**: Real-time (network speed)

### Resource Usage
- **CPU**: Low to medium
- **Memory**: ~50-100 MB
- **Network**: Depends on scan intensity

### Optimization Tips
- Adjust thread count
- Use targeted port ranges
- Filter packet captures
- Close unused tabs

---

## 🎨 Screenshots

### Main Dashboard
Beautiful modern dark theme with intuitive navigation

### Port Scanner
Real-time scanning with progress indicators

### Network Map
Visual representation of network topology

### Vulnerability Reports
Detailed security findings with remediation advice

---

## 📚 Resources

### Learning
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CVE Database](https://cve.mitre.org/)
- [Network Security Basics](https://www.sans.org/)

### Documentation
- [Python Socket Programming](https://docs.python.org/3/library/socket.html)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Network Protocols](https://www.ietf.org/)

---

## 🤝 Support

### Issues & Bugs
Report issues with detailed information:
- Python version
- Operating system
- Error messages
- Steps to reproduce

### Feature Requests
Suggest new features:
- Use case description
- Expected behavior
- Implementation ideas

---

## 📄 License

This project is licensed under the MIT License.

**MIT License** - Free to use, modify, and distribute with attribution.

---

## ⚖️ Disclaimer

This tool is provided for educational and authorized security testing purposes only. Users are responsible for compliance with all applicable laws and regulations. The authors assume no liability for misuse or damage caused by this software.

---

## 🌟 Acknowledgments

- Built with Python and Tkinter
- Uses industry-standard security practices
- Inspired by professional security tools
- Community-driven development

---

## 📞 Contact

For questions, suggestions, or collaboration:
- Create an issue on the repository
- Contribute via pull requests
- Share feedback and improvements

---

<div align="center">

**Made with Python 🐍 | Secured with Best Practices 🔐 | Built for Security Professionals 🛡️**

⭐ Star this project if you find it useful!

</div>
