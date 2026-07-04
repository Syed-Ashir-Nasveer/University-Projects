# README.md 
# 🛡️ Web Application Security Scanner

**Automated Vulnerability Detection & Reporting System**

A comprehensive security scanning tool built with OWASP ZAP, Python, and Flask. Features include automated scanning, multiple report formats, and a beautiful 3D web interface.

---

## 📋 Table of Contents

- [Features](#features)
- [Screenshots](#screenshots)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [API Documentation](#api-documentation)
- [Report Formats](#report-formats)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## ✨ Features

### Core Features
- ✅ **Automated Security Scanning** - Spider, passive, and active vulnerability detection
- ✅ **Multiple Scan Types** - Quick (5-10 min), Standard (15-30 min), Deep (1-2 hours)
- ✅ **6 Report Formats** - HTML, PDF, Word, Excel, JSON, CSV
- ✅ **VIP 3D Dashboard** - Interactive web interface with modern design
- ✅ **Real-time Progress** - Live scan status updates
- ✅ **Historical Data** - Complete scan history with database storage
- ✅ **Risk Categorization** - High, Medium, Low severity levels
- ✅ **REST API** - Complete API for programmatic access

### Report Features
- 📊 Beautiful HTML reports with 3D styling
- 📄 Professional PDF documents
- 📝 Editable Word documents
- 📈 Excel spreadsheets with multiple sheets
- ⚙️ JSON data for API integration
- 📋 CSV files for quick import

### Security Features
- 🔍 SQL Injection detection
- 🔐 XSS vulnerability scanning
- 🛡️ CSRF protection checks
- 📡 Security header validation
- 🔑 Authentication testing
- 📦 Directory traversal detection

---

## 📸 Screenshots

### Dashboard
![Dashboard](screenshots/dashboard.png)

### Scan Results
![Results](screenshots/results.png)

### Report Generation
![Reports](screenshots/reports.png)

---

## 🚀 Installation

### Prerequisites

Before you begin, ensure you have:
- **Python 3.8+** installed
- **OWASP ZAP** installed and running
- **Windows 10/11** or **Linux/Mac**
- **Internet connection** for downloading dependencies

### Step 1: Install OWASP ZAP

1. Download from: https://www.zaproxy.org/download/
2. Install and launch ZAP
3. ZAP should run on `localhost:8080` by default
4. Note the API key (Tools → Options → API)

### Step 2: Clone/Download Project

```bash
# Create project folder
mkdir SecurityScanner
cd SecurityScanner

# Create subfolders
mkdir templates
mkdir static
mkdir reports
```

### Step 3: Install Python Dependencies

```bash
# Install all required packages
pip install -r requirements.txt
```

**Or install individually:**
```bash
pip install flask
pip install python-owasp-zap-v2.4
pip install reportlab
pip install python-docx
pip install openpyxl
pip install requests
```

### Step 4: Verify Installation

```bash
# Test scanner
python scanner.py

# Test report generator
python report_generator.py

# Test web server
python app.py
```

---

## 💻 Usage

### Method 1: Command Line Interface

**Start a scan:**
```bash
python scanner.py
```

**Generate reports:**
```bash
python report_generator.py
```

### Method 2: Web Interface

**Start the web server:**
```bash
python app.py
```

**Access dashboard:**
- Open browser: `http://localhost:5000`
- Enter target URL
- Select scan type
- Click "Start Scan"
- Download reports in any format

### Method 3: REST API

**Start a scan:**
```bash
curl -X POST http://localhost:5000/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{"url": "http://testphp.vulnweb.com", "scanType": "quick"}'
```

**Get scan status:**
```bash
curl http://localhost:5000/api/scan/status/1
```

**Download report:**
```bash
curl http://localhost:5000/api/report/download/1/html -o report.html
```

---

## 📁 Project Structure

```
SecurityScanner/
│
├── 📄 scanner.py              # Core ZAP scanner logic
├── 📄 report_generator.py     # Multi-format report generator
├── 📄 app.py                  # Flask web server & API
├── 📄 config.py               # Configuration settings
├── 📄 requirements.txt        # Python dependencies
├── 📄 README.md              # This file
│
├── 📁 templates/              # HTML templates
│   └── dashboard_3d.html     # VIP dashboard UI
│
├── 📁 static/                 # Static files (CSS/JS/Images)
│   ├── css/
│   ├── js/
│   └── images/
│
├── 📁 reports/                # Generated reports
│   ├── report_1.html
│   ├── report_1.pdf
│   ├── report_1.xlsx
│   └── ...
│
└── 💾 scan_results.db        # SQLite database (auto-created)
```

---

## 🔌 API Documentation

### Endpoints

#### Scanning

**POST /api/scan/start**
- Start a new scan
- Body: `{"url": "http://example.com", "scanType": "quick"}`
- Returns: `{"status": "started", "scan_id": 1}`

**GET /api/scan/status/:id**
- Get scan status and results
- Returns: Complete scan data with vulnerabilities

**GET /api/scans/history**
- Get scan history
- Query: `?limit=10`
- Returns: List of scans

#### Reports

**POST /api/report/generate/:id/:format**
- Generate report in specific format
- Formats: html, pdf, json, csv, docx, xlsx

**GET /api/report/download/:id/:format**
- Download generated report
- Returns: File download

**POST /api/report/all/:id**
- Generate all report formats
- Returns: Status of all generations

#### Statistics

**GET /api/stats**
- Get system statistics
- Returns: Total scans, vulnerabilities, etc.

---

## 📊 Report Formats

### 1. HTML Report (VIP Design)
- **Features:** 3D styling, animations, responsive
- **Use Case:** Presentations, web sharing
- **File Size:** ~150 KB
- **Command:** `generator.generate_html_report(scan_id)`

### 2. PDF Report
- **Features:** Professional layout, printable
- **Use Case:** Official documentation
- **File Size:** ~300 KB
- **Command:** `generator.generate_pdf_report(scan_id)`

### 3. Excel Report
- **Features:** Multiple sheets, formatted cells
- **Use Case:** Data analysis, tracking
- **File Size:** ~50 KB
- **Command:** `generator.generate_excel_report(scan_id)`

### 4. Word Document
- **Features:** Editable, styled
- **Use Case:** Custom reports, client delivery
- **File Size:** ~80 KB
- **Command:** `generator.generate_docx_report(scan_id)`

### 5. JSON Report
- **Features:** Structured data, machine-readable
- **Use Case:** API integration, automation
- **File Size:** ~20 KB
- **Command:** `generator.generate_json_report(scan_id)`

### 6. CSV Report
- **Features:** Simple table, universal format
- **Use Case:** Quick import, data migration
- **File Size:** ~10 KB
- **Command:** `generator.generate_csv_report(scan_id)`

---

## ⚙️ Configuration

Edit `config.py` to customize settings:

```python
# ZAP settings
ZAP_CONFIG = {
    'api_key': 'changeme',
    'proxy_url': 'http://127.0.0.1:8080'
}

# Server settings
SERVER_CONFIG = {
    'host': '0.0.0.0',
    'port': 5000,
    'debug': True
}

# Report settings
REPORT_CONFIG = {
    'output_dir': 'reports/',
    'formats': ['html', 'pdf', 'json', 'csv', 'docx', 'xlsx']
}
```

---

## 🎯 Test Sites (Safe for Scanning)

These sites are designed for security testing:

- http://testphp.vulnweb.com
- http://testhtml5.vulnweb.com
- http://testasp.vulnweb.com
- http://testaspnet.vulnweb.com

**⚠️ WARNING:** Only scan websites you own or have explicit permission to test!

---

## 🔧 Troubleshooting

### Problem: Cannot connect to ZAP
**Solution:**
- Make sure ZAP is running
- Check if port 8080 is available
- Verify API key in config.py

### Problem: ModuleNotFoundError
**Solution:**
```bash
pip install -r requirements.txt
```

### Problem: PDF generation fails
**Solution:**
```bash
pip install --upgrade reportlab
```

### Problem: Dashboard not loading
**Solution:**
- Check if Flask is running: `python app.py`
- Verify port 5000 is free
- Try: `http://127.0.0.1:5000`

### Problem: Scan takes too long
**Solution:**
- Use 'quick' scan type
- Scan smaller websites
- Check ZAP settings for timeout

---

## 📚 Additional Resources

### Documentation
- [OWASP ZAP Docs](https://www.zaproxy.org/docs/)
- [Python ZAP API](https://github.com/zaproxy/zap-api-python)
- [Flask Documentation](https://flask.palletsprojects.com/)

### Security Testing Guides
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Web Security Academy](https://portswigger.net/web-security)

---

## 🎓 For University Projects

### Report Sections to Include:
1. **Introduction** - Problem statement, objectives
2. **Literature Review** - Existing tools, research
3. **System Design** - Architecture, flowcharts, diagrams
4. **Implementation** - Code explanation, screenshots
5. **Testing** - Test cases, results, analysis
6. **Conclusion** - Achievements, limitations, future work

### Presentation Tips:
- Live demo of scanning
- Show all report formats
- Explain vulnerabilities found
- Discuss fix recommendations

---

## 📄 License

This project is for **educational purposes only**.

**Disclaimer:** Unauthorized scanning of websites is illegal. Always obtain proper authorization before testing any web application.

---

## 👨‍💻 Author

**[Your Name]**
- Roll Number: [Your Roll Number]
- University: [Your University]
- Course: [Your Course]
- Year: 2024

---

## 🙏 Acknowledgments

- OWASP ZAP Team for the amazing security tool
- Python community for excellent libraries
- [Your University] for project guidance

---

## 📞 Support

For issues or questions:
1. Check [Troubleshooting](#troubleshooting) section
2. Read OWASP ZAP documentation
3. Check Flask documentation
4. Contact project maintainer

---

## 🔄 Version History

### v1.0 (December 2024)
- Initial release
- Core scanning functionality
- 6 report formats
- Web dashboard
- REST API

---

**Made with ❤️ for Security Research & Education**

**⭐ Star this project if you find it useful!**