"""
app.py
======
Unified Flask Web Server
Complete Security Platform with Web Scanner & Network Monitor

Author: [Your Name]
Date: December 2024
"""

from flask import Flask, render_template, request, jsonify, send_file
from scanner import SecurityScanner
from report_generator import VIPReportGenerator
from network_api import add_network_routes
from config import SERVER_CONFIG
import threading
import sqlite3
import os

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'

# Initialize components
scanner = SecurityScanner()
generator = VIPReportGenerator()

# Add network monitoring routes
add_network_routes(app)

# Store active scans
active_scans = {}


# ============================================================================
# MAIN ROUTES
# ============================================================================

@app.route('/')
def index():
    """Serve unified dashboard"""
    return render_template('index.html')


@app.route('/web-scanner')
def web_scanner():
    """Legacy web scanner page"""
    return render_template('dashboard_3d.html')


@app.route('/network-monitor')
def network_monitor():
    """Legacy network monitor page"""
    return render_template('network_monitor.html')


# ============================================================================
# WEB SCANNER API ROUTES
# ============================================================================

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """
    Start a new web security scan
    
    Request JSON:
        {
            "url": "http://example.com",
            "scanType": "quick"
        }
    
    Returns:
        JSON: {status: "started", scan_id: 123}
    """
    try:
        data = request.json
        target_url = data.get('url')
        scan_type = data.get('scanType', 'quick')
        
        if not target_url:
            return jsonify({'error': 'Target URL is required'}), 400
        
        # Validate URL
        if not target_url.startswith('http'):
            return jsonify({'error': 'Invalid URL format'}), 400
        
        # Start scan in background thread
        def run_scan():
            scan_id = scanner.start_scan(target_url, scan_type)
            if scan_id:
                active_scans[scan_id] = {
                    'status': 'completed',
                    'scan_id': scan_id
                }
        
        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'status': 'started',
            'message': 'Scan started successfully',
            'url': target_url,
            'scanType': scan_type
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/status/<int:scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    """Get scan status and results"""
    try:
        conn = sqlite3.connect(scanner.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
        scan = cursor.fetchone()
        
        if not scan:
            conn.close()
            return jsonify({'error': 'Scan not found'}), 404
        
        cursor.execute('SELECT * FROM vulnerabilities WHERE scan_id = ?', (scan_id,))
        vulns = cursor.fetchall()
        
        result = {
            'scan_id': scan[0],
            'target_url': scan[1],
            'scan_type': scan[2],
            'start_time': scan[3],
            'end_time': scan[4],
            'total_alerts': scan[5],
            'high_risk': scan[6],
            'medium_risk': scan[7],
            'low_risk': scan[8],
            'status': scan[9],
            'vulnerabilities': [
                {
                    'id': v[0],
                    'name': v[2],
                    'severity': v[3],
                    'confidence': v[4],
                    'url': v[5],
                    'description': v[6],
                    'solution': v[7],
                    'reference': v[8]
                }
                for v in vulns
            ]
        }
        
        conn.close()
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scans/history', methods=['GET'])
def get_scan_history():
    """Get scan history"""
    try:
        limit = request.args.get('limit', 10, type=int)
        scans = scanner.get_scan_history(limit)
        
        history = [
            {
                'scan_id': s[0],
                'target_url': s[1],
                'scan_type': s[2],
                'start_time': s[3],
                'end_time': s[4],
                'total_alerts': s[5],
                'high_risk': s[6],
                'medium_risk': s[7],
                'low_risk': s[8],
                'status': s[9]
            }
            for s in scans
        ]
        
        return jsonify(history)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# REPORT GENERATION ROUTES
# ============================================================================

@app.route('/api/report/generate/<int:scan_id>/<format>', methods=['POST'])
def generate_report(scan_id, format):
    """Generate report in specified format"""
    try:
        format = format.lower()
        
        if format == 'html':
            success = generator.generate_html_report(scan_id)
        elif format == 'pdf':
            success = generator.generate_pdf_report(scan_id)
        elif format == 'json':
            success = generator.generate_json_report(scan_id)
        elif format == 'csv':
            success = generator.generate_csv_report(scan_id)
        elif format == 'docx':
            success = generator.generate_docx_report(scan_id)
        elif format in ['xlsx', 'excel']:
            success = generator.generate_excel_report(scan_id)
        else:
            return jsonify({'error': 'Invalid format'}), 400
        
        if success:
            return jsonify({
                'status': 'success',
                'filename': f'report_{scan_id}.{format}',
                'format': format
            })
        else:
            return jsonify({'error': 'Report generation failed'}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/report/download/<int:scan_id>/<format>', methods=['GET'])
def download_report(scan_id, format):
    """Download report file"""
    try:
        format = format.lower()
        
        extensions = {
            'html': 'html',
            'pdf': 'pdf',
            'json': 'json',
            'csv': 'csv',
            'docx': 'docx',
            'word': 'docx',
            'excel': 'xlsx',
            'xlsx': 'xlsx'
        }
        
        if format not in extensions:
            return jsonify({'error': 'Invalid format'}), 400
        
        ext = extensions[format]
        filename = f'reports/report_{scan_id}.{ext}'
        
        if not os.path.exists(filename):
            if format == 'html':
                generator.generate_html_report(scan_id)
            elif format == 'pdf':
                generator.generate_pdf_report(scan_id)
            elif format == 'json':
                generator.generate_json_report(scan_id)
            elif format == 'csv':
                generator.generate_csv_report(scan_id)
            elif format in ['docx', 'word']:
                generator.generate_docx_report(scan_id)
            elif format in ['excel', 'xlsx']:
                generator.generate_excel_report(scan_id)
        
        if os.path.exists(filename):
            return send_file(filename, as_attachment=True)
        else:
            return jsonify({'error': 'Report file not found'}), 404
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/report/all/<int:scan_id>', methods=['POST'])
def generate_all_reports(scan_id):
    """Generate reports in all formats"""
    try:
        generator.generate_all_formats(scan_id)
        
        return jsonify({
            'status': 'success',
            'message': 'All reports generated',
            'scan_id': scan_id,
            'formats': ['html', 'pdf', 'json', 'csv', 'docx', 'xlsx']
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# STATISTICS & DASHBOARD DATA
# ============================================================================

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get overall statistics"""
    try:
        conn = sqlite3.connect(scanner.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM scans')
        total_scans = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM vulnerabilities')
        total_vulns = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE risk_level = 'High'")
        high_risk = cursor.fetchone()[0]
        
        cursor.execute('SELECT target_url, start_time, status FROM scans ORDER BY id DESC LIMIT 5')
        recent = cursor.fetchall()
        
        cursor.execute("SELECT COUNT(*) FROM scans WHERE status = 'completed'")
        completed = cursor.fetchone()[0]
        
        stats = {
            'total_scans': total_scans,
            'completed_scans': completed,
            'total_vulnerabilities': total_vulns,
            'high_risk_count': high_risk,
            'recent_scans': [
                {'url': r[0], 'time': r[1], 'status': r[2]} 
                for r in recent
            ]
        }
        
        conn.close()
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/dashboard/data', methods=['GET'])
def get_dashboard_data():
    """Get complete dashboard data for unified interface"""
    try:
        # Web scanner stats
        conn_web = sqlite3.connect(scanner.db_path)
        cursor_web = conn_web.cursor()
        
        cursor_web.execute('SELECT COUNT(*) FROM scans')
        total_scans = cursor_web.fetchone()[0]
        
        cursor_web.execute('SELECT COUNT(*) FROM vulnerabilities WHERE risk_level = "High"')
        web_threats = cursor_web.fetchone()[0]
        
        conn_web.close()
        
        # Network monitor stats
        try:
            from network_monitor import NetworkMonitor
            network_db = 'network_monitor.db'
            
            if os.path.exists(network_db):
                conn_net = sqlite3.connect(network_db)
                cursor_net = conn_net.cursor()
                
                cursor_net.execute('SELECT COUNT(*) FROM blocked_ips')
                blocked_ips = cursor_net.fetchone()[0]
                
                cursor_net.execute('SELECT COUNT(*) FROM suspicious_activities')
                network_threats = cursor_net.fetchone()[0]
                
                conn_net.close()
            else:
                blocked_ips = 0
                network_threats = 0
        except:
            blocked_ips = 0
            network_threats = 0
        
        return jsonify({
            'web_scanner': {
                'total_scans': total_scans,
                'threats_found': web_threats
            },
            'network_monitor': {
                'blocked_ips': blocked_ips,
                'threats_detected': network_threats
            },
            'system_health': 100,
            'total_threats_blocked': web_threats + network_threats + blocked_ips
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    return jsonify({'error': 'Internal server error'}), 500


# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║        CyberShield Security Platform v2.0                ║
    ║     Web Scanner + Network Monitor + IPS System           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    print("\n[*] Server Configuration:")
    print(f"    Host: {SERVER_CONFIG['host']}")
    print(f"    Port: {SERVER_CONFIG['port']}")
    print(f"    Debug: {SERVER_CONFIG['debug']}")
    
    print("\n[!] IMPORTANT:")
    print("    1. Make sure OWASP ZAP is running on localhost:8080")
    print("    2. For network monitoring, run as Administrator/sudo")
    print("    3. Install Scapy: pip install scapy")
    
    print(f"\n[+] Unified Dashboard available at:")
    print(f"    → http://localhost:{SERVER_CONFIG['port']}")
    print(f"    → http://127.0.0.1:{SERVER_CONFIG['port']}")
    
    print("\n[+] Alternative interfaces:")
    print(f"    → Web Scanner: http://localhost:{SERVER_CONFIG['port']}/web-scanner")
    print(f"    → Network Monitor: http://localhost:{SERVER_CONFIG['port']}/network-monitor")
    
    print("\n[*] Press Ctrl+C to stop the server\n")
    print("="*60 + "\n")
    
    # Run Flask server
    app.run(
        host=SERVER_CONFIG['host'],
        port=SERVER_CONFIG['port'],
        debug=SERVER_CONFIG['debug'],
        threaded=SERVER_CONFIG.get('threaded', True)
    )