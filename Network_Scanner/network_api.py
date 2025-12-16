"""
network_api.py
==============
API routes for Network Monitoring & IPS
Add these routes to your existing app.py

Author: [Your Name]
Date: December 2024
"""

from flask import jsonify, request
from network_monitor import NetworkMonitor
import threading
import sqlite3

# Global network monitor instance
network_monitor = NetworkMonitor()
monitoring_thread = None


# ============================================================================
# NETWORK MONITORING API ROUTES
# ============================================================================

def add_network_routes(app):
    """Add network monitoring routes to Flask app"""
    
    @app.route('/api/network/start', methods=['POST'])
    def start_network_monitoring():
        """Start network monitoring"""
        global monitoring_thread
        
        try:
            data = request.json or {}
            duration = data.get('duration', None)
            interface = data.get('interface', None)
            
            if monitoring_thread and monitoring_thread.is_alive():
                return jsonify({
                    'error': 'Monitoring already in progress'
                }), 400
            
            # Start monitoring in background thread
            monitoring_thread = threading.Thread(
                target=network_monitor.start_monitoring,
                args=(duration,)
            )
            monitoring_thread.daemon = True
            monitoring_thread.start()
            
            return jsonify({
                'status': 'started',
                'message': 'Network monitoring started',
                'duration': duration or 'continuous',
                'interface': interface or 'all'
            })
        
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    
    @app.route('/api/network/stop', methods=['POST'])
    def stop_network_monitoring():
        """Stop network monitoring"""
        try:
            network_monitor.stop_monitoring()
            
            return jsonify({
                'status': 'stopped',
                'message': 'Network monitoring stopped'
            })
        
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    
    @app.route('/api/network/stats', methods=['GET'])
    def get_network_stats():
        """Get current network statistics"""
        try:
            return jsonify({
                'is_monitoring': network_monitor.is_monitoring,
                'stats': network_monitor.stats,
                'blocked_ips_count': len(network_monitor.blocked_ips),
                'packet_count': network_monitor.packet_count
            })
        
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    
    @app.route('/api/network/suspicious', methods=['GET'])
    def get_suspicious_activities():
        """Get suspicious activities"""
        try:
            limit = request.args.get('limit', 50, type=int)
            activities = network_monitor.get_suspicious_activities(limit)
            
            result = [
                {
                    'id': a[0],
                    'timestamp': a[1],
                    'src_ip': a[2],
                    'attack_type': a[3],
                    'details': a[4],
                    'severity': a[5],
                    'blocked': bool(a[6])
                }
                for a in activities
            ]
            
            return jsonify(result)
        
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    
    @app.route('/api/network/blocked-ips', methods=['GET'])
    def get_blocked_ips():
        """Get list of blocked IPs"""
        try:
            blocked = network_monitor.get_blocked_ips()
            
            result = [
                {
                    'id': b[0],
                    'ip_address': b[1],
                    'reason': b[2],
                    'blocked_at': b[3],
                    'unblock_at': b[4]
                }
                for b in blocked
            ]
            
            return jsonify(result)
        
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    
    @app.route('/api/network/unblock/<ip>', methods=['POST'])
    def unblock_ip(ip):
        """Unblock an IP address"""
        try:
            network_monitor.unblock_ip(ip)
            
            return jsonify({
                'status': 'success',
                'message': f'IP {ip} unblocked',
                'ip': ip
            })
        
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    
    @app.route('/api/network/traffic-logs', methods=['GET'])
    def get_traffic_logs():
        """Get traffic logs"""
        try:
            limit = request.args.get('limit', 100, type=int)
            suspicious_only = request.args.get('suspicious', 'false').lower() == 'true'
            
            conn = sqlite3.connect(network_monitor.db_path)
            cursor = conn.cursor()
            
            if suspicious_only:
                cursor.execute('''
                    SELECT * FROM traffic_logs 
                    WHERE is_suspicious = 1 
                    ORDER BY id DESC LIMIT ?
                ''', (limit,))
            else:
                cursor.execute('''
                    SELECT * FROM traffic_logs 
                    ORDER BY id DESC LIMIT ?
                ''', (limit,))
            
            logs = cursor.fetchall()
            conn.close()
            
            result = [
                {
                    'id': log[0],
                    'timestamp': log[1],
                    'src_ip': log[2],
                    'dst_ip': log[3],
                    'protocol': log[4],
                    'src_port': log[5],
                    'dst_port': log[6],
                    'payload': log[7],
                    'is_suspicious': bool(log[8]),
                    'threat_type': log[9],
                    'action_taken': log[10]
                }
                for log in logs
            ]
            
            return jsonify(result)
        
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    
    @app.route('/api/network/dashboard-data', methods=['GET'])
    def get_dashboard_data():
        """Get complete dashboard data"""
        try:
            conn = sqlite3.connect(network_monitor.db_path)
            cursor = conn.cursor()
            
            # Get statistics
            cursor.execute('''
                SELECT COUNT(*) FROM suspicious_activities
            ''')
            total_suspicious = cursor.fetchone()[0]
            
            cursor.execute('''
                SELECT COUNT(*) FROM blocked_ips
            ''')
            total_blocked = cursor.fetchone()[0]
            
            cursor.execute('''
                SELECT COUNT(*) FROM traffic_logs
            ''')
            total_traffic = cursor.fetchone()[0]
            
            # Get recent suspicious activities (last 10)
            cursor.execute('''
                SELECT src_ip, attack_type, severity, timestamp 
                FROM suspicious_activities 
                ORDER BY id DESC LIMIT 10
            ''')
            recent_suspicious = cursor.fetchall()
            
            # Get attack types distribution
            cursor.execute('''
                SELECT attack_type, COUNT(*) as count 
                FROM suspicious_activities 
                GROUP BY attack_type 
                ORDER BY count DESC
            ''')
            attack_distribution = cursor.fetchall()
            
            # Get top attacking IPs
            cursor.execute('''
                SELECT src_ip, COUNT(*) as count 
                FROM suspicious_activities 
                GROUP BY src_ip 
                ORDER BY count DESC LIMIT 10
            ''')
            top_attackers = cursor.fetchall()
            
            conn.close()
            
            return jsonify({
                'summary': {
                    'total_suspicious': total_suspicious,
                    'total_blocked': total_blocked,
                    'total_traffic': total_traffic,
                    'is_monitoring': network_monitor.is_monitoring
                },
                'recent_suspicious': [
                    {
                        'ip': r[0],
                        'type': r[1],
                        'severity': r[2],
                        'time': r[3]
                    }
                    for r in recent_suspicious
                ],
                'attack_distribution': [
                    {'type': a[0], 'count': a[1]}
                    for a in attack_distribution
                ],
                'top_attackers': [
                    {'ip': t[0], 'count': t[1]}
                    for t in top_attackers
                ],
                'current_stats': network_monitor.stats
            })
        
        except Exception as e:
            return jsonify({'error': str(e)}), 500


# ============================================================================
# INTEGRATION EXAMPLE FOR app.py
# ============================================================================

"""
Add this to your existing app.py:

from network_api import add_network_routes

# After creating app
app = Flask(__name__)

# Add network monitoring routes
add_network_routes(app)

# Then run as normal
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
"""
