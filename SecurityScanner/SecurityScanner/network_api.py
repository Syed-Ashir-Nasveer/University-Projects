"""
network_api.py
==============
Network Monitoring API Routes
Provides REST API endpoints for network monitoring features

Author: [Your Name]
Date: December 2024
"""

from flask import jsonify, request
import sqlite3
import os
from datetime import datetime
from config import DATABASE_CONFIG


def add_network_routes(app):
    """Add network monitoring routes to Flask app"""
    
    NETWORK_DB = DATABASE_CONFIG.get('network_db', 'network_monitor.db')
    
    # Initialize database if it doesn't exist
    def init_network_db():
        """Initialize network monitoring database"""
        if not os.path.exists(NETWORK_DB):
            conn = sqlite3.connect(NETWORK_DB)
            cursor = conn.cursor()
            
            # Create blocked IPs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    reason TEXT,
                    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    block_count INTEGER DEFAULT 1
                )
            ''')
            
            # Create suspicious activities table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS suspicious_activities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    activity_type TEXT,
                    severity TEXT,
                    description TEXT,
                    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create network logs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS network_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    source_ip TEXT,
                    dest_ip TEXT,
                    protocol TEXT,
                    port INTEGER,
                    action TEXT,
                    details TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
    
    # Initialize DB on startup
    init_network_db()
    
    
    @app.route('/api/network/status', methods=['GET'])
    def network_status():
        """Get network monitoring status"""
        try:
            conn = sqlite3.connect(NETWORK_DB)
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM blocked_ips')
            blocked_count = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM suspicious_activities')
            suspicious_count = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM network_logs WHERE DATE(timestamp) = DATE("now")')
            today_logs = cursor.fetchone()[0]
            
            conn.close()
            
            return jsonify({
                'status': 'active',
                'blocked_ips': blocked_count,
                'suspicious_activities': suspicious_count,
                'logs_today': today_logs,
                'monitoring_enabled': True
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    
    @app.route('/api/network/blocked-ips', methods=['GET'])
    def get_blocked_ips():
        """Get list of blocked IP addresses"""
        try:
            conn = sqlite3.connect(NETWORK_DB)
            cursor = conn.cursor()
            
            limit = request.args.get('limit', 50, type=int)
            
            cursor.execute('''
                SELECT id, ip_address, reason, blocked_at, block_count 
                FROM blocked_ips 
                ORDER BY blocked_at DESC 
                LIMIT ?
            ''', (limit,))
            
            blocked = cursor.fetchall()
            conn.close()
            
            return jsonify({
                'blocked_ips': [
                    {
                        'id': b[0],
                        'ip_address': b[1],
                        'reason': b[2],
                        'blocked_at': b[3],
                        'block_count': b[4]
                    }
                    for b in blocked
                ]
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    
    @app.route('/api/network/block-ip', methods=['POST'])
    def block_ip():
        """Block an IP address"""
        try:
            data = request.json
            ip_address = data.get('ip_address')
            reason = data.get('reason', 'Manual block')
            
            if not ip_address:
                return jsonify({'error': 'IP address required'}), 400
            
            conn = sqlite3.connect(NETWORK_DB)
            cursor = conn.cursor()
            
            # Check if already blocked
            cursor.execute('SELECT id, block_count FROM blocked_ips WHERE ip_address = ?', (ip_address,))
            existing = cursor.fetchone()
            
            if existing:
                # Update block count
                cursor.execute('''
                    UPDATE blocked_ips 
                    SET block_count = block_count + 1, blocked_at = CURRENT_TIMESTAMP 
                    WHERE ip_address = ?
                ''', (ip_address,))
                message = f'IP {ip_address} block count updated'
            else:
                # Insert new block
                cursor.execute('''
                    INSERT INTO blocked_ips (ip_address, reason) 
                    VALUES (?, ?)
                ''', (ip_address, reason))
                message = f'IP {ip_address} blocked successfully'
            
            conn.commit()
            conn.close()
            
            return jsonify({
                'status': 'success',
                'message': message,
                'ip_address': ip_address
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    
    @app.route('/api/network/unblock-ip/<ip_address>', methods=['DELETE'])
    def unblock_ip(ip_address):
        """Unblock an IP address"""
        try:
            conn = sqlite3.connect(NETWORK_DB)
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM blocked_ips WHERE ip_address = ?', (ip_address,))
            
            if cursor.rowcount > 0:
                conn.commit()
                conn.close()
                return jsonify({
                    'status': 'success',
                    'message': f'IP {ip_address} unblocked'
                })
            else:
                conn.close()
                return jsonify({'error': 'IP not found in blocked list'}), 404
                
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    
    @app.route('/api/network/suspicious', methods=['GET'])
    def get_suspicious_activities():
        """Get suspicious network activities"""
        try:
            conn = sqlite3.connect(NETWORK_DB)
            cursor = conn.cursor()
            
            limit = request.args.get('limit', 100, type=int)
            severity = request.args.get('severity', None)
            
            if severity:
                cursor.execute('''
                    SELECT id, ip_address, activity_type, severity, description, detected_at 
                    FROM suspicious_activities 
                    WHERE severity = ?
                    ORDER BY detected_at DESC 
                    LIMIT ?
                ''', (severity, limit))
            else:
                cursor.execute('''
                    SELECT id, ip_address, activity_type, severity, description, detected_at 
                    FROM suspicious_activities 
                    ORDER BY detected_at DESC 
                    LIMIT ?
                ''', (limit,))
            
            activities = cursor.fetchall()
            conn.close()
            
            return jsonify({
                'suspicious_activities': [
                    {
                        'id': a[0],
                        'ip_address': a[1],
                        'activity_type': a[2],
                        'severity': a[3],
                        'description': a[4],
                        'detected_at': a[5]
                    }
                    for a in activities
                ]
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    
    @app.route('/api/network/log-activity', methods=['POST'])
    def log_activity():
        """Log a suspicious activity"""
        try:
            data = request.json
            ip_address = data.get('ip_address')
            activity_type = data.get('activity_type', 'Unknown')
            severity = data.get('severity', 'Medium')
            description = data.get('description', '')
            
            if not ip_address:
                return jsonify({'error': 'IP address required'}), 400
            
            conn = sqlite3.connect(NETWORK_DB)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO suspicious_activities 
                (ip_address, activity_type, severity, description) 
                VALUES (?, ?, ?, ?)
            ''', (ip_address, activity_type, severity, description))
            
            activity_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            return jsonify({
                'status': 'success',
                'message': 'Activity logged',
                'activity_id': activity_id
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    
    @app.route('/api/network/logs', methods=['GET'])
    def get_network_logs():
        """Get network traffic logs"""
        try:
            conn = sqlite3.connect(NETWORK_DB)
            cursor = conn.cursor()
            
            limit = request.args.get('limit', 100, type=int)
            protocol = request.args.get('protocol', None)
            
            if protocol:
                cursor.execute('''
                    SELECT id, timestamp, source_ip, dest_ip, protocol, port, action, details 
                    FROM network_logs 
                    WHERE protocol = ?
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (protocol, limit))
            else:
                cursor.execute('''
                    SELECT id, timestamp, source_ip, dest_ip, protocol, port, action, details 
                    FROM network_logs 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (limit,))
            
            logs = cursor.fetchall()
            conn.close()
            
            return jsonify({
                'logs': [
                    {
                        'id': log[0],
                        'timestamp': log[1],
                        'source_ip': log[2],
                        'dest_ip': log[3],
                        'protocol': log[4],
                        'port': log[5],
                        'action': log[6],
                        'details': log[7]
                    }
                    for log in logs
                ]
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    
    @app.route('/api/network/stats', methods=['GET'])
    def get_network_stats():
        """Get network monitoring statistics"""
        try:
            conn = sqlite3.connect(NETWORK_DB)
            cursor = conn.cursor()
            
            # Total blocked IPs
            cursor.execute('SELECT COUNT(*) FROM blocked_ips')
            total_blocked = cursor.fetchone()[0]
            
            # High severity threats
            cursor.execute('SELECT COUNT(*) FROM suspicious_activities WHERE severity = "High"')
            high_threats = cursor.fetchone()[0]
            
            # Medium severity threats
            cursor.execute('SELECT COUNT(*) FROM suspicious_activities WHERE severity = "Medium"')
            medium_threats = cursor.fetchone()[0]
            
            # Today's activities
            cursor.execute('SELECT COUNT(*) FROM suspicious_activities WHERE DATE(detected_at) = DATE("now")')
            today_activities = cursor.fetchone()[0]
            
            # Recent blocked IPs (last 5)
            cursor.execute('''
                SELECT ip_address, reason, blocked_at 
                FROM blocked_ips 
                ORDER BY blocked_at DESC 
                LIMIT 5
            ''')
            recent_blocks = cursor.fetchall()
            
            conn.close()
            
            return jsonify({
                'total_blocked_ips': total_blocked,
                'high_severity_threats': high_threats,
                'medium_severity_threats': medium_threats,
                'today_activities': today_activities,
                'recent_blocks': [
                    {
                        'ip': b[0],
                        'reason': b[1],
                        'time': b[2]
                    }
                    for b in recent_blocks
                ]
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    
    @app.route('/api/network/clear-logs', methods=['DELETE'])
    def clear_logs():
        """Clear old network logs"""
        try:
            days = request.args.get('days', 30, type=int)
            
            conn = sqlite3.connect(NETWORK_DB)
            cursor = conn.cursor()
            
            cursor.execute('''
                DELETE FROM network_logs 
                WHERE timestamp < datetime('now', '-' || ? || ' days')
            ''', (days,))
            
            deleted_count = cursor.rowcount
            conn.commit()
            conn.close()
            
            return jsonify({
                'status': 'success',
                'message': f'Deleted {deleted_count} old log entries',
                'deleted_count': deleted_count
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    
    print("[+] Network monitoring routes added successfully")