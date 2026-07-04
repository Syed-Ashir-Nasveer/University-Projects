# config.py 
"""
config.py
=========
Configuration file for Security Scanner
All settings and configurations in one place

Author: [Your Name]
Date: December 2024
"""

# ============================================================================
# ZAP Configuration
# ============================================================================
ZAP_CONFIG = {
    'api_key': 'kni1il6oqkr5t7e2em3g0papvk',    # ZAP API key (default: ndke8q5tkgsrp4mh1sf00l8nv0)
    'proxy_url': 'http://127.0.0.1:8080',      # ZAP proxy URL
    'proxy_host': '127.0.0.1',                  # ZAP proxy host
    'proxy_port': 8080,                         # ZAP proxy port
    'timeout': 300,                             # Request timeout in seconds
    'max_depth': 5,                             # Maximum crawling depth
    'thread_count': 2                           # Number of threads for scanning
}

# ============================================================================
# Database Configuration
# ============================================================================
DATABASE_CONFIG = {
    'db_name': 'scan_results.db',              # SQLite database filename
    'scanner_db': 'scanner.db',                 # Scanner database (legacy support)
    'network_db': 'network_monitor.db',        # Network monitoring database
    'backup_enabled': True,                     # Enable automatic backups
    'backup_interval': 24,                      # Backup interval in hours
    'backup_location': 'backups/'               # Backup folder location
}

# Legacy support
DB_CONFIG = DATABASE_CONFIG

# ============================================================================
# Scan Types Configuration
# ============================================================================
SCAN_TYPES = {
    'quick': {
        'name': 'Quick Scan',
        'duration': '5-10 minutes',
        'description': 'Fast scan with spider and passive checks',
        'includes': ['Spider', 'Passive Scan'],
        'active_scan': False
    },
    'standard': {
        'name': 'Standard Scan',
        'duration': '15-30 minutes',
        'description': 'Comprehensive scan with active testing',
        'includes': ['Spider', 'Passive Scan', 'Active Scan'],
        'active_scan': True
    },
    'deep': {
        'name': 'Deep Scan',
        'duration': '1-2 hours',
        'description': 'Thorough scan with all security checks',
        'includes': ['Spider', 'Passive Scan', 'Active Scan', 'Full Policy'],
        'active_scan': True
    }
}

# ============================================================================
# Report Configuration
# ============================================================================
REPORT_CONFIG = {
    'output_dir': 'reports/',                   # Report output directory
    'formats': ['html', 'pdf', 'json', 'csv', 'docx', 'xlsx'],  # Available formats
    'auto_cleanup': True,                       # Auto delete old reports
    'cleanup_days': 30,                         # Keep reports for X days
    'max_report_age_days': 30,                  # Legacy support
    'template_style': 'vip',                    # Report template (vip/standard/minimal)
    'include_screenshots': False,               # Include screenshots in reports
    'max_report_size': 50                       # Max report size in MB
}

# ============================================================================
# Server Configuration
# ============================================================================
SERVER_CONFIG = {
    'host': '0.0.0.0',                         # Server host (0.0.0.0 for all interfaces)
    'port': 5000,                               # Server port
    'debug': True,                              # Debug mode (set False in production)
    'threaded': True,                           # Multi-threading support
    'max_connections': 100                      # Maximum concurrent connections
}

# ============================================================================
# Email Configuration (Optional)
# ============================================================================
EMAIL_CONFIG = {
    'enabled': False,                           # Enable email notifications
    'smtp_server': 'smtp.gmail.com',           # SMTP server
    'smtp_port': 587,                           # SMTP port
    'sender_email': 'scanner@company.com',     # Sender email
    'sender_password': 'your_password',         # Email password
    'use_tls': True,                            # Use TLS encryption
    'recipients': []                            # List of recipient emails
}

# ============================================================================
# Logging Configuration
# ============================================================================
LOGGING_CONFIG = {
    'enabled': True,                            # Enable logging
    'log_file': 'scanner.log',                 # Log file name
    'log_level': 'INFO',                        # Log level (DEBUG/INFO/WARNING/ERROR)
    'max_log_size': 10,                         # Max log file size in MB
    'backup_count': 5                           # Number of backup log files
}

# ============================================================================
# Security Configuration
# ============================================================================
SECURITY_CONFIG = {
    'allowed_domains': [],                      # Whitelist of allowed domains (empty = all)
    'blocked_domains': [],                      # Blacklist of blocked domains
    'require_auth': False,                      # Require authentication for web interface
    'api_key_required': False,                  # Require API key for API endpoints
    'rate_limit': 100,                          # Max requests per hour per IP
    'rate_limit_requests': 100,                 # Legacy support (per minute)
    'session_timeout': 3600,                    # Session timeout in seconds
    'max_scan_threads': 5                       # Maximum scan threads
}

# ============================================================================
# UI Configuration
# ============================================================================
UI_CONFIG = {
    'theme': 'dark',                            # UI theme (dark/light)
    'language': 'en',                           # Interface language
    'date_format': '%Y-%m-%d %H:%M:%S',        # Date display format
    'results_per_page': 20,                     # Results per page in listings
    'auto_refresh': True,                       # Auto refresh scan status
    'refresh_interval': 5                       # Refresh interval in seconds
}

# ============================================================================
# Test Sites (Safe for Scanning)
# ============================================================================
TEST_SITES = [
    'http://testphp.vulnweb.com',
    'http://testhtml5.vulnweb.com',
    'http://testasp.vulnweb.com',
    'http://testaspnet.vulnweb.com'
]

# ============================================================================
# Vulnerability Severity Colors
# ============================================================================
SEVERITY_COLORS = {
    'High': '#e74c3c',                          # Red
    'Medium': '#f39c12',                        # Orange
    'Low': '#3498db',                           # Blue
    'Informational': '#95a5a6'                  # Gray
}

# ============================================================================
# Report Templates
# ============================================================================
REPORT_TEMPLATES = {
    'html': {
        'header_color': '#667eea',
        'accent_color': '#764ba2',
        'font_family': 'Segoe UI, sans-serif'
    },
    'pdf': {
        'page_size': 'A4',
        'margin': 20,
        'font_size': 11
    }
}

# ============================================================================
# Feature Flags
# ============================================================================
FEATURES = {
    'enable_api': True,                         # Enable REST API
    'enable_web_ui': True,                      # Enable web interface
    'enable_cli': True,                         # Enable command-line interface
    'enable_email_reports': False,              # Enable email reports
    'enable_scheduled_scans': False,            # Enable scheduled scans
    'enable_webhooks': False,                   # Enable webhook notifications
    'enable_export': True                       # Enable data export
}

# ============================================================================
# Advanced Settings
# ============================================================================
ADVANCED_CONFIG = {
    'max_scan_time': 7200,                      # Max scan time in seconds (2 hours)
    'concurrent_scans': 3,                      # Max concurrent scans
    'cache_enabled': True,                      # Enable result caching
    'cache_timeout': 3600,                      # Cache timeout in seconds
    'compression_enabled': True,                # Enable response compression
    'debug_mode': False                         # Advanced debug mode
}

# ============================================================================
# Custom User Settings (Can be modified by users)
# ============================================================================
USER_SETTINGS = {
    'default_scan_type': 'quick',               # Default scan type
    'auto_generate_reports': True,              # Auto-generate reports after scan
    'notification_enabled': False,              # Enable notifications
    'save_scan_history': True                   # Save scan history
}


# ============================================================================
# Helper Functions
# ============================================================================

def get_config(section, key=None):
    """
    Get configuration value
    
    Args:
        section (str): Configuration section name
        key (str): Configuration key (optional)
        
    Returns:
        dict or value: Configuration section or specific value
    """
    config_sections = {
        'zap': ZAP_CONFIG,
        'database': DATABASE_CONFIG,
        'server': SERVER_CONFIG,
        'email': EMAIL_CONFIG,
        'report': REPORT_CONFIG,
        'security': SECURITY_CONFIG
    }
    
    if section not in config_sections:
        return None
    
    if key:
        return config_sections[section].get(key)
    
    return config_sections[section]


def validate_config():
    """Validate configuration settings"""
    errors = []
    
    # Validate ZAP config
    if not ZAP_CONFIG['proxy_url'].startswith('http'):
        errors.append("Invalid ZAP proxy URL")
    
    # Validate server config
    if not (1 <= SERVER_CONFIG['port'] <= 65535):
        errors.append("Invalid server port")
    
    # Validate report config
    if not REPORT_CONFIG['output_dir'].endswith('/'):
        REPORT_CONFIG['output_dir'] += '/'
    
    return errors


# Run validation on import
_validation_errors = validate_config()
if _validation_errors:
    print("[!] Configuration validation errors:")
    for error in _validation_errors:
        print(f"    - {error}")
