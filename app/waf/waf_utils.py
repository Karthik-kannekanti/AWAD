import os
import sqlite3
import json

# Database file path
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'waf.db')

def create_database():
    """Create the SQLite database and tables if they don't exist"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create requests table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip TEXT NOT NULL,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            payload TEXT,
            is_blocked INTEGER NOT NULL,
            attack_type TEXT,
            is_anomaly INTEGER NOT NULL,
            user_agent TEXT,
            feedback INTEGER
        )
    ''')
    
    # Create index on timestamp for faster queries
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON requests (timestamp)')
    
    conn.commit()
    conn.close()

def get_db_connection():
    """Get a connection to the SQLite database"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def format_log_entry(log):
    """Format a log entry for display"""
    # Parse JSON payload if it's a string
    if isinstance(log.get('payload'), str):
        try:
            log['payload'] = json.loads(log['payload'])
        except:
            pass
    
    # Format timestamp
    timestamp = log.get('timestamp', '')
    
    # Format attack type
    attack_type = log.get('attack_type', 'none')
    if attack_type == 'none' or attack_type is None:
        attack_type = 'None'
    else:
        attack_type = attack_type.replace('_', ' ').title()
    
    return {
        'id': log.get('id'),
        'timestamp': timestamp,
        'ip': log.get('ip', ''),
        'method': log.get('method', ''),
        'path': log.get('path', ''),
        'payload': log.get('payload', ''),
        'is_blocked': bool(log.get('is_blocked', 0)),
        'attack_type': attack_type,
        'is_anomaly': bool(log.get('is_anomaly', 0)),
        'user_agent': log.get('user_agent', ''),
        'feedback': log.get('feedback')
    }

def get_attack_color(attack_type):
    """Get a color for an attack type for UI display"""
    colors = {
        'sql_injection': 'danger',
        'xss': 'warning',
        'path_traversal': 'info',
        'command_injection': 'dark',
        'lfi': 'secondary',
        'none': 'success'
    }
    return colors.get(attack_type, 'primary')

def truncate_string(s, max_length=50):
    """Truncate a string to a maximum length"""
    if not s:
        return ''
    if len(s) <= max_length:
        return s
    return s[:max_length] + '...'
