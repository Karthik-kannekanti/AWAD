import os
import json
import sqlite3
import datetime
from flask import Flask, request, render_template, jsonify, Response, redirect, url_for
from flask_socketio import SocketIO
from flask_cors import CORS
import numpy as np
from sklearn.ensemble import IsolationForest
import requests
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import WAF modules
from waf.waf_core import WAFCore
from waf.waf_utils import create_database, get_db_connection

# Import dashboard WebSocket functions if available
try:
    from dashboard_app import emit_new_log, emit_stats_update, emit_feedback_update, emit_logs_cleared
    dashboard_available = True
    print("Dashboard WebSocket functions imported successfully")
except ImportError:
    dashboard_available = False
    print("Dashboard not available, WebSocket updates will be limited to this app only")

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'autonomous-waf-demo-secret-key')
app.wsgi_app = ProxyFix(app.wsgi_app)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Initialize WAF
waf = WAFCore()

# Create database if it doesn't exist
create_database()

# Target website to protect (configurable)
TARGET_WEBSITE = os.environ.get('TARGET_WEBSITE', 'https://bhanuprakashchintal.vercel.app/')

# Initialize anomaly detection model
model = IsolationForest(contamination=0.1, random_state=42)
model_trained = False

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def proxy(path):
    """
    Main proxy function that intercepts all requests, analyzes them with the WAF,
    and either blocks them or forwards them to the target website.
    """
    global model_trained
    
    # Skip WAF analysis for static files and analytics page
    if path.startswith(('static/', 'waf-analytics')):
        if path == 'waf-analytics':
            return render_template('analytics.html', target_website=TARGET_WEBSITE)
        return app.send_static_file(path.replace('static/', '', 1))
    
    # Extract request details
    client_ip = request.remote_addr
    method = request.method
    url = f"{TARGET_WEBSITE}{path}"
    headers = dict(request.headers)
    params = dict(request.args)
    user_agent = request.headers.get('User-Agent', '')
    
    # For POST/PUT requests, get the body
    body = request.get_data().decode('utf-8') if request.data else ''
    
    # Combine all parameters for WAF analysis
    payload = {
        'params': params,
        'body': body,
        'headers': headers
    }
    
    # WAF analysis
    attack_type, is_blocked = waf.analyze_request(method, path, payload)
    
    # Anomaly detection
    features = waf.extract_features(method, path, payload)
    
    # Add features to training data
    waf.train_anomaly_detection(features)
    
    # Train model when we have enough data
    if len(waf.feature_data) >= 100 and not model_trained:
        try:
            model.fit(waf.feature_data)
            model_trained = True
        except Exception as e:
            print(f"Error training anomaly detection model: {e}")
    
    # Check if request is anomalous
    is_anomaly = waf.is_anomalous(features, model) if model_trained else False
    
    # Log the request
    conn = get_db_connection()
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    cursor.execute('''
        INSERT INTO requests (timestamp, ip, method, path, payload, is_blocked, attack_type, is_anomaly, user_agent)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, client_ip, method, path, json.dumps(payload), is_blocked, attack_type, is_anomaly, user_agent))
    
    request_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    # Create log entry object
    log_entry = {
        'id': request_id,
        'timestamp': timestamp,
        'ip': client_ip,
        'method': method,
        'path': path,
        'is_blocked': is_blocked,
        'attack_type': attack_type,
        'is_anomaly': is_anomaly,
        'user_agent': user_agent
    }
    
    # Emit the new log entry via WebSocket for this app
    socketio.emit('new_log', log_entry)
    
    # Also emit to dashboard if available
    if dashboard_available:
        try:
            emit_new_log(log_entry)
            print(f"Log entry {request_id} sent to dashboard")
        except Exception as e:
            print(f"Error sending log to dashboard: {e}")
    
    # Update stats
    update_stats()
    
    # If blocked, return a block page
    if is_blocked:
        return render_template('blocked.html', 
                               attack_type=attack_type, 
                               request_details={
                                   'method': method,
                                   'path': path,
                                   'ip': client_ip,
                                   'timestamp': timestamp
                               })
    
    # If not blocked, proxy the request to the target website
    try:
        # Forward the request to the target website
        if method == 'GET':
            resp = requests.get(url, headers=headers, params=params, timeout=10)
        elif method == 'POST':
            resp = requests.post(url, headers=headers, data=request.data, params=params, timeout=10)
        elif method == 'PUT':
            resp = requests.put(url, headers=headers, data=request.data, params=params, timeout=10)
        elif method == 'DELETE':
            resp = requests.delete(url, headers=headers, params=params, timeout=10)
        else:
            # Default to GET for other methods
            resp = requests.get(url, headers=headers, params=params, timeout=10)
        
        # Return the response from the target website
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in resp.raw.headers.items()
                  if name.lower() not in excluded_headers]
        
        response = Response(resp.content, resp.status_code, headers)
        return response
    
    except Exception as e:
        return jsonify({'error': str(e), 'message': 'Error connecting to target website'}), 500

@app.route('/waf-analytics')
def analytics_page():
    """Render the analytics page with the floating toolbox"""
    return render_template('analytics.html', target_website=TARGET_WEBSITE)

@app.route('/api/stats')
def get_stats():
    """API endpoint to get current WAF statistics"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get total requests
    cursor.execute('SELECT COUNT(*) FROM requests')
    total_requests = cursor.fetchone()[0]
    
    # Get blocked requests
    cursor.execute('SELECT COUNT(*) FROM requests WHERE is_blocked = 1')
    blocked_requests = cursor.fetchone()[0]
    
    # Get anomalous requests
    cursor.execute('SELECT COUNT(*) FROM requests WHERE is_anomaly = 1')
    anomalous_requests = cursor.fetchone()[0]
    
    # Get attack types distribution
    cursor.execute('''
        SELECT attack_type, COUNT(*) as count 
        FROM requests 
        WHERE attack_type IS NOT NULL AND attack_type != 'none'
        GROUP BY attack_type
    ''')
    attack_types = {row[0]: row[1] for row in cursor.fetchall()}
    
    # Get recent logs (last 10)
    cursor.execute('''
        SELECT id, timestamp, ip, method, path, is_blocked, attack_type, is_anomaly
        FROM requests
        ORDER BY id DESC
        LIMIT 10
    ''')
    recent_logs = [dict(zip(['id', 'timestamp', 'ip', 'method', 'path', 'is_blocked', 'attack_type', 'is_anomaly'], row))
                  for row in cursor.fetchall()]
    
    # Get requests over time (last hour by minute)
    cursor.execute('''
        SELECT strftime('%Y-%m-%d %H:%M:00', timestamp) as minute, 
               COUNT(*) as count,
               SUM(is_blocked) as blocked,
               SUM(is_anomaly) as anomalous
        FROM requests
        WHERE timestamp >= datetime('now', '-1 hour')
        GROUP BY minute
        ORDER BY minute
    ''')
    time_series = [dict(zip(['minute', 'count', 'blocked', 'anomalous'], row)) 
                  for row in cursor.fetchall()]
    
    conn.close()
    
    return jsonify({
        'total_requests': total_requests,
        'blocked_requests': blocked_requests,
        'anomalous_requests': anomalous_requests,
        'attack_types': attack_types,
        'recent_logs': recent_logs,
        'time_series': time_series
    })

@app.route('/api/simulate-attack', methods=['POST'])
def simulate_attack():
    """API endpoint to simulate an attack"""
    data = request.json
    attack_type = data.get('attack_type')
    custom_payload = data.get('custom_payload', '')
    
    # Generate attack payload based on attack type
    if attack_type == 'custom' and custom_payload:
        payload = custom_payload
    else:
        payload = waf.generate_attack_payload(attack_type)
    
    # Analyze the payload directly with the WAF
    path = f"test?payload={payload}"
    
    # Extract request details for logging
    client_ip = request.remote_addr
    method = "GET"
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Create a mock payload for WAF analysis
    mock_payload = {
        'params': {'payload': payload},
        'body': '',
        'headers': {'User-Agent': 'WAF-Attack-Simulator/1.0'}
    }
    
    # Perform WAF analysis directly
    attack_type_detected, is_blocked = waf.analyze_request(method, path, mock_payload)
    
    # Log the simulated attack
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO requests (timestamp, ip, method, path, payload, is_blocked, attack_type, is_anomaly, user_agent)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, client_ip, method, path, json.dumps(mock_payload), is_blocked, attack_type_detected, False, 'WAF-Attack-Simulator/1.0'))
    
    request_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    # Emit the new log entry via WebSocket
    log_entry = {
        'id': request_id,
        'timestamp': timestamp,
        'ip': client_ip,
        'method': method,
        'path': path,
        'is_blocked': is_blocked,
        'attack_type': attack_type_detected,
        'is_anomaly': False
    }
    socketio.emit('new_log', log_entry)
    
    # Update stats
    update_stats()
    
    return jsonify({
        'attack_type': attack_type,
        'payload': payload,
        'was_blocked': is_blocked,
        'detected_as': attack_type_detected,
        'status_code': 200
    })

@app.route('/api/clear-logs', methods=['POST'])
def clear_logs():
    """API endpoint to clear all logs (for testing purposes)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('DELETE FROM requests')
    
    conn.commit()
    conn.close()
    
    # Reset anomaly detection model
    global model_trained
    model_trained = False
    waf.feature_data = []
    
    # Emit logs cleared event via WebSocket for this app
    socketio.emit('logs_cleared', {
        'timestamp': datetime.datetime.now().isoformat(),
        'message': 'All logs cleared'
    })
    
    # Also emit to dashboard if available
    if dashboard_available:
        try:
            emit_logs_cleared()
            print("Logs cleared event sent to dashboard")
        except Exception as e:
            print(f"Error sending logs cleared event to dashboard: {e}")
    
    # Update stats
    update_stats()
    
    return jsonify({'success': True, 'message': 'All logs cleared'})

@app.route('/api/feedback', methods=['POST'])
def submit_feedback():
    """API endpoint to submit feedback on a log entry"""
    data = request.json
    log_id = data.get('log_id')
    is_attack = data.get('is_attack')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE requests
        SET feedback = ?
        WHERE id = ?
    ''', (is_attack, log_id))
    
    conn.commit()
    conn.close()
    
    # Emit feedback update via WebSocket for this app
    socketio.emit('feedback_update', {
        'log_id': log_id,
        'is_attack': is_attack
    })
    
    # Also emit to dashboard if available
    if dashboard_available:
        try:
            emit_feedback_update(log_id, is_attack)
            print(f"Feedback update for log {log_id} sent to dashboard")
        except Exception as e:
            print(f"Error sending feedback to dashboard: {e}")
    
    return jsonify({'success': True})

def update_stats():
    """Update statistics and emit via WebSocket"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get total requests
    cursor.execute('SELECT COUNT(*) FROM requests')
    total_requests = cursor.fetchone()[0]
    
    # Get blocked requests
    cursor.execute('SELECT COUNT(*) FROM requests WHERE is_blocked = 1')
    blocked_requests = cursor.fetchone()[0]
    
    # Get anomalous requests
    cursor.execute('SELECT COUNT(*) FROM requests WHERE is_anomaly = 1')
    anomalous_requests = cursor.fetchone()[0]
    
    # Get attack types distribution
    cursor.execute('''
        SELECT attack_type, COUNT(*) as count 
        FROM requests 
        WHERE attack_type IS NOT NULL AND attack_type != 'none'
        GROUP BY attack_type
    ''')
    attack_types = {row[0]: row[1] for row in cursor.fetchall()}
    
    conn.close()
    
    # Create stats object
    stats = {
        'total_requests': total_requests,
        'blocked_requests': blocked_requests,
        'anomalous_requests': anomalous_requests,
        'attack_types': attack_types
    }
    
    # Emit updated stats via WebSocket for this app
    socketio.emit('stats_update', stats)
    
    # Also emit to dashboard if available
    if dashboard_available:
        try:
            emit_stats_update()
            print("Stats update sent to dashboard")
        except Exception as e:
            print(f"Error sending stats to dashboard: {e}")

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors"""
    return render_template('blocked.html', 
                          attack_type='none', 
                          request_details={
                              'method': request.method,
                              'path': request.path,
                              'ip': request.remote_addr,
                              'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                          }), 404

@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors"""
    return jsonify({'error': str(e), 'message': 'Internal server error'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"Starting WAF application on port {port}...")
    print(f"Target website: {TARGET_WEBSITE}")
    print(f"Access the analytics page at: http://localhost:{port}/waf-analytics")
    socketio.run(app, host='0.0.0.0', port=port, debug=True)
