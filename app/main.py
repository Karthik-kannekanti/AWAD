import os
import json
import sqlite3
import datetime
import io
import csv
from flask import Flask, request, render_template, jsonify, send_file, Response, redirect, url_for
from flask_socketio import SocketIO
from flask_cors import CORS
from dotenv import load_dotenv
import numpy as np
from sklearn.ensemble import IsolationForest
import requests
from werkzeug.middleware.proxy_fix import ProxyFix

from waf.waf_core import WAFCore
from waf.waf_utils import create_database, get_db_connection, format_log_entry

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'autonomous-waf-demo-secret-key')
app.wsgi_app = ProxyFix(app.wsgi_app)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

waf = WAFCore()
create_database()
model = IsolationForest(contamination=0.1, random_state=42)
model_trained = False
TARGET_WEBSITE = os.environ.get('TARGET_WEBSITE', 'https://bhanuprakashchintal.vercel.app/')

connected_clients = 0

@socketio.on('connect')
def handle_connect():
    global connected_clients
    connected_clients += 1
    emit_stats_update()

@socketio.on('disconnect')
def handle_disconnect():
    global connected_clients
    connected_clients -= 1

def emit_stats_update():
    stats = get_stats_data()
    socketio.emit('stats_update', stats)

def emit_new_log(log_entry):
    socketio.emit('new_log', log_entry)

def emit_feedback_update(log_id, is_attack):
    socketio.emit('feedback_update', {'log_id': log_id, 'is_attack': is_attack})

def emit_logs_cleared():
    socketio.emit('logs_cleared', {'timestamp': datetime.datetime.now().isoformat()})

def get_stats_data():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM requests')
    total_requests = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM requests WHERE is_blocked = 1')
    blocked_requests = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM requests WHERE is_anomaly = 1')
    anomalous_requests = cursor.fetchone()[0]
    cursor.execute('''SELECT attack_type, COUNT(*) FROM requests WHERE attack_type IS NOT NULL AND attack_type != 'none' GROUP BY attack_type''')
    attack_types = {row[0]: row[1] for row in cursor.fetchall()}
    cursor.execute('''SELECT strftime('%Y-%m-%d %H:00:00', timestamp), COUNT(*), SUM(is_blocked), SUM(is_anomaly) FROM requests WHERE timestamp >= datetime('now', '-1 day') GROUP BY 1 ORDER BY 1''')
    time_series = [dict(zip(['hour', 'count', 'blocked', 'anomalous'], row)) for row in cursor.fetchall()]
    conn.close()
    return {
        'total_requests': total_requests,
        'blocked_requests': blocked_requests,
        'anomalous_requests': anomalous_requests,
        'attack_types': attack_types,
        'time_series': time_series
    }

@app.route('/')
def home_redirect():
    return redirect(url_for('analytics_page'))

@app.route('/waf-analytics')
def analytics_page():
    return render_template('analytics.html', target_website=TARGET_WEBSITE)

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def proxy(path):
    global model_trained
    if path.startswith(('static/', 'waf-analytics')):
        if path == 'waf-analytics':
            return render_template('analytics.html', target_website=TARGET_WEBSITE)
        return app.send_static_file(path.replace('static/', '', 1))

    client_ip = request.remote_addr
    method = request.method
    url = f"{TARGET_WEBSITE}{path}"
    headers = dict(request.headers)
    params = dict(request.args)
    user_agent = request.headers.get('User-Agent', '')
    body = request.get_data().decode('utf-8') if request.data else ''
    payload = {'params': params, 'body': body, 'headers': headers}
    attack_type, is_blocked = waf.analyze_request(method, path, payload)
    features = waf.extract_features(method, path, payload)
    waf.train_anomaly_detection(features)
    if len(waf.feature_data) >= 100 and not model_trained:
        try:
            model.fit(waf.feature_data)
            model_trained = True
        except Exception as e:
            print(f"Error training model: {e}")
    is_anomaly = waf.is_anomalous(features, model) if model_trained else False
    conn = get_db_connection()
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute('''INSERT INTO requests (timestamp, ip, method, path, payload, is_blocked, attack_type, is_anomaly, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''', (timestamp, client_ip, method, path, json.dumps(payload), is_blocked, attack_type, is_anomaly, user_agent))
    request_id = cursor.lastrowid
    conn.commit()
    conn.close()
    log_entry = {'id': request_id, 'timestamp': timestamp, 'ip': client_ip, 'method': method, 'path': path, 'is_blocked': is_blocked, 'attack_type': attack_type, 'is_anomaly': is_anomaly, 'user_agent': user_agent}
    emit_new_log(log_entry)
    emit_stats_update()
    if is_blocked:
        return render_template('blocked.html', attack_type=attack_type, request_details={'method': method, 'path': path, 'ip': client_ip, 'timestamp': timestamp})
    try:
        resp = requests.request(method, url, headers=headers, data=request.data, params=params, timeout=10)
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded_headers]
        return Response(resp.content, resp.status_code, headers)
    except Exception as e:
        return jsonify({'error': str(e), 'message': 'Error connecting to target website'}), 500

@app.route('/api/logs')
def get_logs():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM requests ORDER BY id DESC LIMIT 50')
    column_names = [description[0] for description in cursor.description]
    logs = [dict(zip(column_names, row)) for row in cursor.fetchall()]
    conn.close()
    for log in logs:
        try:
            log['payload'] = json.loads(log['payload'])
        except:
            pass
    return jsonify({'logs': [format_log_entry(log) for log in logs]})

@app.route('/api/feedback', methods=['POST'])
def submit_feedback():
    data = request.json
    log_id = data.get('log_id')
    is_attack = data.get('is_attack')
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE requests SET feedback = ? WHERE id = ?', (is_attack, log_id))
    conn.commit()
    conn.close()
    emit_feedback_update(log_id, is_attack)
    return jsonify({'success': True})

@app.route('/api/clear-logs', methods=['POST'])
def clear_logs():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM requests')
    conn.commit()
    conn.close()
    global model_trained
    model_trained = False
    waf.feature_data = []
    emit_logs_cleared()
    emit_stats_update()
    return jsonify({'success': True, 'message': 'All logs cleared'})

@app.errorhandler(404)
def page_not_found(e):
    return render_template('blocked.html', attack_type='none', request_details={'method': request.method, 'path': request.path, 'ip': request.remote_addr, 'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': str(e), 'message': 'Internal server error'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=True)
