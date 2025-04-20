import os
import json
import sqlite3
import datetime
from flask import Flask, render_template, request, jsonify, send_file, Response
from flask_socketio import SocketIO
from flask_cors import CORS
from dotenv import load_dotenv
import io
import csv
import eventlet

# Load environment variables
load_dotenv()

# Import WAF utilities
from waf.waf_utils import get_db_connection, format_log_entry

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'autonomous-waf-dashboard-secret-key')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Global variable to track connected clients
connected_clients = 0

@socketio.on('connect')
def handle_connect():
    """Handle client connection to WebSocket"""
    global connected_clients
    connected_clients += 1
    print(f"Client connected. Total connected clients: {connected_clients}")
    # Send initial stats to the newly connected client
    emit_stats_update()

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection from WebSocket"""
    global connected_clients
    connected_clients -= 1
    print(f"Client disconnected. Total connected clients: {connected_clients}")

def emit_stats_update():
    """Emit updated stats to all connected clients"""
    stats = get_stats_data()
    socketio.emit('stats_update', stats)

def emit_new_log(log_entry):
    """Emit new log entry to all connected clients"""
    socketio.emit('new_log', log_entry)

def emit_feedback_update(log_id, is_attack):
    """Emit feedback update to all connected clients"""
    socketio.emit('feedback_update', {'log_id': log_id, 'is_attack': is_attack})

def emit_logs_cleared():
    """Emit logs cleared event to all connected clients"""
    socketio.emit('logs_cleared', {'timestamp': datetime.datetime.now().isoformat()})

def get_stats_data():
    """Get dashboard statistics data"""
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
    
    # Get requests over time (last 24 hours by hour)
    cursor.execute('''
        SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as hour, 
               COUNT(*) as count,
               SUM(is_blocked) as blocked,
               SUM(is_anomaly) as anomalous
        FROM requests
        WHERE timestamp >= datetime('now', '-1 day')
        GROUP BY hour
        ORDER BY hour
    ''')
    time_series = [dict(zip(['hour', 'count', 'blocked', 'anomalous'], row)) 
                   for row in cursor.fetchall()]
    
    # Get top 10 IPs
    cursor.execute('''
        SELECT ip, COUNT(*) as count
        FROM requests
        GROUP BY ip
        ORDER BY count DESC
        LIMIT 10
    ''')
    top_ips = [dict(zip(['ip', 'count'], row)) for row in cursor.fetchall()]
    
    # Get top 10 paths
    cursor.execute('''
        SELECT path, COUNT(*) as count
        FROM requests
        GROUP BY path
        ORDER BY count DESC
        LIMIT 10
    ''')
    top_paths = [dict(zip(['path', 'count'], row)) for row in cursor.fetchall()]
    
    # Get attack success rate
    cursor.execute('''
        SELECT 
            COUNT(*) as total_attacks,
            SUM(is_blocked) as blocked_attacks
        FROM requests
        WHERE attack_type != 'none' AND attack_type IS NOT NULL
    ''')
    attack_stats = cursor.fetchone()
    if attack_stats and attack_stats[0] > 0:
        total_attacks = attack_stats[0]
        blocked_attacks = attack_stats[1]
        attack_success_rate = (blocked_attacks / total_attacks) * 100
    else:
        attack_success_rate = 0
    
    # Get most recent attacks
    cursor.execute('''
        SELECT id, timestamp, ip, method, path, attack_type
        FROM requests
        WHERE attack_type != 'none' AND attack_type IS NOT NULL
        ORDER BY id DESC
        LIMIT 5
    ''')
    recent_attacks = [dict(zip(['id', 'timestamp', 'ip', 'method', 'path', 'attack_type'], row)) 
                     for row in cursor.fetchall()]
    
    conn.close()
    
    return {
        'total_requests': total_requests,
        'blocked_requests': blocked_requests,
        'anomalous_requests': anomalous_requests,
        'attack_types': attack_types,
        'time_series': time_series,
        'top_ips': top_ips,
        'top_paths': top_paths,
        'attack_success_rate': attack_success_rate,
        'recent_attacks': recent_attacks
    }

@app.route('/')
def dashboard():
    """Render the main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/logs')
def get_logs():
    """API endpoint to get all logs with pagination and filtering"""
    # Get query parameters
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    attack_type = request.args.get('attack_type')
    is_blocked = request.args.get('is_blocked')
    is_anomaly = request.args.get('is_anomaly')
    search = request.args.get('search', '')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    # Calculate offset
    offset = (page - 1) * per_page
    
    # Build query
    query = 'SELECT * FROM requests WHERE 1=1'
    params = []
    
    if attack_type and attack_type != 'all':
        query += ' AND attack_type = ?'
        params.append(attack_type)
    
    if is_blocked is not None:
        query += ' AND is_blocked = ?'
        params.append(int(is_blocked == 'true'))
    
    if is_anomaly is not None:
        query += ' AND is_anomaly = ?'
        params.append(int(is_anomaly == 'true'))
    
    if search:
        if search.startswith('id:'):
            # Search by ID
            try:
                log_id = int(search.split('id:')[1].strip())
                query += ' AND id = ?'
                params.append(log_id)
            except ValueError:
                pass
        else:
            # General search
            query += ' AND (path LIKE ? OR ip LIKE ? OR payload LIKE ? OR user_agent LIKE ?)'
            search_param = f'%{search}%'
            params.extend([search_param, search_param, search_param, search_param])
    
    # Date range filtering
    if start_date:
        query += ' AND timestamp >= ?'
        params.append(start_date)
    
    if end_date:
        query += ' AND timestamp <= ?'
        params.append(end_date)
    
    # Add order and pagination
    query += ' ORDER BY id DESC LIMIT ? OFFSET ?'
    params.extend([per_page, offset])
    
    # Execute query
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(query, params)
    
    # Convert to list of dictionaries
    column_names = [description[0] for description in cursor.description]
    logs = [dict(zip(column_names, row)) for row in cursor.fetchall()]
    
    # Format logs for display
    formatted_logs = []
    for log in logs:
        # Parse JSON payload
        if log.get('payload'):
            try:
                log['payload'] = json.loads(log['payload'])
            except:
                pass
        
        # Format the log entry
        formatted_logs.append(format_log_entry(log))
    
    # Get total count for pagination
    count_query = 'SELECT COUNT(*) FROM requests WHERE 1=1'
    count_params = []
    
    if attack_type and attack_type != 'all':
        count_query += ' AND attack_type = ?'
        count_params.append(attack_type)
    
    if is_blocked is not None:
        count_query += ' AND is_blocked = ?'
        count_params.append(int(is_blocked == 'true'))
    
    if is_anomaly is not None:
        count_query += ' AND is_anomaly = ?'
        count_params.append(int(is_anomaly == 'true'))
    
    if search:
        if search.startswith('id:'):
            # Search by ID
            try:
                log_id = int(search.split('id:')[1].strip())
                count_query += ' AND id = ?'
                count_params.append(log_id)
            except ValueError:
                pass
        else:
            # General search
            count_query += ' AND (path LIKE ? OR ip LIKE ? OR payload LIKE ? OR user_agent LIKE ?)'
            search_param = f'%{search}%'
            count_params.extend([search_param, search_param, search_param, search_param])
    
    # Date range filtering for count
    if start_date:
        count_query += ' AND timestamp >= ?'
        count_params.append(start_date)
    
    if end_date:
        count_query += ' AND timestamp <= ?'
        count_params.append(end_date)
    
    cursor.execute(count_query, count_params)
    total_count = cursor.fetchone()[0]
    
    conn.close()
    
    return jsonify({
        'logs': formatted_logs,
        'total': total_count,
        'page': page,
        'per_page': per_page,
        'total_pages': (total_count + per_page - 1) // per_page
    })

@app.route('/api/stats')
def get_stats():
    """API endpoint to get dashboard statistics"""
    return jsonify(get_stats_data())

@app.route('/api/export-logs')
def export_logs():
    """API endpoint to export logs as CSV"""
    # Get filter parameters
    attack_type = request.args.get('attack_type')
    is_blocked = request.args.get('is_blocked')
    is_anomaly = request.args.get('is_anomaly')
    search = request.args.get('search', '')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    # Build query
    query = 'SELECT * FROM requests WHERE 1=1'
    params = []
    
    if attack_type and attack_type != 'all':
        query += ' AND attack_type = ?'
        params.append(attack_type)
    
    if is_blocked is not None:
        query += ' AND is_blocked = ?'
        params.append(int(is_blocked == 'true'))
    
    if is_anomaly is not None:
        query += ' AND is_anomaly = ?'
        params.append(int(is_anomaly == 'true'))
    
    if search:
        query += ' AND (path LIKE ? OR ip LIKE ? OR payload LIKE ?)'
        search_param = f'%{search}%'
        params.extend([search_param, search_param, search_param])
    
    # Date range filtering
    if start_date:
        query += ' AND timestamp >= ?'
        params.append(start_date)
    
    if end_date:
        query += ' AND timestamp <= ?'
        params.append(end_date)
    
    query += ' ORDER BY id DESC'
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(query, params)
    
    # Get column names
    column_names = [description[0] for description in cursor.description]
    
    # Get all rows
    rows = cursor.fetchall()
    
    conn.close()
    
    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(column_names)
    
    # Write data rows
    for row in rows:
        # Process each row to handle JSON and other formatting
        processed_row = []
        for i, item in enumerate(row):
            if column_names[i] == 'payload' and item:
                # Format JSON payload
                try:
                    processed_item = json.dumps(json.loads(item))
                except:
                    processed_item = item
            elif column_names[i] in ['is_blocked', 'is_anomaly']:
                # Convert booleans to Yes/No
                processed_item = 'Yes' if item else 'No'
            else:
                processed_item = item
            processed_row.append(processed_item)
        writer.writerow(processed_row)
    
    # Prepare response
    output.seek(0)
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment; filename=waf_logs_{timestamp}.csv'
        }
    )

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
    
    # Emit feedback update via WebSocket
    emit_feedback_update(log_id, is_attack)
    
    return jsonify({'success': True})

@app.route('/api/clear-logs', methods=['POST'])
def clear_logs():
    """API endpoint to clear all logs (for testing purposes)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('DELETE FROM requests')
    
    conn.commit()
    conn.close()
    
    # Emit update via WebSocket
    emit_logs_cleared()
    
    return jsonify({'success': True, 'message': 'All logs cleared'})

@app.route('/api/log/<int:log_id>')
def get_log_details(log_id):
    """API endpoint to get details of a specific log entry"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM requests WHERE id = ?', (log_id,))
    log = cursor.fetchone()
    
    conn.close()
    
    if not log:
        return jsonify({'error': 'Log not found'}), 404
    
    # Convert to dictionary
    column_names = [description[0] for description in cursor.description]
    log_dict = dict(zip(column_names, log))
    
    # Parse JSON payload
    if log_dict.get('payload'):
        try:
            log_dict['payload'] = json.loads(log_dict['payload'])
        except:
            pass
    
    # Format the log entry
    formatted_log = format_log_entry(log_dict)
    
    return jsonify(formatted_log)

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors"""
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors"""
    return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('DASHBOARD_PORT', 5001))
    print(f"Starting dashboard application on port {port}...")
    print(f"Access the dashboard at: http://localhost:{port}")
    socketio.run(app, host='0.0.0.0', port=port, debug=True)
