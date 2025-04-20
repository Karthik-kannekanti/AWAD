# Autonomous WAF Demo with Real-Time Analytics and Attack Simulation

A modern, interactive Web Application Firewall (WAF) demo system with real-time analytics, attack simulation, and a dashboard for monitoring and analysis.

## Features

- **WAF Functionality**: Protects websites against common web attacks (SQL Injection, XSS, Path Traversal, etc.)
- **Real-Time Analytics**: Live monitoring of traffic, attacks, and anomalies
- **Attack Simulation**: One-click attack testing and custom payload testing
- **Interactive Dashboard**: Comprehensive log review, filtering, and analytics
- **Floating Toolbox**: Draggable and resizable overlay for real-time monitoring

## Setup Instructions

1. Clone this repository:
   ```
   git clone <repository-url>
   cd autonomous-waf-demo
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Start the WAF application:
   ```
   python app/app.py
   ```

4. Start the dashboard application:
   ```
   python app/dashboard_app.py
   ```

5. Access the applications:
   - Main WAF application: http://localhost:5000
   - Dashboard: http://localhost:5001

## Usage

### Main Application
- The main page displays the protected website with a floating analytics toolbox
- Use the toolbox to view real-time stats, simulate attacks, and see recent logs
- Drag and resize the toolbox as needed

### Dashboard
- View detailed logs of all requests
- Filter and search through logs
- View comprehensive analytics
- Mark logs as attacks or false positives

## Warning

This application is for educational and demonstration purposes only. It is not intended for production use or to protect real websites against actual attacks.

## Technical Stack

- **Backend**: Python (Flask), SQLite, scikit-learn
- **Frontend**: HTML, CSS, JavaScript, Bootstrap 5, Chart.js
- **Real-Time Updates**: Flask-SocketIO

## License

This project is for educational purposes only.
