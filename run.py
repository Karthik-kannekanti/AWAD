import os
import sys
import subprocess
import time
import webbrowser
from threading import Thread

def start_waf():
    """Start the WAF application"""
    print("Starting WAF application on port 5000...")
    os.environ['PORT'] = '5000'
    subprocess.run([sys.executable, 'app/app.py'], cwd=os.path.dirname(os.path.abspath(__file__)))

def start_dashboard():
    """Start the dashboard application"""
    print("Starting dashboard application on port 5001...")
    os.environ['DASHBOARD_PORT'] = '5001'
    subprocess.run([sys.executable, 'app/dashboard_app.py'], cwd=os.path.dirname(os.path.abspath(__file__)))

def open_browser():
    """Open browser tabs for the applications after a short delay"""
    time.sleep(3)  # Give the servers time to start
    print("Opening applications in browser...")
    webbrowser.open('http://localhost:5000/waf-analytics')
    time.sleep(1)
    webbrowser.open('http://localhost:5001')

if __name__ == '__main__':
    print("=" * 60)
    print("Autonomous WAF Demo with Real-Time Analytics and Attack Simulation")
    print("=" * 60)
    print("Starting applications...")
    
    # Start browser opener thread
    browser_thread = Thread(target=open_browser)
    browser_thread.daemon = True
    browser_thread.start()
    
    # Ask user which application to start
    print("\nWhich application would you like to start?")
    print("1. WAF Application (port 5000)")
    print("2. Dashboard Application (port 5001)")
    print("3. Both Applications (recommended)")
    
    choice = input("\nEnter your choice (1-3) [default: 3]: ").strip() or "3"
    
    if choice == "1":
        start_waf()
    elif choice == "2":
        start_dashboard()
    else:
        print("\nStarting both applications in separate terminals...")
        print("Please open two separate terminals and run the following commands:")
        print("\nTerminal 1:")
        print(f"python app/app.py")
        print("\nTerminal 2:")
        print(f"python app/dashboard_app.py")
        
        # Try to start both if possible
        try:
            # On Windows, try to start both applications in separate windows
            if os.name == 'nt':
                subprocess.Popen([sys.executable, 'app/app.py'], 
                                 creationflags=subprocess.CREATE_NEW_CONSOLE,
                                 cwd=os.path.dirname(os.path.abspath(__file__)))
                time.sleep(1)
                subprocess.Popen([sys.executable, 'app/dashboard_app.py'], 
                                 creationflags=subprocess.CREATE_NEW_CONSOLE,
                                 cwd=os.path.dirname(os.path.abspath(__file__)))
            else:
                print("Unable to automatically start both applications in separate terminals.")
                print("Please manually start each application in separate terminals.")
        except Exception as e:
            print(f"Error starting applications: {e}")
            print("Please manually start each application in separate terminals.")
