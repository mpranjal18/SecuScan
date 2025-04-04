import subprocess
import time
import logging
import os

def start_services():
    # Start the email monitor
    email_monitor_process = subprocess.Popen([
        'python', 'scanner/automation/email_monitor.py'
    ])
    
    # Start the API service
    api_service_process = subprocess.Popen([
        'python', 'scanner/automation/api.py'
    ])
    
    logging.info(f"Started email monitor (PID: {email_monitor_process.pid})")
    logging.info(f"Started API service (PID: {api_service_process.pid})")
    
    # Keep the process running
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("Shutting down services...")

if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    start_services() 