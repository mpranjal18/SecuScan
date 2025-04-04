import subprocess
import logging
import os
import sys
from datetime import datetime
from email_monitor import EmailMonitor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='secuscan_startup.log',
    filemode='a'
)
logger = logging.getLogger('SecuScanStartup')

def start_services():
    """Start all SecuScan services"""
    try:
        # Start the email monitor in a separate process
        email_monitor_process = subprocess.Popen([
            sys.executable,  # Use current Python interpreter
            'scanner/automation/email_monitor.py'
        ])
        logger.info(f"Started email monitor (PID: {email_monitor_process.pid})")
        
        # Start the API service if needed
        api_service_process = subprocess.Popen([
            sys.executable,
            'scanner/automation/api.py'
        ])
        logger.info(f"Started API service (PID: {api_service_process.pid})")
        
        return email_monitor_process, api_service_process
        
    except Exception as e:
        logger.error(f"Failed to start services: {e}")
        raise

def monitor_processes(processes):
    """Monitor running processes and restart if needed"""
    while True:
        for process in processes:
            if process.poll() is not None:  # Process has terminated
                logger.warning(f"Process {process.pid} terminated unexpectedly. Restarting...")
                # Restart the process
                new_process = subprocess.Popen(process.args)
                processes.remove(process)
                processes.append(new_process)
                logger.info(f"Restarted process with new PID: {new_process.pid}")
        
        # Sleep for a while before next check
        import time
        time.sleep(60)  # Check every minute

if __name__ == "__main__":
    logger.info("Starting SecuScan services...")
    
    try:
        # Start all services
        running_processes = list(start_services())
        
        # Monitor and keep processes running
        monitor_processes(running_processes)
        
    except KeyboardInterrupt:
        logger.info("Received shutdown signal. Stopping services...")
        for process in running_processes:
            process.terminate()
        logger.info("Services stopped")
    except Exception as e:
        logger.error(f"Error in startup script: {e}")
        sys.exit(1) 