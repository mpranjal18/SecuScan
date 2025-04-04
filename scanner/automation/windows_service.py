import win32serviceutil
import win32service
import win32event
import servicemanager
import socket
import sys
import os
import subprocess
import logging
from pathlib import Path

class SecuScanService(win32serviceutil.ServiceFramework):
    _svc_name_ = "SecuScanService"
    _svc_display_name_ = "SecuScan Vulnerability Scanner"
    _svc_description_ = "Automated vulnerability scanning service with email monitoring"
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.processes = []
        
        # Setup logging
        log_dir = Path("C:/SecuScan/logs")
        log_dir.mkdir(parents=True, exist_ok=True)
        logging.basicConfig(
            filename=log_dir / "service.log",
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('SecuScanService')
    
    def SvcStop(self):
        """Stop the service"""
        self.logger.info('Stopping service...')
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        
        # Terminate all child processes
        for process in self.processes:
            try:
                process.terminate()
            except:
                pass
    
    def SvcDoRun(self):
        """Run the service"""
        self.logger.info('Starting service...')
        try:
            # Start the email monitor
            script_dir = Path(__file__).parent
            monitor_script = script_dir / 'email_monitor.py'
            
            process = subprocess.Popen([
                sys.executable,
                str(monitor_script)
            ])
            self.processes.append(process)
            self.logger.info(f'Started email monitor (PID: {process.pid})')
            
            # Wait for stop event
            win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)
            
        except Exception as e:
            self.logger.error(f'Service error: {e}')
            raise

if __name__ == '__main__':
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(SecuScanService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(SecuScanService) 