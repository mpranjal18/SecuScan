import os
import sys
import subprocess
import logging
from pathlib import Path

def install_service():
    """Install SecuScan as a Windows service"""
    try:
        # Create necessary directories
        service_dir = "C:\\SecuScan"
        log_dir = os.path.join(service_dir, "logs")
        os.makedirs(service_dir, exist_ok=True)
        os.makedirs(log_dir, exist_ok=True)
        
        # Install required packages
        print("Installing required packages...")
        subprocess.check_call([
            sys.executable, 
            "-m", 
            "pip", 
            "install", 
            "pywin32",
            "psutil"
        ])
        
        print("✅ Packages installed successfully")
        return True
        
    except Exception as e:
        print(f"❌ Error installing service: {str(e)}")
        return False

if __name__ == "__main__":
    # Run as administrator check
    try:
        is_admin = os.getuid() == 0
    except AttributeError:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        
    if not is_admin:
        print("❌ This script must be run as administrator")
        print("Please right-click and select 'Run as administrator'")
        sys.exit(1)
        
    # Install service
    success = install_service()
    if not success:
        sys.exit(1) 