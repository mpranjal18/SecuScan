import os
import sys
import subprocess
import logging
from pathlib import Path
import requests
import argparse

def install_service(server_ip):
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
        
        # Test connection to the specified server
        print(f"\nTesting connection to server {server_ip}...")
        try:
            response = requests.get(f'https://{server_ip}:5500/health', verify=False)
            print(f"✅ Connection successful: {response.text}")
        except requests.exceptions.RequestException as e:
            print(f"❌ Connection failed: {str(e)}")
            print("Please check if:")
            print("1. The server is running")
            print("2. The IP address is correct")
            print("3. The firewall allows connections on port 5500")
            return False
            
        return True
        
    except Exception as e:
        print(f"❌ Error installing service: {str(e)}")
        return False

if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Install SecuScan service')
    parser.add_argument('172.25.2.105', required=True, help='IP address of the SecuScan server')
    args = parser.parse_args()
    
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
        
    # Install service with the specified server IP
    success = install_service(args.server_ip)
    if not success:
        sys.exit(1) 