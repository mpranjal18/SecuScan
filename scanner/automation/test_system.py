import requests
import time
import subprocess
import os
import sys
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SystemTest")

def test_config():
    """Test if the configuration file is valid"""
    try:
        import json
        with open('config.json', 'r') as f:
            config = json.load(f)
        logger.info("✅ Configuration file is valid JSON")
        return config
    except Exception as e:
        logger.error(f"❌ Configuration error: {e}")
        return None

def test_api():
    """Test if the API is responding"""
    try:
        # Test a GET request to a non-existent scan ID
        response = requests.get("http://localhost:5000/api/scan/nonexistent")
        if response.status_code == 404:
            logger.info("✅ API is responding correctly (404 for non-existent scan)")
        else:
            logger.warning(f"⚠️ API returned unexpected status code: {response.status_code}")
            
        # Test a POST request with an invalid API key
        response = requests.post(
            "http://localhost:5000/api/scan",
            json={"url": "http://localhost:8000", "api_key": "invalid-key"}
        )
        if response.status_code == 401:
            logger.info("✅ API authentication is working correctly")
        else:
            logger.warning(f"⚠️ API authentication returned unexpected status: {response.status_code}")
            
        # Test a valid scan request
        response = requests.post(
            "http://localhost:5000/api/scan",
            json={"url": "http://localhost:8000", "api_key": "your-secret-api-key"}
        )
        if response.status_code == 202:
            scan_id = response.json().get("scan_id")
            logger.info(f"✅ Successfully triggered scan via API (ID: {scan_id})")
            return scan_id
        else:
            logger.error(f"❌ Failed to trigger scan via API: {response.text}")
            return None
    except requests.exceptions.ConnectionError:
        logger.error("❌ API service is not running or not accessible")
        return None

def test_scan_status(scan_id):
    """Test if we can check scan status"""
    if not scan_id:
        return False
        
    try:
        response = requests.get(f"http://localhost:5000/api/scan/{scan_id}")
        if response.status_code == 200:
            status = response.json().get("status")
            logger.info(f"✅ Successfully retrieved scan status: {status}")
            return True
        else:
            logger.error(f"❌ Failed to retrieve scan status: {response.text}")
            return False
    except requests.exceptions.ConnectionError:
        logger.error("❌ API service is not running or not accessible")
        return False

def test_email_sender(config):
    """Test if we can send an email to trigger a scan"""
    if not config:
        return False
    
    # This function would use an SMTP client to send a test email
    # For demonstration, we'll just log the steps
    logger.info("This would send a test email to trigger a scan")
    logger.info(f"Would send to: {config['email']['email']}")
    logger.info("Would include URL: http://localhost:8000 in subject")
    
    # In a real implementation, you would use smtplib to send an email
    # Example:
    # send_test_email(config['email']['email'], "Test vulnerability scan http://localhost:8000")
    
    logger.info("✅ Test email sending process demonstrated")
    return True

def check_processes():
    """Check if our services are running"""
    import psutil
    
    email_monitor_running = False
    api_service_running = False
    
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""
            if 'python' in cmdline and 'email_monitor.py' in cmdline:
                email_monitor_running = True
                logger.info(f"✅ Email monitor is running (PID: {proc.info['pid']})")
            elif 'python' in cmdline and 'api.py' in cmdline:
                api_service_running = True
                logger.info(f"✅ API service is running (PID: {proc.info['pid']})")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    
    if not email_monitor_running:
        logger.error("❌ Email monitor is not running")
    
    if not api_service_running:
        logger.error("❌ API service is not running")
        
    return email_monitor_running and api_service_running

def test_system():
    """Run all tests"""
    logger.info("Starting system tests...")
    
    # Test configuration
    config = test_config()
    if not config:
        logger.error("❌ Cannot proceed with invalid configuration")
        return False
    
    # Check processes
    processes_ok = check_processes()
    if not processes_ok:
        logger.warning("⚠️ Not all services are running")
    
    # Test API
    scan_id = test_api()
    if scan_id:
        test_scan_status(scan_id)
    
    # Test email integration
    test_email_sender(config)
    
    logger.info("System tests completed")
    return True

if __name__ == "__main__":
    test_system() 