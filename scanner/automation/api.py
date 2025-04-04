from flask import Flask, request, jsonify
import subprocess
import logging
import os
import time

app = Flask(__name__)

# Setup logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('ScanAPI')

ACTIVE_SCANS = {}

@app.route('/api/scan', methods=['POST'])
def trigger_scan():
    data = request.json
    
    # Validate request
    if not data or 'url' not in data:
        return jsonify({"error": "URL is required"}), 400
        
    url = data['url']
    mode = data.get('mode', 'active')
    api_key = data.get('api_key', '')
    
    # Validate API key - implement your own authentication logic
    if not validate_api_key(api_key):
        return jsonify({"error": "Invalid API key"}), 401
        
    # Validate URL is allowed
    if not is_url_allowed(url):
        return jsonify({"error": "URL domain not in allowed list"}), 403
    
    # Build scan command
    cmd = [
        'python',
        'scanner/web/app.py',
        '--url', url,
        '--mode', mode,
        '--headless',
        '--report-file', f"reports/scan_{int(time.time())}.json"
    ]
    
    try:
        # Launch scan
        process = subprocess.Popen(cmd)
        scan_id = str(int(time.time()))
        
        # Register scan
        ACTIVE_SCANS[scan_id] = {
            'pid': process.pid,
            'url': url,
            'start_time': time.time(),
            'status': 'running'
        }
        
        return jsonify({
            "scan_id": scan_id,
            "status": "started",
            "url": url
        }), 202
        
    except Exception as e:
        logger.error(f"Failed to start scan: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    if scan_id not in ACTIVE_SCANS:
        return jsonify({"error": "Scan not found"}), 404
        
    scan_info = ACTIVE_SCANS[scan_id]
    
    # Check if process is still running
    import psutil
    try:
        if not psutil.pid_exists(scan_info['pid']):
            scan_info['status'] = 'completed'
    except:
        scan_info['status'] = 'unknown'
        
    return jsonify(scan_info), 200

def validate_api_key(api_key):
    # In production, use environment variables for the API key
    valid_key = os.environ.get('SECUSCAN_API_KEY', 'your-secret-api-key')
    return api_key == valid_key
    
def is_url_allowed(url):
    """Check if URL is for an allowed domain (including localhost)"""
    from urllib.parse import urlparse
    allowed_domains = ['localhost', '127.0.0.1']  # Update with your domains
    
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    # Remove port number if present
    if ':' in domain:
        domain = domain.split(':')[0]
        
    return domain in allowed_domains

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000) 