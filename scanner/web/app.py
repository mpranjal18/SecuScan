from flask import Flask, request, render_template, jsonify, send_file
from flask_cors import CORS
import os
import sys
from datetime import datetime
import matplotlib.pyplot as plt
import io
import base64
import urllib3
import logging
import ssl
import socket
import time

# Add project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if project_root not in sys.path:
    sys.path.append(project_root)

from scanner.core.scanner import SecurityScanner
from scanner.report.generator import ReportGenerator

# Disable SSL warnings for outgoing requests (not for our server)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
# Enable CORS for all routes with more permissive settings for local network
CORS(app, resources={
    r"/*": {
        "origins": ["*"],
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True,
        "expose_headers": ["Content-Disposition"]
    }
})

def get_local_ip():
    """Get the local IP address of the machine"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        logger.error(f"Error getting local IP: {str(e)}")
        return "0.0.0.0"

def check_network_connectivity():
    """Check if the server is accessible from the network"""
    try:
        # Try to create a test socket
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.settimeout(5)  # 5 second timeout
        test_socket.bind(('0.0.0.0', 8080))
        test_socket.close()
        return True
    except Exception as e:
        logger.error(f"Network connectivity check failed: {str(e)}")
        return False

def create_ssl_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert_path = os.path.join(os.path.dirname(__file__), 'cert.pem')
    key_path = os.path.join(os.path.dirname(__file__), 'key.pem')
    
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        # Generate self-signed certificate if not exists
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        import datetime

        # Generate key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Generate certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecuScan Development"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        ).sign(private_key, hashes.SHA256())

        # Write certificate and private key to files
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

    context.load_cert_chain(cert_path, key_path)
    return context

def generate_risk_charts(vulnerabilities):
    # Count vulnerabilities by risk level
    risk_counts = {'high': 0, 'medium': 0, 'low': 0}
    for vuln in vulnerabilities:
        risk_level = vuln['risk_level'].lower()
        if risk_level in risk_counts:
            risk_counts[risk_level] += 1

    # Create pie chart
    plt.figure(figsize=(8, 6))
    colors = ['red', 'orange', 'yellow']
    plt.pie(
        risk_counts.values(),
        labels=risk_counts.keys(),
        colors=colors,
        autopct='%1.1f%%'
    )
    plt.title('Vulnerabilities by Risk Level')
    
    # Save to base64 string
    img_stream = io.BytesIO()
    plt.savefig(img_stream, format='png')
    plt.close()
    img_stream.seek(0)
    pie_chart = base64.b64encode(img_stream.read()).decode()

    # Create bar chart
    plt.figure(figsize=(10, 6))
    plt.bar(risk_counts.keys(), risk_counts.values(), color=colors)
    plt.title('Number of Vulnerabilities by Risk Level')
    plt.ylabel('Number of Vulnerabilities')
    
    # Save to base64 string
    img_stream = io.BytesIO()
    plt.savefig(img_stream, format='png')
    plt.close()
    img_stream.seek(0)
    bar_chart = base64.b64encode(img_stream.read()).decode()

    return pie_chart, bar_chart

def validate_url(url):
    if not url:
        return False, "URL is required"
    return True, None

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        mode = data.get('mode', 'passive')

        # Validate URL
        is_valid, error = validate_url(url)
        if not is_valid:
            return jsonify({"error": error}), 400

        logger.info(f"Starting scan of {url} in {mode} mode")
        scanner = SecurityScanner(mode=mode)
        
        # Run the scan
        results = scanner.scan(url)
        
        # Check for errors
        if "error" in results:
            return jsonify({"error": results["error"]}), 400

        # Get vulnerability counts
        summary = results.get("summary", {})
        high_risk = summary.get("high", 0)
        medium_risk = summary.get("medium", 0)
        low_risk = summary.get("low", 0)
        total = summary.get("total", 0)

        # Format vulnerabilities by risk level
        vulnerabilities_by_risk = {
            "high": [],
            "medium": [],
            "low": []
        }

        for vuln in results.get("vulnerabilities", []):
            risk_level = vuln.get("risk_level", "").lower()
            # Use ML-adjusted risk if available
            if "ml_adjusted_risk" in vuln:
                risk_level = vuln.get("ml_adjusted_risk", risk_level).lower()
            
            if risk_level in vulnerabilities_by_risk:
                vuln_data = {
                    "name": vuln.get("name", "Unknown"),
                    "description": vuln.get("description", "No description"),
                    "evidence": vuln.get("evidence", "No evidence"),
                    "fix_recommendation": vuln.get("fix_recommendation", "No recommendation")
                }
                # Add ML insights if available
                if "ml_insights" in vuln:
                    vuln_data["ml_insights"] = vuln.get("ml_insights")
                if "ml_anomaly_detected" in vuln:
                    vuln_data["ml_anomaly_detected"] = vuln.get("ml_anomaly_detected")
                    vuln_data["ml_anomaly_score"] = vuln.get("ml_anomaly_score")
                vulnerabilities_by_risk[risk_level].append(vuln_data)

        response = {
            "success": True,
            "summary": {
                "total": total,
                "high_risk": high_risk,
                "medium_risk": medium_risk,
                "low_risk": low_risk
            },
            "vulnerabilities": vulnerabilities_by_risk,
            "message": f"Scan completed. Found {total} vulnerabilities ({high_risk} high, {medium_risk} medium, {low_risk} low risk)"
        }
        
        # Add ML insights if available
        if "ml_insights" in results:
            response["ml_insights"] = results["ml_insights"]

        logger.info(f"Scan completed successfully: {response['message']}")
        return jsonify(response)

    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500

@app.route('/download_report', methods=['POST'])
def download_report():
    try:
        data = request.json
        vulnerabilities = data.get('vulnerabilities', [])
        url = data.get('url', 'Unknown')
        
        report_gen = ReportGenerator(format='pdf')
        report_file = report_gen.generate(vulnerabilities, url)
        
        # Send file and then delete it
        response = send_file(
            report_file,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        )
        
        @response.call_on_close
        def cleanup():
            try:
                if os.path.exists(report_file):
                    os.remove(report_file)
            except Exception as e:
                print(f"Error cleaning up report file: {str(e)}")
        
        return response
        
    except Exception as e:
        print(f"Error generating report: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "server_ip": get_local_ip()
    })

def check_port_availability(port):
    """Check if the port is available"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('0.0.0.0', port))
            return True
    except socket.error:
        return False

if __name__ == '__main__':
    # Check if port is available
    if not check_port_availability(8080):
        logger.error("Port 8080 is already in use!")
        logger.info("Please try these steps:")
        logger.info("1. Close any other instances of the server")
        logger.info("2. Wait a few seconds and try again")
        logger.info("3. If the problem persists, restart your computer")
        sys.exit(1)

    # Check network connectivity before starting
    if not check_network_connectivity():
        logger.error("Network connectivity check failed. Please check your firewall settings.")
        sys.exit(1)

    ssl_context = create_ssl_context()
    local_ip = get_local_ip()
    
    # Log detailed network information
    logger.info("=" * 50)
    logger.info("Starting SecuScan Server")
    logger.info("=" * 50)
    logger.info(f"Server IP: {local_ip}")
    logger.info("Port: 8080")
    logger.info("Protocol: HTTPS")
    logger.info("=" * 50)
    logger.info("Make sure your firewall allows incoming connections on port 8080")
    logger.info("=" * 50)
    
    # Start the server with increased timeout
    app.run(
        host='0.0.0.0',
        port=8080,
        ssl_context=ssl_context,
        debug=False,
        threaded=True
    ) 