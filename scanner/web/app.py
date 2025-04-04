from flask import Flask, request, render_template, jsonify, send_file
import os
import sys
from datetime import datetime
import matplotlib.pyplot as plt
import io
import base64
import urllib3
import logging

# Add project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if project_root not in sys.path:
    sys.path.append(project_root)

from scanner.core.scanner import SecurityScanner
from scanner.report.generator import ReportGenerator

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
            if risk_level in vulnerabilities_by_risk:
                vulnerabilities_by_risk[risk_level].append({
                    "name": vuln.get("name", "Unknown"),
                    "description": vuln.get("description", "No description"),
                    "evidence": vuln.get("evidence", "No evidence"),
                    "fix_recommendation": vuln.get("fix_recommendation", "No recommendation")
                })

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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5500, debug=True) 