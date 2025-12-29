# SecuScan - Automated Security Scanner

SecuScan is an automated vulnerability scanning system that monitors email for scan requests and performs security assessments of web applications.

## Features

- **Email-Based Automation**: Monitors Gmail for scan requests
- **Automated Scanning**: Triggers scans automatically when requests are received
- **Security Checks**:
  - HTTP Security Headers Analysis
  - SSL/TLS Certificate Validation
  - Common Vulnerability Detection
  - Input Validation Testing
- **Reporting**: Generates detailed vulnerability reports
- **Email Notifications**: Sends status updates and results via email

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/SecuScan.git
cd SecuScan
```

2. Install required packages:
```bash
pip install pywin32 requests psutil
```

3. Configure Gmail:
- Enable 2-Factor Authentication
- Generate App Password:
  1. Go to Google Account Settings
  2. Security → App Passwords
  3. Select 'Mail' and 'Windows Computer'
  4. Copy the generated password

4. Update configuration:
Create `config.json` in the root directory:
```json
{
    "email": {
        "imap_server": "imap.gmail.com",
        "email": "your.email@gmail.com",
        "password": "your-app-password",
        "allowed_senders": [
            "trusted.email@example.com"
        ]
    },
    "monitoring": {
        "check_interval": 300,
        "allowed_domains": [
            "localhost",
            "127.0.0.1"
        ],
        "scan_timeout": 3600,
        "max_concurrent_scans": 3
    }
}
```

## Directory Structure

## Automated Scanning & Notifications

### Email Notification Setup

1. Configure email settings in `config.json`:
```

## Running the Scanner

### Method 1: Direct Scanning

1. Start the SecuScan service:
```bash
python scanner/automation/windows_service.py start
```

2. Send a scan request via email:
   - From: Your registered email
   - To: mpranjal0718@gmail.com
   - Subject: "Scan Request http://your-target-url"
   - Body: "Please scan this target"

3. Monitor scan progress:
   - Check reports folder: `C:\SecuScan\reports`
   - View service logs: `C:\SecuScan\logs\service.log`

### Method 2: Manual Testing

1. Navigate to the scanner directory:
```bash
cd C:\Users\HP\scanner\automation
```

2. Run the email monitor directly:
```bash
python email_monitor.py
```

3. Send a test scan request and monitor the console output.

### Viewing Scan Results

1. Access reports in the default directory:
```bash
dir C:\SecuScan\reports
```

2. View the latest report:
```bash
type C:\SecuScan\reports\scan_report_[timestamp].txt
```

### Common Scan Commands

```bash
# Start the scanner service
python scanner\automation\windows_service.py start

# Stop the scanner service
python scanner\automation\windows_service.py stop

# Restart the scanner service
python scanner\automation\windows_service.py restart

# Check service status
sc query SecuScanService
```

### Troubleshooting Scans

1. If scan reports are not generating:
   - Verify the reports directory exists: `C:\SecuScan\reports`
   - Check directory permissions
   - Review service logs for errors

2. If email monitoring isn't working:
   - Verify email credentials in `config.json`
   - Check IMAP connection
   - Ensure allowed senders are configured

3. If service won't start:
   - Run Command Prompt as Administrator
   - Check for conflicting services
   - Verify all dependencies are installed