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