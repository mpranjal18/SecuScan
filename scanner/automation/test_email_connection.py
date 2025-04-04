from email_monitor import EmailMonitor

def test_email_connection():
    monitor = EmailMonitor()
    mail = monitor.connect_email()
    
    if mail:
        print("✅ Successfully connected to email server")
        mail.logout()
        return True
    else:
        print("❌ Failed to connect to email server")
        return False

if __name__ == "__main__":
    test_email_connection() 