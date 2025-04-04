from email_monitor import EmailMonitor
import sys
import logging

# Configure logging to stdout for this test
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def test_email_connection_detailed():
    """Test email connection with detailed diagnostics"""
    print("Email Connection Test - Detailed Diagnostics")
    print("===========================================")
    
    try:
        print("1. Loading email monitor...")
        monitor = EmailMonitor()
        print("   ✅ EmailMonitor class initialized")
        
        print(f"2. Loaded configuration:")
        print(f"   Server: {monitor.config['email']['imap_server']}")
        print(f"   Email: {monitor.config['email']['email']}")
        print(f"   Password: {'*' * 8} (masked for security)")
        
        print("3. Attempting connection...")
        mail = monitor.connect_email()
        
        if mail:
            print("   ✅ Successfully connected to email server")
            
            print("4. Checking mailboxes...")
            status, mailboxes = mail.list()
            if status == 'OK':
                print(f"   ✅ Found {len(mailboxes)} mailboxes")
            
            print("5. Testing INBOX access...")
            status, data = mail.select('INBOX')
            if status == 'OK':
                print(f"   ✅ Selected INBOX with {data[0].decode()} messages")
                
                print("6. Searching for a sample message...")
                status, messages = mail.search(None, 'ALL')
                if status == 'OK':
                    if messages[0]:
                        msg_count = len(messages[0].split())
                        print(f"   ✅ Found {msg_count} messages in INBOX")
                    else:
                        print("   ⚠️ INBOX is empty")
            
            print("7. Closing connection...")
            mail.close()
            mail.logout()
            print("   ✅ Successfully closed connection")
            
            print("\n✅ ALL TESTS PASSED - Email connection is working correctly")
            return True
        else:
            print("   ❌ Failed to connect to email server")
            print("\nPossible issues:")
            print("1. Incorrect credentials in config.json")
            print("2. IMAP access not enabled for this account")
            print("3. Gmail security settings blocking access")
            print("4. Network connectivity issues")
            return False
            
    except Exception as e:
        print(f"❌ Error during testing: {e}")
        print("\nStack trace for debugging:")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_email_connection_detailed() 