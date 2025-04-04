import imaplib
import sys
import getpass

def test_gmail_connection():
    """Test connection to Gmail with detailed error reporting"""
    print("Gmail Connection Troubleshooter")
    print("===============================")
    
    # Get credentials (either from args or prompt)
    if len(sys.argv) >= 3:
        email = sys.argv[1]
        password = sys.argv[2]
    else:
        email = input("Enter your Gmail address: ")
        password = getpass.getpass("Enter your app password: ")
    
    try:
        print(f"Connecting to imap.gmail.com... ", end="")
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        print("✅ Connected")
        
        print(f"Authenticating with {email}... ", end="")
        mail.login(email, password)
        print("✅ Authentication successful")
        
        print("Listing available mailboxes... ", end="")
        status, mailboxes = mail.list()
        if status == 'OK':
            print(f"✅ Found {len(mailboxes)} mailboxes")
        else:
            print(f"⚠️ Unexpected response: {status}")
        
        print("Selecting INBOX... ", end="")
        status, data = mail.select('INBOX')
        if status == 'OK':
            print(f"✅ Selected INBOX with {data[0].decode()} messages")
        else:
            print(f"⚠️ Failed to select INBOX: {status}")
        
        mail.logout()
        print("✅ Connection test completed successfully")
        return True
    except imaplib.IMAP4.error as e:
        print(f"❌ IMAP error: {e}")
        print("\nPossible solutions:")
        print("1. Verify your password is correct")
        print("2. For Gmail, make sure you're using an App Password if 2FA is enabled")
        print("3. Check that IMAP is enabled in Gmail settings")
        print("   (Gmail → Settings → Forwarding and POP/IMAP → Enable IMAP)")
        print("4. Make sure Google hasn't blocked the login attempt (check your email for alerts)")
        return False
    except Exception as e:
        print(f"❌ Connection error: {e}")
        print("\nPossible solutions:")
        print("1. Check your internet connection")
        print("2. Verify the IMAP server address is correct")
        print("3. Make sure your firewall isn't blocking the connection")
        return False

if __name__ == "__main__":
    test_gmail_connection() 