import sqlite3
import requests

def populate_vulnerable_puma():
    # Test data for vulnerable Puma
    products = [
        {
            'name': 'Gaming Mouse',
            'description': 'High-performance gaming mouse with RGB lighting',
            'price': 49.99
        },
        {
            'name': 'Mechanical Keyboard',
            'description': 'Cherry MX switches with customizable backlighting',
            'price': 129.99
        },
        {
            'name': 'Gaming Headset',
            'description': '7.1 surround sound with noise-cancelling mic',
            'price': 89.99
        },
        {
            'name': 'Gaming Monitor',
            'description': '27-inch 144Hz display with 1ms response time',
            'price': 299.99
        },
        {
            'name': 'Gaming Chair',
            'description': 'Ergonomic design with lumbar support',
            'price': 199.99
        }
    ]

    print("Adding products to vulnerable Puma...")
    for product in products:
        try:
            response = requests.post(
                'http://localhost:5000/add_product',
                data=product
            )
            if response.status_code == 200:
                print(f"Added {product['name']} successfully")
            else:
                print(f"Failed to add {product['name']}: {response.text}")
        except Exception as e:
            print(f"Error adding {product['name']}: {str(e)}")

def populate_secure_puma():
    # Test data for secure Puma
    products = [
        {
            'name': 'Secure Laptop',
            'description': 'Encrypted storage with secure boot',
            'price': 999.99
        },
        {
            'name': 'Firewall Router',
            'description': 'Enterprise-grade security features',
            'price': 199.99
        },
        {
            'name': 'Security Camera',
            'description': 'Motion detection with encrypted stream',
            'price': 149.99
        },
        {
            'name': 'Smart Lock',
            'description': 'Biometric authentication system',
            'price': 249.99
        },
        {
            'name': 'Password Manager',
            'description': 'Zero-knowledge encryption storage',
            'price': 39.99
        }
    ]

    print("\nAdding products to secure Puma...")
    for product in products:
        try:
            response = requests.post(
                'http://localhost:5001/add_product',
                data=product
            )
            if response.status_code == 200:
                print(f"Added {product['name']} successfully")
            else:
                print(f"Failed to add {product['name']}: {response.text}")
        except Exception as e:
            print(f"Error adding {product['name']}: {str(e)}")

if __name__ == '__main__':
    # Make sure both Puma servers are running first
    populate_vulnerable_puma()
    populate_secure_puma() 