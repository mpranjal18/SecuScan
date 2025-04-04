from flask import Flask, request, render_template, redirect, url_for
import sqlite3
import os

app = Flask(__name__)

# Vulnerable database setup
def init_db():
    try:
        conn = sqlite3.connect('products.db')
        c = conn.cursor()
        
        # Create products table
        c.execute('''
            CREATE TABLE IF NOT EXISTS products
            (id INTEGER PRIMARY KEY AUTOINCREMENT,
             name TEXT,
             description TEXT,
             price REAL)
        ''')
        
        # Create users table
        c.execute('''
            CREATE TABLE IF NOT EXISTS users
            (id INTEGER PRIMARY KEY,
             username TEXT,
             password TEXT)
        ''')
        
        # Add some initial test data
        c.execute('''
            INSERT INTO products (name, description, price)
            VALUES 
            ('Test Product 1', 'Description 1', 19.99),
            ('Test Product 2', 'Description 2', 29.99)
        ''')
        
        conn.commit()
        print("Database initialized successfully!")  # Debug print
    except Exception as e:
        print(f"Error initializing database: {str(e)}")
    finally:
        conn.close()

# Vulnerable route - SQL Injection
@app.route('/products')
def products():
    search = request.args.get('search', '')
    
    # Vulnerable SQL query
    conn = sqlite3.connect('products.db')
    c = conn.cursor()
    # WARNING: This is intentionally vulnerable to SQL injection
    query = f"SELECT * FROM products WHERE name LIKE '%{search}%'"
    c.execute(query)
    products = c.fetchall()
    conn.close()
    
    # Convert products to dictionaries for template
    product_list = []
    for product in products:
        product_list.append({
            'id': product[0],
            'name': product[1],
            'description': product[2],
            'price': product[3]
        })
    
    return render_template('products.html', products=product_list)

# Vulnerable route - Command Injection
@app.route('/export')
def export_products():
    format = request.args.get('format', 'csv')
    
    # WARNING: This is intentionally vulnerable to command injection
    os.system(f'cat products.db > export.{format}')
    
    return f'Products exported to export.{format}'

# Vulnerable route - Buffer Overflow
@app.route('/subscribe', methods=['POST'])
def subscribe():
    email = request.form.get('email', '')
    
    # Vulnerable to buffer overflow
    try:
        with open('subscribers.txt', 'a') as f:
            f.write(email + '\n')
    except:
        return 'Subscription failed', 500
        
    return 'Subscription successful!'

# Add this route at the beginning of the routes section
@app.route('/')
def home():
    return render_template('home.html')

# Add this route after the init_db function
@app.route('/add_product', methods=['POST'])
def add_product():
    try:
        name = request.form.get('name', '')
        description = request.form.get('description', '')
        price = float(request.form.get('price', 0))  # Convert price to float
        
        # Vulnerable to SQL injection
        conn = sqlite3.connect('products.db')
        c = conn.cursor()
        # Fixed the SQL syntax but kept it vulnerable to injection
        query = f"INSERT INTO products (name, description, price) VALUES ('{name}', '{description}', {price})"
        print(f"Executing query: {query}")  # Debug print
        c.execute(query)
        conn.commit()
        conn.close()
        
        return redirect(url_for('products'))
    except Exception as e:
        print(f"Error adding product: {str(e)}")  # For debugging
        return f"Error adding product: {str(e)}", 500

if __name__ == '__main__':
    init_db()
    app.run(debug=True) 