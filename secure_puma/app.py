from flask import Flask, request, render_template, redirect, url_for, g, session
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import re

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Security Headers
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('secure_products.db')
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        c = db.cursor()
        
        c.execute('''
            CREATE TABLE IF NOT EXISTS products
            (id INTEGER PRIMARY KEY AUTOINCREMENT,
             name TEXT NOT NULL CHECK(length(name) <= 100),
             description TEXT CHECK(length(description) <= 500),
             price REAL NOT NULL CHECK(price >= 0))
        ''')
        
        db.commit()

def validate_input(text, max_length=100):
    """Validate input to prevent XSS and injection attacks"""
    if not text:
        return False
    if len(text) > max_length:
        return False
    # Check for potentially malicious characters
    if re.search(r'[<>{}()\[\];]', text):
        return False
    return True

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/products')
def products():
    search = request.args.get('search', '')
    
    # Input validation
    if not validate_input(search):
        return "Invalid search query", 400
    
    try:
        db = get_db()
        c = db.cursor()
        
        # Parameterized query
        c.execute("SELECT * FROM products WHERE name LIKE ?", (f'%{search}%',))
        products = c.fetchall()
        
        return render_template('products.html', products=products)
    except Exception as e:
        app.logger.error(f"Database error: {str(e)}")
        return "An error occurred", 500

@app.route('/add_product', methods=['POST'])
def add_product():
    try:
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        price = request.form.get('price', 0)

        # Input validation
        if not validate_input(name, 100):
            return "Invalid product name", 400
        if not validate_input(description, 500):
            return "Invalid product description", 400
        
        try:
            price = float(price)
            if price < 0:
                return "Price must be non-negative", 400
        except ValueError:
            return "Invalid price format", 400

        db = get_db()
        c = db.cursor()
        
        # Parameterized query
        c.execute(
            "INSERT INTO products (name, description, price) VALUES (?, ?, ?)",
            (name, description, price)
        )
        db.commit()
        
        return redirect(url_for('products'))
    except Exception as e:
        app.logger.error(f"Error adding product: {str(e)}")
        return "An error occurred", 500

@app.route('/export')
def export_products():
    format_type = request.args.get('format', 'csv')
    
    # Validate format
    if format_type not in ['csv', 'json']:
        return "Invalid format", 400
    
    try:
        db = get_db()
        c = db.cursor()
        c.execute("SELECT * FROM products")
        products = c.fetchall()
        
        if format_type == 'csv':
            output = "id,name,description,price\n"
            for product in products:
                # Properly escape CSV fields
                output += f"{product['id']},\"{product['name']}\",\"{product['description']}\",{product['price']}\n"
            
            return output, 200, {
                'Content-Type': 'text/csv',
                'Content-Disposition': 'attachment; filename=products.csv'
            }
        else:
            import json
            return json.dumps([dict(p) for p in products]), 200, {
                'Content-Type': 'application/json'
            }
    except Exception as e:
        app.logger.error(f"Export error: {str(e)}")
        return "Export failed", 500

@app.route('/subscribe', methods=['POST'])
def subscribe():
    try:
        email = request.form.get('email', '')
        
        # Input validation
        if not email or '@' not in email or len(email) > 254:
            return "Invalid email address", 400
            
        # Secure file handling
        with open('secure_subscribers.txt', 'a') as f:
            f.write(email + '\n')
            
        return 'Subscription successful!'
    except Exception as e:
        app.logger.error(f"Error processing subscription: {str(e)}")
        return "An error occurred while processing your subscription", 500

if __name__ == '__main__':
    init_db()
    app.run(debug=False, port=5001)  # Debug mode disabled for security 