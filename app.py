"""
Vercel entrypoint for SecuScan Flask application.
This file is required by Vercel to locate the Flask app.
Vercel looks for a variable named 'app' that is a Flask instance.
"""
import os
import sys

# Add project root to Python path
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Import the Flask app from scanner.web.app
from scanner.web.app import app

# Vercel requires the app variable to be directly accessible at module level
# This is the Flask WSGI application that Vercel will use

