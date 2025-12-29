"""
Vercel entrypoint for SecuScan Flask application.
This file is required by Vercel to locate the Flask app.
"""
import os
import sys

# Add project root to Python path
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Import the Flask app from scanner.web.app
from scanner.web.app import app

# Export the app for Vercel
# Vercel looks for a variable named 'app' in the entrypoint file
__all__ = ['app']

