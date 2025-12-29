"""
Alternative Vercel entrypoint - Vercel also checks api/ directory
"""
import os
import sys

# Add project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Import the Flask app from scanner.web.app
from scanner.web.app import app

# Vercel requires the app variable
__all__ = ['app']

