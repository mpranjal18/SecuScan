import os
import sys
from pathlib import Path

# Add the project root to Python path
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.append(project_root)

from scanner.core.scanner import SecurityScanner
from scanner.report.generator import ReportGenerator
import argparse

def create_project_structure():
    """Create the entire project directory structure and files"""
    base_dirs = [
        'scanner/web/static/css',
        'scanner/web/static/js',
        'scanner/web/templates',
        'scanner/core',
        'scanner/analyzers',
        'scanner/utils',
        'scanner/report',
        'vulnerable_puma/templates',
        'secure_puma/templates'
    ]
    
    # Create directories
    for dir_path in base_dirs:
        os.makedirs(dir_path, exist_ok=True)
        # Create __init__.py in Python package directories
        if dir_path.startswith('scanner'):
            init_file = os.path.join(dir_path, '__init__.py')
            if not os.path.exists(init_file):
                open(init_file, 'a').close()

def setup_environment():
    """Setup environment variables based on the operating system"""
    # Create project structure if it doesn't exist
    create_project_structure()
    
    # Add the project root to PYTHONPATH
    if sys.platform == 'win32':
        # Windows
        if project_root not in sys.path:
            sys.path.append(project_root)
        os.environ['PYTHONPATH'] = project_root
    else:
        # Unix/Linux/Mac
        os.environ['PYTHONPATH'] = f"{os.environ.get('PYTHONPATH', '')}:{project_root}"

def main():
    parser = argparse.ArgumentParser(description='Security Scanner for Web Applications')
    parser.add_argument('url', help='URL to scan')
    parser.add_argument('--mode', choices=['passive', 'active'], default='passive',
                      help='Scanning mode (default: passive)')
    parser.add_argument('--format', choices=['pdf', 'json'], default='pdf',
                      help='Report format (default: pdf)')
    args = parser.parse_args()

    try:
        print(f"Starting {args.mode} scan of {args.url}")
        scanner = SecurityScanner(mode=args.mode)
        vulnerabilities = scanner.scan(args.url)
        
        # Generate report
        report_gen = ReportGenerator(format=args.format)
        report_file = report_gen.generate(vulnerabilities, args.url)
        
        if vulnerabilities:
            print(f"\nFound {len(vulnerabilities)} vulnerabilities!")
            print(f"Report generated: {report_file}")
        else:
            print("\nNo vulnerabilities found.")
            print(f"Clean report generated: {report_file}")
            
    except Exception as e:
        print(f"Error during scan: {str(e)}")

if __name__ == '__main__':
    main()