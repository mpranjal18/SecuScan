from typing import List, Dict
from bs4 import BeautifulSoup
from requests import Response
from .base import BaseAnalyzer
import requests
import re

class StackOverflowAnalyzer(BaseAnalyzer):
    def __init__(self):
        super().__init__()
        self.recursive_patterns = [
            r'function.*\{.*\1.*\}',  # Recursive function definition
            r'while.*true',  # Infinite loop
            r'for.*;;'  # Infinite loop
        ]
    
    def passive_scan(self, response: Response, soup: BeautifulSoup) -> List[Dict]:
        vulnerabilities = []
        
        # Check for potentially dangerous recursive patterns in JavaScript
        scripts = soup.find_all('script')
        for script in scripts:
            script_content = script.string or ''
            for pattern in self.recursive_patterns:
                if re.search(pattern, script_content, re.IGNORECASE):
                    vulnerabilities.append(
                        self.create_vulnerability_report(
                            name='Potential Stack Overflow',
                            description='Dangerous recursive pattern detected',
                            risk_level='medium',
                            evidence=f'Pattern: {pattern}',
                            fix_recommendation='Add recursion limits and proper termination conditions'
                        )
                    )
        
        return vulnerabilities
    
    def active_scan(self, url: str, response: Response, soup: BeautifulSoup) -> List[Dict]:
        return self.passive_scan(response, soup) 