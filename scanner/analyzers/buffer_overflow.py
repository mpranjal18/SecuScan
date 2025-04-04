from ..analyzers.base import BaseAnalyzer
import requests
from bs4 import BeautifulSoup
from requests import Response
from typing import List, Dict
import time

class BufferOverflowAnalyzer(BaseAnalyzer):
    def __init__(self):
        super().__init__()
        self.name = "Buffer Overflow Analyzer"
        # Categorized test strings by risk level
        self.high_risk_payloads = [
            "A" * 5000,  # Very long string
            "A" * 10000,  # Extremely long string
            "%x" * 1000,  # Long format string
            "%n" * 500,   # Dangerous format string
            "\x41" * 5000  # Long raw bytes
        ]
        self.medium_risk_payloads = [
            "A" * 1000,  # Medium length string
            "A" * 2000,  # Longer string
            "%s" * 200,  # Medium format string
            "A" * 500 + "%x" * 50,  # Mixed payload
            "\x41" * 1000  # Medium raw bytes
        ]
        self.session = requests.Session()

    def analyze(self, url, mode='passive'):
        print(f"[Buffer Overflow] Starting analysis of {url}")
        self.clear_results()
        response = self._safe_request('GET', url)
        if not response:
            return []
        
        soup = BeautifulSoup(response.text, 'html.parser')
        vulnerabilities = []
        
        # Test both passive and active regardless of mode to ensure thorough scanning
        passive_results = self.passive_scan(response, soup)
        active_results = self.active_scan(url, response, soup)
        
        vulnerabilities.extend(passive_results)
        vulnerabilities.extend(active_results)
        
        # Add vulnerability counts to results
        if vulnerabilities:
            high_risks = len([v for v in vulnerabilities if v['risk_level'] == 'high'])
            medium_risks = len([v for v in vulnerabilities if v['risk_level'] == 'medium'])
            print(f"[Buffer Overflow] Found {high_risks} high risk and {medium_risks} medium risk vulnerabilities")
        
        return vulnerabilities

    def passive_scan(self, response: Response, soup: BeautifulSoup) -> List[Dict]:
        vulnerabilities = []
        print("[Buffer Overflow] Starting passive scan")
        
        try:
            forms = soup.find_all('form')
            for form in forms:
                inputs = form.find_all(['input', 'textarea'])
                for input_field in inputs:
                    field_type = input_field.get('type', '')
                    field_name = input_field.get('name', '').lower()
                    max_length = input_field.get('maxlength')
                    
                    # Check for unbounded fields
                    if not max_length:
                        vulnerabilities.append(
                            self.create_vulnerability_report(
                                name='Unbounded Input Field',
                                description=f'Input field "{field_name}" has no length restriction',
                                risk_level='high',
                                evidence=f'Field {field_name} missing maxlength attribute',
                                fix_recommendation='Implement proper input length validation and add maxlength restrictions'
                            )
                        )
                    # Check for large maxlength fields
                    elif max_length and int(max_length) > 1000:
                        vulnerabilities.append(
                            self.create_vulnerability_report(
                                name='Large Input Field Limit',
                                description=f'Input field "{field_name}" has a very large maximum length',
                                risk_level='medium',
                                evidence=f'Field maxlength: {max_length}',
                                fix_recommendation='Review and reduce maximum input length if possible'
                            )
                        )
        except Exception as e:
            print(f"Error in passive scan: {str(e)}")
        
        return vulnerabilities

    def active_scan(self, url: str, response: Response, soup: BeautifulSoup) -> List[Dict]:
        vulnerabilities = []
        print(f"[Buffer Overflow] Starting active scan for {url}")
        
        try:
            # Test search functionality
            search_paths = ['/search', '/query', '/find', '/products/search']
            for path in search_paths:
                search_url = requests.compat.urljoin(url, path)
                
                # Test high risk payloads
                for payload in self.high_risk_payloads:
                    response = self._safe_request('GET', search_url, params={'q': payload})
                    if self._check_response_for_overflow(response, payload):
                        vulnerabilities.append(
                            self.create_vulnerability_report(
                                name='Critical Buffer Overflow in Search',
                                description='Search function vulnerable to buffer overflow',
                                risk_level='high',
                                evidence=f'Server error with payload length: {len(payload)}',
                                fix_recommendation='Implement input length validation and use secure string handling'
                            )
                        )
                        break
                
                # Test medium risk payloads
                for payload in self.medium_risk_payloads:
                    response = self._safe_request('GET', search_url, params={'q': payload})
                    if self._check_response_for_overflow(response, payload):
                        vulnerabilities.append(
                            self.create_vulnerability_report(
                                name='Potential Buffer Overflow in Search',
                                description='Search function shows signs of buffer overflow vulnerability',
                                risk_level='medium',
                                evidence=f'Anomalous response with payload length: {len(payload)}',
                                fix_recommendation='Review input handling and implement proper validation'
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
                    action = requests.compat.urljoin(url, action)
                
                method = form.get('method', 'get').lower()
                inputs = form.find_all(['input', 'textarea'])
                
                # Test high risk payloads
                for payload in self.high_risk_payloads:
                    data = {}
                    for input_field in inputs:
                        if input_field.get('type') not in ['submit', 'button', 'image']:
                            data[input_field.get('name', 'Unknown')] = payload
                    
                    try:
                        if method == 'post':
                            response = self._safe_request('POST', action, data=data)
                        else:
                            response = self._safe_request('GET', action, params=data)
                        
                        if self._check_response_for_overflow(response, payload):
                            vulnerabilities.append(
                                self.create_vulnerability_report(
                                    name='Critical Buffer Overflow in Form',
                                    description=f'Form at {action} vulnerable to buffer overflow',
                                    risk_level='high',
                                    evidence=f'Server error with payload length: {len(payload)}',
                                    fix_recommendation='Implement proper input validation and use secure string handling'
                                )
                            )
                            break
                    except requests.exceptions.RequestException:
                        vulnerabilities.append(
                            self.create_vulnerability_report(
                                name='Critical Form Vulnerability',
                                description='Form submission caused application crash',
                                risk_level='high',
                                evidence=f'Application crash with payload length: {len(payload)}',
                                fix_recommendation='Implement proper error handling and input validation'
                            )
                        )
                        break
                
                # Test medium risk payloads
                for payload in self.medium_risk_payloads:
                    data = {}
                    for input_field in inputs:
                        if input_field.get('type') not in ['submit', 'button', 'image']:
                            data[input_field.get('name', 'Unknown')] = payload
                    
                    try:
                        if method == 'post':
                            response = self._safe_request('POST', action, data=data)
                        else:
                            response = self._safe_request('GET', action, params=data)
                        
                        if self._check_response_for_overflow(response, payload):
                            vulnerabilities.append(
                                self.create_vulnerability_report(
                                    name='Potential Form Vulnerability',
                                    description=f'Form at {action} shows signs of buffer overflow vulnerability',
                                    risk_level='medium',
                                    evidence=f'Anomalous response with payload length: {len(payload)}',
                                    fix_recommendation='Review input handling and implement proper validation'
                                )
                            )
                            break
                    except:
                        pass

        except Exception as e:
            print(f"Error in active scan: {str(e)}")
        
        return vulnerabilities

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

    def _check_response_for_overflow(self, response, payload) -> bool:
        if not response:
            return False

        # Check for signs of buffer overflow
        indicators = [
            # Error messages
            "stack overflow",
            "buffer overflow",
            "memory corruption",
            "segmentation fault",
            "access violation",
            # Stack traces
            "stack trace",
            "call stack",
            # Memory addresses
            "0x",
            # Common error patterns
            "internal server error",
            "application error",
            "runtime error",
            # Ruby specific errors
            "ruby",
            "rack",
            "sinatra",
            # Generic error indicators
            "error",
            "exception",
            "overflow",
            "memory",
            "crash"
        ]

        if response.text:
            response_text = response.text.lower()
            for indicator in indicators:
                if indicator in response_text:
                    print(f"[Buffer Overflow] Found indicator: {indicator} for payload length: {len(payload)}")
                    return True

        # Check response status
        if response.status_code >= 500:
            print(f"[Buffer Overflow] Server error {response.status_code} with payload length: {len(payload)}")
            return True

        # Check response size anomalies
        if len(response.text) < 100 and response.status_code != 404:  # Unexpectedly short response
            print(f"[Buffer Overflow] Unusually short response with payload length: {len(payload)}")
            return True

        return False 