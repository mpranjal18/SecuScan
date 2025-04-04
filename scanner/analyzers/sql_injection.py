from typing import List, Dict
from bs4 import BeautifulSoup
from requests import Response
from .base import BaseAnalyzer
import requests
import re
from urllib.parse import urljoin

class SQLInjectionAnalyzer(BaseAnalyzer):
    def __init__(self):
        super().__init__()
        self.name = "SQL Injection Analyzer"
        self.payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "admin' --",
            "' OR 'x'='x",
            "1' OR '1'='1",
            "1 OR 1=1",
            "' OR ''='",
            "1' OR '1'='1' --",
            "' OR 1=1#",
            "' OR 1=1/*"
        ]
        self.sql_patterns = [
            r'SQL syntax.*?MySQL',
            r'Warning.*?\Wmysqli?_',
            r'MySQLSyntaxErrorException',
            r'valid MySQL result',
            r'check the manual that corresponds to your MySQL server version',
            r'Unknown column \'[^\']+\' in \'field list\'',
            r'MySqlClient\.',
            r'com\.mysql\.jdbc',
            r'Syntax error or access violation'
        ]

    def analyze(self, url, mode='passive'):
        self.clear_results()
        
        if mode == 'passive':
            return self._passive_analysis(url)
        else:
            return self._active_analysis(url)

    def _get_forms(self, url):
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            return soup.find_all('form')
        except:
            return []

    def _passive_analysis(self, url):
        forms = self._get_forms(url)
        
        for form in forms:
            inputs = form.find_all(['input', 'textarea'])
            for input_field in inputs:
                if input_field.get('type') in ['text', 'search', 'password', None]:
                    self.add_vulnerability(
                        name="Potential SQL Injection Point",
                        description=f"Found an input field that might be vulnerable to SQL injection: {input_field.get('name', 'Unknown field')}",
                        risk_level="Medium",
                        location=f"{url} - Form input: {input_field.get('name', 'Unknown field')}",
                        recommendation="Use parameterized queries or prepared statements. Validate and sanitize all user inputs."
                    )
        
        return self.get_results()

    def _active_analysis(self, url):
        forms = self._get_forms(url)
        
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
                
                try:
                    if method == 'post':
                        response = requests.post(action, data=data)
                    else:
                        response = requests.get(action, params=data)
                    
                    # Check for SQL error messages
                    error_patterns = [
                        "SQL syntax",
                        "mysql_fetch",
                        "ORA-",
                        "PostgreSQL",
                        "SQLite",
                        "SQLSTATE",
                    ]
                    
                    for pattern in error_patterns:
                        if pattern.lower() in response.text.lower():
                            self.add_vulnerability(
                                name="SQL Injection Vulnerability",
                                description=f"SQL injection vulnerability detected using payload: {payload}",
                                risk_level="High",
                                location=f"{action} - Form input",
                                recommendation="Use parameterized queries or prepared statements. Implement proper input validation and sanitization."
                            )
                            break
                            
                except Exception as e:
                    print(f"Error testing SQL injection: {str(e)}")
        
        return self.get_results()

    def check_response_for_sql_error(self, response_text: str) -> bool:
        error_patterns = [
            'sql syntax',
            'mysql error',
            'sqlite_error',
            'database error',
            'ORA-',
            'SQL Server',
            'syntax error',
            'unterminated'
        ]
        return any(pattern.lower() in response_text.lower() for pattern in error_patterns)

    def passive_scan(self, response: Response, soup: BeautifulSoup) -> List[Dict]:
        vulnerabilities = []
        
        # Check for SQL patterns in response
        for pattern in self.sql_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                vulnerabilities.append(
                    self.create_vulnerability_report(
                        name='SQL Pattern Exposure',
                        description='SQL query pattern detected in response',
                        risk_level='high',
                        evidence=f'Found SQL pattern: {pattern}',
                        fix_recommendation='Use parameterized queries and remove SQL query exposure'
                    )
                )

        # Check for potential SQL injection points
        forms = soup.find_all('form')
        for form in forms:
            inputs = form.find_all(['input', 'textarea'])
            for input_field in inputs:
                field_type = input_field.get('type', '')
                field_name = input_field.get('name', '').lower()
                
                if any(keyword in field_name for keyword in ['search', 'query', 'id', 'user', 'name', 'email']):
                    vulnerabilities.append(
                        self.create_vulnerability_report(
                            name='Potential SQL Injection Point',
                            description=f'Input field "{field_name}" might be vulnerable to SQL injection',
                            risk_level='medium',
                            evidence=f'Form input field: {field_name}',
                            fix_recommendation='Use parameterized queries and input validation'
                        )
                    )

        return vulnerabilities

    def active_scan(self, url: str, response: Response, soup: BeautifulSoup) -> List[Dict]:
        vulnerabilities = self.passive_scan(response, soup)
        
        # Test forms
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            inputs = form.find_all(['input', 'textarea'])
            
            for input_field in inputs:
                field_name = input_field.get('name')
                if not field_name:
                    continue
                
                for payload in self.payloads:
                    try:
                        if method == 'get':
                            test_url = f"{url.rstrip('/')}/{action}?{field_name}={payload}"
                            test_response = requests.get(test_url, verify=False)
                        else:
                            test_response = requests.post(
                                f"{url.rstrip('/')}/{action}",
                                data={field_name: payload},
                                verify=False
                            )
                        
                        if self.check_response_for_sql_error(test_response.text):
                            vulnerabilities.append(
                                self.create_vulnerability_report(
                                    name='SQL Injection Vulnerability',
                                    description=f'SQL injection successful with payload: {payload}',
                                    risk_level='high',
                                    evidence=f'Field: {field_name}, Response contains SQL error',
                                    fix_recommendation='Use parameterized queries and input validation'
                                )
                            )
                            
                    except Exception as e:
                        print(f"Error testing payload {payload}: {str(e)}")
                        continue

        # Test URL parameters
        if '?' in url:
            base_url = url.split('?')[0]
            params = dict(param.split('=') for param in url.split('?')[1].split('&'))
            
            for param_name, param_value in params.items():
                for payload in self.payloads:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    try:
                        test_response = requests.get(base_url, params=test_params, verify=False)
                        if self.check_response_for_sql_error(test_response.text):
                            vulnerabilities.append(
                                self.create_vulnerability_report(
                                    name='SQL Injection in URL Parameter',
                                    description=f'URL parameter "{param_name}" is vulnerable to SQL injection',
                                    risk_level='high',
                                    evidence=f'Parameter: {param_name}, Payload: {payload}',
                                    fix_recommendation='Use parameterized queries for URL parameters'
                                )
                            )
                    except Exception as e:
                        print(f"Error testing URL parameter {param_name}: {str(e)}")
                        continue

        return vulnerabilities

    def _get_product_urls(self, base_url):
        try:
            response = requests.get(base_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            product_links = soup.find_all('a', href=re.compile(r'/product/\d+'))
            return [f"{base_url}{link['href']}" for link in product_links]
        except:
            return []

        return vulnerabilities 