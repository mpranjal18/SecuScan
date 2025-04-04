from scanner.analyzers.base import BaseAnalyzer
import requests
from bs4 import BeautifulSoup
import re
from requests import Response
from typing import List, Dict

class XSSAnalyzer(BaseAnalyzer):
    def __init__(self):
        super().__init__()
        self.name = "Cross-Site Scripting (XSS) Analyzer"
        self.test_vectors = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<img src='x' onerror='alert(\"XSS\")'/>",
            "<script>console.log('XSS')</script>",
            "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\"",
            "javascript:alert(1)//",
            "\"><img src=x onerror=alert('XSS')>"
        ]

    def analyze(self, url, mode='passive'):
        self.clear_results()
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        if mode == 'passive':
            return self.passive_scan(response, soup)
        else:
            return self.active_scan(url, response, soup)

    def passive_scan(self, response: Response, soup: BeautifulSoup) -> List[Dict]:
        vulnerabilities = []
        
        # Check for potentially vulnerable input fields
        forms = soup.find_all('form')
        for form in forms:
            inputs = form.find_all(['input', 'textarea'])
            for input_field in inputs:
                if input_field.get('type') in ['text', 'search', None]:
                    vulnerabilities.append(
                        self.create_vulnerability_report(
                            name='Potential XSS Point',
                            description=f'Input field might be vulnerable to XSS: {input_field.get("name", "Unknown field")}',
                            risk_level='medium',
                            evidence=f'Form input field: {input_field.get("name", "Unknown field")}',
                            fix_recommendation='Implement input validation and output encoding'
                        )
                    )
        
        return vulnerabilities

    def active_scan(self, url: str, response: Response, soup: BeautifulSoup) -> List[Dict]:
        vulnerabilities = []
        
        # Test search functionality
        search_url = f"{url}/search"
        try:
            for vector in self.test_vectors:
                params = {'q': vector}
                response = requests.get(search_url, params=params)
                if vector.lower() in response.text.lower():
                    vulnerabilities.append(
                        self.create_vulnerability_report(
                            name='Reflected XSS in Search Function',
                            description='The search functionality is vulnerable to reflected XSS attacks',
                            risk_level='high',
                            evidence=f'XSS payload was reflected: {vector}',
                            fix_recommendation='Implement proper input validation and output encoding'
                        )
                    )
                    break
        except:
            pass

        # Test product comments/reviews
        try:
            product_urls = self._get_product_urls(url)
            for product_url in product_urls:
                for vector in self.test_vectors:
                    data = {
                        'comment': vector,
                        'rating': '5'
                    }
                    response = requests.post(f"{product_url}/comment", data=data)
                    if vector.lower() in response.text.lower():
                        vulnerabilities.append(
                            self.create_vulnerability_report(
                                name='Stored XSS in Product Comments',
                                description='The product comments feature is vulnerable to stored XSS attacks',
                                risk_level='high',
                                evidence=f'XSS payload was stored and reflected: {vector}',
                                fix_recommendation='Implement proper input validation and output encoding for user-submitted content'
                            )
                        )
                        break
        except:
            pass

        # Test add product form
        add_product_url = f"{url}/add_product"
        try:
            for vector in self.test_vectors:
                data = {
                    'name': f"Test Product {vector}",
                    'description': vector,
                    'price': '19.99'
                }
                response = requests.post(add_product_url, data=data)
                if vector.lower() in response.text.lower():
                    vulnerabilities.append(
                        self.create_vulnerability_report(
                            name='Stored XSS in Product Details',
                            description='The product submission form is vulnerable to stored XSS attacks',
                            risk_level='high',
                            evidence=f'XSS payload was stored in product details: {vector}',
                            fix_recommendation='Implement proper input validation and output encoding for product information'
                        )
                    )
                    break
        except:
            pass

        # Test user profile
        profile_url = f"{url}/profile"
        try:
            for vector in self.test_vectors:
                data = {
                    'name': vector,
                    'bio': vector
                }
                response = requests.post(profile_url, data=data)
                if vector.lower() in response.text.lower():
                    vulnerabilities.append(
                        self.create_vulnerability_report(
                            name='Stored XSS in User Profile',
                            description='The user profile update feature is vulnerable to stored XSS attacks',
                            risk_level='high',
                            evidence=f'XSS payload was stored in user profile: {vector}',
                            fix_recommendation='Implement proper input validation and output encoding for user profile data'
                        )
                    )
                    break
        except:
            pass

        return vulnerabilities

    def _get_product_urls(self, base_url):
        try:
            response = requests.get(base_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            product_links = soup.find_all('a', href=re.compile(r'/product/\d+'))
            return [f"{base_url}{link['href']}" for link in product_links]
        except:
            return [] 