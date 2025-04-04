import concurrent.futures
from typing import List, Dict
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from selenium import webdriver
from scanner.analyzers.rce import RCEAnalyzer
from scanner.analyzers.buffer_overflow import BufferOverflowAnalyzer
from scanner.analyzers.stack_overflow import StackOverflowAnalyzer
from scanner.analyzers.sql_injection import SQLInjectionAnalyzer
from scanner.analyzers.xss import XSSAnalyzer
import time

class SecurityScanner:
    def __init__(self, mode='passive'):
        self.mode = mode
        self.analyzers = [
            SQLInjectionAnalyzer(),
            XSSAnalyzer(),
            RCEAnalyzer(),
            BufferOverflowAnalyzer()
        ]
    
    def validate_url(self, url: str) -> str:
        """Validate and format the URL properly"""
        if not url:
            raise ValueError("URL cannot be empty")
            
        # Add http:// if no protocol specified
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        # Validate URL format
        try:
            result = urlparse(url)
            if not all([result.scheme, result.netloc]):
                raise ValueError("Invalid URL format")
            return url
        except Exception as e:
            raise ValueError(f"Invalid URL: {str(e)}")
    
    def scan(self, url: str) -> Dict:
        """Main scanning function"""
        try:
            # Validate and normalize URL
            url = self.validate_url(url)
            print(f"\nStarting security scan of {url}")
            print("=" * 50)
            
            # Check if URL is accessible
            if not self._check_url_accessible(url):
                return {"error": "URL is not accessible"}
            
            all_vulnerabilities = []
            
            # Run each analyzer
            for analyzer in self.analyzers:
                try:
                    print(f"\nRunning {analyzer.name}...")
                    vulnerabilities = analyzer.analyze(url, self.mode)
                    if vulnerabilities:
                        all_vulnerabilities.extend(vulnerabilities)
                        self._print_analyzer_results(analyzer.name, vulnerabilities)
                except Exception as e:
                    print(f"Error running {analyzer.name}: {str(e)}")
            
            # Print summary
            print("\nScan Summary")
            print("=" * 50)
            summary = self._get_summary_counts(all_vulnerabilities)
            self._print_summary(all_vulnerabilities)
            
            return {
                "vulnerabilities": all_vulnerabilities,
                "summary": summary
            }
            
        except Exception as e:
            print(f"Scan error: {str(e)}")
            return {"error": str(e)}
            
    def _check_url_accessible(self, url: str) -> bool:
        """Check if the URL is accessible"""
        try:
            response = requests.get(url, timeout=10, verify=False)
            return response.status_code == 200
        except:
            return False
            
    def _print_analyzer_results(self, analyzer_name: str, vulnerabilities: List[Dict]) -> None:
        """Print results from an individual analyzer"""
        if vulnerabilities:
            print(f"\n{analyzer_name} Results:")
            print("-" * 40)
            for vuln in vulnerabilities:
                if isinstance(vuln, dict):  # Ensure vuln is a dictionary
                    print(f"\nVulnerability: {vuln.get('name', 'Unknown')}")
                    print(f"Risk Level: {vuln.get('risk_level', 'Unknown').upper()}")
                    print(f"Description: {vuln.get('description', 'No description')}")
                    print(f"Evidence: {vuln.get('evidence', 'No evidence')}")
                    print(f"Fix: {vuln.get('fix_recommendation', 'No recommendation')}")
                    print("-" * 40)
    
    def _get_summary_counts(self, vulnerabilities: List[Dict]) -> Dict:
        """Get summary counts of vulnerabilities by risk level"""
        summary = {
            'high': 0,
            'medium': 0,
            'low': 0,
            'total': len(vulnerabilities)
        }
        
        for vuln in vulnerabilities:
            if isinstance(vuln, dict):  # Ensure vuln is a dictionary
                risk_level = vuln.get('risk_level', '').lower()
                if risk_level in summary:
                    summary[risk_level] += 1
                    
        return summary
    
    def _print_summary(self, vulnerabilities: List[Dict]) -> None:
        """Print summary of all vulnerabilities found"""
        summary = self._get_summary_counts(vulnerabilities)
        
        print(f"\nTotal Vulnerabilities Found: {summary['total']}")
        print(f"High Risk: {summary['high']}")
        print(f"Medium Risk: {summary['medium']}")
        print(f"Low Risk: {summary['low']}")
        
        if vulnerabilities:
            print("\nVulnerabilities by Risk Level:")
            
            # Print high risk vulnerabilities
            print("\nHigh Risk Vulnerabilities:")
            for vuln in vulnerabilities:
                if isinstance(vuln, dict) and vuln.get('risk_level', '').lower() == 'high':
                    print(f"- {vuln.get('name', 'Unknown')}")
            
            # Print medium risk vulnerabilities
            print("\nMedium Risk Vulnerabilities:")
            for vuln in vulnerabilities:
                if isinstance(vuln, dict) and vuln.get('risk_level', '').lower() == 'medium':
                    print(f"- {vuln.get('name', 'Unknown')}")
            
            # Print low risk vulnerabilities
            print("\nLow Risk Vulnerabilities:")
            for vuln in vulnerabilities:
                if isinstance(vuln, dict) and vuln.get('risk_level', '').lower() == 'low':
                    print(f"- {vuln.get('name', 'Unknown')}")
        
        print("\nScan completed!")
        print("=" * 50)
        
    def _crawl(self, base_url: str, max_pages: int = 10) -> List[str]:
        """Crawl the website to find all pages"""
        pages = set([base_url])
        crawled = set()
        
        while pages and len(crawled) < max_pages:
            url = pages.pop()
            if url in crawled:
                continue
                
            try:
                response = requests.get(url)
                crawled.add(url)
                
                # Parse links
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a'):
                    href = link.get('href')
                    if not href:
                        continue
                        
                    # Convert relative URLs to absolute
                    href = urljoin(base_url, href)
                    
                    # Only include URLs from the same domain
                    if urlparse(href).netloc == urlparse(base_url).netloc:
                        pages.add(href)
                        
            except requests.RequestException:
                continue
                
        return list(crawled)
        
    def _normalize_url(self, url: str) -> str:
        """Normalize URL by adding protocol if missing"""
        if not url.startswith(('http://', 'https://')):
            return 'http://' + url
        return url

    def scan_with_selenium(self, url: str) -> List[Dict]:
        try:
            # Validate and format URL
            url = self.validate_url(url)
            print(f"Scanning URL: {url}")  # Debug print
            
            # Initialize Selenium WebDriver
            driver = webdriver.Chrome()
            driver.get(url)
            
            vulnerabilities = []
            # Run each analyzer
            for analyzer in self.analyzers:
                try:
                    print(f"Running analyzer: {analyzer.__class__.__name__}")  # Debug print
                    if self.mode == 'passive':
                        results = analyzer.passive_scan(driver.page_source)
                    else:
                        results = analyzer.active_scan(url, driver.page_source)
                    if results:
                        print(f"Found vulnerabilities: {len(results)}")  # Debug print
                        vulnerabilities.extend(results)
                except Exception as analyzer_error:
                    print(f"Analyzer error: {str(analyzer_error)}")
                    continue
            
            print(f"Total vulnerabilities found: {len(vulnerabilities)}")  # Debug print
            return vulnerabilities
        except Exception as e:
            print(f"Scanning error: {str(e)}")
            raise ValueError(f"Failed to scan {url}: {str(e)}")
        finally:
            driver.quit() 