from abc import ABC, abstractmethod
from typing import List, Dict
from bs4 import BeautifulSoup
from requests import Response

class BaseAnalyzer(ABC):
    def __init__(self):
        self.name = self.__class__.__name__
        self.results = []
        self.risk_levels = {
            'high': 3,
            'medium': 2,
            'low': 1
        }
    
    @abstractmethod
    def passive_scan(self, response: Response, soup: BeautifulSoup) -> List[Dict]:
        pass
    
    @abstractmethod
    def active_scan(self, url: str, response: Response, soup: BeautifulSoup) -> List[Dict]:
        pass
    
    def create_vulnerability_report(self, name: str, description: str, risk_level: str, 
                                 evidence: str, fix_recommendation: str) -> Dict:
        return {
            'name': name,
            'description': description,
            'risk_level': risk_level,
            'evidence': evidence,
            'fix_recommendation': fix_recommendation
        }

    def analyze(self, url, mode='passive'):
        """
        Analyze the target URL for vulnerabilities.
        
        Args:
            url (str): The URL to analyze
            mode (str): The scan mode ('passive' or 'active')
            
        Returns:
            list: List of detected vulnerabilities
        """
        raise NotImplementedError("Analyzer must implement analyze method")

    def add_vulnerability(self, name, description, risk_level, location, recommendation):
        """
        Add a detected vulnerability to results.
        
        Args:
            name (str): Name of the vulnerability
            description (str): Description of the vulnerability
            risk_level (str): Risk level ('High', 'Medium', 'Low')
            location (str): Where the vulnerability was found
            recommendation (str): How to fix the vulnerability
        """
        self.results.append({
            'name': name,
            'description': description,
            'risk_level': risk_level,
            'location': location,
            'recommendation': recommendation
        })

    def get_results(self):
        """
        Get the analysis results.
        
        Returns:
            list: List of detected vulnerabilities
        """
        return self.results

    def clear_results(self):
        """Clear all previous results."""
        self.results = [] 