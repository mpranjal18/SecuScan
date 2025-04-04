import json
from typing import List, Dict
from datetime import datetime
import fpdf  # You'll need to install fpdf2
import matplotlib.pyplot as plt
import os
import io
from fpdf import FPDF

class ReportGenerator:
    def __init__(self, format='pdf'):
        self.format = format

    def generate_risk_charts(self, vulnerabilities):
        # Count vulnerabilities by risk level
        risk_counts = {'high': 0, 'medium': 0, 'low': 0}
        for vuln in vulnerabilities:
            risk_level = vuln['risk_level'].lower()
            if risk_level in risk_counts:
                risk_counts[risk_level] += 1

        # Create pie chart
        plt.figure(figsize=(8, 6))
        colors = ['red', 'orange', 'yellow']
        plt.pie(
            risk_counts.values(),
            labels=risk_counts.keys(),
            colors=colors,
            autopct='%1.1f%%'
        )
        plt.title('Vulnerabilities by Risk Level')
        
        # Save pie chart
        pie_chart = 'pie_chart.png'
        plt.savefig(pie_chart)
        plt.close()

        # Create bar chart
        plt.figure(figsize=(10, 6))
        plt.bar(risk_counts.keys(), risk_counts.values(), color=colors)
        plt.title('Number of Vulnerabilities by Risk Level')
        plt.ylabel('Number of Vulnerabilities')
        
        # Save bar chart
        bar_chart = 'bar_chart.png'
        plt.savefig(bar_chart)
        plt.close()

        return pie_chart, bar_chart

    def generate(self, vulnerabilities, url):
        if self.format == 'pdf':
            return self._generate_pdf(vulnerabilities, url)
        else:
            return self._generate_json(vulnerabilities)

    def generate_data(self, vulnerabilities):
        return {
            'total': len(vulnerabilities),
            'by_risk_level': {
                'high': len([v for v in vulnerabilities if v['risk_level'].lower() == 'high']),
                'medium': len([v for v in vulnerabilities if v['risk_level'].lower() == 'medium']),
                'low': len([v for v in vulnerabilities if v['risk_level'].lower() == 'low'])
            },
            'vulnerabilities': vulnerabilities
        }

    def _generate_pdf(self, vulnerabilities, url):
        try:
            # Create PDF
            pdf = FPDF()
            pdf.add_page()

            # Title
            pdf.set_font('Arial', 'B', 24)
            pdf.cell(0, 20, 'Security Scan Report', ln=True, align='C')

            # Scan Information
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 10, 'Scan Information', ln=True)
            pdf.set_font('Arial', '', 12)
            pdf.cell(0, 10, f'Target URL: {url}', ln=True)
            pdf.cell(0, 10, f'Scan Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', ln=True)
            pdf.cell(0, 10, f'Total Vulnerabilities Found: {len(vulnerabilities)}', ln=True)

            # Generate and add charts
            try:
                # Create temporary directory if it doesn't exist
                temp_dir = os.path.join(os.getcwd(), 'temp')
                os.makedirs(temp_dir, exist_ok=True)

                pie_chart = os.path.join(temp_dir, f'pie_chart_{datetime.now().strftime("%Y%m%d_%H%M%S")}.png')
                bar_chart = os.path.join(temp_dir, f'bar_chart_{datetime.now().strftime("%Y%m%d_%H%M%S")}.png')
                
                pie_chart, bar_chart = self.generate_risk_charts(vulnerabilities)
                
                # Add pie chart
                if os.path.exists(pie_chart):
                    pdf.add_page()
                    pdf.set_font('Arial', 'B', 16)
                    pdf.cell(0, 10, 'Risk Level Distribution', ln=True, align='C')
                    pdf.image(pie_chart, x=10, y=50, w=190)
                
                # Add bar chart
                if os.path.exists(bar_chart):
                    pdf.add_page()
                    pdf.set_font('Arial', 'B', 16)
                    pdf.cell(0, 10, 'Vulnerability Count by Risk Level', ln=True, align='C')
                    pdf.image(bar_chart, x=10, y=50, w=190)

                # Clean up temporary files
                if os.path.exists(pie_chart):
                    os.remove(pie_chart)
                if os.path.exists(bar_chart):
                    os.remove(bar_chart)
            except Exception as e:
                print(f"Error generating charts: {str(e)}")

            # Vulnerability Details
            pdf.add_page()
            pdf.set_font('Arial', 'B', 16)
            pdf.cell(0, 10, 'Detailed Findings', ln=True)

            # Count vulnerabilities by risk level
            risk_counts = {'high': 0, 'medium': 0, 'low': 0}
            for vuln in vulnerabilities:
                risk_level = vuln['risk_level'].lower()
                if risk_level in risk_counts:
                    risk_counts[risk_level] += 1

            # Summary table
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 10, 'Risk Level Summary:', ln=True)
            pdf.set_font('Arial', '', 12)
            for level, count in risk_counts.items():
                pdf.cell(0, 10, f'{level.capitalize()}: {count}', ln=True)

            # Detailed findings
            for vuln in vulnerabilities:
                pdf.add_page()
                pdf.set_font('Arial', 'B', 14)
                pdf.cell(0, 10, vuln['name'], ln=True)
                
                pdf.set_font('Arial', 'B', 12)
                pdf.cell(0, 10, f"Risk Level: {vuln['risk_level']}", ln=True)
                
                pdf.set_font('Arial', '', 12)
                pdf.multi_cell(0, 10, f"Description: {vuln['description']}")
                pdf.multi_cell(0, 10, f"Evidence: {vuln['evidence']}")
                pdf.multi_cell(0, 10, f"Fix Recommendation: {vuln['fix_recommendation']}")

            # Save the report to a temporary file
            report_path = os.path.join(os.getcwd(), 'temp', f'security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf')
            pdf.output(report_path)
            return report_path

        except Exception as e:
            print(f"Error generating PDF: {str(e)}")
            raise

    def _generate_json(self, vulnerabilities: List[Dict]) -> str:
        report = {
            'scan_date': datetime.now().isoformat(),
            'vulnerabilities': vulnerabilities,
            'summary': {
                'total_vulnerabilities': len(vulnerabilities),
                'risk_levels': {
                    'critical': len([v for v in vulnerabilities if v['risk_level'].lower() == 'critical']),
                    'high': len([v for v in vulnerabilities if v['risk_level'].lower() == 'high']),
                    'medium': len([v for v in vulnerabilities if v['risk_level'].lower() == 'medium']),
                    'low': len([v for v in vulnerabilities if v['risk_level'].lower() == 'low'])
                }
            }
        }
        
        filename = f'security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
            
        return filename 