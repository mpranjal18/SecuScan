let currentStep = 1;
let scanResults = null;

function nextStep(step) {
    document.getElementById(`step${step}`).classList.add('hidden');
    document.getElementById(`step${step + 1}`).classList.remove('hidden');
    currentStep = step + 1;
}

function prevStep(step) {
    document.getElementById(`step${step}`).classList.add('hidden');
    document.getElementById(`step${step - 1}`).classList.remove('hidden');
    currentStep = step - 1;
    
    // Reset form when going back
    if (currentStep === 1) {
        document.getElementById('scanForm').reset();
    }
}

function showError(message) {
    const errorMessage = document.getElementById('errorMessage');
    if (errorMessage) {
        errorMessage.textContent = message;
        errorMessage.style.display = 'block';
    }
    
    const loadingSpinner = document.getElementById('loadingSpinner');
    if (loadingSpinner) {
        loadingSpinner.classList.add('hidden');
    }
}

function startScan(event) {
    event.preventDefault();
    
    const url = document.getElementById('url').value.trim();
    const mode = document.getElementById('mode').value;
    const resultsDiv = document.getElementById('results');
    const loadingSpinner = document.getElementById('loadingSpinner');
    const errorMessage = document.getElementById('errorMessage');
    
    // Clear previous results and errors
    resultsDiv.innerHTML = '';
    errorMessage.style.display = 'none';
    
    // Show loading
    loadingSpinner.classList.remove('hidden');
    
    // Validate URL
    if (!url) {
        showError('URL is required');
        return;
    }

    // Make API request
    fetch('/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            url: url,
            mode: mode
        })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        loadingSpinner.classList.add('hidden');
        
        if (data.error) {
            throw new Error(data.error);
        }

        // Display results
        displayResults(data);
    })
    .catch(error => {
        loadingSpinner.classList.add('hidden');
        showError('Error during scan: ' + error.message);
        console.error('Error:', error);
    });
}

function generateTextReport(data) {
    const report = `
Scan Summary
==================================================

Total Vulnerabilities Found: ${data.summary.total}
High Risk: ${data.summary.high_risk}
Medium Risk: ${data.summary.medium_risk}
Low Risk: ${data.summary.low_risk}

Vulnerabilities by Risk Level:

High Risk Vulnerabilities:
${formatVulnerabilities(data.vulnerabilities.high)}

Medium Risk Vulnerabilities:
${formatVulnerabilities(data.vulnerabilities.medium)}

Low Risk Vulnerabilities:
${formatVulnerabilities(data.vulnerabilities.low)}

Scan completed!`;

    return report;
}

function formatVulnerabilities(vulns) {
    if (!vulns || vulns.length === 0) return '';
    return vulns.map(v => `- ${v.name}\n  Description: ${v.description}\n  Evidence: ${v.evidence}\n  Fix: ${v.fix_recommendation}\n`).join('\n');
}

function downloadTextReport() {
    if (!scanResults) {
        showError('No scan results available');
        return;
    }

    const textContent = generateTextReport(scanResults);
    const blob = new Blob([textContent], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security_scan_report_${new Date().toISOString().slice(0,19).replace(/[:]/g, '')}.txt`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    a.remove();
}

function displayResults(data) {
    const resultsDiv = document.getElementById('results');
    if (!resultsDiv) return;
    
    resultsDiv.innerHTML = '';
    scanResults = data;  // Store the results for potential report generation

    // Create summary section
    const summaryDiv = document.createElement('div');
    summaryDiv.className = 'summary-section';
    
    // Ensure we have a valid summary object
    const summary = {
        total: 0,
        high_risk: 0,
        medium_risk: 0,
        low_risk: 0,
        ...data.summary
    };

    summaryDiv.innerHTML = `
        <h2>Scan Summary</h2>
        <div class="risk-counts">
            <div class="risk-count high">
                <span class="count">${summary.high_risk || 0}</span>
                <span class="label">High Risk</span>
            </div>
            <div class="risk-count medium">
                <span class="count">${summary.medium_risk || 0}</span>
                <span class="label">Medium Risk</span>
            </div>
            <div class="risk-count low">
                <span class="count">${summary.low_risk || 0}</span>
                <span class="label">Low Risk</span>
            </div>
        </div>
        <p class="total-vulns">Total Vulnerabilities: ${summary.total || 0}</p>
        <div class="action-buttons">
            <button onclick="downloadTextReport()" class="download-btn">Download Text Report</button>
        </div>
    `;
    resultsDiv.appendChild(summaryDiv);

    // Ensure we have a valid vulnerabilities object
    const vulnerabilities = {
        high: [],
        medium: [],
        low: [],
        ...(data.vulnerabilities || {})
    };

    // Display vulnerabilities by risk level
    const riskLevels = ['high', 'medium', 'low'];
    
    riskLevels.forEach(level => {
        const vulns = vulnerabilities[level] || [];
        if (vulns.length > 0) {
            const sectionDiv = document.createElement('div');
            sectionDiv.className = `vulnerability-section ${level}-risk`;
            
            sectionDiv.innerHTML = `
                <h3>${level.charAt(0).toUpperCase() + level.slice(1)} Risk Vulnerabilities</h3>
                <div class="vulnerabilities">
                    ${vulns.map(vuln => `
                        <div class="vulnerability-card">
                            <h4>${vuln.name || 'Unnamed Vulnerability'}</h4>
                            <p><strong>Description:</strong> ${vuln.description || 'No description available'}</p>
                            <p><strong>Evidence:</strong> ${vuln.evidence || 'No evidence available'}</p>
                            <p><strong>Fix:</strong> ${vuln.fix_recommendation || 'No fix recommendation available'}</p>
                        </div>
                    `).join('')}
                </div>
            `;
            
            resultsDiv.appendChild(sectionDiv);
        }
    });

    // Show the results section
    const resultsSection = document.getElementById('resultsSection');
    if (resultsSection) {
        resultsSection.style.display = 'block';
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }

    // Display charts if available
    if (data.charts) {
        const pieChart = document.getElementById('pieChart');
        const barChart = document.getElementById('barChart');
        if (pieChart) pieChart.src = 'data:image/png;base64,' + data.charts.pie;
        if (barChart) barChart.src = 'data:image/png;base64,' + data.charts.bar;
    }
}

async function downloadReport() {
    if (!scanResults) {
        alert('No scan results available');
        return;
    }

    try {
        const response = await fetch('/download_report', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                vulnerabilities: scanResults.vulnerabilities,
                url: document.getElementById('urlInput').value
            })
        });

        if (!response.ok) throw new Error('Failed to generate report');

        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `security_report_${new Date().toISOString().slice(0,19).replace(/[:]/g, '')}.pdf`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        a.remove();
    } catch (error) {
        alert('Error downloading report: ' + error.message);
    }
}

// Add event listener when the document is loaded
document.addEventListener('DOMContentLoaded', function() {
    const welcomeCard = document.querySelector('.welcome-card');
    const scanForm = document.getElementById('scanForm');
    const startScanBtn = document.getElementById('startScanBtn');
    const backBtn = document.querySelector('.back-btn');
    const loadingSpinner = document.getElementById('loadingSpinner');
    const errorMessage = document.getElementById('errorMessage');
    const resultsSection = document.getElementById('resultsSection');

    // Show scan form when Start Scan button is clicked
    if (startScanBtn) {
        startScanBtn.addEventListener('click', function() {
            welcomeCard.classList.add('hidden');
            scanForm.classList.remove('hidden');
        });
    }

    // Go back to welcome screen
    if (backBtn) {
        backBtn.addEventListener('click', function() {
            scanForm.classList.add('hidden');
            welcomeCard.classList.remove('hidden');
            // Clear any previous results or errors
            errorMessage.style.display = 'none';
            resultsSection.classList.add('hidden');
        });
    }

    // Handle form submission
    if (scanForm) {
        scanForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const urlInput = document.getElementById('url');
            const modeInput = document.getElementById('mode');
            const url = urlInput.value.trim();
            const mode = modeInput.value;
            
            if (!url) {
                showError('Please enter a URL');
                return;
            }

            // Hide previous error messages
            const errorMessage = document.getElementById('errorMessage');
            if (errorMessage) {
                errorMessage.style.display = 'none';
            }

            // Show loading spinner
            const loadingSpinner = document.getElementById('loadingSpinner');
            if (loadingSpinner) {
                loadingSpinner.classList.remove('hidden');
            }
            
            fetch('/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    url: url,
                    mode: mode
                })
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                if (loadingSpinner) {
                    loadingSpinner.classList.add('hidden');
                }
                
                if (data.error) {
                    throw new Error(data.error);
                }

                displayResults(data);
            })
            .catch(error => {
                if (loadingSpinner) {
                    loadingSpinner.classList.add('hidden');
                }
                showError(error.message || 'An error occurred during the scan');
                console.error('Error:', error);
            });
        });
    }
}); 