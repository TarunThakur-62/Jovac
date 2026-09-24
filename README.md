PhishGuard-AI v5
PhishGuard-AI v5 is an advanced Python-based cybersecurity framework developed for phishing detection, URL analysis, and security investigation. The project combines rule-based security checks, machine learning, network analysis, and threat intelligence techniques to identify suspicious URLs and domains. It provides a terminal-based interface for performing different types of security scans and generating meaningful analysis results.
Features
- Advanced phishing URL detection
- Machine Learning based prediction
- URL syntax and feature analysis
- Domain and hostname analysis
- DNS information analysis
- TLS/SSL certificate verification
- Domain age checking
- IP address analysis
- Subdomain detection
- Suspicious keyword detection
- Punycode detection
- URL shortener detection
- Credential and special-character detection
- Risk score calculation
- Prediction confidence analysis
- Threat intelligence checks
- Scan history management
- Security report generation
- Modular Python architecture
- Interactive terminal interface
Technologies Used
Python, Machine Learning, Linux, DNS, TLS/SSL, JSON, Git and GitHub.
Project Structure
PhishGuard-AI-v5-Final/
├── main.py
├── model.pkl
├── checks/
├── reports/
├── history/
├── data/
└── README.md

Installation and Setup
First, clone the repository using the following command:
git clone -b Phishgurd https://github.com/TarunThakur-62/Jovac.git

Navigate to the project directory:
cd Jovac/PhishGuard-AI-v5-Final

Create a Python virtual environment:
python3 -m venv .venv

Activate the virtual environment:
source .venv/bin/activate

Install the required dependencies:
pip install -r requirements.txt

Run the application:
python3 main.py

After execution, the interactive menu will provide multiple options for URL analysis, machine learning prediction, network checks, DNS/TLS analysis, threat intelligence, history, and report generation.
Objective
The primary objective of PhishGuard-AI v5 is to provide a practical and modular security framework for detecting and investigating potential phishing threats. The project demonstrates how machine learning and traditional cybersecurity techniques can be combined to improve security analysis and threat identification.
Disclaimer
PhishGuard-AI v5 is developed strictly for educational, research, and authorized cybersecurity testing purposes. Do not use this tool to analyze systems, domains, or URLs without proper authorization.
Author
Tarun Thakur
Cybersecurity Student | Ethical Hacking Enthusiast
GitHub: TarunThakur-62
