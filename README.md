# Mini-Project-OWASP
This project is a beginner-level cybersecurity learning project developed as part of my cybersecurity training journey. It combines the programming knowledge I have learned with AI-assisted development to create a simple tool that helps identify potential security issues related to the OWASP Top 10 Web Application Security Risks. 



# 🔐 OWASP Security Lab

OWASP Security Lab is a Python-based desktop application designed to help students and cybersecurity enthusiasts explore common web security issues based on the **OWASP Top 10**. The application scans a target web application for common security weaknesses, explains the findings, and generates reports to help users understand potential risks.

Instead of acting as an exploitation tool, the project focuses on **security assessment and education**, making it suitable for learning how web vulnerabilities are identified and analyzed in a controlled environment.

---

## 🚀 Features

- Scan web applications for common OWASP Top 10 vulnerabilities
- Check HTTP security headers
- Analyze cookie security settings
- Detect input validation weaknesses
- Review authentication-related security issues
- Calculate risk scores for discovered findings
- Generate detailed PDF security reports
- User-friendly GUI built with CustomTkinter
- Built-in learning section explaining each vulnerability
- Logging and scan history support

---

## 📂 Project Structure

```text
OWASP-Security-Lab/
│
├── gui/
│   ├── Dashboard
│   ├── Scan Page
│   ├── Findings Page
│   ├── Reports Page
│   ├── Learning Page
│   └── Settings Page
│
├── scanner/
│   ├── Scanner Engine
│   ├── HTTP Headers
│   ├── Cookies
│   ├── Authentication Checks
│   ├── Input Validation
│   ├── Configuration
│   └── Data Models
│
├── reports/
│   └── PDF Report Generator
│
├── database/
│   └── Database Manager
│
├── utils/
│   ├── Risk Scoring
│   ├── Threat Intelligence
│   └── Logging
│
├── assets/
├── main.py
└── requirements.txt
```

---

## ⚙️ Technologies

- Python 3.11+
- CustomTkinter
- SQLite
- Requests
- BeautifulSoup (where applicable)
- ReportLab
- Windows/Linux compatible

---

## 🎯 How It Works

The application performs a series of security assessments against a target web application.

The scanning workflow includes:

1. Connecting to the target website.
2. Inspecting HTTP response headers.
3. Checking cookie security attributes.
4. Evaluating authentication-related configurations.
5. Testing for common input validation issues.
6. Assigning a risk score based on the detected findings.
7. Saving the results and generating a PDF security report.

---

## 📊 Security Checks

The scanner evaluates several common security areas, including:

- Missing or insecure HTTP security headers
- Weak cookie configurations
- Authentication security issues
- Input validation weaknesses
- Configuration-related security problems
- Overall risk scoring based on discovered findings

> **Note:** The scan results are intended to highlight potential security issues. Manual verification is recommended before drawing conclusions or making security decisions.

---

## 🖥️ Requirements

- Python 3.11 or later
- Dependencies listed in `requirements.txt`

---

## ▶️ Installation

```bash
git clone https://github.com/yourusername/OWASP-Security-Lab.git

cd OWASP-Security-Lab

pip install -r requirements.txt

python main.py
```

---

## 📚 Educational Purpose

This project was created as a learning platform for understanding the **OWASP Top 10** and the fundamentals of secure web application assessment. It demonstrates how common security checks are performed while helping users understand why these vulnerabilities matter and how they can be mitigated.

---

## ⚠️ Disclaimer

OWASP Security Lab is intended **solely for educational and defensive cybersecurity purposes**. The application is designed to assess web applications that you own or are explicitly authorized to test. Always obtain proper permission before scanning any systems. Unauthorized security testing may violate laws or organizational policies.

---

## 📌 GitHub Description

**A Python-based web security assessment tool that scans applications for OWASP Top 10 security issues, analyzes common misconfigurations, and generates detailed security reports for educational purposes.**
```
