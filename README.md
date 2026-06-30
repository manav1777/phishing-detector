# Phishing Detection Tool

## Overview

The **Phishing Detection Tool** is a Python and Flask web application that analyzes URLs for common phishing indicators and suspicious patterns. The tool evaluates a submitted URL, calculates a risk score, and highlights characteristics that may indicate phishing or spoofing attempts.

This project was built to demonstrate how phishing detection systems can identify deceptive URLs commonly used in credential theft and social engineering attacks.

---

## Features

* Analyze URLs for phishing-related indicators
* Generate a risk score based on detected patterns
* Classify URLs as Low, Medium, or High Risk
* Detect suspicious keywords commonly used in phishing attacks
* Identify fake subdomain techniques
* Detect suspicious domain extensions
* User-friendly web interface with built-in examples

---

## Tech Stack

* Python
* Flask
* HTML
* CSS
* Regular Expressions (Regex)

---

## Example Analysis

Input:

```text
http://paypal-secure-login.verify-account.ru
```

Output:

```text
Score: 70/100

Risk Level: High

Detected Indicators:
- Suspicious keywords
- Fake subdomain trick
- Suspicious domain extension
```

---

## How It Works

1. The user submits a URL through the web interface.
2. The application analyzes the URL structure.
3. Detection rules evaluate common phishing indicators.
4. A risk score is calculated.
5. The detected indicators and risk level are displayed to the user.

---

## Installation

Install the required dependency:

```bash
pip install flask
```

Run the application:

```bash
python app.py
```

Open your browser:

```text
http://127.0.0.1:5000
```

---

## Skills Demonstrated

* Cybersecurity analysis
* Phishing detection concepts
* URL parsing and validation
* Pattern matching with regular expressions
* Risk scoring systems
* Flask web development

---

## Key Learning Outcomes

* Understanding phishing attack techniques
* Recognizing deceptive URL structures
* Building rule-based detection systems
* Designing risk classification models
* Developing security-focused web applications

---

## Security Concepts Covered

* Phishing URLs
* Domain spoofing
* Typosquatting techniques
* Fake subdomains
* Social engineering indicators
* Risk assessment and scoring

---

## Future Improvements

* Machine learning-based phishing detection
* Domain reputation checking
* WHOIS integration
* Real-time threat intelligence feeds
* Expanded URL analysis rules
* Scan history and reporting

---

## Author

**Manav Patel**
Cybersecurity Student
Drexel University
