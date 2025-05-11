# 🚨 Red Team Web Recon Tool

A web-based automated vulnerability scanner built with **Flask**, designed to assist red teamers and ethical hackers with **quick reconnaissance** of target websites.

This tool performs **multiple security checks** including:

- SQL Injection
- XSS Injection
- SSL Certificate Validation
- Open Port Detection

---

## 🎯 Key Features

✅ Detects SQL Injection vulnerabilities by injecting payloads into discovered form fields

✅ Detects XSS reflection in HTML responses using dynamic analysis

🔍 Uses BeautifulSoup to automatically extract input fields from the target web page for payload injection

📂 Supports custom payload uploads: users can provide their own payloads via sql.txt and xss.txt files

✅ Verifies SSL certificate status and expiration

✅ Scans for open common ports (e.g., 80, 443, 22, etc.)

📝 Simple web interface built with Flask for entering URLs and viewing scan results

🧠 Easy to extend: currently stores results in memory, but can be upgraded to use a database

---

![image](https://github.com/user-attachments/assets/b1bfbcc4-37cc-4aec-8a7a-20311ae6b19e)


## 🚀 Getting Started
To run this tool locally: 
📥 Installation bash git clone https://github.com/akmal-cyb/Red-Team-Web-Recon-Tool.git
You can run and debug the project easily in PyCharm by opening the project folder and running app.py.





