from flask import Flask, render_template, request
import requests
from flask_mail import Mail, Message
import ssl
import socket
import time
from bs4 import BeautifulSoup

app = Flask(__name__)

# Placeholder to store scan results (this will be changed later to a database)
scan_results = []


@app.route('/')
def index():
    return render_template('index.html', results=scan_results)


@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url')

    # Perform vulnerability checks
    scan_result = perform_scan(url)

    scan_results.append(scan_result)
    return render_template('index.html', results=scan_results)


def perform_scan(url):
    result = {
        'url': url,
        'sql_injection': check_sql_injection(url),
        'xss': check_xss(url),
        'ssl': check_ssl(url),
        'open_ports': check_open_ports(url)
    }

    return result


# Function to load payloads from a file
def load_payloads(file_path):
    with open(file_path, 'r') as file:
        return file.read().splitlines()





def check_sql_injection(url):
    sql_payloads = load_payloads('sql.txt')  # Load SQL payloads from the file
    form_fields = find_input_fields(url)  # Find input fields dynamically

    vulnerabilities = {}
    for field in form_fields:
        for payload in sql_payloads:
            test_url = f"{url}?{field}={payload}"  # Inject SQL payload into input fields
            try:
                response = requests.get(test_url)
                if "error" in response.text or "syntax" in response.text:
                    if field not in vulnerabilities:
                        vulnerabilities[field] = "SQL Injection Detected"
            except requests.exceptions.RequestException:
                continue  # If there's a request error, continue checking other fields

    return vulnerabilities if vulnerabilities else "No SQL Injection Detected"


def check_xss(url):
    xss_payloads = load_payloads('xss.txt')  # Load XSS payloads from the file
    form_fields = find_input_fields(url)  # Find input fields dynamically

    vulnerabilities = {}

    # Loop through all form fields and inject XSS payloads
    for field in form_fields:
        for payload in xss_payloads:
            # Inject payload into the URL
            test_url = f"{url}?{field}={payload}"
            try:
                response = requests.get(test_url)

                # Check if the payload is reflected in the response body
                if payload in response.text:
                    # Check if the payload is reflected within JavaScript context (e.g., <script> tag)
                    if "<script>" in response.text or "<img" in response.text:
                        vulnerabilities[field] = "XSS Detected"
                        break  # Stop checking further payloads once we find a vulnerability

            except requests.exceptions.RequestException:
                continue  # If there's a request error, continue checking other fields

    return vulnerabilities if vulnerabilities else "No XSS Detected"


def find_input_fields(url):
    try:
        # Fetch the webpage content
        response = requests.get(url)

        # Check if the request was successful
        if response.status_code != 200:
            print(f"Failed to fetch page. Status code: {response.status_code}")
            return []

        # Parse the page content with BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')

        form_fields = []

        # Find all input, select, textarea, and button fields
        inputs = soup.find_all(['input', 'textarea', 'select', 'button'])

        # Extract 'name' attributes (and 'id' or 'class' if needed)
        for element in inputs:
            name = element.get('name')
            if name:  # Only consider elements with a 'name' attribute
                form_fields.append(name)
            else:
                # Optionally, include fields without a 'name' attribute if you want to explore them
                id_attr = element.get('id')
                class_attr = element.get('class')
                if id_attr or class_attr:
                    form_fields.append(f"ID/Class: {id_attr or class_attr}")

        return form_fields

    except requests.exceptions.RequestException as e:
        print(f"Error fetching URL: {e}")
        return []

def check_ssl(url):
    # Check if the URL starts with "http:// or "https://"
    if not (url.startswith("http://") or url.startswith("https://")):
        return "Invalid URL format. Please use http:// or https://"

    # Remove the protocol part of the URL (http:// or https://)
    domain = url.split("//")[-1].split("/")[0]

    try:
        # Create a socket connection and check the SSL certificate
        context = ssl.create_default_context()
        connection = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        connection.connect((domain, 443))  # Connect to HTTPS port

        cert = connection.getpeercert()
        cert_expiry = cert['notAfter']  # Expiry date of SSL certificate

        # Check if the SSL certificate is expired
        if cert_expiry < ssl.cert_time_to_seconds(time.time()):
            return "Expired SSL certificate"

        return "Valid SSL certificate"

    except socket.gaierror:
        # This error occurs when DNS resolution fails
        return "Unable to resolve domain or DNS lookup failed"
    except ssl.SSLError:
        # If SSL connection fails, the certificate is expired
        return "Expired SSL certificate"
    except Exception as e:
        # Any other errors
        return f"An error occurred: {str(e)}"


# Placeholder for open port check (to be improved)
def check_open_ports(url):
    common_ports = [80, 443, 21, 22, 23, 25, 8080, 3306]  # Common ports for HTTP, HTTPS, FTP, MySQL, etc.
    open_ports = []

    # Remove 'http://' or 'https://' from the URL
    domain = url.split("//")[-1].split("/")[0]

    for port in common_ports:
        try:
            # Try to connect to the port
            sock = socket.create_connection((domain, port), timeout=5)
            open_ports.append(port)
            sock.close()
        except socket.error:
            pass  # If connection fails, it's not open

    if open_ports:
        return f"Open ports: {', '.join(map(str, open_ports))}"
    else:
        return "No open ports found"


if __name__ == '__main__':
    app.run(debug=True)
