from flask import Flask, render_template, request, jsonify
import os
import subprocess
import requests
import dns.resolver
import whois
import shodan
import socket

app = Flask(__name__, template_folder=os.path.dirname(os.path.abspath(__file__)))  # Set template folder to the current directory

# SHODAN API (Set your API key here)
SHODAN_API_KEY = 'OefcMxcunkm72Po71vVtX8zUN57vQtAC'
api = shodan.Shodan(SHODAN_API_KEY)

# SecurityTrails API (Set your API key here)
SECURITYTRAILS_API_KEY = 'Trd1LDxB7JVbslNfoqDSeGyF-VbWQOaz'

# Route for the main lookup page
@app.route('/')
def index():
    return render_template('index.html')  # This will now look in the same folder as app.py

# Route for the domain lookup functionality
@app.route('/lookup', methods=['POST'])
def lookup():
    domain = request.form.get('domain')
    result = {}

    if not domain:
        return jsonify({"error": "Domain not provided"}), 400

    try:
        # WHOIS Lookup
        result['whois'] = whois_lookup(domain)

        # DNS Lookup (IP address and Nameservers)
        ip, nameservers = get_ip_and_nameservers(domain)
        if ip is None:
            return jsonify({"error": nameservers}), 500

        result['ip'] = ip
        result['nameservers'] = nameservers

        # IP Info (IPinfo)
        result['ip_info'] = get_ipinfo(ip)

        # DNS History Search
        result['dns_history'] = get_dns_history(domain)

        # Subdomain Enumeration
        result['subdomains'] = enumerate_subdomains(domain)

        # Reverse IP Lookup
        result['reverse_ip'] = reverse_ip_lookup(domain)

        # HTTP Header Analysis
        result['http_headers'] = http_header_analysis(domain)

        # SSL/TLS Certificate Transparency Logs
        result['ssl_logs'] = ssl_certificate_logs(domain)

        # Reverse DNS Lookup
        result['reverse_dns'] = reverse_dns(domain)

        # Port Scanning
        result['port_scan'] = port_scan(domain)

        # Traceroute
        result['traceroute'] = traceroute(domain)

        # BGP Data (Border Gateway Protocol)
        result['bgp_data'] = bgp_analysis(domain)

        # Mail Server (MX) Lookup
        result['mx_lookup'] = mx_lookup(domain)

        # Shodan IP Lookup (Origin IP Finder)
        result['shodan_data'] = shodan_ip_lookup(domain)

        # DNSDumpster Lookup (placeholder)
        result['dns_dumpster'] = dns_dumpster_lookup(domain)

        # SecurityTrails Lookup
        result['securitytrails'] = securitytrails_lookup(domain)

        # ThreatCrowd Lookup (replacing Censys)
        result['threatcrowd'] = threatcrowd_lookup(domain)

        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)})

# Function to get WHOIS information
def whois_lookup(domain):
    try:
        domain_info = whois.whois(domain)
        return domain_info
    except Exception as e:
        return str(e)

# Function to get IP address and nameservers
def get_ip_and_nameservers(domain):
    try:
        ip = socket.gethostbyname(domain)
        result = dns.resolver.resolve(domain, 'NS')
        nameservers = [str(ns) for ns in result]
        return ip, nameservers
    except Exception as e:
        return None, str(e)

# Function to get IP information
def get_ipinfo(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        return response.json()
    except Exception as e:
        return str(e)

# DNS History Search using SecurityTrails API
def get_dns_history(domain):
    try:
        url = f"https://api.securitytrails.com/v1/domain/{domain}/history/dns"
        headers = {"APIKEY": SECURITYTRAILS_API_KEY}
        response = requests.get(url, headers=headers)
        return response.json()
    except Exception as e:
        return str(e)

# Subdomain Enumeration using Sublist3r
def enumerate_subdomains(domain):
    try:
        output = subprocess.check_output(['sublist3r', '-d', domain])
        subdomains = output.decode().splitlines()
        return subdomains
    except Exception as e:
        return str(e)

# Reverse IP Lookup
def reverse_ip_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        reverse_ip = socket.gethostbyaddr(ip)
        return reverse_ip
    except Exception as e:
        return str(e)

# HTTP Header Analysis
def http_header_analysis(domain):
    try:
        response = requests.get(f'http://{domain}', timeout=5)
        headers = response.headers
        return dict(headers)
    except Exception as e:
        return str(e)

# SSL/TLS Certificate Transparency Logs
def ssl_certificate_logs(domain):
    try:
        response = requests.get(f"https://crt.sh/?q={domain}&output=json")
        cert_data = response.json()
        return cert_data
    except Exception as e:
        return str(e)

# Reverse DNS Lookup
def reverse_dns(domain):
    try:
        ip = socket.gethostbyname(domain)
        return socket.gethostbyaddr(ip)
    except Exception as e:
        return str(e)

# Port Scanning using Nmap
def port_scan(domain):
    try:
        output = subprocess.check_output(['nmap', '-Pn', domain])
        return output.decode()
    except Exception as e:
        return str(e)

# Traceroute
def traceroute(domain):
    try:
        output = subprocess.check_output(['traceroute', domain])
        return output.decode()
    except Exception as e:
        return str(e)

# BGP Data (Border Gateway Protocol)
def bgp_analysis(domain):
    try:
        # Use external services like Hurricane Electric BGP Toolkit
        # Example placeholder:
        return f'BGP data analysis for {domain}'
    except Exception as e:
        return str(e)

# Mail Server (MX) Lookup
def mx_lookup(domain):
    try:
        resolver = dns.resolver.Resolver()
        mx_records = resolver.resolve(domain, 'MX')
        return [str(record.exchange) for record in mx_records]
    except Exception as e:
        return str(e)

# Shodan IP Lookup
def shodan_ip_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        host = api.host(ip)
        return host
    except shodan.APIError as e:
        return str(e)

# DNSDumpster Lookup (placeholder for integration)
def dns_dumpster_lookup(domain):
    try:
        # Implement DNS Dumpster API or scraping logic
        return f"DNSDumpster data for {domain}"
    except Exception as e:
        return str(e)

# SecurityTrails Lookup for domain data
def securitytrails_lookup(domain):
    try:
        url = f"https://api.securitytrails.com/v1/domain/{domain}"
        headers = {"APIKEY": SECURITYTRAILS_API_KEY}
        response = requests.get(url, headers=headers)
        return response.json()
    except Exception as e:
        return str(e)

# ThreatCrowd Lookup for domain or IP (replacing Censys)
def threatcrowd_lookup(domain):
    try:
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        response = requests.get(url)
        return response.json()
    except Exception as e:
        return str(e)

# Running the Flask app
if __name__ == '__main__':
    app.run(debug=True)
