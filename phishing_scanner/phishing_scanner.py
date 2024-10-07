

import requests
from bs4 import BeautifulSoup
import re
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime

def scan_phishing_links(url):
    try:
       
        response = requests.get(url, timeout=10) #http request to the URL
        response.raise_for_status()
        html_content = response.text

        soup = BeautifulSoup(html_content, 'html.parser') #parsing html

        links = soup.find_all('a')

        
        phishing_patterns = [       #list of common pattern
            r'account\.log-in\.php',
            r'login\.php',
            r'signin\.php',
            r'auth\.php',
            r'signup\.php',
            r'register\.php',
            r'reset\.php',
            r'forgot\.php',
            r'account\.php',
            r'user\.php',
            r'profile\.php'
        ]

        
        phishing_links = [] 
        for link in links:
            href = link.get('href')
            if href:
                for pattern in phishing_patterns: #checking
                    if re.search(pattern, href, re.IGNORECASE):
                        phishing_links.append(href)

        return phishing_links

    except requests.exceptions.RequestException as e:
        print(f"Error fetching URL: {e}")
        return []

def check_blacklist_domains(url, blacklist_file):
    try:
        with open(blacklist_file, 'r') as file:
            blacklist_domains = [line.strip() for line in file]

        return url in blacklist_domains
    except FileNotFoundError:
        print(f"Blacklist file '{blacklist_file}' not found.")
        return False

def check_ssl_certificate(url):
    parsed_url = urlparse(url)
    
    
    if parsed_url.scheme != 'https':
        print("No SSL check is performed because the URL does not use HTTPS.")
        return False

    hostname = parsed_url.hostname
    port = 443 
    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                # Enhanced SSL checks
                expiry_date_str = cert['notAfter']
                expiry_date = datetime.strptime(expiry_date_str, "%b %d %H:%M:%S %Y %Z")
                issuer = dict(x[0] for x in cert['issuer'])
                subject = dict(x[0] for x in cert['subject'])

                print(f"SSL Certificate Details:")
                print(f" - Subject: {subject}")
                print(f" - Issuer: {issuer}")
                print(f" - Expiry Date: {expiry_date}")

                if expiry_date < datetime.now():
                    print("SSL certificate is expired!")
                    return False
                else:
                    print("SSL certificate is valid.")
                    return True
    except ssl.SSLError as e:
        print(f"SSL certificate error: {e}")
        return False
    except Exception as e:
        print(f"SSL certificate check failed: {e}")
        return False

def main():
 
    url = input("Enter the URL to scan: ")

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            print("Invalid URL format. Please provide a valid URL.")
            return
    except Exception as e:
        print(f"Error parsing URL: {e}")
        return

    blacklist_file = 'blacklist_domains.txt'  #Checking URL for blacklist

    is_blacklisted = check_blacklist_domains(url, blacklist_file)

    has_ssl = check_ssl_certificate(url) #SSL certificate only for HTTPS URLs

    if is_blacklisted and not has_ssl:
        print("This is a phishing link because it is in the blacklist and does not have an SSL certificate.")
    elif is_blacklisted:
        print("This is a phishing link because it is in the blacklist.")
    elif not has_ssl:
        print("This URL does not have an SSL certificate or the certificate is expired.")
    else:
        print("No phishing links detected based on SSL and blacklist checks.")


    phishing_links = scan_phishing_links(url)
    if phishing_links:
        print("Detected Phishing Links:", phishing_links)
    else:
        print("No phishing links detected.")

if __name__ == "__main__":
    main()


"
idea to improve it :
checking nmap usuall ports,
bower intrigation
api intrigation 
ai intrigaion
 "
