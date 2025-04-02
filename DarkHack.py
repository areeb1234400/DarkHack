import os
import requests
import shodan
import whois
import socket
import dns.resolver
import subprocess
from bs4 import BeautifulSoup
from googlesearch import search

# Shodan API Key (Replace with your actual API key)
SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"

# Function: Subdomain Enumeration
def subdomain_enum():
    domain = input("Enter domain for subdomain enumeration: ").strip()
    wordlist = ["www", "mail", "ftp", "dev", "test", "admin", "beta", "portal"]

    print(f"Enumerating subdomains for {domain}...\n")
    for sub in wordlist:
        subdomain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(subdomain)
            print(f"[+] {subdomain} -> {ip}")
        except socket.gaierror:
            pass

# Function: WHOIS & DNS Lookup
def whois_lookup():
    domain = input("Enter domain for WHOIS lookup: ").strip()
    try:
        info = whois.whois(domain)
        print(info)
    except Exception as e:
        print(f"WHOIS Lookup Error: {e}")

def dns_lookup():
    domain = input("Enter domain for DNS lookup: ").strip()
    record_types = ["A", "MX", "NS", "TXT"]

    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record)
            print(f"\n{record} Records:")
            for answer in answers:
                print(answer.to_text())
        except dns.resolver.NoAnswer:
            print(f"No {record} records found for {domain}.")
        except dns.resolver.NXDOMAIN:
            print(f"Domain {domain} does not exist.")

# Function: Port Scanning
def port_scan():
    target = input("Enter IP or domain for port scanning: ").strip()
    print(f"Scanning {target} for open ports...")

    command = f"nmap -sS -T4 -p- {target}"
    subprocess.run(command, shell=True)

# Function: Web Scraper
def web_scraper():
    url = input("Enter URL to scrape: ").strip()
    print(f"Scraping {url} for data...")

    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(url, headers=headers)
        soup = BeautifulSoup(response.text, "html.parser")

        print("\nExtracted Links:")
        for link in soup.find_all("a", href=True):
            print(link["href"])
    except requests.exceptions.RequestException as e:
        print(f"Web Scraping Error: {e}")

# Function: Social Media Recon
def social_recon():
    username = input("Enter username for social media recon: ").strip()
    platforms = {
        "GitHub": f"https://github.com/{username}",
        "Twitter": f"https://twitter.com/{username}",
        "Instagram": f"https://www.instagram.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}"
    }

    for platform, url in platforms.items():
        try:
            response = requests.get(url)
            if response.status_code == 200:
                print(f"[+] {platform} Profile Found: {url}")
            else:
                print(f"[-] {platform} Profile Not Found")
        except requests.exceptions.RequestException:
            print(f"[-] Error accessing {platform}")

# Function: Google Dorking
def google_dorking():
    dork = input("Enter Google Dork query: ").strip()
    print(f"Searching Google for: {dork}")

    try:
        for result in search(dork, num=5, stop=5, pause=2):
            print(result)
    except Exception as e:
        print(f"Google Dorking Error: {e}")

# Function: Shodan Search
def shodan_search():
    query = input("Enter Shodan search query: ").strip()
    print(f"Searching Shodan for: {query}")

    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        results = api.search(query)

        for result in results["matches"][:5]:
            print(f"IP: {result['ip_str']} | Port: {result['port']} | Org: {result.get('org', 'N/A')}")
    except shodan.APIError as e:
        print(f"Shodan Error: {e}")

# Main Menu
def main():
    print("""
    ██████╗  █████╗ ██████╗ ██╗  ██╗██╗  ██╗
    ██╔══██╗██╔══██╗██╔══██╗██║  ██║██║  ██║
    ██████╔╝███████║██████╔╝███████║███████║
    ██╔═══╝ ██╔══██║██╔═══╝ ██╔══██║██╔══██║
    ██║     ██║  ██║██║     ██║  ██║██║  ██║
    ╚═╝     ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝
    """)

    print("[1] Subdomain Enumeration")
    print("[2] WHOIS & DNS Lookup")
    print("[3] Port Scanning")
    print("[4] Web Scraper & Crawler")
    print("[5] Social Media Recon")
    print("[6] Google Dorking")
    print("[7] Shodan Search")

    choice = input("Choose an option (1-7): ").strip()

    if choice == "1":
        subdomain_enum()
    elif choice == "2":
        whois_lookup()
        dns_lookup()
    elif choice == "3":
        port_scan()
    elif choice == "4":
        web_scraper()
    elif choice == "5":
        social_recon()
    elif choice == "6":
        google_dorking()
    elif choice == "7":
        shodan_search()
    else:
        print("Invalid choice. Exiting...")

if __name__ == "__main__":
    main()
