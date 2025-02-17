#!/usr/bin/env python3

import sys
import socket
import subprocess
import requests
import whois
import nmap

def dns_lookup(target):
    """
    Resolve the domain/IP to get DNS information.
    """
    dns_info = {}
    try:
        # socket.gethostbyname_ex returns (hostname, aliaslist, ipaddrlist)
        hostname, aliases, ip_addresses = socket.gethostbyname_ex(target)
        dns_info["Resolved Hostname"] = hostname
        dns_info["Aliases"] = aliases
        dns_info["IP Addresses"] = ip_addresses
    except socket.gaierror as e:
        dns_info["Error"] = f"DNS resolution failed: {e}"
    return dns_info


def whois_lookup(target):
    """
    Perform a WHOIS lookup on the domain. 
    If the target is an IP, results may vary or be limited.
    """
    try:
        w = whois.whois(target)
        # Convert the WHOIS object to a dict for easy printing
        return dict(w)
    except Exception as e:
        return {"Error": f"WHOIS lookup failed: {e}"}


def http_fingerprint(target):
    """
    Make a simple HTTP and HTTPS request to gather headers and status.
    """
    results = {}
    for scheme in ["http", "https"]:
        url = f"{scheme}://{target}"
        try:
            r = requests.get(url, timeout=5)
            results[scheme] = {
                "Status Code": r.status_code,
                "Headers": dict(r.headers),
                "Server": r.headers.get("Server", "N/A"),
                "Title": parse_html_title(r.text)
            }
        except requests.exceptions.RequestException as e:
            results[scheme] = {"Error": str(e)}
    return results


def parse_html_title(html_content):
    """
    A very basic HTML title parser.
    """
    start = html_content.lower().find("<title>")
    end = html_content.lower().find("</title>")
    if start != -1 and end != -1:
        return html_content[start+7:end].strip()
    return "N/A"


def nmap_scan(target, ports="80,443,8080,8443"):
    """
    Use python-nmap to scan for open ports and gather basic service info.
    The default scan list is for common HTTP/HTTPS ports.
    Adjust ports as needed.
    """
    nm = nmap.PortScanner()
    scan_data = {}
    try:
        # -sV for version detection; can be changed based on needs
        nm.scan(hosts=target, ports=ports, arguments="-sV")
        
        if target in nm.all_hosts():
            host_data = nm[target]
            scan_data["State"] = host_data.state()
            scan_data["Scan Stats"] = nm.scanstats()
            scan_data["Open Ports"] = {}
            
            for proto in host_data.all_protocols():
                lport = host_data[proto].keys()
                for port in lport:
                    port_state = host_data[proto][port]["state"]
                    service_name = host_data[proto][port]["name"]
                    product = host_data[proto][port].get("product", "")
                    version = host_data[proto][port].get("version", "")
                    extrainfo = host_data[proto][port].get("extrainfo", "")
                    scan_data["Open Ports"][port] = {
                        "Protocol": proto,
                        "State": port_state,
                        "Service": service_name,
                        "Product": product,
                        "Version": version,
                        "Extra Info": extrainfo
                    }
        else:
            scan_data["Error"] = f"No information returned for {target}"
    except Exception as e:
        scan_data["Error"] = f"Nmap scan failed: {e}"
    
    return scan_data


def print_report(dns_info, whois_info, http_info, nmap_info, target):
    """
    Nicely format the results for console output.
    """
    print("=" * 60)
    print(f" Web Application Fingerprinting Report for: {target}")
    print("=" * 60)
    
    # DNS Section
    print("\n[+] DNS Information:")
    for k, v in dns_info.items():
        print(f"    {k}: {v}")
    
    # WHOIS Section
    print("\n[+] WHOIS Information:")
    if "Error" in whois_info:
        print(f"    {whois_info['Error']}")
    else:
        # Print some key WHOIS fields
        interesting_fields = [
            "domain_name", "registrar", "creation_date", 
            "expiration_date", "name_servers"
        ]
        for field in interesting_fields:
            if field in whois_info:
                print(f"    {field}: {whois_info[field]}")
    
    # HTTP Fingerprinting
    print("\n[+] HTTP Fingerprint:")
    for scheme, data in http_info.items():
        print(f"    Scheme: {scheme.upper()}")
        if "Error" in data:
            print(f"       Error: {data['Error']}")
        else:
            print(f"       Status Code: {data['Status Code']}")
            print(f"       Server: {data['Server']}")
            print(f"       Title: {data['Title']}")
            print(f"       Headers:")
            for header_key, header_value in data["Headers"].items():
                print(f"         {header_key}: {header_value}")

    # Nmap Results
    print("\n[+] Nmap Scan Results:")
    if "Error" in nmap_info:
        print(f"    {nmap_info['Error']}")
    else:
        print(f"    Host State: {nmap_info['State']}")
        print(f"    Scan Stats: {nmap_info['Scan Stats']}")
        if "Open Ports" in nmap_info:
            print("    Open Ports:")
            for port, details in nmap_info["Open Ports"].items():
                print(f"        Port {port}/{details['Protocol']}: {details['State']} - {details['Service']}")
                if details['Product'] or details['Version']:
                    print(f"            Product/Version: {details['Product']} {details['Version']}")
                if details['Extra Info']:
                    print(f"            Extra Info: {details['Extra Info']}")

    print("=" * 60)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <domain_or_ip>")
        sys.exit(1)
    
    target = sys.argv[1]
    
    dns_info = dns_lookup(target)
    whois_info = whois_lookup(target)
    http_info = http_fingerprint(target)
    nmap_info = nmap_scan(target)

    print_report(dns_info, whois_info, http_info, nmap_info, target)


if __name__ == "__main__":
    main() 