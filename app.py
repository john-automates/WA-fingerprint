#!/usr/bin/env python3

import sys
import os
import socket
import subprocess
import requests
import whois
import nmap

print("[+] START: Web App Fingerprinting Tool")
print("[~] Importing required modules...")

# All required modules imported; continuing...


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
        print(f"[+] DNS lookup successful for: {target}")
    except socket.gaierror as e:
        dns_info["Error"] = f"DNS resolution failed: {e}"
        print(f"[ERROR] DNS lookup failed for {target}: {e}")
    return dns_info


def whois_lookup(target):
    """
    Perform a WHOIS lookup on the domain. 
    If the target is an IP, results may vary or be limited.
    """
    try:
        w = whois.whois(target)
        print(f"[+] WHOIS lookup successful for: {target}")
        # Convert the WHOIS object to a dict for easy printing
        return dict(w)
    except Exception as e:
        print(f"[ERROR] WHOIS lookup failed for {target}: {e}")
        return {"Error": f"WHOIS lookup failed: {e}"}


def parse_html_title(html_content):
    """
    A very basic HTML title parser.
    """
    start = html_content.lower().find("<title>")
    end = html_content.lower().find("</title>")
    if start != -1 and end != -1:
        return html_content[start+7:end].strip()
    return "N/A"


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
            print(f"[+] HTTP fingerprint successful for {scheme.upper()}://{target}")
        except requests.exceptions.RequestException as e:
            results[scheme] = {"Error": str(e)}
            print(f"[ERROR] HTTP request failed for {scheme.upper()}://{target}: {e}")
    return results


def nmap_scan(target, ports="80,443,8080,8443"):
    """
    Use python-nmap to scan for open ports and gather basic service info.
    The default scan list is for common HTTP/HTTPS ports. Adjust ports as needed.
    """
    nm = nmap.PortScanner()
    scan_data = {}
    try:
        print(f"[~] Starting Nmap scan for: {target}")
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
            print(f"[+] Nmap scan completed for: {target}")
        else:
            scan_data["Error"] = f"No information returned for {target}"
            print(f"[ERROR] Nmap scan did not return information for: {target}")
    except Exception as e:
        scan_data["Error"] = f"Nmap scan failed: {e}"
        print(f"[ERROR] Nmap scan failed for {target}: {e}")
        
    return scan_data


def generate_report(dns_info, whois_info, http_info, nmap_info, target):
    """
    Generate a string report with all the gathered information.
    """
    lines = []
    lines.append("=" * 60)
    lines.append(f" Web Application Fingerprinting Report for: {target}")
    lines.append("=" * 60)
    lines.append("")
    
    # DNS Section
    lines.append("[+] DNS Information:")
    for k, v in dns_info.items():
        lines.append(f"    {k}: {v}")
    lines.append("")
    
    # WHOIS Section
    lines.append("[+] WHOIS Information:")
    if "Error" in whois_info:
        lines.append(f"    {whois_info['Error']}")
    else:
        interesting_fields = ["domain_name", "registrar", "creation_date", "expiration_date", "name_servers"]
        for field in interesting_fields:
            if field in whois_info and whois_info[field]:
                lines.append(f"    {field}: {whois_info[field]}")
    lines.append("")
    
    # HTTP Fingerprinting
    lines.append("[+] HTTP Fingerprint:")
    for scheme, data in http_info.items():
        lines.append(f"    Scheme: {scheme.upper()}")
        if "Error" in data:
            lines.append(f"       Error: {data['Error']}")
        else:
            lines.append(f"       Status Code: {data['Status Code']}")
            lines.append(f"       Server: {data['Server']}")
            lines.append(f"       Title: {data['Title']}")
            lines.append(f"       Headers:")
            for header_key, header_value in data["Headers"].items():
                lines.append(f"         {header_key}: {header_value}")
    lines.append("")
    
    # Nmap Results
    lines.append("[+] Nmap Scan Results:")
    if "Error" in nmap_info:
        lines.append(f"    {nmap_info['Error']}")
    else:
        lines.append(f"    Host State: {nmap_info.get('State', 'N/A')}")
        lines.append(f"    Scan Stats: {nmap_info.get('Scan Stats', 'N/A')}")
        if "Open Ports" in nmap_info and nmap_info["Open Ports"]:
            lines.append("    Open Ports:")
            for port, details in nmap_info["Open Ports"].items():
                lines.append(f"        Port {port}/{details['Protocol']}: {details['State']} - {details['Service']}")
                if details['Product'] or details['Version']:
                    lines.append(f"            Product/Version: {details['Product']} {details['Version']}")
                if details['Extra Info']:
                    lines.append(f"            Extra Info: {details['Extra Info']}")
    lines.append("=" * 60)
    
    return "\n".join(lines)


def main():
    print("[~] Checking command line arguments...")
    if len(sys.argv) < 2:
        print(f"[ERROR] Usage: {sys.argv[0]} <domain_or_ip>")
        sys.exit(1)
    
    target = sys.argv[1]
    print(f"[DEBUG] Target to analyze: {target}")
    
    # Perform lookups and scans
    dns_info = dns_lookup(target)
    whois_info = whois_lookup(target)
    http_info = http_fingerprint(target)
    nmap_info = nmap_scan(target)

    # Generate report string
    report = generate_report(dns_info, whois_info, http_info, nmap_info, target)

    # Print report to console
    print(report)

    # Create outputs directory if not present
    print("[~] Preparing output directory...")
    os.makedirs("outputs", exist_ok=True)
    output_file = os.path.join("outputs", f"{target}_fingerprint_report.txt")
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"[+] Report saved to: {output_file}")
    except Exception as e:
        print(f"[ERROR] Could not write report to file: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
    print("[+] END: Web App Fingerprinting Tool")
