# Web Application Fingerprinting Tool

A Python script that performs basic web application fingerprinting by gathering information about a target domain/IP address. The script collects:

1. DNS information (hostname resolution, IP addresses)
2. WHOIS data (domain registration information)
3. HTTP/HTTPS response headers and server information
4. Open ports and service detection using Nmap

## Prerequisites

- Python 3.7 or higher
- Nmap installed on your system
  - Windows: Download and install from [Nmap's official website](https://nmap.org/download.html)
  - Linux: `sudo apt-get install nmap` (Debian/Ubuntu) or `sudo yum install nmap` (RHEL/CentOS)

## Installation

1. Clone or download this repository
2. Install the required Python packages:
   ```powershell
   pip install -r requirements.txt
   ```

## Usage

Run the script by providing a target domain or IP address:

```powershell
python web_fingerprint.py example.com
```

The script will output:
- DNS resolution information
- WHOIS lookup data
- HTTP/HTTPS response headers and server details
- Nmap port scan results for common web ports (80, 443, 8080, 8443)

## Notes

- This is a basic fingerprinting tool for educational purposes
- Some features require administrative/root privileges (especially Nmap scanning)
- Be mindful of scanning restrictions and legal implications when using against targets
- For Windows users: Make sure Nmap is added to your system's PATH environment variable

## Disclaimer

This tool is for educational purposes only. Ensure you have permission to scan any target systems. Unauthorized scanning may be illegal in your jurisdiction. 