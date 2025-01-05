import socket
import urllib.parse
import re
import requests


def validate_url(address):
    """Validate a URL using a simple regex."""
    pattern = re.compile(
        r"^(https?:\/\/)?"  # Optional scheme
        r"(([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})$"  # Domain
    )
    return pattern.match(address)


def get_ip(address):
    """Resolve domain to IP address."""
    try:
        parsed_url = urllib.parse.urlparse(
            address if address.startswith("http") else f"http://{address}"
        )
        domain = parsed_url.netloc or parsed_url.path
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        print(f"Failed to resolve IP for: {address}")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def reverse_dns_lookup(ip_address):
    """Perform reverse DNS lookup."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror:
        return "No reverse DNS record found."


def scan_ports(ip_address, ports=(80, 443, 22, 21, 25)):
    """Scan common ports."""
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)  # Timeout for connection
                if s.connect_ex((ip_address, port)) == 0:
                    open_ports.append(port)
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
    return open_ports


def ip_geolocation(ip_address):
    """Get geolocation data for an IP address using an external API."""
    api_url = f"https://ipinfo.io/{ip_address}/json"
    try:
        response = requests.get(api_url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                "City": data.get("city", "Unknown"),
                "Region": data.get("region", "Unknown"),
                "Country": data.get("country", "Unknown"),
                "Organization": data.get("org", "Unknown"),
                "Location": data.get("loc", "Unknown"),
            }
        else:
            return {
                "Error": f"Failed to fetch data. HTTP Status: {response.status_code}"
            }
    except requests.RequestException as e:
        return {"Error": str(e)}


def main():
    website = input("Enter a website URL (e.g., example.com): ").strip()

    if not validate_url(website):
        print("Invalid URL. Please provide a valid domain (e.g., example.com).")
        return

    ip_address = get_ip(website)
    if not ip_address:
        print(f"Failed to fetch IP address for {website}.")
        return

    print(f"\n[+] Website: {website}\n[+] IP Address: {ip_address}")

    # Reverse DNS Lookup
    hostname = reverse_dns_lookup(ip_address)
    print(f"[+] Reverse DNS: {hostname}")

    # Port Scanning
    print("\nScanning common ports...")
    open_ports = scan_ports(ip_address)
    if open_ports:
        print(f"[+] Open Ports: {', '.join(map(str, open_ports))}")
    else:
        print("[+] No open ports found.")

    # IP Geolocation
    print("\nFetching geolocation information...")
    geolocation = ip_geolocation(ip_address)
    for key, value in geolocation.items():
        print(f"[+] {key}: {value}")


if __name__ == "__main__":
    main()
