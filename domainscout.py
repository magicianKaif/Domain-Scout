
import socket
import urllib.parse
import re
import requests
import argparse
import nmap


def validate_url(address):
    pattern = re.compile(r"^(https?:\/\/)?(([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})$")
    return pattern.match(address)


def get_ip(address):
    try:
        parsed_url = urllib.parse.urlparse(address if address.startswith("http") else f"http://{address}")
        domain = parsed_url.netloc or parsed_url.path
        return socket.gethostbyname(domain)
    except Exception as e:
        print(f"[!] Failed to resolve IP: {e}")
        return None


def reverse_dns_lookup(ip_address):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror:
        return "No reverse DNS record found."


def ip_geolocation(ip_address):
    try:
        response = requests.get(f"https://ipinfo.io/{ip_address}/json", timeout=5)
        data = response.json()
        return {
            "City": data.get("city", "Unknown"),
            "Region": data.get("region", "Unknown"),
            "Country": data.get("country", "Unknown"),
            "Organization": data.get("org", "Unknown"),
            "Location": data.get("loc", "Unknown"),
        }
    except Exception as e:
        return {"Error": str(e)}


def perform_nmap_scan(ip_address, ports="1-65535"):
    nm = nmap.PortScanner()
    print(f"\n[+] Scanning {ip_address} ports {ports} with Nmap...")
    try:
        nm.scan(ip_address, ports, arguments="-sV -O --script vuln")
        result = {"OS": "Unknown", "Ports": []}
        for host in nm.all_hosts():
            result["OS"] = nm[host].get("osmatch", [{}])[0].get("name", "Unknown OS")
            for proto in nm[host].all_protocols():
                for port in nm[host][proto]:
                    svc = nm[host][proto][port]
                    result["Ports"].append({
                        "port": port,
                        "state": svc.get("state", ""),
                        "name": svc.get("name", ""),
                        "product": svc.get("product", ""),
                        "version": svc.get("version", ""),
                        "cpe": svc.get("cpe", ""),
                    })
        return result
    except Exception as e:
        return {"Error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="Advanced Website/IP Scanner by magician slime")
    parser.add_argument("-u", "--url", required=True, help="Target website or IP")
    parser.add_argument("-p", "--ports", default="1-1000", help="Custom port list (e.g., 21,22,80) or 'all'")
    args = parser.parse_args()

    if not validate_url(args.url):
        print("[!] Invalid URL format.")
        return

    ip = get_ip(args.url)
    if not ip:
        return

    print(f"\n[+] Target: {args.url}")
    print(f"[+] IP: {ip}")
    print(f"[+] Reverse DNS: {reverse_dns_lookup(ip)}")

    geo = ip_geolocation(ip)
    print("\n[+] Geolocation:")
    for k, v in geo.items():
        print(f"   {k}: {v}")

    ports = args.ports if args.ports != "all" else "1-65535"
    scan = perform_nmap_scan(ip, ports)
    print(f"\n[+] OS Detection: {scan.get('OS', 'Unknown')}")
    print("\n[+] Open Ports and Services:")
    for svc in scan.get("Ports", []):
        print(f" - Port {svc['port']} [{svc['state']}] {svc['name']} {svc['product']} {svc['version']}")
        if svc['cpe']:
            print(f"   â†³ CPE: {svc['cpe']}")

if __name__ == "__main__":
    main()
