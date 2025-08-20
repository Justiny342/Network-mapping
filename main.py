import nmap
import sys
import requests

def get_vulnerabilities(cpe):
    """
    Queries the CVEDB API for vulnerabilities associated with a given CPE.
    """
    if not cpe:
        return None

    # Fix CPE format if needed
    if cpe.startswith('cpe:/'):
        cpe = 'cpe:2.3:' + cpe[5:]

    try:
        url = f"https://cvedb.shodan.io/cves?cpe23={cpe}"
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for bad status codes
        return response.json()
    except Exception as e:
        print(f"Error querying vulnerability database: {e}", file=sys.stderr)
        return None

def scan_host(host):
    """
    Scans the given host for open ports, services, and vulnerabilities.
    """
    try:
        nm = nmap.PortScanner()
        # Scan for services and versions, and try to get CPEs
        nm.scan(host, '1-1024', arguments='-sV')
        scan_results = []
        for host in nm.all_hosts():
            host_info = {"host": host, "hostname": nm[host].hostname(), "state": nm[host].state(), "protocols": []}
            if 'tcp' in nm[host]:
                proto_info = {"protocol": 'tcp', "ports": []}
                lport = nm[host]['tcp'].keys()
                sorted_lport = sorted(lport)
                for port in sorted_lport:
                    port_info = nm[host]['tcp'][port]
                    if port_info['state'] == 'open':
                        cpe = port_info.get('cpe', '')
                        if cpe == 'cpe:/o:linux:linux_kernel':
                            vulnerabilities = None
                        else:
                            vulnerabilities = get_vulnerabilities(cpe)
                        port_info['vulnerabilities'] = vulnerabilities
                        proto_info["ports"].append(port_info)
                host_info["protocols"].append(proto_info)
            scan_results.append(host_info)
        return scan_results
    except nmap.PortScannerError:
        print("Nmap not found", file=sys.stderr)
        return []

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="A simple vulnerability scanner.")
    parser.add_argument("host", help="The target host to scan.")
    args = parser.parse_args()

    target = args.host

    print(f"Scanning {target} for open ports, services, and vulnerabilities...")
    results = scan_host(target)
    if results:
        for result in results:
            print(f"Host: {result['host']} ({result['hostname']})")
            print(f"State: {result['state']}")
            for proto in result["protocols"]:
                print("----------")
                print(f"Protocol: {proto['protocol']}")
                for port_info in proto["ports"]:
                    print(f"  Port: {port_info['name']} ({port_info['product']} {port_info['version']})")
                    print(f"  State: {port_info['state']}")
                    cpe = port_info.get('cpe', 'N/A')
                    print(f"  CPE: {cpe}")
                    vulnerabilities = port_info.get('vulnerabilities')
                    if vulnerabilities and vulnerabilities.get('total', 0) > 0:
                        print("  Vulnerabilities:")
                        for vuln in vulnerabilities.get('data', []):
                            print(f"    - {vuln['cve_id']}: {vuln['summary']}")
                    else:
                        print("  No vulnerabilities found for this service.")
    else:
        print(f"No open ports found on {target} or host is down.")
