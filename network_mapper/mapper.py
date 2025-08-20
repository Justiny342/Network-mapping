import xml.etree.ElementTree as ET
import os

# We will try to import diagrams, but we expect this to fail
try:
    from diagrams import Diagram, Cluster
    from diagrams.aws.compute import EC2
    from diagrams.aws.network import ELB
    DIAGRAMS_AVAILABLE = True
except ImportError:
    DIAGRAMS_AVAILABLE = False

def parse_nmap_xml(xml_file):
    """
    Parses the Nmap XML output file and extracts host information.
    """
    hosts = []
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        for host in root.findall('host'):
            host_info = {}

            address_element = host.find('address')
            if address_element is not None:
                host_info['ip'] = address_element.get('addr')
            else:
                continue

            hostname_element = host.find('hostnames/hostname')
            if hostname_element is not None:
                host_info['hostname'] = hostname_element.get('name')
            else:
                host_info['hostname'] = host_info['ip']

            ports = []
            for port in host.findall('ports/port'):
                port_info = {}
                port_info['portid'] = port.get('portid')
                service_element = port.find('service')
                if service_element is not None:
                    port_info['service'] = service_element.get('name')
                    port_info['product'] = service_element.get('product')
                ports.append(port_info)
            host_info['ports'] = ports

            hosts.append(host_info)

    except ET.ParseError as e:
        print(f"Error parsing XML file: {e}")

    return hosts

def get_dns_servers():
    """
    Reads and parses /etc/resolv.conf to get DNS servers.
    """
    dns_servers = []
    try:
        with open("/etc/resolv.conf", "r") as f:
            for line in f:
                if line.strip().startswith("nameserver"):
                    dns_servers.append(line.strip().split()[1])
    except FileNotFoundError:
        print("Could not find /etc/resolv.conf")
    return dns_servers

def create_network_diagram(hosts, dns_servers, output_filename="network_map"):
    """
    Creates a visual representation of the network using diagrams.
    """
    if not DIAGRAMS_AVAILABLE:
        print("\n'diagrams' library not found. Skipping diagram creation.")
        print("Please install it with: pip install diagrams")
        return

    with Diagram("Network Map", show=False, filename=output_filename):
        with Cluster("Discovered Hosts"):
            host_nodes = []
            for host in hosts:
                # Choose an icon based on open ports
                icon = EC2
                for port in host['ports']:
                    if port['portid'] == '80' or port['portid'] == '443':
                        icon = ELB
                        break

                label = f"{host['hostname']}\n{host['ip']}"
                host_nodes.append(icon(label=label))

        with Cluster("DNS Servers"):
            dns_nodes = [EC2(label=server) for server in dns_servers]

def main():
    """
    Main function to run the command-line version of the network mapper.
    """
    # Build a robust path to the scan file, which is in the project root
    script_dir = os.path.dirname(os.path.abspath(__file__))
    scan_results_file = os.path.join(script_dir, "..", "network_scan.xml")

    if not os.path.exists(scan_results_file):
        print(f"Error: Nmap scan file not found at {scan_results_file}")
        print("Please run the nmap scan first.")
    else:
        discovered_hosts = parse_nmap_xml(scan_results_file)
        dns_servers = get_dns_servers()

        # Print the discovered information
        for host in discovered_hosts:
            print(f"Host: {host['hostname']} ({host['ip']})")
            if host['ports']:
                print("  Open Ports:")
                for port in host['ports']:
                    service = port.get('product', port.get('service', 'unknown'))
                    print(f"    - {port['portid']}/tcp: {service}")
            else:
                print("  No open ports found.")
            print("-" * 20)

        print("DNS Servers:")
        for server in dns_servers:
            print(f"  - {server}")

        # Create the diagram
        create_network_diagram(discovered_hosts, dns_servers)
        if DIAGRAMS_AVAILABLE:
            print("\nNetwork map image generated as network_map.png")

if __name__ == "__main__":
    main()
