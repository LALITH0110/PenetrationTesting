import nmap
import json
import socket

def resolve_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None
def scan_service_version(target_ip, output_file):
    scanner = nmap.PortScanner()
    print(f"Scanning {target_ip} for service/version detection...")
    scanner.scan(target_ip, arguments='-sV -O --script vuln')

    with open(output_file, 'w') as f:
        for host in scanner.all_hosts():
            f.write(f"\nHost: {host} ({scanner[host].hostname()})\n")
            f.write(f"State: {scanner[host].state()}\n")

            for protocol in scanner[host].all_protocols():
                f.write(f"\nProtocol: {protocol}\n")
                ports = scanner[host][protocol].keys()
                for port in ports:
                    port_info = scanner[host][protocol][port]
                    f.write(f"Port: {port}\tState: {port_info['state']}\tService: {port_info['name']}\n")
                    if 'product' in port_info:
                        f.write(f"Service version: {port_info['product']} {port_info['version']}\n")

            if 'osmatch' in scanner[host]:
                for osmatch in scanner[host]['osmatch']:
                    f.write(f"OS: {osmatch['name']} ({osmatch['accuracy']}% accuracy)\n")

            for protocol in scanner[host].all_protocols():
                ports = scanner[host][protocol].keys()
                for port in ports:
                    port_info = scanner[host][protocol][port]
                    if 'script' in port_info:
                        for script, output in port_info['script'].items():
                            f.write(f"[{script}] => {output}\n")

    print(f"Results saved to {output_file}")
    print_important_info(scanner, target_ip)

def print_important_info(scanner, target_ip):
    host_data = {
        "IP": target_ip,
        "State": scanner[target_ip].state(),
        "OS": {},
        "Ports": []
    }

    if 'osmatch' in scanner[target_ip]:
        os_match = scanner[target_ip]['osmatch'][0]
        host_data["OS"] = {
            "Name": os_match['name'],
            "Version": os_match['osclass'][0]['osgen'],
            "Accuracy": f"{os_match['accuracy']}%"
        }

    for protocol in scanner[target_ip].all_protocols():
        ports = scanner[target_ip][protocol].keys()
        for port in ports:
            port_info = scanner[target_ip][protocol][port]
            port_data = {
                "Port": port,
                "Protocol": protocol,
                "State": port_info['state'],
                "Service": port_info['name'],
                "Service Version": f"{port_info.get('product', '')} {port_info.get('version', '')}".strip(),
                "Vulnerabilities": []
            }

            if 'script' in port_info:
                for script, output in port_info['script'].items():
                    if script == 'vulners':
                        vulns = parse_vulners_output(output)
                        port_data["Vulnerabilities"] = vulns

            host_data["Ports"].append(port_data)

    print(json.dumps(host_data, indent=2))

def parse_vulners_output(output):
    vulnerabilities = []
    for line in output.split('\n'):
        if line.strip() and not line.startswith('cpe:'):
            parts = line.split()
            if len(parts) >= 3 and parts[1].replace('.', '').isdigit():
                vuln = {
                    "CVE": parts[0],
                    "Severity": float(parts[1]),
                    "URL": parts[2]
                }
                if float(vuln["Severity"]) > 0.0:
                    vulnerabilities.append(vuln)
    return vulnerabilities

if __name__ == "__main__":
    target_website = input("Enter the Domain to scan for service/version detection: ")
    target_ip = resolve_domain(target_website)
    output_file = "nmap_scan_results.txt"
    scan_service_version(target_ip, output_file)