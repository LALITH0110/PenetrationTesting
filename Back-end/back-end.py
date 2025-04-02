import json
from urllib.parse import urlparse
from bson import ObjectId
from flask import Flask, request, jsonify
import subprocess
from flask_cors import CORS
from pymongo import MongoClient
import requests
import nmap
import threading
from pymongo.errors import AutoReconnect
import time
import socket
import os
import json

from dotenv import load_dotenv  # New import to load environment variables
from openai import OpenAI

from cveGPT2 import getActionPlanFromCVEid

load_dotenv()  # New line to load environment variables

# Access the API key from the environment variable
openai_api_key = os.getenv("OPEN_API_KEY")

# Check if the API key is present
if not openai_api_key:
    raise ValueError(
        "API Key not found. Ensure that OPENAI_API_KEY is set in the .env file.")

# Initialize OpenAI client with the API key
client_openai = OpenAI(api_key=openai_api_key)

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# MongoDB connection with retry mechanism
def connect_to_mongo():
    max_retries = 5
    mongo_uri = os.getenv("MONGO_URI")
    if not mongo_uri:
        raise ValueError("Environment variable MONGO_URI is not set")
    for i in range(max_retries):
        try:
            client = MongoClient(
                mongo_uri,
                tls=True,
                tlsAllowInvalidCertificates=True
            )
            print("Done")
            return client
        except AutoReconnect as e:
            print(f"AutoReconnect error: {e}, retrying...")
            time.sleep(5)
    raise Exception("Failed to connect to MongoDB after multiple retries")

# Set up the MongoDB connection
client = connect_to_mongo()
db = client['nmap_scans']  # Database name
scan_collection = db['scans']  # Collection name

# Nmap scanner object
nm = nmap.PortScanner()
ongoing_scans = {}  # Dictionary to track ongoing scans

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    link = data.get('ipAddress')

    print(f"Received link address: {link}")  # Debugging line

    if not link:
        return jsonify({'error': 'ipAddress is required'}), 400

    domain = urlparse(link).netloc
    if not domain:
        return jsonify({'error': 'Invalid link provided'}), 400

    try:
        # Convert domain to IP address
        ip_address = socket.gethostbyname(domain)
    except socket.gaierror:
        return jsonify({'error': 'Failed to resolve IP address'}), 400

    scan_document = {
        "link":link,
        "domain": domain,
        "IP": ip_address,
        "Completed": False
    }
    try:
        result = scan_collection.insert_one(scan_document)
        print(f"Initial scan record inserted for IP {ip_address} with ID {result.inserted_id}")
    except Exception as e:
        print(f"Error inserting initial scan record for IP {ip_address}: {e}")
        return jsonify({'error': 'Failed to start the scan'}), 500

    # Start the scan in a separate thread
    thread = threading.Thread(target=scan_service_version, args=(ip_address, result.inserted_id))
    thread.start()

    return jsonify({'message': 'Scan started', 'ipAddress': ip_address}), 202

def scan_service_version(target_ip, document_id):
    scanner = nmap.PortScanner()
    print(f"Scanning {target_ip} for service/version detection...")
    try:
        scanner.scan(target_ip, arguments='-sV -O --script vuln', sudo=True)
        host_data = gather_important_info(scanner, target_ip)
    except nmap.PortScannerError as e:
        print(f"Nmap scan error for IP {target_ip}: {str(e)}")
        host_data = {
            "IP": target_ip,
            "Error": f"Nmap scan failed: {str(e)}",
            "OS": {"Name": "Unknown", "Version": "Unknown", "Accuracy": "Unknown"},
            "Ports": []
        }
    except Exception as e:
        print(f"Unexpected error during scan for IP {target_ip}: {str(e)}")
        host_data = {
            "IP": target_ip,
            "Error": f"Unexpected error: {str(e)}",
            "OS": {"Name": "Unknown", "Version": "Unknown", "Accuracy": "Unknown"},
            "Ports": []
        }

    try:
        scan_collection.update_one(
            {"_id": document_id},
            {"$set": {"Completed": True, "ScanData": host_data}}
        )
        print(f"Data for IP {target_ip} updated in MongoDB.")
    except Exception as e:
        print(f"Error updating data for IP {target_ip} in MongoDB: {e}")

    print(f"Results saved to MongoDB for IP {target_ip}")

def gather_important_info(scanner, target_ip):
    host_data = {
        "IP": target_ip,
        "State": scanner[target_ip].state(),
        "OS": {},
        "Ports": []
    }

    try:
        if 'osmatch' in scanner[target_ip] and scanner[target_ip]['osmatch']:
            os_match = scanner[target_ip]['osmatch'][0]
            host_data["OS"] = {
                "Name": os_match.get('name', 'Unknown'),
                "Version": os_match['osclass'][0].get('osgen', 'Unknown') if os_match.get('osclass') else 'Unknown',
                "Accuracy": f"{os_match.get('accuracy', 'Unknown')}%"
            }
        else:
            host_data["OS"] = {
                "Name": "Unknown",
                "Version": "Unknown",
                "Accuracy": "Unknown"
            }

        for protocol in scanner[target_ip].all_protocols():
            ports = scanner[target_ip][protocol].keys()
            for port in ports:
                port_info = scanner[target_ip][protocol][port]
                port_data = {
                    "Port": port,
                    "Protocol": protocol,
                    "State": port_info.get('state', "Unknown"),
                    "Service": port_info.get('name', "Unknown"),
                    "Service Version": f"{port_info.get('product', '')} {port_info.get('version', '')}".strip(),
                    "Vulnerabilities": []
                }

                if 'script' in port_info and 'vulners' in port_info['script']:
                    vulns = parse_vulners_output(port_info['script']['vulners'])
                    port_data["Vulnerabilities"] = vulns

                host_data["Ports"].append(port_data)

    except Exception as e:
        print(f"Error gathering information for IP {target_ip}: {str(e)}")
        host_data["Error"] = str(e)

    return host_data

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
                if float(vuln["Severity"]) >= 0:
                    if(vuln["CVE"]):
                        print("Getting Action plan for CVE:"+vuln["CVE"])
                        actionplan = getActionPlanFromCVEid(vuln["CVE"], client_openai)
                    else:
                        actionplan = {}
                    vuln["insights"] = actionplan
                    vulnerabilities.append(vuln)
    return vulnerabilities

def run_scan(ip_address):
    with app.app_context():  # Push the application context
        try:
            result = subprocess.run(
                ['C:\\Program Files (x86)\\Nmap\\nmap.exe', '-Pn', '-sS', '-p-', ip_address],
                capture_output=True, text=True, check=True)
            output = result.stdout

            # Parse the output to extract open ports
            open_ports = []
            lines = output.split('\n')
            port_section = False

            for line in lines:
                if 'PORT' in line and 'STATE' in line:
                    port_section = True
                    continue
                if port_section:
                    if line.strip() == '':
                        break
                    parts = line.split()
                    if len(parts) >= 3:
                        port_info = {
                            'port': parts[0],
                            'state': parts[1],
                            'service': parts[2]
                        }
                        open_ports.append(port_info)

            # Store scan result in MongoDB
            scan_result = {
                'ipAddress': ip_address,
                'open_ports': open_ports,
                'status': 'complete'  # Indicate that the scan is complete
            }
            result_id = scan_collection.insert_one(scan_result).inserted_id  # Get the inserted ID

            ongoing_scans[ip_address] = {'id': str(result_id), 'status': 'complete'}

            print({
                '_id': str(result_id),
                'status': 'complete'
            })

        except subprocess.CalledProcessError as e:
            print({'error': 'An error occurred while running the scan', 'details': str(e)})
        except Exception as e:
            print({'error': 'An unexpected error occurred', 'details': str(e)})


@app.route('/scan-status', methods=['GET'])
def scan_status():
    try:
        scans = scan_collection.find({}, {"IP": 1, "Completed": 1, "_id": 1, "domain": 1})
        scan_list = []

        for scan in scans:
            scan['_id'] = str(scan['_id'])
            scan_list.append(scan)

        if scan_list:
            return jsonify(scan_list), 200
        else:
            return jsonify([]), 200
    except Exception as e:
        print(f"Error retrieving scan status: {e}")
        return jsonify({'error': 'An error occurred while fetching scan status'}), 500

@app.route('/scan/get', methods=['POST'])
def get_scan():
    data = request.json
    document_id = data.get('id')

    if not document_id:
        return jsonify({'error': 'Document ID is required'}), 400

    try:
        obj_id = ObjectId(document_id)
        document = scan_collection.find_one({"_id": obj_id})

        if document:
            document['_id'] = str(document['_id'])
            return jsonify(document), 200
        else:
            return jsonify({'error': 'Document not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000)

