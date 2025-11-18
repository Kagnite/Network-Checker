#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Checker - Professional DevOps Edition (Final Exam Version)
"""

import socket
import sys
import argparse
import json
import ipaddress
import urllib.request
import urllib.error
import time
import platform
import struct
import subprocess
import re
import csv
import io
from datetime import datetime

# --- Configs ---
RETRIES = 3
RETRY_DELAY = 1.0
TIMEOUT = 3.0

class Colors:
    """ANSI colors for pretty terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'
    
    @staticmethod
    def disable():
        """Disable all colors"""
        Colors.GREEN = Colors.RED = Colors.YELLOW = Colors.CYAN = Colors.BOLD = Colors.RESET = ''

    @staticmethod
    def auto_configure():
        """
        Smart detection: 
        If running on Windows (which often has bad ANSI support in older CMD/PS),
        disable colors automatically to avoid garbage characters like ←[96m.
        """
        if platform.system() == 'Windows':
            Colors.disable()

# --- Platform Specific Logic ---

def get_windows_net_info(local_ip):
    """
    ROBUST Windows Network Info using ipconfig.
    This method is more reliable than WMIC for extracting standard network info.
    """
    info = {'subnet': 'N/A', 'gateway': 'N/A'}
    
    try:
        # Use ipconfig /all for reliable, text-based output.
        # ipconfig is a core utility on all Windows systems.
        cmd = 'ipconfig /all'
        # Using 'latin-1' or 'cp437' for decoding standard command output on Windows
        output = subprocess.check_output(cmd, shell=True).decode('latin-1', errors='ignore')
        
        # 1. Find the block for the correct adapter (containing local_ip)
        # Searches for an adapter section which contains the local IP address.
        adapter_block_pattern = re.compile(
            # Start of the line identifying the adapter's IPv4 address entry, 
            # followed by the specific local_ip, and captures until the next adapter block or end of file.
            r'(.+?(?:IPv4 Address|IP Address)\s*[\.\s:]+)\s*' + re.escape(local_ip).replace('.', r'\.') + r'(.+?)(?=\r?\n\r?\n|$)', 
            re.DOTALL | re.IGNORECASE
        )
        match_block = adapter_block_pattern.search(output)
        
        if match_block:
            adapter_info = match_block.group(0)
            
            # 2. Subnet Mask
            # Regex for standard English "Subnet Mask" followed by its IP
            subnet_pattern = re.compile(
                r'Subnet Mask\s*[\.\s:]+\s*([\d\.]+)', 
                re.IGNORECASE
            )
            match_subnet = subnet_pattern.search(adapter_info)
            if match_subnet:
                info['subnet'] = match_subnet.group(1).strip()
                
            # 3. Default Gateway
            # Regex for standard English "Default Gateway" followed by its IP
            gateway_pattern = re.compile(
                r'Default Gateway\s*[\.\s:]+\s*([\d\.]+)', 
                re.IGNORECASE
            )
            match_gateway = gateway_pattern.search(adapter_info)
            if match_gateway:
                info['gateway'] = match_gateway.group(1).strip()

    except Exception:
        # Ignore exceptions gracefully
        pass 
        
    return info

def get_linux_net_info(local_ip):
    """Robust Linux Network Info using /proc and ip command"""
    info = {'subnet': 'N/A', 'gateway': 'N/A'}
    try:
        with open('/proc/net/route', 'r') as f:
            for line in f:
                fields = line.strip().split()
                if len(fields) >= 8 and fields[1] == '00000000':
                    gw_hex = fields[2]
                    info['gateway'] = socket.inet_ntoa(struct.pack('<L', int(gw_hex, 16)))
                    break
    except: pass

    try:
        output = subprocess.check_output(['ip', '-o', '-f', 'inet', 'addr', 'show'], stderr=subprocess.DEVNULL).decode()
        pattern = re.compile(re.escape(local_ip) + r'/(\d+)')
        match = pattern.search(output)
        if match:
            cidr = int(match.group(1))
            host_bits = 32 - cidr
            netmask = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << host_bits)))
            info['subnet'] = f"{netmask} (/{cidr})"
    except: pass
    return info

def get_macos_net_info(local_ip):
    """MacOS Network Info"""
    info = {'subnet': 'N/A', 'gateway': 'N/A'}
    try:
        out_gw = subprocess.check_output(['route', '-n', 'get', 'default'], stderr=subprocess.DEVNULL).decode()
        match_gw = re.search(r'gateway:\s+([\d\.]+)', out_gw)
        if match_gw:
            info['gateway'] = match_gw.group(1)
            
        out_if = subprocess.check_output(['ifconfig'], stderr=subprocess.DEVNULL).decode()
        for line in out_if.split('\n'):
            if local_ip in line and 'netmask' in line:
                match_mask = re.search(r'netmask\s+(0x[0-9a-fA-F]+)', line)
                if match_mask:
                    hex_mask = int(match_mask.group(1), 16)
                    netmask = socket.inet_ntoa(struct.pack('>I', hex_mask))
                    cidr = bin(hex_mask).count('1')
                    info['subnet'] = f"{netmask} (/{cidr})"
                    break
    except: pass
    return info

# --- Core Logic ---

def get_local_network_info():
    """Determine Local IP, Gateway, and Subnet"""
    result = {
        'local_ip': '', 'ip_type': '', 
        'subnet': 'N/A', 'gateway': 'N/A', 'error': ''
    }
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('8.8.8.8', 80))
            local_ip = s.getsockname()[0]
            result['local_ip'] = local_ip
            result['ip_type'] = 'Private' if ipaddress.ip_address(local_ip).is_private else 'Public'
            
        sys_plat = platform.system()
        if sys_plat == 'Windows':
            net_data = get_windows_net_info(local_ip)
        elif sys_plat == 'Linux':
            net_data = get_linux_net_info(local_ip)
        elif sys_plat == 'Darwin':
            net_data = get_macos_net_info(local_ip)
        else:
            net_data = {}
            
        result.update(net_data)
    except Exception as e:
        result['error'] = f"Interface Error: {str(e)}"
    return result

def check_tcp_connection(name, host, port):
    """TCP Connectivity Check with Retries"""
    result = {
        'name': name, 'host': host, 'port': port,
        'status': 'FAIL', 'latency': 0, 'details': ''
    }
    
    for attempt in range(RETRIES):
        try:
            start = time.time()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(TIMEOUT)
                sock.connect((host, port))
            
            latency = (time.time() - start) * 1000
            result['status'] = 'OK'
            result['latency'] = round(latency, 2)
            result['details'] = 'Connected'
            return result 
            
        except socket.timeout:
            result['details'] = 'Timeout (Likely Filtered)'
        except ConnectionRefusedError:
            result['details'] = 'Refused (Service Down/Blocked)'
        except socket.gaierror:
            result['details'] = 'DNS Failed'
        except Exception as e:
            result['details'] = str(e)
        
        if attempt < RETRIES - 1:
            time.sleep(RETRY_DELAY)
            
    return result

def check_http_service(name, url):
    """HTTP Service Check"""
    result = {
        'name': name, 'url': url,
        'status': 'FAIL', 'latency': 0, 'details': ''
    }
    
    for attempt in range(RETRIES):
        try:
            start = time.time()
            req = urllib.request.Request(
                url, 
                headers={'User-Agent': 'DevOpsPro/2.0'}
            )
            with urllib.request.urlopen(req, timeout=TIMEOUT+2) as response:
                latency = (time.time() - start) * 1000
                result['status'] = 'OK'
                result['latency'] = round(latency, 2)
                result['details'] = f"HTTP {response.getcode()}"
                return result
                
        except urllib.error.HTTPError as e:
            result['details'] = f"HTTP Error {e.code}"
            result['status'] = 'WARN' 
            return result
        except Exception as e:
            result['details'] = str(e).replace('urlopen error', '').strip()
        
        if attempt < RETRIES - 1:
            time.sleep(RETRY_DELAY)
            
    return result

def analyze_internet_status(results):
    """Analyze results to determine filtering status"""
    google = next((x for x in results['tcp_checks'] if 'Google' in x['name']), None)
    youtube = next((x for x in results['tcp_checks'] if 'Restricted' in x['name']), None)
    
    status = "UNKNOWN"
    color = Colors.YELLOW
    
    if not google or google['status'] != 'OK':
        status = "NO INTERNET ACCESS"
        color = Colors.RED
    elif google['status'] == 'OK':
        if youtube and youtube['status'] == 'OK':
            status = "UNRESTRICTED INTERNET (Open)"
            color = Colors.GREEN
        elif youtube and 'Timeout' in youtube['details']:
            status = "RESTRICTED INTERNET (Filtered)"
            color = Colors.YELLOW
        else:
            status = "PARTIAL INTERNET (Check details)"
            
    return status, color

# --- Reporting ---

def print_report(data, analysis):
    """Renders the final report to the console."""
    
    # Extract OS name for prominent display
    os_name = data.get('system', 'Unknown OS')
    
    # Print Header with OS name
    print(f"\n{Colors.BOLD}DevOps Network Diagnostics - Professional Edition ({os_name}){Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
    
    # Local Info
    print(f"\n{Colors.BOLD}[1] Local Network Configuration{Colors.RESET}")
    net = data['local_info']
    if net['error']:
        print(f"  {Colors.RED}Error:{Colors.RESET} {net['error']}")
    else:
        print(f"  • IP Address : {Colors.GREEN}{net['local_ip']}{Colors.RESET} ({net['ip_type']})")
        print(f"  • Subnet Mask: {net['subnet']}")
        print(f"  • Gateway    : {net['gateway']}")

    # TCP Checks
    print(f"\n{Colors.BOLD}[2] Service Connectivity{Colors.RESET}")
    print(f"  {Colors.CYAN}{'Target':<25} {'Status':<10} {'Latency':<10} {'Details'}{Colors.RESET}")
    print(f"  {'-'*25} {'-'*10} {'-'*10} {'-'*15}")
    
    for item in data['tcp_checks']:
        status_color = Colors.GREEN if item['status'] == 'OK' else Colors.RED
        lat = f"{item['latency']}ms" if item['latency'] else "-"
        print(f"  {item['name']:<25} {status_color}{item['status']:<10}{Colors.RESET} {lat:<10} {item['details']}")

    # HTTP Check
    print(f"\n{Colors.BOLD}[3] Hamrah Academy Access{Colors.RESET}")
    ac = data['http_check']
    status_color = Colors.GREEN if ac['status'] == 'OK' else Colors.RED
    print(f"  • URL: {ac['url']}")
    print(f"  • Result: {status_color}{ac['status']}{Colors.RESET} - {ac['details']} ({ac['latency']}ms)")

    # Diagnosis
    status_text, status_color = analysis
    print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}FINAL DIAGNOSIS:{Colors.RESET} {status_color}{status_text}{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--json', action='store_true', help='Output raw JSON')
    args = parser.parse_args()
    
    # Auto-configure colors based on OS (Disabled on Windows for safety)
    Colors.auto_configure()
    
    if args.json:
        Colors.disable()
        
    data = {
        'timestamp': datetime.now().isoformat(),
        'system': platform.system(),
        'local_info': get_local_network_info(),
        'tcp_checks': [],
        'http_check': {}
    }
    
    targets = [
        ('Google DNS', '8.8.8.8', 53),
        ('Restricted (YouTube)', 'www.youtube.com', 443)
    ]
    
    for name, host, port in targets:
        data['tcp_checks'].append(check_tcp_connection(name, host, port))
        
    data['http_check'] = check_http_service('Hamrah Academy', 'https://hamrah.academy')
    
    analysis = analyze_internet_status(data)
    
    if args.json:
        data['final_diagnosis'] = analysis[0]
        print(json.dumps(data, indent=2))
    else:
        print_report(data, analysis)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
