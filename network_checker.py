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
    ENHANCED Windows Network Info using ipconfig with multiple robust parsing strategies.
    Uses standard library only: subprocess, re, socket, struct.
    Implements multiple fallback strategies for maximum reliability.
    """
    info = {'subnet': 'N/A', 'gateway': 'N/A'}
    
    try:
        cmd = 'ipconfig /all'
        output = subprocess.check_output(cmd, shell=True).decode('latin-1', errors='ignore')
        
        # STRATEGY 1: Advanced Regex with Flexible Whitespace
        # This handles most common ipconfig output variations
        adapter_info = _extract_adapter_block_strategy1(output, local_ip)
        
        if adapter_info:
            # Try multiple regex patterns for Subnet Mask with increasing flexibility
            subnet_patterns = [
                r'Subnet\s+Mask\s*[\.:\s]*\s*([\d\.]+)',
                r'(?:Subnet|Subnetmask)\s*[\.:\s]+\s*([\d\.]+)',
                r'(?i:subnet[\s\-]*mask)\s*[\.:\s]*\s*([\d\.]+)',
            ]
            
            for pattern in subnet_patterns:
                match = re.search(pattern, adapter_info, re.IGNORECASE)
                if match:
                    info['subnet'] = match.group(1).strip()
                    break
            
            # Try multiple regex patterns for Default Gateway with increasing flexibility
            gateway_patterns = [
                r'Default\s+Gateway\s*[\.:\s]*\s*([\d\.]+)',
                r'(?:Default|Def\.?)\s+Gateway\s*[\.:\s]+\s*([\d\.]+)',
                r'(?i:default[\s\-]*gateway)\s*[\.:\s]*\s*([\d\.]+)',
            ]
            
            for pattern in gateway_patterns:
                match = re.search(pattern, adapter_info, re.IGNORECASE)
                if match:
                    info['gateway'] = match.group(1).strip()
                    break
        
        # STRATEGY 2: Line-by-Line State Machine Parser (Fallback)
        # If Strategy 1 fails, use a more robust line-by-line approach
        if info['subnet'] == 'N/A' or info['gateway'] == 'N/A':
            fallback_info = _parse_ipconfig_line_by_line(output, local_ip)
            if info['subnet'] == 'N/A':
                info['subnet'] = fallback_info.get('subnet', 'N/A')
            if info['gateway'] == 'N/A':
                info['gateway'] = fallback_info.get('gateway', 'N/A')
                
    except Exception:
        pass
        
    return info


def _extract_adapter_block_strategy1(output, local_ip):
    """
    Extract the network adapter block containing the specified local_ip.
    Returns the text block or None if not found.
    """
    escaped_ip = re.escape(local_ip)
    
    # Pattern 1: Look for adapter block with IPv4/IP Address containing our IP
    # Captures from start of adapter to next double newline (adapter separator)
    pattern = re.compile(
        r'(?:Ethernet adapter|Wireless LAN adapter)[^\n]*\n'
        r'((?:.*\n)*?'
        r'.*?(?:IPv4 Address|IP Address)[^\n:]*[\.:\s]+[^\d]*' + escaped_ip + r'(?:\(Preferred\))?[^\n]*\n'
        r'(?:.*\n)*?)'
        r'(?=\r?\n\r?\n|\Z)',
        re.IGNORECASE | re.MULTILINE
    )
    
    match = pattern.search(output)
    if match:
        return match.group(1)
    
    # Pattern 2: Simpler fallback - find any block containing our IP
    lines = output.split('\n')
    for i, line in enumerate(lines):
        if local_ip in line and ('IPv4' in line or 'IP Address' in line):
            start = max(0, i - 10)
            end = min(len(lines), i + 20)
            return '\n'.join(lines[start:end])
    
    return None


def _parse_ipconfig_line_by_line(output, local_ip):
    """
    Robust line-by-line parser for ipconfig output.
    State machine approach: finds the adapter with local_ip, then extracts subnet/gateway.
    """
    info = {'subnet': 'N/A', 'gateway': 'N/A'}
    lines = output.split('\n')
    
    found_ip = False
    for i, line in enumerate(lines):
        line_stripped = line.strip()
        
        # Check if we found our IP address
        if local_ip in line and ('IPv4' in line or 'IP Address' in line):
            found_ip = True
            continue
        
        # Once we found our IP, look for subnet and gateway in nearby lines
        if found_ip:
            # Look for empty line (end of adapter block)
            if not line_stripped:
                break
            
            # Extract Subnet Mask - very flexible matching
            if 'subnet' in line_stripped.lower() and 'mask' in line_stripped.lower():
                ip_match = re.search(r'([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})', line_stripped)
                if ip_match:
                    info['subnet'] = ip_match.group(1)
            
            # Extract Default Gateway - very flexible matching
            if 'gateway' in line_stripped.lower():
                ip_match = re.search(r'([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})', line_stripped)
                if ip_match:
                    info['gateway'] = ip_match.group(1)
    
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

# --- Latency Trend Monitoring (DevOps Feature) ---

HISTORY_FILE = 'network_history.json'
HISTORY_CSV = 'network_history.csv'

def load_history():
    """Load historical latency data from JSON file"""
    try:
        with open(HISTORY_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {'checks': []}

def save_history(history):
    """Save historical data to JSON file"""
    try:
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history, f, indent=2)
    except Exception:
        pass

def save_to_csv(data):
    """Append current check to CSV file for spreadsheet analysis"""
    try:
        file_exists = False
        try:
            with open(HISTORY_CSV, 'r'):
                file_exists = True
        except FileNotFoundError:
            pass
        
        with open(HISTORY_CSV, 'a', newline='') as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(['Timestamp', 'Target', 'Status', 'Latency_ms', 'Details'])
            
            for check in data['tcp_checks']:
                writer.writerow([
                    data['timestamp'], 
                    check['name'], 
                    check['status'], 
                    check['latency'], 
                    check['details']
                ])
    except Exception:
        pass

def calculate_statistics(history, target_name):
    """Calculate latency statistics for a specific target"""
    latencies = []
    for check in history.get('checks', []):
        for tcp_check in check.get('tcp_checks', []):
            if tcp_check['name'] == target_name and tcp_check['latency'] > 0:
                latencies.append(tcp_check['latency'])
    
    if not latencies:
        return None
    
    latencies.sort()
    n = len(latencies)
    
    return {
        'count': n,
        'min': round(min(latencies), 2),
        'max': round(max(latencies), 2),
        'avg': round(sum(latencies) / n, 2),
        'median': round(latencies[n // 2], 2),
        'stddev': round((sum((x - sum(latencies)/n) ** 2 for x in latencies) / n) ** 0.5, 2)
    }

def detect_anomaly(current_latency, stats):
    """Detect if current latency is anomalous (>2 standard deviations from mean)"""
    if not stats or current_latency == 0:
        return False, ""
    
    threshold = stats['avg'] + (2 * stats['stddev'])
    if current_latency > threshold:
        increase = round(((current_latency - stats['avg']) / stats['avg']) * 100, 1)
        return True, f"ANOMALY: {increase}% above baseline"
    return False, ""

def print_monitoring_report(data, history):
    """Print monitoring report with trend analysis"""
    os_name = data.get('system', 'Unknown OS')
    
    print(f"\n{Colors.BOLD}Network Latency Monitoring Report ({os_name}){Colors.RESET}")
    print(f"{Colors.CYAN}{'='*70}{Colors.RESET}")
    print(f"Timestamp: {data['timestamp']}")
    print(f"Historical Checks: {len(history.get('checks', []))}")
    
    print(f"\n{Colors.BOLD}Current Status & Trend Analysis{Colors.RESET}")
    print(f"  {Colors.CYAN}{'Target':<20} {'Current':<12} {'Baseline':<12} {'Status':<30}{Colors.RESET}")
    print(f"  {'-'*20} {'-'*12} {'-'*12} {'-'*30}")
    
    for check in data['tcp_checks']:
        stats = calculate_statistics(history, check['name'])
        
        current_str = f"{check['latency']}ms" if check['latency'] else "FAIL"
        baseline_str = f"{stats['avg']}ms" if stats else "N/A"
        
        is_anomaly, anomaly_msg = detect_anomaly(check['latency'], stats)
        
        if check['status'] != 'OK':
            status_color = Colors.RED
            status_msg = check['details']
        elif is_anomaly:
            status_color = Colors.YELLOW
            status_msg = anomaly_msg
        else:
            status_color = Colors.GREEN
            status_msg = "Normal"
        
        print(f"  {check['name']:<20} {current_str:<12} {baseline_str:<12} {status_color}{status_msg:<30}{Colors.RESET}")
    
    print(f"\n{Colors.BOLD}Statistical Summary{Colors.RESET}")
    for check in data['tcp_checks']:
        stats = calculate_statistics(history, check['name'])
        if stats:
            print(f"\n  {Colors.CYAN}{check['name']}{Colors.RESET}")
            print(f"    Min/Avg/Max: {stats['min']}/{stats['avg']}/{stats['max']} ms")
            print(f"    Std Dev: {stats['stddev']} ms | Samples: {stats['count']}")
    
    print(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}")
    print(f"Data saved to: {HISTORY_FILE} and {HISTORY_CSV}")
    print(f"{Colors.CYAN}{'='*70}{Colors.RESET}\n")

def monitoring_mode(interval=60):
    """Continuous monitoring mode with configurable interval"""
    print(f"{Colors.BOLD}Starting Network Latency Monitoring{Colors.RESET}")
    print(f"Interval: {interval} seconds | Press Ctrl+C to stop\n")
    
    check_count = 0
    try:
        while True:
            check_count += 1
            print(f"{Colors.CYAN}[Check #{check_count}] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
            
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
            
            history = load_history()
            history['checks'].append(data)
            
            if len(history['checks']) > 1000:
                history['checks'] = history['checks'][-1000:]
            
            save_history(history)
            save_to_csv(data)
            
            print_monitoring_report(data, history)
            
            if check_count == 1:
                print(f"{Colors.YELLOW}Building baseline... collect at least 5-10 samples for accurate anomaly detection{Colors.RESET}\n")
            
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print(f"\n{Colors.GREEN}Monitoring stopped. Total checks: {check_count}{Colors.RESET}")
        print(f"Historical data saved to {HISTORY_FILE}")

def main():
    parser = argparse.ArgumentParser(
        description='Network Checker - Professional DevOps Edition with Latency Monitoring'
    )
    parser.add_argument('--json', action='store_true', help='Output raw JSON')
    parser.add_argument('--monitor', action='store_true', help='Enable continuous latency monitoring')
    parser.add_argument('--interval', type=int, default=60, help='Monitoring interval in seconds (default: 60)')
    args = parser.parse_args()
    
    # Auto-configure colors based on OS (Disabled on Windows for safety)
    Colors.auto_configure()
    
    if args.json:
        Colors.disable()
    
    # MONITORING MODE: Continuous checks with trend analysis
    if args.monitor:
        Colors.auto_configure()
        monitoring_mode(args.interval)
        return
        
    # STANDARD MODE: Single check
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
