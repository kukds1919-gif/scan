#!/usr/bin/env python3

"""
PortRadar — Port & Vulnerability Scanner (Python Implementation)

Features:
- Automatic TCP connect scan for all ports 1-65535
- Banner grabbing for service info
- Query known CVEs using NVD API (optional)

Usage:
$ python portradar.py --target 192.168.0.10 --cve --out result.json
"""

import argparse
import socket
import concurrent.futures
import time
import json
import re
import requests
import os
from datetime import datetime, timezone
from tqdm import tqdm

# Settings
CONNECT_TIMEOUT = 1.5
BANNER_TIMEOUT = 2.0
MAX_WORKERS = 200
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def print_intro():
    art = r"""
 ____                  ____            _             
|  _ \ __ _ ___ ___   |  _ \ __ _ _ __| |_ ___  _ __ 
| |_) / _` / __/ __|  | |_) / _` | '__| __/ _ \| '__|
|  __/ (_| \__ \__ \  |  __/ (_| | |  | || (_) | |   
|_|   \__,_|___/___/  |_|   \__,_|_|   \__\___/|_|   

"""
    print(art)
    print("PortRadar - Port & Vulnerability Scanner")
    print("Developer Team 6조: 유연태,권석환,박정준, 김동수, 안세건")
    print("="*60)

# Port scan (TCP connect)
def scan_port(host, port, timeout=CONNECT_TIMEOUT):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass

# Banner grabbing
def grab_banner(host, port, timeout=BANNER_TIMEOUT):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((host, port))
        # Some services send banner immediately
        try:
            data = s.recv(4096)
            if data:
                return data.decode('utf-8', errors='replace').strip()
        except socket.timeout:
            pass
        # Basic HTTP request for HTTP ports
        if port in (80, 8080, 8000, 8008, 8888):
            req = b"GET / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode()
            try:
                s.sendall(req)
                data = s.recv(4096)
                return data.decode('utf-8', errors='replace').split('\r\n\r\n', 1)[0]
            except Exception:
                pass
        return ''
    except Exception:
        return ''
    finally:
        try:
            s.close()
        except Exception:
            pass

# NVD API CVE search (simple keyword)
def search_nvd(keyword, api_key='5dfabd3f-0c8e-4987-b461-35f7c3f683a7', start_index=0, results_per_page=20):
    params = {
        'keywordSearch': keyword,
        'startIndex': start_index,
        'resultsPerPage': results_per_page
    }
    headers = {}
    if api_key:
        headers['apiKey'] = api_key
    try:
        r = requests.get(NVD_API_BASE, params=params, headers=headers, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {'error': str(e)}

# Port to service keyword mapping (simple heuristic)
PORT_SERVICE_MAP = {
    "20": "FTP Data Transfer",
    "21": "FTP Control",
    "22": "SSH - Secure Shell",
    "23": "Telnet - Unsecured Remote Login",
    "25": "SMTP - Email Sending",
    "53": "DNS - Domain Name Service",
    "67": "DHCP Server",
    "68": "DHCP Client",
    "69": "TFTP - Trivial File Transfer",
    "80": "HTTP - Web Traffic",
    "110": "POP3 - Email Retrieval",
    "123": "NTP - Network Time Protocol",
    "135": "RPC Endpoint Mapper",
    "137": "NetBIOS Name Service",
    "138": "NetBIOS Datagram Service",
    "139": "NetBIOS Session Service",
    "143": "IMAP - Email Retrieval",
    "161": "SNMP - Simple Network Management Protocol",
    "162": "SNMP Trap",
    "389": "LDAP - Lightweight Directory Access Protocol",
    "443": "HTTPS - Secure Web Traffic",
    "445": "SMB - Windows File/Printer Sharing",
    "465": "SMTPS - SMTP Secure",
    "514": "Syslog",
    "587": "SMTP - Message Submission",
    "631": "IPP - Internet Printing Protocol",
    "636": "LDAPS - LDAP Secure",
    "989": "FTPS - Data",
    "990": "FTPS - Control",
    "993": "IMAPS - IMAP Secure",
    "995": "POP3S - POP3 Secure",
    "1080": "SOCKS Proxy",
    "1433": "Microsoft SQL Server",
    "1434": "Microsoft SQL Monitor",
    "1521": "Oracle Database",
    "1723": "PPTP VPN",
    "2049": "NFS - Network File System",
    "3306": "MySQL Database",
    "3389": "RDP - Remote Desktop",
    "5432": "PostgreSQL Database",
    "5900": "VNC Remote Desktop",
    "8080": "HTTP Proxy / Alternative HTTP",
    "8443": "HTTPS Alternate"
}

# Format report
def make_report(host, open_ports_info, cve_map):
    report = {
        'target': host,
        'scan_time': datetime.now(timezone.utc).isoformat(),
        'open_ports': []
    }
    for info in open_ports_info:
        svc = info.get('service', '').strip()
        if not svc:
            svc = 'unknown'
        p = {
            'port': info['port'],
            'service_guess': info.get('service', ''),
            'banner': info.get('banner', ''),
            'found_cves': cve_map.get(info['port'], [])
        }
        report['open_ports'].append(p)
    return report

# Main scanning function
def run_scan(host, workers=MAX_WORKERS, query_cve=False, nvd_api_key=None):
    ports = range(1, 65536)
    print(f"[PortRadar] Starting scan on {host} for all 65535 ports")
    open_ports = []
    open_ports_info = []
    start = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_port, host, p): p for p in ports}
        for fut in tqdm(concurrent.futures.as_completed(futures), total=len(ports), desc="Scanning ports", unit="port"):
            p = futures[fut]
            try:
                ok = fut.result()
            except Exception:
                ok = False
            if ok:
                print(f"[Open] Port {p} is open")
                open_ports.append(p)
    
    # Banner grabbing
    if open_ports:
        print('[PortRadar] Starting banner grabbing...')
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(open_ports), workers)) as ex:
            futures = {ex.submit(grab_banner, host, p): p for p in open_ports}
            for fut in tqdm(concurrent.futures.as_completed(futures), total=len(open_ports), desc="Grabbing banners", unit="port"):
                p = futures[fut]
                banner = ''
                try:
                    banner = fut.result()
                except Exception:
                    banner = ''
                svc = PORT_SERVICE_MAP.get(p, '')
                if not svc:
                    if banner:
                        m = re.search(r"(?i)server:\s*([^\r\n]+)", banner)
                        if m:
                            svc = m.group(1).split('/')[0]
                        else:
                            m2 = re.search(r"<title>([^<]+)</title>", banner, re.I)
                            if m2:
                                svc = 'http (title)'
                open_ports_info.append({'port': p, 'banner': banner, 'service': svc})
    else:
        print('[PortRadar] No open ports found.')

    cve_map = {}
    if query_cve and open_ports_info:
        print('[PortRadar] Querying CVEs from NVD...')
        api_key = nvd_api_key or os.getenv('NVD_API_KEY')
        for info in open_ports_info:
            keywords = set()
            if info.get('service'):
                keywords.add(info['service'])
            if info.get('banner'):
                m = re.search(r"([A-Za-z0-9_.-]{3,})/(\d+[\.\d\w-]*)", info['banner'])
                if m:
                    keywords.add(m.group(1))
            if info['port'] in PORT_SERVICE_MAP:
                keywords.add(PORT_SERVICE_MAP[info['port']])
            found = []
            for kw in keywords:
                if not kw:
                    continue
                print(f"  - Searching CVE with keyword '{kw}' for port {info['port']}...")
                res = search_nvd(kw, api_key)
                if 'error' in res:
                    print(f"    ! NVD query failed: {res['error']}")
                    continue
                items = res.get('vulnerabilities') or res.get('results') or []
                for item in items[:5]:
                    cve_id = None
                    desc = ''
                    if isinstance(item, dict):
                        if 'cve' in item:
                            cve_id = item['cve'].get('id')
                            descs = item['cve'].get('descriptions', [])
                            if descs:
                                desc = descs[0].get('value', '')
                        else:
                            cve_id = item.get('cve') or item.get('id')
                    if cve_id:
                        found.append({'id': cve_id, 'desc': desc})
            cve_map[info['port']] = found

    report = make_report(host, open_ports_info, cve_map)
    elapsed = time.time() - start
    print(f"[PortRadar] Scan completed in {elapsed:.1f} seconds")
    return report

def print_report(report):
    print('\n' + '='*60)
    print("PortRadar Scan Report")
    print(f"Target: {report['target']}")
    print(f"Scan Time: {report['scan_time']}")
    print('='*60)
    if not report['open_ports']:
        print("No open ports found.")
    else:
        for p in report['open_ports']:
            print(f"\nPort: {p['port']}")
            print(f" Service (guess): {p['service_guess']}")
            if p['banner']:
                print(" Banner:")
                for line in p['banner'].splitlines():
                    print("  " + line)
            if p['found_cves']:
                print(" Found CVEs:")
                for c in p['found_cves']:
                    print(f"  - {c.get('id')} : {c.get('desc')[:200]}")
            print('-'*60)

# CLI
def main():
    print_intro()
    parser = argparse.ArgumentParser(description='PortRadar — Port & Vulnerability Scanner')
    parser.add_argument('--target', '-t', required=True, help='Target host (IP or domain)')
    parser.add_argument('--workers', '-w', type=int, default=100, help='Number of concurrent workers')
    parser.add_argument('--cve', '-c', action='store_true', help='Perform CVE lookup via NVD')
    #parser.add_argument('--nvd-api-key', default=None, help='NVD API key (optional)')
    parser.add_argument('--out', '-o', default=None, help='Save JSON output to file')

    args = parser.parse_args()
    report = run_scan(
            args.target, 
            workers=args.workers, 
            query_cve=args.cve, 
            nvd_api_key='5dfabd3f-0c8e-4987-b461-35f7c3f683a7'    
    )
    print_report(report)
    
    if args.out:
        try:
            with open(args.out, 'w', encoding='utf-8') as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            print(f"Results saved to {args.out}.")
        except Exception as e:
            print(f"Failed to save results: {e}")

if __name__ == '__main__':
    main()
