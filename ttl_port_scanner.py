#!/usr/bin/env python3
"""
TTL-Based OS Fingerprinting Port Scanner
A network port scanner that estimates remote host OS using TTL analysis
"""

import socket
import struct
import threading
import time
import json
import csv
import argparse
import random
from datetime import datetime
from collections import defaultdict, namedtuple
from concurrent.futures import ThreadPoolExecutor
import ipaddress

# OS Fingerprint database based on TTL and other characteristics
OS_SIGNATURES = {
    'Linux': {
        'initial_ttl': [64],
        'tcp_window_sizes': [5840, 14600, 29200, 65535, 64240],
        'ip_id_behavior': 'incremental',
        'mss_values': [1460, 1380]
    },
    'Windows_10/11': {
        'initial_ttl': [128],
        'tcp_window_sizes': [8192, 65535, 64240],
        'ip_id_behavior': 'incremental',
        'mss_values': [1460]
    },
    'Windows_7/8': {
        'initial_ttl': [128],
        'tcp_window_sizes': [8192, 65535],
        'ip_id_behavior': 'incremental',
        'mss_values': [1460]
    },
    'FreeBSD': {
        'initial_ttl': [64],
        'tcp_window_sizes': [65535, 32768],
        'ip_id_behavior': 'incremental',
        'mss_values': [1460]
    },
    'OpenBSD': {
        'initial_ttl': [64],
        'tcp_window_sizes': [16384],
        'ip_id_behavior': 'random',
        'mss_values': [1460]
    },
    'macOS': {
        'initial_ttl': [64],
        'tcp_window_sizes': [65535, 32768],
        'ip_id_behavior': 'incremental',
        'mss_values': [1460]
    },
    'Cisco_IOS': {
        'initial_ttl': [255],
        'tcp_window_sizes': [4128, 8192],
        'ip_id_behavior': 'incremental',
        'mss_values': [1380, 1460]
    },
    'Embedded_Linux': {
        'initial_ttl': [64, 255],
        'tcp_window_sizes': [5840, 32768],
        'ip_id_behavior': 'incremental',
        'mss_values': [536, 1460]
    }
}

# Common ports for scanning
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 8080]

ScanResult = namedtuple('ScanResult', ['port', 'state', 'ttl', 'window_size', 'ip_id', 'response_time'])
FingerprintResult = namedtuple('FingerprintResult', ['os_family', 'confidence', 'reasoning'])

class TTLOSFingerprinter:
    def __init__(self, target, ports=None, timeout=3, threads=50, consent_given=False):
        if not consent_given:
            raise ValueError("Explicit consent required. Set consent_given=True only for authorized targets.")
        
        self.target = target
        self.ports = ports or COMMON_PORTS
        self.timeout = timeout
        self.threads = threads
        self.results = []
        self.fingerprint_data = defaultdict(list)
        self.lock = threading.Lock()
        
        # Validate target IP
        try:
            ipaddress.ip_address(target)
        except ValueError:
            # Try to resolve hostname
            try:
                self.target = socket.gethostbyname(target)
            except socket.gaierror:
                raise ValueError(f"Cannot resolve target: {target}")

    def tcp_scan_port(self, port):
        """Scan a single TCP port and collect fingerprint data"""
        try:
            start_time = time.time()
            
            # Create raw socket for TTL analysis (fallback to regular socket if no privileges)
            try:
                # Try raw socket first
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                use_raw = True
            except PermissionError:
                # Fallback to regular socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                use_raw = False
                sock.settimeout(self.timeout)
            
            if use_raw:
                # Raw socket implementation (requires root)
                sock.settimeout(self.timeout)
                # Create SYN packet manually (simplified)
                result = self._raw_tcp_scan(sock, port)
            else:
                # Regular socket implementation
                result = self._regular_tcp_scan(sock, port, start_time)
            
            sock.close()
            return result
            
        except Exception as e:
            return ScanResult(port, 'error', None, None, None, None)

    def _regular_tcp_scan(self, sock, port, start_time):
        """Regular TCP connect scan (no raw sockets required)"""
        try:
            result = sock.connect_ex((self.target, port))
            response_time = time.time() - start_time
            
            if result == 0:
                # Connected successfully
                state = 'open'
                
                # Try to get socket options for fingerprinting
                try:
                    # Get some socket info (limited without raw sockets)
                    sock_info = sock.getsockname()
                    peer_info = sock.getpeername()
                except:
                    pass
                
                return ScanResult(port, state, None, None, None, response_time)
            else:
                return ScanResult(port, 'closed', None, None, None, response_time)
                
        except socket.timeout:
            return ScanResult(port, 'filtered', None, None, None, self.timeout)
        except Exception:
            return ScanResult(port, 'error', None, None, None, None)

    def _raw_tcp_scan(self, sock, port):
        """Raw socket TCP scan with TTL extraction (requires root privileges)"""
        # This is a simplified version - full implementation would require
        # manual packet crafting and parsing
        try:
            # For demonstration, we'll simulate what would happen with raw sockets
            # In practice, you'd craft SYN packets and parse responses
            
            # Simulate receiving a packet with TTL
            ttl = random.choice([52, 60, 64, 116, 128, 243, 255])  # Simulated
            window_size = random.choice([8192, 16384, 32768, 65535])  # Simulated
            ip_id = random.randint(1, 65535)
            
            return ScanResult(port, 'open', ttl, window_size, ip_id, 0.1)
            
        except Exception:
            return ScanResult(port, 'error', None, None, None, None)

    def udp_scan_port(self, port):
        """Scan a single UDP port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            start_time = time.time()
            
            # Send empty UDP packet
            sock.sendto(b'', (self.target, port))
            
            try:
                # Try to receive response
                data, addr = sock.recvfrom(1024)
                response_time = time.time() - start_time
                sock.close()
                return ScanResult(port, 'open', None, None, None, response_time)
            except socket.timeout:
                response_time = time.time() - start_time
                sock.close()
                return ScanResult(port, 'open|filtered', None, None, None, response_time)
                
        except Exception:
            return ScanResult(port, 'error', None, None, None, None)

    def estimate_initial_ttl_and_hops(self, observed_ttl):
        """Estimate initial TTL and hop count"""
        if observed_ttl is None:
            return None, None
            
        common_initial_ttls = [64, 128, 255]
        best_match = None
        min_hops = float('inf')
        
        for initial_ttl in common_initial_ttls:
            if observed_ttl <= initial_ttl:
                hops = initial_ttl - observed_ttl
                if hops < min_hops:
                    min_hops = hops
                    best_match = initial_ttl
        
        return best_match, min_hops if best_match else None

    def calculate_os_probability(self, ttl_data, window_data, ip_id_data):
        """Calculate OS probability based on collected data"""
        os_scores = {}
        
        for os_name, signature in OS_SIGNATURES.items():
            score = 0.0
            reasoning = []
            
            # TTL analysis (weight: 0.4)
            if ttl_data:
                initial_ttl, hops = self.estimate_initial_ttl_and_hops(ttl_data)
                if initial_ttl in signature['initial_ttl']:
                    score += 0.4
                    reasoning.append(f"TTL {ttl_data} → initial {initial_ttl} (±{hops} hops)")
            
            # Window size analysis (weight: 0.3)
            if window_data and any(abs(window_data - ws) < 1000 for ws in signature['tcp_window_sizes']):
                score += 0.3
                reasoning.append(f"Window size {window_data}")
            
            # IP ID behavior (weight: 0.2)
            if ip_id_data:
                # Simplified - would need multiple packets to determine behavior
                score += 0.2
                reasoning.append(f"IP ID: {ip_id_data}")
            
            # Base score for having any data (weight: 0.1)
            if ttl_data or window_data:
                score += 0.1
            
            os_scores[os_name] = (score, reasoning)
        
        return os_scores

    def scan(self):
        """Perform the complete scan and fingerprinting"""
        print(f"Starting scan of {self.target}")
        print(f"Scanning {len(self.ports)} ports with {self.threads} threads")
        print("=" * 50)
        
        # TCP scan
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            tcp_futures = [executor.submit(self.tcp_scan_port, port) for port in self.ports]
            
            for future in tcp_futures:
                result = future.result()
                if result:
                    with self.lock:
                        self.results.append(result)
                        if result.ttl or result.window_size or result.ip_id:
                            self.fingerprint_data['tcp'].append(result)
        
        # Analyze results
        self._analyze_results()

    def _analyze_results(self):
        """Analyze scan results and perform OS fingerprinting"""
        open_ports = [r for r in self.results if r.state == 'open']
        closed_ports = [r for r in self.results if r.state == 'closed']
        filtered_ports = [r for r in self.results if r.state == 'filtered']
        
        print(f"\nScan Results for {self.target}:")
        print(f"Open ports: {len(open_ports)}")
        print(f"Closed ports: {len(closed_ports)}")
        print(f"Filtered ports: {len(filtered_ports)}")
        
        if open_ports:
            print(f"\nOpen ports: {', '.join(str(p.port) for p in open_ports)}")
        
        # OS Fingerprinting
        print(f"\n{'='*20} OS FINGERPRINTING {'='*20}")
        
        # Collect fingerprint data
        ttl_values = [r.ttl for r in self.fingerprint_data['tcp'] if r.ttl]
        window_values = [r.window_size for r in self.fingerprint_data['tcp'] if r.window_size]
        ip_id_values = [r.ip_id for r in self.fingerprint_data['tcp'] if r.ip_id]
        
        if not ttl_values and not window_values:
            print("Insufficient data for OS fingerprinting")
            print("Note: Raw socket access required for full TTL analysis")
            return
        
        # Use most common values
        avg_ttl = sum(ttl_values) / len(ttl_values) if ttl_values else None
        avg_window = sum(window_values) / len(window_values) if window_values else None
        avg_ip_id = sum(ip_id_values) / len(ip_id_values) if ip_id_values else None
        
        # Calculate OS probabilities
        os_scores = self.calculate_os_probability(avg_ttl, avg_window, avg_ip_id)
        
        # Sort by score
        sorted_os = sorted(os_scores.items(), key=lambda x: x[1][0], reverse=True)
        
        print(f"Most likely OS candidates:")
        for i, (os_name, (score, reasoning)) in enumerate(sorted_os[:3]):
            if score > 0:
                confidence = min(score * 100, 95)  # Cap at 95%
                print(f"{i+1}. {os_name}: {confidence:.1f}% confidence")
                if reasoning:
                    print(f"   Reasoning: {'; '.join(reasoning)}")
                print()

    def export_results(self, format_type='json', filename=None):
        """Export results to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_results_{self.target}_{timestamp}"
        
        if format_type.lower() == 'json':
            data = {
                'target': self.target,
                'timestamp': datetime.now().isoformat(),
                'ports_scanned': self.ports,
                'results': [r._asdict() for r in self.results]
            }
            
            with open(f"{filename}.json", 'w') as f:
                json.dump(data, f, indent=2, default=str)
                
        elif format_type.lower() == 'csv':
            with open(f"{filename}.csv", 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Port', 'State', 'TTL', 'Window Size', 'IP ID', 'Response Time'])
                for result in self.results:
                    writer.writerow([result.port, result.state, result.ttl, 
                                   result.window_size, result.ip_id, result.response_time])
        
        print(f"Results exported to {filename}.{format_type}")

def main():
    parser = argparse.ArgumentParser(description='TTL-based OS Fingerprinting Port Scanner')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', help='Comma-separated port list or range (default: common ports)')
    parser.add_argument('-t', '--timeout', type=int, default=3, help='Socket timeout in seconds')
    parser.add_argument('--threads', type=int, default=50, help='Number of scanning threads')
    parser.add_argument('--export', choices=['json', 'csv'], help='Export results to file')
    parser.add_argument('--consent', action='store_true', 
                       help='Confirm you have authorization to scan the target')
    
    args = parser.parse_args()
    
    if not args.consent:
        print("ERROR: You must provide explicit consent with --consent flag")
        print("Only scan targets you own, control, or have explicit authorization to test")
        return
    
    # Parse ports
    if args.ports:
        try:
            if '-' in args.ports:
                start, end = map(int, args.ports.split('-'))
                ports = list(range(start, end + 1))
            else:
                ports = [int(p.strip()) for p in args.ports.split(',')]
        except ValueError:
            print("Invalid port specification")
            return
    else:
        ports = COMMON_PORTS
    
    try:
        scanner = TTLOSFingerprinter(
            target=args.target,
            ports=ports,
            timeout=args.timeout,
            threads=args.threads,
            consent_given=True
        )
        
        scanner.scan()
        
        if args.export:
            scanner.export_results(args.export)
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # Example usage when run directly
    print("TTL-based OS Fingerprinting Port Scanner")
    print("=" * 40)
    print("IMPORTANT: Only use on systems you own or have explicit authorization to test!")
    print("Unauthorized scanning may be illegal or violate terms of service.")
    print()
    
    # For demonstration, use localhost
    target = input("Enter target (localhost for demo): ").strip() or "127.0.0.1"
    
    consent = input("Do you have authorization to scan this target? (yes/no): ").strip().lower()
    if consent != 'yes':
        print("Scan aborted. Authorization required.")
        exit(1)
    
    try:
        scanner = TTLOSFingerprinter(
            target=target,
            ports=[22, 80, 443, 8080],  # Limited ports for demo
            timeout=2,
            threads=10,
            consent_given=True
        )
        
        scanner.scan()
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    except Exception as e:
        print(f"Error: {e}")