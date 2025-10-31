#!/usr/bin/env python3
"""
ParaProbe - Advanced Parameter Discovery Tool
Discovers hidden GET/POST parameters in web applications
"""

import requests
import argparse
import threading
import time
import sys
import json
from urllib.parse import urlparse, parse_qs, urlencode
from queue import Queue
from typing import List, Dict, Set
import re

# Colors
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    
    @staticmethod
    def disable():
        Colors.HEADER = ''
        Colors.OKBLUE = ''
        Colors.OKCYAN = ''
        Colors.OKGREEN = ''
        Colors.WARNING = ''
        Colors.FAIL = ''
        Colors.ENDC = ''
        Colors.BOLD = ''

class ParaProbe:
    def __init__(self, url: str, wordlist: str, method: str = 'GET', 
                 threads: int = 10, delay: float = 0, headers: Dict = None,
                 placeholder: str = 'FUZZ', stable_check: int = 3, follow_redirects: bool = False):
        self.url = url
        self.wordlist = wordlist
        self.method = method.upper()
        self.threads = threads
        self.delay = delay
        self.headers = headers or {}
        self.placeholder = placeholder
        self.stable_check = stable_check
        self.follow_redirects = follow_redirects
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        if self.headers:
            self.session.headers.update(self.headers)
        
        self.found_params = []
        self.queue = Queue()
        self.lock = threading.Lock()
        self.total_requests = 0
        self.baseline_length = 0
        self.baseline_code = 0
        self.baseline_reflection = False
        
    def load_wordlist(self) -> List[str]:
        """Load parameter wordlist"""
        try:
            with open(self.wordlist, 'r') as f:
                params = [line.strip() for line in f if line.strip()]
            print(f"{Colors.OKGREEN}[+] Loaded {len(params)} parameters from wordlist{Colors.ENDC}")
            return params
        except FileNotFoundError:
            print(f"{Colors.FAIL}[!] Error: Wordlist file not found: {self.wordlist}{Colors.ENDC}")
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error loading wordlist: {e}{Colors.ENDC}")
            sys.exit(1)
    
    def establish_baseline(self):
        """Establish baseline response for comparison"""
        print(f"{Colors.OKCYAN}[*] Establishing baseline...{Colors.ENDC}")
        
        lengths = []
        codes = []
        reflections = []
        
        # Make multiple requests with random param to establish stable baseline
        for i in range(self.stable_check):
            test_param = f"nonexistent_param_{i}" + "x" * 10
            
            try:
                if self.method == 'GET':
                    response = self.session.get(
                        self.url,
                        params={test_param: self.placeholder},
                        timeout=10,
                        allow_redirects=self.follow_redirects
                    )
                else:  # POST
                    response = self.session.post(
                        self.url,
                        data={test_param: self.placeholder},
                        timeout=10,
                        allow_redirects=self.follow_redirects
                    )
                
                lengths.append(len(response.text))
                codes.append(response.status_code)
                reflections.append(self.placeholder in response.text)
                
            except Exception as e:
                print(f"{Colors.FAIL}[!] Error establishing baseline: {e}{Colors.ENDC}")
                sys.exit(1)
        
        # Check if responses are stable
        if len(set(lengths)) > 1 or len(set(codes)) > 1:
            print(f"{Colors.WARNING}[!] Warning: Baseline responses are unstable{Colors.ENDC}")
            print(f"{Colors.WARNING}[*] Lengths: {lengths}{Colors.ENDC}")
            print(f"{Colors.WARNING}[*] Codes: {codes}{Colors.ENDC}")
            print(f"{Colors.WARNING}[*] This may cause false positives{Colors.ENDC}")
        
        # Warning for redirects
        if all(c in [301, 302, 303, 307, 308] for c in codes):
            print(f"{Colors.FAIL}[!] WARNING: Server is redirecting (Status: {codes[0]}){Colors.ENDC}")
            print(f"{Colors.WARNING}[*] You may need authentication or to use --follow-redirects{Colors.ENDC}")
            print(f"{Colors.WARNING}[*] Try adding session cookies with -H \"Cookie: session=...\"{{Colors.ENDC}}\n")
        
        self.baseline_length = max(set(lengths), key=lengths.count)
        self.baseline_code = max(set(codes), key=codes.count)
        self.baseline_reflection = any(reflections)
        
        print(f"{Colors.OKGREEN}[+] Baseline established:{Colors.ENDC}")
        print(f"    Status Code: {self.baseline_code}")
        print(f"    Response Length: {self.baseline_length}")
        print(f"    Reflection: {self.baseline_reflection}")
        print()
    
    def test_parameter(self, param: str) -> bool:
        """Test a single parameter"""
        try:
            if self.method == 'GET':
                response = self.session.get(
                    self.url,
                    params={param: self.placeholder},
                    timeout=10,
                    allow_redirects=self.follow_redirects
                )
            else:  # POST
                response = self.session.post(
                    self.url,
                    data={param: self.placeholder},
                    timeout=10,
                    allow_redirects=self.follow_redirects
                )
            
            with self.lock:
                self.total_requests += 1
            
            # Check for differences from baseline
            length_diff = abs(len(response.text) - self.baseline_length)
            code_diff = response.status_code != self.baseline_code
            reflection = self.placeholder in response.text
            reflection_diff = reflection != self.baseline_reflection
            
            # Detection heuristics
            found = False
            reason = ""
            
            # 1. Status code change
            if code_diff:
                found = True
                reason = f"Status: {response.status_code}"
            
            # 2. Significant length difference (>5% or >50 bytes)
            elif length_diff > 50 or (self.baseline_length > 0 and length_diff / self.baseline_length > 0.05):
                found = True
                reason = f"Length: {len(response.text)} (diff: {length_diff})"
            
            # 3. Reflection behavior change
            elif reflection_diff:
                found = True
                reason = "Reflection detected"
            
            # 4. Error messages in response
            elif self.check_error_messages(response.text, param):
                found = True
                reason = "Error message detected"
            
            if found:
                with self.lock:
                    result = {
                        'param': param,
                        'method': self.method,
                        'status': response.status_code,
                        'length': len(response.text),
                        'reason': reason
                    }
                    self.found_params.append(result)
                    print(f"{Colors.OKGREEN}[+] FOUND: {Colors.BOLD}{param}{Colors.ENDC} ({reason})")
            
            return found
            
        except requests.exceptions.Timeout:
            return False
        except Exception as e:
            return False
    
    def check_error_messages(self, response_text: str, param: str) -> bool:
        """Check for error messages indicating parameter existence"""
        error_patterns = [
            rf"parameter ['\"]?{param}['\"]?",
            rf"missing.*{param}",
            rf"{param}.*required",
            rf"invalid.*{param}",
            rf"undefined.*{param}",
            rf"{param}.*not.*found",
            rf"expects.*{param}",
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False
    
    def worker(self):
        """Worker thread for testing parameters"""
        while True:
            param = self.queue.get()
            if param is None:
                break
            
            self.test_parameter(param)
            
            if self.delay > 0:
                time.sleep(self.delay)
            
            self.queue.task_done()
    
    def scan(self):
        """Main scanning function"""
        print(f"{Colors.BOLD}{Colors.OKCYAN}{'='*60}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.OKCYAN}ParaProbe - Parameter Discovery{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.OKCYAN}{'='*60}{Colors.ENDC}\n")
        
        print(f"{Colors.OKBLUE}[*] Target: {self.url}{Colors.ENDC}")
        print(f"{Colors.OKBLUE}[*] Method: {self.method}{Colors.ENDC}")
        print(f"{Colors.OKBLUE}[*] Threads: {self.threads}{Colors.ENDC}")
        print(f"{Colors.OKBLUE}[*] Wordlist: {self.wordlist}{Colors.ENDC}\n")
        
        # Load wordlist
        params = self.load_wordlist()
        
        # Establish baseline
        self.establish_baseline()
        
        # Start scanning
        print(f"{Colors.OKCYAN}[*] Starting parameter discovery...{Colors.ENDC}\n")
        start_time = time.time()
        
        # Start worker threads
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Add parameters to queue
        for param in params:
            self.queue.put(param)
        
        # Wait for completion
        self.queue.join()
        
        # Stop workers
        for _ in range(self.threads):
            self.queue.put(None)
        for t in threads:
            t.join()
        
        elapsed = time.time() - start_time
        
        # Results
        print(f"\n{Colors.BOLD}{Colors.OKCYAN}{'='*60}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.OKGREEN}Scan Complete!{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.OKCYAN}{'='*60}{Colors.ENDC}\n")
        
        print(f"{Colors.OKBLUE}[*] Total requests: {self.total_requests}{Colors.ENDC}")
        print(f"{Colors.OKBLUE}[*] Time elapsed: {elapsed:.2f}s{Colors.ENDC}")
        print(f"{Colors.OKBLUE}[*] Requests/sec: {self.total_requests/elapsed:.2f}{Colors.ENDC}\n")
        
        if self.found_params:
            print(f"{Colors.OKGREEN}[+] Found {len(self.found_params)} parameters:{Colors.ENDC}\n")
            for result in self.found_params:
                print(f"  {Colors.BOLD}→ {result['param']}{Colors.ENDC}")
                print(f"    Method: {result['method']}, Status: {result['status']}, "
                      f"Length: {result['length']}, Reason: {result['reason']}")
        else:
            print(f"{Colors.WARNING}[!] No parameters discovered{Colors.ENDC}")
        
        print()
        return self.found_params
    
    def export_json(self, filename: str):
        """Export results to JSON"""
        if self.found_params:
            with open(filename, 'w') as f:
                json.dump(self.found_params, f, indent=2)
            print(f"{Colors.OKGREEN}[+] Results exported to {filename}{Colors.ENDC}")

def main():
    parser = argparse.ArgumentParser(
        description='ParaProbe - Discover hidden parameters in web applications',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 paraprobe.py -u https://example.com/api/user -w params.txt
  python3 paraprobe.py -u https://api.example.com -w params.txt -m POST
  python3 paraprobe.py -u https://example.com -w params.txt -t 20 -d 0.1
  python3 paraprobe.py -u https://example.com -w params.txt -o results.json
  python3 paraprobe.py -u https://example.com -w params.txt -H "Authorization: Bearer token"
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-w', '--wordlist', required=True, help='Parameter wordlist file')
    parser.add_argument('-m', '--method', default='GET', choices=['GET', 'POST'], 
                       help='HTTP method (default: GET)')
    parser.add_argument('-t', '--threads', type=int, default=10, 
                       help='Number of threads (default: 10)')
    parser.add_argument('-d', '--delay', type=float, default=0, 
                       help='Delay between requests in seconds (default: 0)')
    parser.add_argument('-H', '--header', action='append', 
                       help='Custom header (can be used multiple times)')
    parser.add_argument('-p', '--placeholder', default='FUZZ', 
                       help='Placeholder value for parameters (default: FUZZ)')
    parser.add_argument('-s', '--stable', type=int, default=3,
                       help='Number of baseline requests for stability check (default: 3)')
    parser.add_argument('-o', '--output', help='Export results to JSON file')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    
    args = parser.parse_args()
    
    # Disable colors if requested
    if args.no_color:
        Colors.disable()
    
    # Parse custom headers
    headers = {}
    if args.header:
        for header in args.header:
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
    
    # Initialize scanner
    scanner = ParaProbe(
        url=args.url,
        wordlist=args.wordlist,
        method=args.method,
        threads=args.threads,
        delay=args.delay,
        headers=headers,
        placeholder=args.placeholder,
        stable_check=args.stable
    )
    
    # Run scan
    try:
        results = scanner.scan()
        
        # Export if requested
        if args.output and results:
            scanner.export_json(args.output)
            
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Scan interrupted by user{Colors.ENDC}")
        sys.exit(0)

if __name__ == '__main__':
    main()
