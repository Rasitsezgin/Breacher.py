#!/usr/bin/env python3
"""
Breacher  - Admin Panel Discovery
Only shows successful findings (200) and critical vulnerabilities
-------------------------------------------------------------------------------------------
python breacher.py -u https://example.com
python breacher.py -u https://example.com --fast
python breacher.py -u https://example.com -t 15 --type php
"""

import requests
import sys
import time
import json
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
import argparse
import warnings

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

@dataclass
class Finding:
    url: str
    status_code: int
    content_length: int
    response_time: float
    server: str
    title: str
    vulnerability: Optional[str] = None
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> Dict:
        return asdict(self)

class SilentScanner:
    def __init__(self, target_url: str, config: Dict):
        self.target_url = self._normalize_url(target_url)
        self.config = config
        self.findings: List[Finding] = []
        self.session = self._create_session()
        self.start_time = None
        self.total_scanned = 0
        
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0'
        ]
        
        # Vulnerability patterns
        self.vuln_patterns = {
            'Directory Listing': ['Index of /', 'Parent Directory', '<title>Index of'],
            'phpinfo()': ['phpinfo()', 'PHP Version', 'System </td>'],
            'Config Exposure': ['DB_PASSWORD', 'database_password', 'api_key', 'secret_key'],
            'Backup File': ['.sql', '.backup', '.old', '.bak'],
            'Git Exposure': ['.git/config', 'repositoryformatversion'],
            'ENV File': ['APP_KEY=', 'DB_HOST=', 'AWS_ACCESS'],
            'SQL Error': ['mysql_fetch', 'SQLException', 'ORA-', 'PostgreSQL'],
            'Debug Mode': ['DEBUG = True', 'debug_mode', 'SQLSTATE'],
            'Admin Panel': ['admin login', 'administrator login', 'dashboard'],
            'Install Page': ['installation', 'setup wizard', 'install.php'],
            'Upload Form': ['file upload', 'choose file', 'enctype="multipart'],
            'Login Panel': ['username', 'password', 'login', 'signin'],
        }
    
    def _normalize_url(self, url: str) -> str:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        if not url.endswith('/'):
            url += '/'
        return url
    
    def _create_session(self) -> requests.Session:
        session = requests.Session()
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.3,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=50, pool_maxsize=50)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
    
    def _get_random_user_agent(self) -> str:
        import random
        return random.choice(self.user_agents)
    
    def _check_vulnerability(self, response: requests.Response) -> Optional[str]:
        """Check response for known vulnerabilities"""
        content = response.text.lower()
        url_lower = response.url.lower()
        
        for vuln_name, patterns in self.vuln_patterns.items():
            for pattern in patterns:
                if pattern.lower() in content or pattern.lower() in url_lower:
                    return vuln_name
        
        return None
    
    def scan_path(self, path: str) -> Optional[Finding]:
        """Scan single path - only return if status 200"""
        full_url = urljoin(self.target_url, path.lstrip('/'))
        
        try:
            if self.config.get('delay', 0) > 0:
                time.sleep(self.config['delay'])
            
            start_time = time.time()
            response = self.session.get(
                full_url,
                timeout=self.config.get('timeout', 10),
                verify=False,
                allow_redirects=True,
                headers={
                    'User-Agent': self._get_random_user_agent(),
                    'Accept': '*/*',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Connection': 'keep-alive'
                }
            )
            response_time = time.time() - start_time
            
            self.total_scanned += 1
            
            # Only process 200 OK responses
            if response.status_code == 200:
                server = response.headers.get('Server', 'Unknown')
                
                # Extract title
                title = "N/A"
                if 'text/html' in response.headers.get('Content-Type', ''):
                    try:
                        import re
                        title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
                        if title_match:
                            title = title_match.group(1).strip()[:100]
                    except:
                        pass
                
                # Check for vulnerabilities
                vulnerability = self._check_vulnerability(response)
                
                finding = Finding(
                    url=full_url,
                    status_code=200,
                    content_length=len(response.content),
                    response_time=response_time,
                    server=server,
                    title=title,
                    vulnerability=vulnerability
                )
                
                return finding
            
            return None
            
        except:
            return None
    
    def load_wordlist(self, wordlist_path: str, file_type: Optional[str] = None) -> List[str]:
        """Load and filter wordlist"""
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                paths = [line.strip() for line in f if line.strip()]
            
            if file_type:
                filtered_paths = []
                for path in paths:
                    ext = path.split('.')[-1].lower() if '.' in path else ''
                    
                    if file_type == 'html' and ext not in ['asp', 'aspx', 'php', 'jsp']:
                        filtered_paths.append(path)
                    elif file_type == 'asp' and ext in ['asp', 'aspx']:
                        filtered_paths.append(path)
                    elif file_type == 'php' and ext == 'php':
                        filtered_paths.append(path)
                    elif file_type == 'jsp' and ext in ['jsp', 'jsf']:
                        filtered_paths.append(path)
                    elif not file_type:
                        filtered_paths.append(path)
                
                paths = filtered_paths
            
            return paths
            
        except FileNotFoundError:
            print(f"{Colors.RED}[!] Wordlist not found: {wordlist_path}{Colors.END}")
            sys.exit(1)
    
    def run_scan(self, paths: List[str]):
        """Execute scan with threading"""
        self.start_time = time.time()
        total_paths = len(paths)
        
        print(f"{Colors.CYAN}[*] Scanning {self.target_url} with {total_paths} paths...{Colors.END}\n")
        
        with ThreadPoolExecutor(max_workers=self.config['threads']) as executor:
            future_to_path = {executor.submit(self.scan_path, path): path for path in paths}
            
            for future in as_completed(future_to_path):
                result = future.result()
                if result:
                    self.findings.append(result)
                    
                    # Print finding immediately
                    vuln_indicator = f" [{Colors.RED}{result.vulnerability}{Colors.END}]" if result.vulnerability else ""
                    print(f"{Colors.GREEN}[+] {result.url}{Colors.END} [{result.content_length} bytes] {result.title[:50]}{vuln_indicator}")
    
    def save_results(self):
        """Save results to JSON file"""
        if not self.findings:
            return None
        
        output_dir = Path("reports")
        output_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = output_dir / f"findings_{timestamp}.json"
        
        report_data = {
            "scan_info": {
                "target": self.target_url,
                "timestamp": timestamp,
                "total_scanned": self.total_scanned,
                "successful_finds": len(self.findings),
                "vulnerabilities_found": len([f for f in self.findings if f.vulnerability])
            },
            "findings": [f.to_dict() for f in self.findings]
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=4)
        
        return report_file
    
    def print_summary(self):
        """Print minimal summary"""
        elapsed = time.time() - self.start_time
        vuln_count = len([f for f in self.findings if f.vulnerability])
        
        print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"{Colors.GREEN}[✓] Scan Complete{Colors.END}")
        print(f"    Total Scanned: {self.total_scanned}")
        print(f"    Findings (200): {len(self.findings)}")
        print(f"    Vulnerabilities: {vuln_count}")
        print(f"    Duration: {elapsed:.2f}s")
        print(f"{Colors.BOLD}{'='*70}{Colors.END}\n")

def main():
    parser = argparse.ArgumentParser(description="Breacher Pro - Silent Mode (200 OK only)")
    
    parser.add_argument("-u", "--url", required=True, dest='target',
                       help="Target URL")
    parser.add_argument("-w", "--wordlist", default="paths.txt",
                       help="Wordlist file (default: paths.txt)")
    parser.add_argument("--type", choices=['html', 'php', 'asp', 'jsp'],
                       help="Filter by file type")
    parser.add_argument("--path-prefix", dest='prefix',
                       help="Path prefix")
    parser.add_argument("-t", "--threads", type=int, default=10,
                       help="Threads (default: 10)")
    parser.add_argument("--delay", type=float, default=0,
                       help="Delay between requests")
    parser.add_argument("--timeout", type=int, default=10,
                       help="Request timeout")
    parser.add_argument("--fast", action="store_true",
                       help="Fast mode (20 threads)")
    
    args = parser.parse_args()
    
    if args.fast:
        args.threads = 20
    
    if args.threads > 50:
        args.threads = 50
    
    config = {
        'threads': args.threads,
        'delay': args.delay,
        'timeout': args.timeout
    }
    
    scanner = SilentScanner(args.target, config)
    
    if args.prefix:
        scanner.target_url = urljoin(scanner.target_url, args.prefix.lstrip('/'))
        if not scanner.target_url.endswith('/'):
            scanner.target_url += '/'
    
    paths = scanner.load_wordlist(args.wordlist, args.type)
    
    if not paths:
        print(f"{Colors.RED}[!] No paths to scan{Colors.END}")
        sys.exit(1)
    
    try:
        scanner.run_scan(paths)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted by user{Colors.END}")
    
    scanner.print_summary()
    
    if scanner.findings:
        report_file = scanner.save_results()
        if report_file:
            print(f"{Colors.GREEN}[+] Results saved: {report_file}{Colors.END}\n")
        
        # Show vulnerabilities summary
        vulns = [f for f in scanner.findings if f.vulnerability]
        if vulns:
            print(f"{Colors.RED}{Colors.BOLD}[!] VULNERABILITIES DETECTED:{Colors.END}")
            for finding in vulns:
                print(f"    {Colors.RED}→{Colors.END} {finding.url}")
                print(f"      Type: {finding.vulnerability}")
                print(f"      Title: {finding.title}\n")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Terminated{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {str(e)}{Colors.END}")
        sys.exit(1)
