#KULLANIMI :    python breacher.py -u http://example.com

import requests
import threading 
import argparse
from urllib.parse import urljoin

def print_banner():
    """Prints a fancy banner for the tool."""
    print ('''\033[1;34m______   ______ _______ _______ _______ _     _ _______  ______
|_____] |_____/ |______ |_____| |       |_____| |______ |_____/
|_____] |    \_ |______ |     | |_____  |     | |______ |    \_

                          \033[37mMade with \033[91m<3\033[37m By D3V\033[1;m''')
    print ('\n  I am not responsible for your shit and if you get some error while')
    print (' running Breacher, there are good chances that target isn\'t responding.\n')
    print ('\033[1;31m--------------------------------------------------------------------------\033[1;m\n')

def check_robots_txt(target_url):
    """Checks for the presence of robots.txt and prints its content if found."""
    robots_url = urljoin(target_url, '/robots.txt')
    print(f'  Attempting to fetch {robots_url}...')
    try:
        r = requests.get(robots_url, timeout=5) # Added a timeout for robustness
        if r.status_code == 200 and '<html' not in r.text.lower():
            print ('  \033[1;32m[+]\033[0m Robots.txt found. Check for any interesting entry\n')
            print (r.text)
        else:
            print ('  \033[1;31m[-]\033[1;m Robots.txt not found or is an HTML error page.\n')
    except requests.exceptions.RequestException as e:
        print (f'  \033[1;31m[-]\033[1;m Failed to retrieve robots.txt: {e}\n')
    print ('\033[1;31m--------------------------------------------------------------------------\033[1;m\n')

def scan_path(target_url, path):
    """
    Constructs the full URL, sends a GET request, and reports the status.
    """
    full_url = urljoin(target_url, path)
    try:
        r = requests.get(full_url, timeout=10) # Increased timeout for potential slower responses
        http_status = r.status_code
        if http_status == 200:
            print (f'  \033[1;32m[+]\033[0m Admin panel found: {full_url}')
        elif http_status == 404:
            print (f'  \033[1;31m[-]\033[1;m {full_url} (Not Found)')
        elif http_status in [301, 302, 303, 307, 308]: # More comprehensive redirection checks
            print (f'  \033[1;32m[+]\033[0m Potential redirection found: {full_url} (Status: {http_status})')
        else:
            print (f'  \033[1;31m[-]\033[1;m {full_url} (Status: {http_status})')
    except requests.exceptions.ConnectionError:
        print (f'  \033[1;31m[!]\033[1;m Connection error for: {full_url}')
    except requests.exceptions.Timeout:
        print (f'  \033[1;31m[!]\033[1;m Timeout for: {full_url}')
    except requests.exceptions.RequestException as e:
        print (f'  \033[1;31m[!]\033[1;m An error occurred for {full_url}: {e}')

def get_paths(filepath, file_type=None):
    """
    Reads paths from a wordlist, optionally filtering by file type.
    """
    paths = []
    try:
        with open(filepath, 'r') as wordlist:
            for line in wordlist:
                path = line.strip()
                if not path: # Skip empty lines
                    continue

                # Apply type filtering if specified
                if file_type:
                    path_extension = path.split('.')[-1] if '.' in path else ''
                    if file_type.lower() == 'html' and path_extension not in ['asp', 'php']:
                        paths.append(path)
                    elif file_type.lower() == 'asp' and path_extension not in ['html', 'php']:
                        paths.append(path)
                    elif file_type.lower() == 'php' and path_extension not in ['html', 'asp']:
                        paths.append(path)
                    elif file_type.lower() not in ['html', 'asp', 'php']: # If type is something else, add all
                         paths.append(path)
                else: # No type specified, add all paths
                    paths.append(path)
    except FileNotFoundError:
        print (f'\033[1;31m[-]\033[1;m Wordlist file "{filepath}" not found!')
        quit()
    return paths

def main():
    parser = argparse.ArgumentParser(description="Breacher: A simple web path scanner.")
    parser.add_argument("-u", "--url", help="Target URL (e.g., http://example.com)", dest='target', required=True)
    parser.add_argument("--path-prefix", help="Custom path prefix (e.g., /admin)", dest='prefix')
    parser.add_argument("--type", help="Filter paths by type (e.g., html, asp, php)", dest='type')
    parser.add_argument("--fast", help="Use multi-threading for faster scanning", dest='fast', action="store_true")
    parser.add_argument("--wordlist", help="Path to the wordlist file (default: paths.txt)", default="paths.txt")
    args = parser.parse_args()

    print_banner()

    target_url = args.target
    # Ensure target_url has a scheme for urljoin to work correctly
    if not target_url.startswith('http://') and not target_url.startswith('https://'):
        target_url = 'http://' + target_url

    # Normalize target URL for consistent path joining
    if not target_url.endswith('/'):
        target_url += '/'

    # Add custom prefix if provided
    if args.prefix:
        target_url = urljoin(target_url, args.prefix.lstrip('/'))
        if not target_url.endswith('/'): # Ensure trailing slash for prefix if it's a directory
            target_url += '/'

    print(f'  Target URL: \033[1;33m{target_url}\033[0m\n')

    check_robots_txt(target_url)

    all_paths = get_paths(args.wordlist, args.type)
    if not all_paths:
        print('\033[1;31m[-]\033[1;m No paths to scan after filtering. Exiting.')
        quit()

    print(f'  Starting scan for {len(all_paths)} paths...\n')

    if args.fast:
        num_threads = 2 # You could make this configurable or dynamic based on CPU cores
        chunk_size = len(all_paths) // num_threads
        threads = []
        for i in range(num_threads):
            start_index = i * chunk_size
            end_index = (i + 1) * chunk_size if i < num_threads - 1 else len(all_paths)
            paths_chunk = all_paths[start_index:end_index]
            if paths_chunk: # Only create a thread if there's work to do
                thread = threading.Thread(target=lambda p=paths_chunk: [scan_path(target_url, path) for path in p])
                threads.append(thread)
                thread.start()

        for thread in threads:
            thread.join()
    else:
        for path in all_paths:
            scan_path(target_url, path)

    print ('\n\033[1;32m[+]\033[0m Scan complete.\n')

if __name__ == '__main__':
    main()
