#!/usr/bin/env python3
import requests
from urllib.parse import urljoin
import sys
import urllib3
import argparse
import re
from requests.exceptions import SSLError, ConnectionError

# ANSI color codes (no external dependencies)
R = '\033[31m'  # Red
G = '\033[32m'  # Green
Y = '\033[33m'  # Yellow
C = '\033[36m'  # Cyan
B = '\033[34m'  # Blue
W = '\033[37m'  # White
BR = '\033[1m'  # Bold
RS = '\033[0m'  # Reset

ASCII_HEADER = f"""{BR}
______  _   _  _____   _____
| ___ \\| | | ||_   _| /  ___|
| |_/ /| | | |  | |   \\ `--.   ___  __ _  _ __   _ __    ___  _ __
|  __/ | | | |  | |    `--. \\ / __|/ _` || '_ \\ | '_ \\  / _ \\| '__|
| |    | |_| |  | |   /\\__/ /| (__| (_| || | | || | | ||  __/| |
\\_|     \\___/   \\_/   \\____/  \\___|\\__,_||_| |_||_| |_| \\___||_|
{RS}"""

TOOL_NOTICE = f"""{Y}
[!] AUTHORIZED USE ONLY: This tool is restricted to security professionals with explicit permission
[!] PURPOSE: Identifies writable web directories in Apache Tomcat via HTTP PUT method [CVE-2025-24813]
[!] REFERENCE: https://nvd.nist.gov/vuln/detail/CVE-2025-24813
{RS}"""

common_dirs = [
    '',
    'uploads/',
    'upload/',
    'files/',
    'webdav/',
    'temp/',
    'work/',
    'logs/',
    'webapps/',  
    'ROOT/',
]

def color_status(code):
    """Colorize HTTP status codes"""
    if isinstance(code, str):
        return f"{R}{code}{RS}"
    if 200 <= code < 300:
        return f"{G}{code}{RS}"
    elif code >= 400:
        return f"{R}{code}{RS}"
    return f"{Y}{code}{RS}"

def print_banner(text, color=Y, width=60):
    """Print a formatted banner"""
    print(f"{color}{'═' * width}{RS}")
    print(f"{color}{text.center(width)}{RS}")
    print(f"{color}{'═' * width}{RS}")

def scan_put_writable(base_url, verbose=False, ignore_ssl=False):
    test_filename = 'put_test.txt'
    test_content = b'PUT test file.'
    results = []
    headers = {'Content-Type': 'text/plain'}

    for d in common_dirs:
        target_url = urljoin(base_url, d + test_filename)
        try:
            if verbose:
                print(f"{B}[*]{RS} Testing {C}{target_url}{RS}")

            # Try HTTPS first if URL starts with https://
            if target_url.startswith('https://'):
                try:
                    resp = requests.put(target_url, data=test_content, headers=headers,
                                      timeout=5, verify=not ignore_ssl, allow_redirects=False)
                except requests.exceptions.SSLError:
                    http_url = target_url.replace('https://', 'http://')
                    if verbose:
                        print(f"{Y}[!]{RS} HTTPS failed, trying HTTP: {C}{http_url}{RS}")
                    resp = requests.put(http_url, data=test_content, headers=headers,
                                      timeout=5, verify=False, allow_redirects=False)
                    target_url = http_url
            else:
                resp = requests.put(target_url, data=test_content, headers=headers,
                                  timeout=5, verify=not ignore_ssl, allow_redirects=False)

            put_status = resp.status_code
            get_status = None
            confirmed = False

            if put_status in [200, 201, 204]:
                try:
                    get_resp = requests.get(target_url, timeout=5, verify=not ignore_ssl,
                                          allow_redirects=False)
                    get_status = get_resp.status_code
                    confirmed = (get_status == 200 and get_resp.content == test_content)
                except Exception as e:
                    if verbose:
                        print(f"{R}[!]{RS} GET failed: {e}")
                    get_status = f"GET_ERROR: {str(e)}"

            results.append({
                'dir': d or '/',
                'put_status': put_status,
                'get_status': get_status,
                'confirmed': confirmed,
                'url': target_url
            })

        except Exception as e:
            if verbose:
                print(f"{R}[!]{RS} Request failed: {e}")
            continue

    return results

def process_target(base_url, verbose=False, ignore_ssl=False):
    if not base_url.endswith('/'):
        base_url += '/'

    print_banner(f"Scanning {base_url}", C)
    results = scan_put_writable(base_url, verbose=verbose, ignore_ssl=ignore_ssl)

    print(f"\n{BR}DIRECTORY TEST RESULTS:{RS}")
    for r in results:
        file_url = urljoin(base_url, r['dir'] + 'put_test.txt')

        if r['put_status'] in [200, 201, 204]:
            if r['confirmed']:
                print(f"  {G}✓{RS} {r['dir']: <10} PUT={color_status(r['put_status'])} GET={color_status(r['get_status'])} {G}CONFIRMED{RS}")
                print(f"       {W}File URL: {C}{file_url}{RS}")
            else:
                print(f"  {Y}?{RS} {r['dir']: <10} PUT={color_status(r['put_status'])} GET={color_status(r['get_status'])} {Y}NEEDS REVIEW{RS}")
                print(f"       {W}Verify: {C}curl -X PUT --data 'test' {file_url}{RS}")
                print(f"       {W}Check:  {C}curl {file_url}{RS}")
        else:
            print(f"  {R}✗{RS} {r['dir']: <10} PUT={color_status(r['put_status'])} {R}FAILED{RS}")

    # Summary
    confirmed = [r for r in results if r['confirmed']]
    if confirmed:
        print_banner("CONFIRMED WRITABLE DIRECTORIES", G)
        for r in confirmed:
            print(f"  {G}✓{RS} {r['dir']} (HTTP {color_status(r['put_status'])})")
            print(f"     {W}URL: {C}{r['url']}{RS}")

    unconfirmed = [r for r in results if not r['confirmed'] and r['put_status'] in [200, 201, 204]]
    if unconfirmed:
        print_banner("REQUIRES MANUAL VERIFICATION", Y)
        for r in unconfirmed:
            print(f"  {Y}?{RS} {r['dir']} (HTTP {color_status(r['put_status'])})")
            print(f"     {W}GET returned: {color_status(r['get_status'])}{RS}")
            print(f"     {W}Test URL: {C}{r['url']}{RS}")

def main():
    print(ASCII_HEADER)
    print(TOOL_NOTICE)
    print(f"{B}[*]{RS} Usage: Provide base URL (with/without scheme)")
    print(f"{B}[*]{RS} Protocol: Will try HTTPS first, fall back to HTTP\n")

    parser = argparse.ArgumentParser(
        description=f"{Y}Scan for HTTP PUT writable directories{RS}",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('base_url', nargs='?', help='Target URL (e.g., target:8080/)')
    parser.add_argument('-f', '--file', help='File containing target URLs')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--ignore-ssl', action='store_true', help='Ignore SSL errors')
    args = parser.parse_args()

    if args.ignore_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    targets = []
    if args.file:
        try:
            with open(args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"{R}[!]{RS} Error reading file: {e}")
            sys.exit(1)
    elif args.base_url:
        targets.append(args.base_url)
    else:
        parser.print_help()
        sys.exit(1)

    for target in targets:
        if not re.match(r'^https?://', target):
            target = 'https://' + target  # Default to HTTPS first
        process_target(target, verbose=args.verbose, ignore_ssl=args.ignore_ssl)

if __name__== "__main__":
    main()
