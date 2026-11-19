#!/usr/bin/env python3
"""Source-free, two-URL informational diagnostic. Not SignalIndex commercial code."""
import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.parse
import urllib.request


def check(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Only credential-free HTTPS URLs are accepted')
    request = urllib.request.Request(url, headers={'User-Agent': 'VeriProof-public-eval/1.0'})
    with urllib.request.urlopen(request, timeout=10) as response:
        data = response.read(262145)
        if len(data) > 262144:
            raise ValueError('Response exceeds 256 KiB limit')
        return {'url': url, 'http_status': response.status, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'verified_price': False}


def main():
    parser = argparse.ArgumentParser(description='Public two-URL SHA-256 retrieval diagnostic; network requests are made')
    parser.add_argument('urls', nargs=2, metavar='HTTPS_URL')
    args = parser.parse_args()
    results = []
    for url in args.urls:
        try:
            results.append({'status': 'PASS', **check(url)})
        except (ValueError, urllib.error.URLError, TimeoutError, OSError) as exc:
            results.append({'url': url, 'status': 'FAIL', 'error_type': type(exc).__name__})
    print(json.dumps({'diagnostic': 'SignalIndex public 2-URL preview', 'results': results, 'disclaimer': 'Content digests are not verified price claims.'}, indent=2))
    return 1 if any(row['status'] == 'FAIL' for row in results) else 0

if __name__ == '__main__':
    sys.exit(main())
