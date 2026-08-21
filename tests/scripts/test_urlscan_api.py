#!/usr/bin/env python3
"""
Quick manual check that a URLScan.io API key works.

Uses only the standard library so it can run before the project's dependencies
are installed, and so verifying a key needs no extra packages.

Usage:
    export TYPO_SNIPER_URLSCAN_API_KEY='your-api-key'
    python3 tests/scripts/test_urlscan_api.py
"""

import json
import os
import sys
import urllib.error
import urllib.request

TIMEOUT = 30


def _request(url, api_key, payload=None):
    """
    Perform an HTTP request and return (status, body_text).

    Args:
        url: Target URL
        api_key: URLScan.io API key
        payload: Optional dictionary to POST as JSON

    Returns:
        Tuple of (status_code, response_body)
    """
    headers = {'API-Key': api_key}
    data = None

    if payload is not None:
        data = json.dumps(payload).encode('utf-8')
        headers['Content-Type'] = 'application/json'

    request = urllib.request.Request(url, data=data, headers=headers)

    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return response.status, response.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        # A non-2xx status is the answer here, not an error
        return e.code, e.read().decode('utf-8', 'replace')


def test_urlscan_api():
    """Submit a scan to confirm the API key is accepted."""
    api_key = os.getenv('TYPO_SNIPER_URLSCAN_API_KEY') or os.getenv('URLSCAN_API_KEY')

    if not api_key:
        print("❌ ERROR: URLScan API key not found in environment!")
        print("\nPlease set one of these environment variables:")
        print("  export TYPO_SNIPER_URLSCAN_API_KEY='your-api-key'")
        print("  export URLSCAN_API_KEY='your-api-key'")
        return False

    print(f"✓ Found API key: {api_key[:8]}...{api_key[-4:]}")
    print("\nTesting URLScan.io API...")

    submit_url = "https://urlscan.io/api/v1/scan/"
    payload = {'url': 'https://example.com', 'visibility': 'private'}

    try:
        print(f"\n1. Submitting test scan to {submit_url}...")
        status, body = _request(submit_url, api_key, payload)
        print(f"   Status Code: {status}")

        if status == 200:
            result = json.loads(body)
            print("   ✅ SUCCESS! API key is valid.")
            print(f"\n   Scan UUID: {result.get('uuid')}")
            print(f"   Result URL: {result.get('result')}")
            return True

        if status == 401:
            print("   ❌ UNAUTHORIZED: Invalid API key!")
            print(f"\n   Response: {body}")
            return False

        if status == 429:
            print("   ⚠️  RATE LIMITED: Too many requests!")
            print("   Your API key is valid but you've hit the rate limit.")
            return True  # The key is valid, just throttled

        if status == 400:
            print("   ⚠️  BAD REQUEST: Check the request format")
            print(f"\n   Response: {body}")
            return False

        print(f"   ⚠️  UNEXPECTED STATUS: {status}")
        print(f"\n   Response: {body}")
        return False

    except TimeoutError:
        print("   ❌ TIMEOUT: Request took too long")
        return False
    except urllib.error.URLError as e:
        print(f"   ❌ CONNECTION ERROR: Could not reach URLScan.io ({e.reason})")
        return False
    except Exception as e:
        print(f"   ❌ ERROR: {e}")
        return False


def test_urlscan_quota():
    """Report the account's quota, when the endpoint is available."""
    api_key = os.getenv('TYPO_SNIPER_URLSCAN_API_KEY') or os.getenv('URLSCAN_API_KEY')

    if not api_key:
        return

    print("\n2. Checking API quota limits...")

    try:
        status, body = _request("https://urlscan.io/user/quotas/", api_key)
        if status == 200:
            print(f"   ✅ Quota info: {body}")
        else:
            print(f"   ⚠️  Could not retrieve quota (Status: {status})")
            print("   Note: Some accounts may not have access to the quota endpoint")
    except Exception as e:
        print(f"   ⚠️  Could not check quota: {e}")


if __name__ == "__main__":
    print("=" * 60)
    print("URLScan.io API Key Test")
    print("=" * 60)

    success = test_urlscan_api()
    test_urlscan_quota()

    print("\n" + "=" * 60)
    if success:
        print("✅ URLScan API key is working!")
    else:
        print("❌ URLScan API key test failed!")
        print("\nTroubleshooting steps:")
        print("1. Verify your API key at: https://urlscan.io/user/profile")
        print("2. Make sure the key is correctly set in your environment")
        print("3. Check if you've exceeded rate limits (free tier: ~50/day)")
        print("4. Ensure the key has not expired")
    print("=" * 60)

    sys.exit(0 if success else 1)
