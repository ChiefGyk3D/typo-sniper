#!/usr/bin/env python3
"""
Quick test script to verify URLScan.io API key is working.
"""

import os
import sys
import requests
import json
import time

def test_urlscan_api():
    """Test URLScan.io API key."""
    
    # Try to get API key from environment
    api_key = os.getenv('TYPO_SNIPER_URLSCAN_API_KEY') or os.getenv('URLSCAN_API_KEY')
    
    if not api_key:
        print("❌ ERROR: URLScan API key not found in environment!")
        print("\nPlease set one of these environment variables:")
        print("  export TYPO_SNIPER_URLSCAN_API_KEY='your-api-key'")
        print("  export URLSCAN_API_KEY='your-api-key'")
        return False
    
    print(f"✓ Found API key: {api_key[:8]}...{api_key[-4:]}")
    print("\nTesting URLScan.io API...")
    
    # Test with a simple scan submission
    submit_url = "https://urlscan.io/api/v1/scan/"
    headers = {
        "API-Key": api_key,
        "Content-Type": "application/json"
    }
    data = {
        "url": "https://example.com",
        "visibility": "private"
    }
    
    try:
        print(f"\n1. Submitting test scan to {submit_url}...")
        response = requests.post(submit_url, headers=headers, json=data, timeout=30)
        
        print(f"   Status Code: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print("   ✅ SUCCESS! API key is valid.")
            print(f"\n   Scan UUID: {result.get('uuid')}")
            print(f"   Result URL: {result.get('result')}")
            print(f"   API Response: {json.dumps(result, indent=2)}")
            return True
            
        elif response.status_code == 401:
            print("   ❌ UNAUTHORIZED: Invalid API key!")
            print(f"\n   Response: {response.text}")
            return False
            
        elif response.status_code == 429:
            print("   ⚠️  RATE LIMITED: Too many requests!")
            print("   Your API key is valid but you've hit the rate limit.")
            print(f"\n   Response: {response.text}")
            return True  # Key is valid, just rate limited
            
        elif response.status_code == 400:
            print("   ⚠️  BAD REQUEST: Check the request format")
            print(f"\n   Response: {response.text}")
            return False
            
        else:
            print(f"   ⚠️  UNEXPECTED STATUS: {response.status_code}")
            print(f"\n   Response: {response.text}")
            return False
            
    except requests.exceptions.Timeout:
        print("   ❌ TIMEOUT: Request took too long")
        return False
        
    except requests.exceptions.ConnectionError:
        print("   ❌ CONNECTION ERROR: Could not reach URLScan.io")
        return False
        
    except Exception as e:
        print(f"   ❌ ERROR: {e}")
        return False


def test_urlscan_quota():
    """Check URLScan.io API quota."""
    
    api_key = os.getenv('TYPO_SNIPER_URLSCAN_API_KEY') or os.getenv('URLSCAN_API_KEY')
    
    if not api_key:
        return
    
    print("\n2. Checking API quota limits...")
    
    # URLScan.io doesn't have a dedicated quota endpoint, but we can check rate limits
    # from the response headers of a simple request
    
    try:
        # Try to get user info (if available)
        user_url = "https://urlscan.io/user/quotas/"
        headers = {"API-Key": api_key}
        
        response = requests.get(user_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            print(f"   ✅ Quota info: {response.json()}")
        else:
            print(f"   ⚠️  Could not retrieve quota (Status: {response.status_code})")
            print("   Note: Some accounts may not have access to quota endpoint")
            
    except Exception as e:
        print(f"   ⚠️  Could not check quota: {e}")


if __name__ == "__main__":
    print("="*60)
    print("URLScan.io API Key Test")
    print("="*60)
    
    success = test_urlscan_api()
    test_urlscan_quota()
    
    print("\n" + "="*60)
    if success:
        print("✅ URLScan API key is working!")
    else:
        print("❌ URLScan API key test failed!")
        print("\nTroubleshooting steps:")
        print("1. Verify your API key at: https://urlscan.io/user/profile")
        print("2. Make sure the key is correctly set in your environment")
        print("3. Check if you've exceeded rate limits (free tier: ~50/day)")
        print("4. Ensure the key has not expired")
    print("="*60)
    
    sys.exit(0 if success else 1)
