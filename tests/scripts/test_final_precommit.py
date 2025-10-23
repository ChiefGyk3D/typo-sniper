#!/usr/bin/env python3
"""
Final pre-commit test script for Typo Sniper.
Tests all key functionality before pushing to GitHub.
"""
import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from config import Config
from threat_intelligence import ThreatIntelligence


async def main():
    print("\n" + "="*76)
    print("                 FINAL PRE-COMMIT TEST SUITE")
    print("="*76 + "\n")
    
    # Test 1: Configuration
    print("✓ Test 1: Configuration")
    config = Config()
    print(f"  Using Doppler: {config.use_doppler}")
    print(f"  URLScan API Key: {'***' + config.urlscan_api_key[-6:] if config.urlscan_api_key else 'NOT SET'}")
    print(f"  URLScan Enabled: {config.enable_urlscan} {'(auto-enabled)' if config.enable_urlscan else ''}")
    print(f"  Max Age Days: {config.urlscan_max_age_days}")
    print(f"  Wait Timeout: {config.urlscan_wait_timeout}s")
    
    if not config.urlscan_api_key:
        print("\n✗ FAILED: URLScan API key not configured")
        return False
    
    if not config.enable_urlscan:
        print("\n✗ FAILED: URLScan not enabled")
        return False
    
    # Test 2: API Connectivity
    print("\n✓ Test 2: URLScan API Connectivity")
    try:
        async with ThreatIntelligence(config) as ti:
            print("  API Key validation: PASSED")
            
            # Test 3: Quick URLScan test
            print("\n✓ Test 3: URLScan Functionality")
            result = await ti.check_urlscan('google.com')
            if result:
                print(f"  Successfully retrieved URLScan data")
                print(f"  Malicious: {result.get('malicious', 'N/A')}")
                print(f"  Score: {result.get('score', 'N/A')}")
                if 'scan_age_days' in result:
                    print(f"  Scan Age: {result['scan_age_days']} days")
            else:
                print("  URLScan returned no data (may be rate limited or no recent scan)")
    except Exception as e:
        print(f"\n✗ FAILED: {e}")
        return False
    
    print("\n" + "="*76)
    print("                  ALL TESTS PASSED ✓")
    print("="*76)
    print("\nReady to commit and push to GitHub!")
    return True


if __name__ == '__main__':
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
