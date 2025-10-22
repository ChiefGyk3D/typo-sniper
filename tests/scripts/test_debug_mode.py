#!/usr/bin/env python3
"""
Test script to verify debug mode is working with enhanced detection.
"""

import sys
import asyncio
import logging
from pathlib import Path

sys.path.insert(0, 'src')

from config import Config
from enhanced_detection import generate_enhanced_permutations

async def test_debug_mode():
    """Test debug mode with enhanced detection."""
    
    # Test 1: Without debug mode
    print("=" * 60)
    print("TEST 1: Without debug mode (features disabled)")
    print("=" * 60)
    
    logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")
    
    config = Config.from_file(Path('test_config.yaml'))
    config.debug_mode = False
    
    domain = 'google.com'
    perms = generate_enhanced_permutations(domain, config)
    print(f"\nResult: {len(perms)} permutations generated\n")
    
    # Test 2: With debug mode (features still disabled)
    print("=" * 60)
    print("TEST 2: With debug mode (features disabled - should show why)")
    print("=" * 60)
    
    # Re-setup logging with DEBUG level
    logging.getLogger().setLevel(logging.DEBUG)
    
    config.debug_mode = True
    perms = generate_enhanced_permutations(domain, config)
    print(f"\nResult: {len(perms)} permutations generated\n")
    
    # Test 3: With debug mode and features enabled
    print("=" * 60)
    print("TEST 3: With debug mode (features ENABLED)")
    print("=" * 60)
    
    config.enable_combosquatting = True
    config.enable_idn_homograph = True
    perms = generate_enhanced_permutations(domain, config)
    print(f"\nResult: {len(perms)} permutations generated")
    if perms:
        print(f"First 10 examples: {list(perms)[:10]}")
    print()

if __name__ == '__main__':
    asyncio.run(test_debug_mode())
