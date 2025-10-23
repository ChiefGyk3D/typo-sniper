"""
Caching module for Typo Sniper.

Provides persistent caching of WHOIS lookups to avoid redundant queries.
"""

import json
import logging
import time
from pathlib import Path
from typing import Any, Optional, Dict
import hashlib


class Cache:
    """Simple file-based cache for WHOIS data."""
    
    def __init__(self, cache_dir: Path):
        """
        Initialize cache.
        
        Args:
            cache_dir: Directory to store cache files
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)
        self.logger.debug(f"Cache initialized at: {self.cache_dir}")
    
    def _get_cache_path(self, key: str) -> Path:
        """
        Get cache file path for a given key.
        
        Args:
            key: Cache key
            
        Returns:
            Path to cache file
        """
        # Create a safe filename from the key using SHA-256
        # Note: This is not for cryptographic security, but for creating unique filenames
        # SHA-256 is used instead of MD5 to satisfy security scanners
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        return self.cache_dir / f"{key_hash}.json"
    
    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Get value from cache.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if not found or expired
        """
        cache_path = self._get_cache_path(key)
        
        if not cache_path.exists():
            return None
        
        try:
            with open(cache_path, 'r') as f:
                data = json.load(f)
            
            # Check if expired
            if 'expires_at' in data and data['expires_at'] < time.time():
                self.logger.debug(f"Cache expired for key: {key}")
                cache_path.unlink()
                return None
            
            self.logger.debug(f"Cache hit for key: {key}")
            return data.get('value')
        
        except (json.JSONDecodeError, KeyError, IOError) as e:
            self.logger.warning(f"Error reading cache for {key}: {e}")
            # Remove corrupted cache file
            if cache_path.exists():
                cache_path.unlink()
            return None
    
    def set(self, key: str, value: Dict[str, Any], ttl: int = 86400) -> None:
        """
        Set value in cache.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds (default: 24 hours)
        """
        cache_path = self._get_cache_path(key)
        
        data = {
            'key': key,
            'value': value,
            'created_at': time.time(),
            'expires_at': time.time() + ttl
        }
        
        try:
            with open(cache_path, 'w') as f:
                json.dump(data, f, indent=2)
            self.logger.debug(f"Cached value for key: {key}")
        
        except IOError as e:
            self.logger.warning(f"Error writing cache for {key}: {e}")
    
    def delete(self, key: str) -> None:
        """
        Delete value from cache.
        
        Args:
            key: Cache key
        """
        cache_path = self._get_cache_path(key)
        
        if cache_path.exists():
            cache_path.unlink()
            self.logger.debug(f"Deleted cache for key: {key}")
    
    def clear(self) -> int:
        """
        Clear all cache entries.
        
        Returns:
            Number of cache entries deleted
        """
        count = 0
        for cache_file in self.cache_dir.glob('*.json'):
            cache_file.unlink()
            count += 1
        
        self.logger.info(f"Cleared {count} cache entries")
        return count
    
    def clear_expired(self) -> int:
        """
        Clear expired cache entries.
        
        Returns:
            Number of expired entries deleted
        """
        count = 0
        current_time = time.time()
        
        for cache_file in self.cache_dir.glob('*.json'):
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                
                if data.get('expires_at', 0) < current_time:
                    cache_file.unlink()
                    count += 1
            
            except (json.JSONDecodeError, IOError):
                # Remove corrupted files
                cache_file.unlink()
                count += 1
        
        self.logger.info(f"Cleared {count} expired cache entries")
        return count
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache statistics
        """
        total = 0
        expired = 0
        total_size = 0
        current_time = time.time()
        
        for cache_file in self.cache_dir.glob('*.json'):
            total += 1
            total_size += cache_file.stat().st_size
            
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                
                if data.get('expires_at', 0) < current_time:
                    expired += 1
            
            except (json.JSONDecodeError, IOError):
                expired += 1
        
        return {
            'total_entries': total,
            'expired_entries': expired,
            'valid_entries': total - expired,
            'total_size_bytes': total_size,
            'total_size_mb': round(total_size / 1024 / 1024, 2),
            'cache_dir': str(self.cache_dir)
        }
