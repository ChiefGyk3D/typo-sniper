"""
Configuration management for Typo Sniper.
"""

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ChiefGyk3D
# Typo Sniper is dual-licensed; see COMMERCIAL.md for commercial terms.

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from dotenv import find_dotenv, load_dotenv

from version import __version__

# Load environment variables from .env file (search up directory tree)
# override=True will replace existing empty env vars
load_dotenv(find_dotenv(usecwd=True), override=True)


def _expand_path(value: Any) -> Path:
    """Expand ``~`` and environment variables in a path-like value."""
    return Path(os.path.expandvars(os.path.expanduser(str(value))))


@dataclass
class Config:
    """Configuration settings for Typo Sniper."""
    
    # Performance settings
    max_workers: int = 10
    rate_limit_delay: float = 1.0
    
    # Cache settings
    use_cache: bool = True
    cache_dir: Path = field(default_factory=lambda: Path.home() / '.typo_sniper' / 'cache')
    cache_ttl: int = 86400  # 24 hours
    
    # Filter settings
    months_filter: int = 0  # 0 = no filter
    recent_days: int = 90   # A registration this new is flagged as "recent"
    
    # dnstwist settings
    dnstwist_threads: int = 20
    dnstwist_mxcheck: bool = True
    dnstwist_phash: bool = False
    
    # Output settings
    output_dir: Path = field(default_factory=lambda: Path('results'))
    
    # WHOIS settings
    whois_timeout: int = 15
    whois_retry_count: int = 2
    whois_retry_delay: int = 2
    
    # Enhanced detection features (disabled by default for performance)
    enable_combosquatting: bool = False
    enable_soundalike: bool = False
    enable_idn_homograph: bool = False
    
    # Threat intelligence integrations (optional - require API keys)
    enable_urlscan: bool = False
    urlscan_api_key: str | None = None
    urlscan_free_tier: bool = True  # True = 30 search requests/min (free), False = unlimited (paid)
    urlscan_visibility: str = "public"  # public, unlisted, or private
    urlscan_max_age_days: int = 7  # Submit new scan if existing scan is older than this (days)
    urlscan_wait_timeout: int = 90  # Max seconds to wait for scan results
    
    enable_certificate_transparency: bool = True  # No API key needed
    
    # HTTP probing
    enable_http_probe: bool = True
    http_timeout: int = 10
    http_max_bytes: int = 1_048_576  # Cap on probed response bodies (1 MiB)
    http_max_redirects: int = 5
    user_agent: str = (
        f'TypoSniper/{__version__} (+https://github.com/ChiefGyk3D/typo-sniper)'
    )
    
    # Risk scoring
    enable_risk_scoring: bool = True
    
    # Secrets management
    use_doppler: bool = False
    use_aws_secrets: bool = False
    aws_secret_name: str | None = None
    
    # Debug mode (set by CLI flag, not in config file)
    debug_mode: bool = False
    
    def __post_init__(self):
        """Post-initialization: normalise paths and load secrets from environment."""
        # Expand "~" and environment variables so that a config file containing
        # "cache_dir: ~/.typo_sniper/cache" does not create a literal "~"
        # directory in the working directory.
        self.cache_dir = _expand_path(self.cache_dir)
        self.output_dir = _expand_path(self.output_dir)

        # Check if Doppler should be used (check for Doppler CLI environment variables)
        if os.getenv('DOPPLER_PROJECT') or os.getenv('DOPPLER_TOKEN') or os.getenv('TYPO_SNIPER_USE_DOPPLER'):
            self.use_doppler = True
        
        # Check if AWS Secrets Manager should be used
        if os.getenv('AWS_SECRET_NAME') or os.getenv('TYPO_SNIPER_USE_AWS_SECRETS'):
            self.use_aws_secrets = True
            self.aws_secret_name = os.getenv('AWS_SECRET_NAME') or os.getenv('TYPO_SNIPER_AWS_SECRET_NAME')
        
        # Try to load API keys from environment if not set in config        
        if not self.urlscan_api_key:
            self.urlscan_api_key = os.getenv('TYPO_SNIPER_URLSCAN_API_KEY') or os.getenv('URLSCAN_API_KEY')
        
        # Load feature flags from environment variables
        enable_urlscan_env = os.getenv('ENABLE_URLSCAN') or os.getenv('TYPO_SNIPER_ENABLE_URLSCAN')
        if enable_urlscan_env:
            # Explicit enable/disable takes priority
            self.enable_urlscan = enable_urlscan_env.lower() in ('true', '1', 'yes', 'on')
        elif self.urlscan_api_key and not self.enable_urlscan and (self.use_doppler or self.use_aws_secrets):
            # Auto-enable URLScan ONLY if using managed secrets (Doppler or AWS Secrets Manager)
            # Logic: Managed secrets = production environment = want to use all configured services
            # Manual env vars or .env files still require explicit ENABLE_URLSCAN=true
            self.enable_urlscan = True
    
    @classmethod
    def from_file(cls, config_path: Path) -> 'Config':
        """
        Load configuration from YAML file.
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            Config object
            
        Raises:
            FileNotFoundError: If config file doesn't exist
            ValueError: If path validation fails or file type is invalid
        """
        # Resolve to absolute path to prevent path traversal
        try:
            resolved_path = config_path.resolve()
        except (OSError, RuntimeError) as e:
            raise ValueError(f"Invalid config path: {e}") from e
        
        # Validate file extension (allow .yaml, .yml, and .example variations)
        valid_extensions = ['.yaml', '.yml', '.example']
        has_valid_ext = (resolved_path.suffix.lower() in valid_extensions or 
                        any(resolved_path.name.endswith(ext) for ext in ['.yaml.example', '.yml.example']))
        if not has_valid_ext:
            raise ValueError(f"Config file must be a YAML file (.yaml, .yml, or .example), got: {resolved_path.suffix}")
        
        # Check if file exists and is a regular file (not a directory or special file)
        if not resolved_path.exists():
            raise FileNotFoundError(f"Config file not found: {resolved_path}")
        
        if not resolved_path.is_file():
            raise ValueError(f"Config path must be a regular file: {resolved_path}")
        
        # Validate file is readable
        try:
            with open(resolved_path) as f:
                data = yaml.safe_load(f)
        except PermissionError:
            raise ValueError(f"Permission denied reading config file: {resolved_path}") from None
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in config file: {e}") from e
        
        if not isinstance(data, dict):
            raise ValueError("Config file must contain a YAML dictionary")
        
        return cls.from_dict(data)
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> 'Config':
        """
        Create Config from dictionary.
        
        Args:
            data: Configuration dictionary
            
        Returns:
            Config object
        """
        # Copy so we never mutate the caller's dictionary
        data = dict(data)

        # Convert string paths to Path objects (expansion happens in __post_init__)
        if 'cache_dir' in data:
            data['cache_dir'] = _expand_path(data['cache_dir'])
        if 'output_dir' in data:
            data['output_dir'] = _expand_path(data['output_dir'])
        
        # Filter only valid fields
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}
        
        return cls(**filtered_data)
    
    def to_dict(self) -> dict[str, Any]:
        """
        Convert Config to dictionary.
        
        Returns:
            Configuration dictionary
        """
        data = {}
        for field_name in self.__dataclass_fields__:
            value = getattr(self, field_name)
            if isinstance(value, Path):
                data[field_name] = str(value)
            else:
                data[field_name] = value
        return data
    
    def save(self, config_path: Path) -> None:
        """
        Save configuration to YAML file.
        
        Args:
            config_path: Path to save configuration
            
        Raises:
            ValueError: If path validation fails or file type is invalid
        """
        # Resolve to absolute path to prevent path traversal
        try:
            resolved_path = config_path.resolve()
        except (OSError, RuntimeError) as e:
            raise ValueError(f"Invalid config path: {e}") from e
        
        # Validate file extension
        if resolved_path.suffix.lower() not in ['.yaml', '.yml']:
            raise ValueError(f"Config file must be a YAML file (.yaml or .yml), got: {resolved_path.suffix}")
        
        # Create parent directory with validated path
        resolved_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(resolved_path, 'w') as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False)
