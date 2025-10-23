"""
Configuration management for Typo Sniper.
"""

import os
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Dict, Any
from dotenv import load_dotenv, find_dotenv

# Load environment variables from .env file (search up directory tree)
# override=True will replace existing empty env vars
load_dotenv(find_dotenv(usecwd=True), override=True)


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
    
    # dnstwist settings
    dnstwist_threads: int = 20
    dnstwist_mxcheck: bool = True
    dnstwist_phash: bool = False
    
    # Output settings
    output_dir: Path = field(default_factory=lambda: Path('results'))
    
    # WHOIS settings
    whois_timeout: int = 30
    whois_retry_count: int = 3
    whois_retry_delay: int = 5
    
    # Enhanced detection features (disabled by default for performance)
    enable_combosquatting: bool = False
    enable_soundalike: bool = False
    enable_idn_homograph: bool = False
    
    # Threat intelligence integrations (optional - require API keys)
    enable_urlscan: bool = False
    urlscan_api_key: Optional[str] = None
    urlscan_free_tier: bool = True  # True = 30 search requests/min (free), False = unlimited (paid)
    urlscan_visibility: str = "public"  # public, unlisted, or private
    urlscan_max_age_days: int = 7  # Submit new scan if existing scan is older than this (days)
    urlscan_wait_timeout: int = 90  # Max seconds to wait for scan results
    
    enable_certificate_transparency: bool = True  # No API key needed
    
    # HTTP probing
    enable_http_probe: bool = True
    http_timeout: int = 10
    
    # Risk scoring
    enable_risk_scoring: bool = True
    
    # Machine Learning (optional - requires ML dependencies)
    enable_ml: bool = False
    ml_model_path: Optional[str] = None
    ml_confidence_threshold: float = 0.7  # High confidence threshold (0-1)
    ml_enable_active_learning: bool = False
    ml_uncertainty_threshold: float = 0.15  # For active learning selection
    ml_review_budget: int = 100  # Max domains to flag for review per scan
    
    # Secrets management
    use_doppler: bool = False
    use_aws_secrets: bool = False
    aws_secret_name: Optional[str] = None
    
    # Debug mode (set by CLI flag, not in config file)
    debug_mode: bool = False
    
    def __post_init__(self):
        """Post-initialization to load secrets from environment."""
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
        
        # ML feature flags
        enable_ml_env = os.getenv('ENABLE_ML') or os.getenv('TYPO_SNIPER_ENABLE_ML')
        if enable_ml_env:
            self.enable_ml = enable_ml_env.lower() in ('true', '1', 'yes', 'on')
        
        if not self.ml_model_path:
            self.ml_model_path = os.getenv('ML_MODEL_PATH') or os.getenv('TYPO_SNIPER_ML_MODEL_PATH')
    
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
            raise ValueError(f"Invalid config path: {e}")
        
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
            with open(resolved_path, 'r') as f:
                data = yaml.safe_load(f)
        except PermissionError:
            raise ValueError(f"Permission denied reading config file: {resolved_path}")
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in config file: {e}")
        
        if not isinstance(data, dict):
            raise ValueError("Config file must contain a YAML dictionary")
        
        return cls.from_dict(data)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Config':
        """
        Create Config from dictionary.
        
        Args:
            data: Configuration dictionary
            
        Returns:
            Config object
        """
        # Convert string paths to Path objects
        if 'cache_dir' in data:
            data['cache_dir'] = Path(data['cache_dir'])
        if 'output_dir' in data:
            data['output_dir'] = Path(data['output_dir'])
        
        # Filter only valid fields
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}
        
        return cls(**filtered_data)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert Config to dictionary.
        
        Returns:
            Configuration dictionary
        """
        data = {}
        for field_name, field_def in self.__dataclass_fields__.items():
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
            raise ValueError(f"Invalid config path: {e}")
        
        # Validate file extension
        if resolved_path.suffix.lower() not in ['.yaml', '.yml']:
            raise ValueError(f"Config file must be a YAML file (.yaml or .yml), got: {resolved_path.suffix}")
        
        # Create parent directory with validated path
        resolved_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(resolved_path, 'w') as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False)
