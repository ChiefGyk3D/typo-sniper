"""
Secrets management integration for Typo Sniper.

Supports multiple secrets sources:
1. Environment variables (default)
2. Doppler secrets manager (optional)
3. AWS Secrets Manager (optional)
4. Config file (fallback)
"""

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ChiefGyk3D
# Typo Sniper is dual-licensed; see COMMERCIAL.md for commercial terms.

import json
import logging
import os


class SecretsManager:
    """Manage secrets from multiple sources."""
    
    def __init__(self, use_doppler: bool = False, use_aws: bool = False, aws_secret_name: str | None = None):
        """
        Initialize secrets manager.
        
        Args:
            use_doppler: Whether to use Doppler for secrets
            use_aws: Whether to use AWS Secrets Manager
            aws_secret_name: Name of the AWS secret (e.g., 'typo-sniper/prod')
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.use_doppler = use_doppler
        self.doppler_available = False
        self.use_aws = use_aws
        self.aws_available = False
        self.aws_client = None
        self.aws_secrets = {}
        
        if use_doppler:
            try:
                # Probe for the Doppler SDK without importing it; secrets are
                # read from the environment that `doppler run` injects.
                import importlib.util
                if importlib.util.find_spec('doppler_sdk') is None:
                    raise ImportError('doppler_sdk not installed')
                self.doppler_available = True
                self.doppler_client = None
                self.logger.info("Doppler secrets manager enabled")
            except ImportError:
                self.logger.warning(
                    "Doppler requested but doppler-sdk not installed. "
                    "Install with: pip install doppler-sdk"
                )
                self.use_doppler = False
        
        if use_aws:
            try:
                # Try to import boto3
                import boto3
                self.aws_available = True
                self.aws_client = boto3.client('secretsmanager')
                
                # Load secrets from AWS if secret name provided
                if aws_secret_name:
                    self._load_aws_secrets(aws_secret_name)
                
                self.logger.info("AWS Secrets Manager enabled")
            except ImportError:
                self.logger.warning(
                    "AWS Secrets Manager requested but boto3 not installed. "
                    "Install with: pip install boto3"
                )
                self.use_aws = False
            except Exception as e:
                self.logger.error(f"Failed to initialize AWS Secrets Manager: {e}")
                self.use_aws = False
    
    def _load_aws_secrets(self, secret_name: str) -> None:
        """
        Load secrets from AWS Secrets Manager.
        
        Args:
            secret_name: Name of the AWS secret
        """
        try:
            response = self.aws_client.get_secret_value(SecretId=secret_name)
            
            if 'SecretString' in response:
                self.aws_secrets = json.loads(response['SecretString'])
                self.logger.info("Loaded AWS secrets successfully")
            else:
                self.logger.warning("AWS secret contained no SecretString value")
        except Exception as e:
            # Only the exception type is recorded. Messages raised by a secrets
            # backend can embed response content, and the secret's name can
            # reveal internal structure in a shared log aggregator. The name is
            # operator-configured (a single aws_secret_name), so naming it here
            # would add nothing an operator does not already know.
            self.logger.error("Failed to load AWS secrets (%s)", type(e).__name__)
            self.use_aws = False
    
    def get_secret(self, key: str, default: str | None = None) -> str | None:
        """
        Get a secret value from available sources.
        
        Priority order:
        1. Environment variables (TYPO_SNIPER_<KEY>)
        2. Doppler SDK (if enabled and configured)
        3. AWS Secrets Manager (if enabled and configured)
        4. Default value
        
        Args:
            key: Secret key name (e.g., 'urlscan_api_key')
            default: Default value if secret not found
            
        Returns:
            Secret value or default
        """
        # Check environment variable first (highest priority)
        env_key = f"TYPO_SNIPER_{key.upper()}"
        value = os.getenv(env_key)
        
        if value:
            self.logger.debug(f"Found {key} in environment variable {env_key}")
            return value
        
        # Check Doppler if enabled
        # Note: Doppler CLI injects secrets as environment variables when using 'doppler run'
        # So we check the standard uppercase key format that Doppler uses
        if self.use_doppler and self.doppler_available:
            doppler_key = key.upper()
            value = os.getenv(doppler_key)
            if value:
                self.logger.debug(f"Found {key} from Doppler ({doppler_key})")
                return value
        
        # Check AWS Secrets Manager if enabled
        if self.use_aws and self.aws_available and self.aws_secrets:
            # Try both formats: original key and uppercase
            aws_key = key.lower()
            if aws_key in self.aws_secrets:
                self.logger.debug(f"Found {key} from AWS Secrets Manager")
                return self.aws_secrets[aws_key]
            
            # Try uppercase version
            aws_key_upper = key.upper()
            if aws_key_upper in self.aws_secrets:
                self.logger.debug(f"Found {key} from AWS Secrets Manager ({aws_key_upper})")
                return self.aws_secrets[aws_key_upper]
        
        # Return default
        if default:
            self.logger.debug(f"Using default value for {key}")
        else:
            self.logger.debug(f"No secret found for {key}")
        
        return default
    
    def get_api_key(self, service: str, config_value: str | None = None) -> str | None:
        """
        Get API key for a service.
        
        Args:
            service: Service name (e.g., 'urlscan')
            config_value: Value from config file (fallback)
            
        Returns:
            API key or None
        """
        # Try secrets manager first
        key = f"{service}_api_key"
        api_key = self.get_secret(key)
        
        # Fall back to config file value
        if not api_key and config_value:
            self.logger.debug(f"Using {service} API key from config file")
            return config_value
        
        return api_key
    
    @staticmethod
    def is_doppler_cli_available() -> bool:
        """
        Check if Doppler CLI is installed.
        
        Returns:
            True if doppler command is available
        """
        import shutil
        return shutil.which('doppler') is not None
