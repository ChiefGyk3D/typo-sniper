"""
Configuration management for Typo Sniper.
"""

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ChiefGyk3D
# Typo Sniper is dual-licensed; see COMMERCIAL.md for commercial terms.

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from dotenv import find_dotenv, load_dotenv

from .version import __version__

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
    
    # Registration data lookup
    # RDAP (RFC 7482) speaks HTTPS on 443 and returns structured JSON. WHOIS
    # needs TCP/43, which is blocked on many corporate networks and in most CI
    # sandboxes, where it fails as a silent timeout rather than a clear error.
    use_rdap: bool = True
    rdap_timeout: int = 15
    whois_fallback: bool = True   # Fall back to WHOIS when RDAP has no endpoint

    # Scan history and change detection
    enable_diff: bool = True
    state_dir: Path = field(default_factory=lambda: Path.home() / '.typo_sniper' / 'state')
    history_retain: int = 30      # Scans kept per monitored domain

    # Watch mode
    watch_interval: int = 86400   # Seconds between scans when --watch is set

    # Notifications (fire on changes only, never on the full result set)
    enable_notifications: bool = False
    # slack, discord, teams, matrix, jira, webhook, email
    notify_channels: list = field(default_factory=list)
    notify_timeout: int = 20
    notify_min_changes: int = 1   # Suppress alerts below this many changes
    notify_on_no_changes: bool = False

    slack_webhook_url: str | None = None
    discord_webhook_url: str | None = None
    webhook_url: str | None = None
    webhook_auth_header: str | None = None   # e.g. "Authorization: Bearer xyz"

    # Microsoft Teams. Use a Power Automate "When a Teams webhook request is
    # received" trigger; the older Office 365 connector has been retired.
    teams_webhook_url: str | None = None

    # Matrix, via the client-server API. No SDK required.
    matrix_homeserver: str | None = None      # https://matrix.example.org
    matrix_access_token: str | None = None
    matrix_room_id: str | None = None         # !room:example.org

    # Jira. This is ticketing rather than alerting: one issue per domain,
    # deduplicated by a deterministic label, and capped per run so a first
    # scan of a large brand cannot bury a backlog.
    jira_url: str | None = None               # https://you.atlassian.net
    jira_email: str | None = None
    jira_api_token: str | None = None
    jira_project_key: str | None = None       # e.g. SEC
    jira_issue_type: str = 'Task'
    jira_max_issues_per_run: int = 10
    jira_labels: list = field(default_factory=list)

    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_use_tls: bool = True
    smtp_use_ssl: bool = False
    email_from: str | None = None
    email_to: str | None = None   # Comma-separated

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
    
    # Mail-capability intelligence (SPF / DKIM / DMARC)
    # A lookalike provisioned to send deliverable mail is set up for phishing,
    # which is a materially different threat from a parked registration.
    enable_mail_intel: bool = True
    enable_dkim_probe: bool = True
    dkim_selectors: list = field(default_factory=list)  # empty = common defaults
    dns_timeout: float = 5.0
    dns_nameservers: list = field(default_factory=list)  # empty = system resolvers

    # AI-assisted triage (optional, strictly additive)
    # The model explains findings; it never assigns risk scores. Scores stay
    # deterministic so an analyst can reproduce and defend them in a takedown
    # request. Scan data is attacker-controlled, so it is neutralised and
    # delimited before it reaches a prompt -- see src/ai/prompts.py.
    enable_ai_analysis: bool = False
    ai_provider: str = 'claude'        # claude | openai | gemini | ollama
    ai_model: str = ''                 # empty = the provider's default
    ai_api_key: str | None = None
    ai_base_url: str | None = None     # Ollama host, or an OpenAI-compatible gateway
    ai_max_tokens: int = 4096
    ai_timeout: float = 120.0
    ai_effort: str = 'medium'          # Claude only: low | medium | high | xhigh | max
    ai_min_risk_score: int = 30        # Skip AI on findings below this score
    ai_explain_changes: bool = True    # Also summarise what changed since last scan

    # Learned triage. Ranks findings using the operator's own past decisions;
    # it never replaces the deterministic risk score, which stays the number
    # reported and cited in takedown requests.
    enable_ml_ranking: bool = False
    ml_min_labels: int = 30            # Refuse to train below this many labels
    ml_explain_top: int = 3            # Feature contributions shown per finding

    # Combo-squatting keywords specific to your brand. Product names, campaign
    # names and support portals are far better bait than the generic list.
    custom_keywords: list = field(default_factory=list)
    replace_default_keywords: bool = False  # True = use only custom_keywords

    # HTTP probing
    enable_http_probe: bool = True
    http_timeout: int = 10
    http_max_bytes: int = 1_048_576  # Cap on probed response bodies (1 MiB)
    http_max_redirects: int = 5
    # Refuse to probe hosts that resolve to private, loopback, or otherwise
    # non-global addresses. A lookalike whose A record points at
    # 169.254.169.254 or an internal host would otherwise turn the scanner —
    # typically run inside the defended network — into a fetch-and-report
    # proxy for whatever that address serves.
    http_allow_private: bool = False
    # How many monitored domains to scan at once. Each domain already
    # parallelises its own lookups up to max_workers, so total outbound
    # concurrency is bounded by roughly this times max_workers. 1 restores
    # strictly sequential scanning.
    concurrent_domains: int = 3
    # In watch mode every cycle writes a new timestamped report per format.
    # Keep only the newest N scans' files (0 = keep everything).
    results_retain: int = 0
    # Read what the fetched page appears built to collect: credential forms,
    # off-site form actions, brand mentions. Costs no extra request; the body
    # is already in memory from the probe.
    enable_page_analysis: bool = True
    user_agent: str = (
        f'TypoSniper/{__version__} (+https://github.com/ChiefGyk3D/typo-sniper)'
    )
    
    # Risk scoring
    enable_risk_scoring: bool = True
    
    # Secrets management. Backends are consulted in listed order; an empty
    # list means the default order (env, doppler, aws, vault, azure, gcp,
    # onepassword). Every backend that is not configured is skipped, so the
    # default is safe to leave alone.
    secrets_backends: list = field(default_factory=list)
    use_doppler: bool = False
    use_aws_secrets: bool = False
    # Doppler: only needed for the REST path; `doppler run` needs neither
    doppler_project: str | None = None
    doppler_config: str | None = None
    # AWS Secrets Manager: one JSON secret holding many keys
    aws_secret_name: str | None = None
    aws_region: str | None = None
    # HashiCorp Vault (KV v2)
    vault_addr: str | None = None
    vault_token: str | None = None
    vault_path: str | None = None
    vault_namespace: str | None = None
    # Azure Key Vault
    azure_key_vault_url: str | None = None
    # Google Cloud Secret Manager
    gcp_project_id: str | None = None
    # 1Password, via the op CLI
    onepassword_vault: str | None = None
    onepassword_item: str | None = None
    
    # Debug mode (set by CLI flag, not in config file)
    debug_mode: bool = False
    
    def __post_init__(self):
        """Post-initialization: normalise paths and load secrets from environment."""
        # Directory overrides from the environment. A container image ships a
        # default and the deployment redirects it, so for these three the
        # environment wins — unlike credentials, where an explicit config value
        # is a deliberate act and takes precedence.
        #
        # state_dir especially: it holds the scan history every delta is
        # computed against. Point it at ephemeral storage and the scanner still
        # runs, still reports, and silently never detects a change again.
        for attr, name in (
            ('cache_dir', 'TYPO_SNIPER_CACHE_DIR'),
            ('output_dir', 'TYPO_SNIPER_OUTPUT_DIR'),
            ('state_dir', 'TYPO_SNIPER_STATE_DIR'),
        ):
            value = os.getenv(name)
            if value:
                setattr(self, attr, value)

        # Expand "~" and environment variables so that a config file containing
        # "cache_dir: ~/.typo_sniper/cache" does not create a literal "~"
        # directory in the working directory.
        self.cache_dir = _expand_path(self.cache_dir)
        self.output_dir = _expand_path(self.output_dir)
        self.state_dir = _expand_path(self.state_dir)

        # Doppler and AWS remain callable by environment alone, so an existing
        # deployment that only sets DOPPLER_TOKEN keeps working unchanged.
        if os.getenv('DOPPLER_PROJECT') or os.getenv('DOPPLER_TOKEN') or os.getenv('TYPO_SNIPER_USE_DOPPLER'):
            self.use_doppler = True

        if os.getenv('AWS_SECRET_NAME') or os.getenv('TYPO_SNIPER_USE_AWS_SECRETS'):
            self.use_aws_secrets = True
            if not self.aws_secret_name:
                self.aws_secret_name = (
                    os.getenv('AWS_SECRET_NAME') or os.getenv('TYPO_SNIPER_AWS_SECRET_NAME')
                )

        self.resolve_secrets()

        # Any configured channel implies notifications are wanted
        if self.notify_channels and not self.enable_notifications:
            self.enable_notifications = True

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
    
    # Every field here holds credential material. Each is resolved through the
    # secrets backends, so a deployment can keep all of them in Doppler, Vault,
    # AWS, Azure, GCP, or 1Password and leave the config file free of secrets.
    # The tuple is the vendor-standard environment variables also accepted, for
    # the case where a key is already exported under its usual name.
    SECRET_FIELDS = (
        ('urlscan_api_key', ('URLSCAN_API_KEY',)),
        ('slack_webhook_url', ('SLACK_WEBHOOK_URL',)),
        ('discord_webhook_url', ('DISCORD_WEBHOOK_URL',)),
        ('webhook_url', ()),
        ('webhook_auth_header', ()),
        ('teams_webhook_url', ('TEAMS_WEBHOOK_URL',)),
        ('matrix_homeserver', ('MATRIX_HOMESERVER',)),
        ('matrix_access_token', ('MATRIX_ACCESS_TOKEN',)),
        ('matrix_room_id', ('MATRIX_ROOM_ID',)),
        ('jira_url', ('JIRA_URL',)),
        ('jira_email', ('JIRA_EMAIL',)),
        ('jira_api_token', ('JIRA_API_TOKEN',)),
        ('jira_project_key', ('JIRA_PROJECT_KEY',)),
        ('smtp_host', ()),
        ('smtp_username', ()),
        ('smtp_password', ()),
        ('email_from', ()),
        ('email_to', ()),
        ('ai_api_key', ('ANTHROPIC_API_KEY', 'OPENAI_API_KEY',
                        'GEMINI_API_KEY', 'GOOGLE_API_KEY')),
        ('ai_base_url', ('OLLAMA_HOST',)),
    )

    def resolve_secrets(self) -> None:
        """
        Fill in unset credential fields from the configured secrets backends.

        A value already present in the config file is left alone: an explicit
        setting is a deliberate act and must not be silently overridden by a
        stale entry in a shared vault.
        """
        from .secrets_manager import SecretsManager

        self.secrets = SecretsManager(self, self.secrets_backends or None)

        for attr, aliases in self.SECRET_FIELDS:
            if not getattr(self, attr, None):
                value = self.secrets.get_secret(attr, aliases=aliases)
                if value:
                    setattr(self, attr, value)

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
        if 'state_dir' in data:
            data['state_dir'] = _expand_path(data['state_dir'])
        
        # Filter only valid fields — and say so. A typo like `enable_url_scan:`
        # silently running with defaults is how operators come to believe a
        # feature is on when it is not.
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        unknown = sorted(k for k in data if k not in valid_fields)
        if unknown:
            logging.getLogger(__name__).warning(
                f"Ignoring unknown configuration key(s): {', '.join(unknown)}"
            )
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

        # Never write resolved credentials back to disk. By the time save()
        # runs, resolve_secrets() may have pulled tokens out of Vault, AWS, or
        # 1Password — persisting them in cleartext YAML would defeat the very
        # point of using a secrets backend.
        data = self.to_dict()
        for attr, _aliases in self.SECRET_FIELDS:
            data.pop(attr, None)

        with open(resolved_path, 'w') as f:
            yaml.dump(data, f, default_flow_style=False)
