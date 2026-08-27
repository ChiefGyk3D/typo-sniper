"""
Secret resolution for Typo Sniper.

Typo Sniper handles material that should never sit in a config file: threat
intelligence API keys, Slack and Discord webhook URLs, SMTP passwords, and now
LLM provider keys. This module resolves those from whichever secrets store an
operator already runs, so the repository and the config file stay clean.

Backends, in the order they are consulted by default:

  1. ``env``        - ``TYPO_SNIPER_<KEY>`` environment variables (always on)
  2. ``doppler``    - Doppler, via ``doppler run`` injection or the REST API
  3. ``aws``        - AWS Secrets Manager (one JSON secret holding many keys)
  4. ``vault``      - HashiCorp Vault KV v2, via the REST API
  5. ``azure``      - Azure Key Vault
  6. ``gcp``        - Google Cloud Secret Manager
  7. ``onepassword``- 1Password, via the ``op`` CLI

Doppler and Vault are reached over plain HTTPS with the standard library, so
the two most commonly self-hosted stores work with no extra package installed.
AWS, Azure, GCP, and 1Password use their vendor SDK or CLI, imported lazily so
an unconfigured backend costs nothing.

Two rules hold everywhere in this module:

  * A secret value is never logged, never included in an exception message, and
    never returned by a diagnostic. Only key names and backend names are.
  * A backend failure degrades to the next backend. A secrets store being
    unreachable must not stop a scan that can still run without that key.
"""

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ChiefGyk3D
# Typo Sniper is dual-licensed; see COMMERCIAL.md for commercial terms.

import json
import logging
import os
import shutil
import subprocess
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from typing import Any

ENV_PREFIX = 'TYPO_SNIPER_'

# A remote store that is slow or down must not hang a scan at startup
HTTP_TIMEOUT = 10

logger = logging.getLogger(__name__)


def _canonical(key: str) -> str:
    """Normalise a secret name to lower_snake_case."""
    return key.strip().lower().replace('-', '_')


def _https_json(url: str, headers: dict[str, str]) -> Any:
    """
    Fetch JSON over HTTPS.

    Args:
        url: Absolute https:// URL
        headers: Request headers

    Returns:
        Decoded JSON body

    Raises:
        ValueError: If the URL is not HTTPS
    """
    # A secrets store reached over plain HTTP would put the token and every
    # secret it returns on the wire in clear text.
    if not url.lower().startswith('https://'):
        raise ValueError('refusing to fetch secrets over a non-HTTPS URL')

    request = urllib.request.Request(url, headers=headers)  # noqa: S310 - scheme checked above
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:  # noqa: S310
        return json.loads(response.read().decode('utf-8'))


class SecretBackend(ABC):
    """One source of secrets."""

    name = 'backend'
    install_hint: str | None = None

    def __init__(self, config: Any = None):
        self.config = config
        self.logger = logging.getLogger(f'{__name__}.{self.name}')
        self._cache: dict[str, str | None] = {}
        self._loaded = False
        self._error: str | None = None

    def configured(self) -> bool:
        """Whether the operator has supplied enough settings to try this backend."""
        return True

    @abstractmethod
    def _fetch(self, key: str) -> str | None:
        """Return the value for a canonical key, or None."""

    def get(self, key: str) -> str | None:
        """
        Look up one canonical key, caching both hits and misses.

        Args:
            key: Canonical lower_snake_case secret name

        Returns:
            The value, or None when this backend does not hold it
        """
        if key in self._cache:
            return self._cache[key]

        try:
            value = self._fetch(key)
        except Exception as e:
            # Only the exception type. A backend's message can echo the request
            # body, the token, or the secret itself into the log.
            self._error = type(e).__name__
            self.logger.warning(
                'Secrets backend %s failed (%s); continuing without it',
                self.name, self._error,
            )
            value = None

        self._cache[key] = value
        return value

    def status(self) -> str:
        """A one-line, value-free description for diagnostics."""
        if not self.configured():
            return 'not configured'
        return f'error: {self._error}' if self._error else 'ready'


class EnvBackend(SecretBackend):
    """
    Environment variables.

    Always enabled and always first: an operator overriding a single key for one
    run must not have to reconfigure their secrets store to do it.
    """

    name = 'env'

    def _fetch(self, key: str) -> str | None:
        return os.getenv(f'{ENV_PREFIX}{key.upper()}') or None


class MappingBackend(SecretBackend):
    """A backend that loads every key at once into a flat mapping."""

    def __init__(self, config: Any = None):
        super().__init__(config)
        self._secrets: dict[str, str] = {}

    @abstractmethod
    def _load(self) -> dict[str, str]:
        """Fetch the whole secret set."""

    def _fetch(self, key: str) -> str | None:
        if not self._loaded:
            self._loaded = True
            self._secrets = {
                _canonical(k): v for k, v in self._load().items()
                if isinstance(v, str)
            }
            self.logger.debug(
                'Loaded %d secret(s) from %s', len(self._secrets), self.name
            )
        return self._secrets.get(key)


class DopplerBackend(SecretBackend):
    """
    Doppler.

    Two ways in, tried in order:

      1. Variables injected by ``doppler run`` into the process environment.
         This needs nothing installed and is how most teams already use Doppler.
      2. The Doppler REST API, using a service token from ``DOPPLER_TOKEN``.
         This lets a container read its own config without wrapping the entry
         point in the Doppler CLI.

    Neither path requires the Doppler SDK.
    """

    name = 'doppler'

    def __init__(self, config: Any = None):
        super().__init__(config)
        self._downloaded: dict[str, str] | None = None

    def configured(self) -> bool:
        return bool(
            os.getenv('DOPPLER_TOKEN')
            or os.getenv('DOPPLER_PROJECT')
            or self.cli_available()
        )

    @staticmethod
    def cli_available() -> bool:
        """Whether the ``doppler`` CLI is on PATH."""
        return shutil.which('doppler') is not None

    def _download(self) -> dict[str, str]:
        """Fetch the whole config from the Doppler API."""
        token = os.getenv('DOPPLER_TOKEN')
        if not token:
            return {}

        url = 'https://api.doppler.com/v3/configs/config/secrets/download?format=json'
        project = getattr(self.config, 'doppler_project', None) or os.getenv('DOPPLER_PROJECT')
        doppler_config = getattr(self.config, 'doppler_config', None) or os.getenv('DOPPLER_CONFIG')
        if project:
            url += f'&project={urllib.parse.quote(project)}'
        if doppler_config:
            url += f'&config={urllib.parse.quote(doppler_config)}'

        data = _https_json(url, {'Authorization': f'Bearer {token}'})
        return {k: v for k, v in data.items() if isinstance(v, str)}

    def _fetch(self, key: str) -> str | None:
        # doppler run injects secrets under their own names, unprefixed
        value = os.getenv(key.upper())
        if value:
            return value

        if self._downloaded is None:
            self._downloaded = {_canonical(k): v for k, v in self._download().items()}
        return self._downloaded.get(key)


class AWSSecretsBackend(MappingBackend):
    """
    AWS Secrets Manager.

    Reads one secret holding a JSON object of many keys, which is how the
    console's key/value editor stores them, rather than one AWS secret per key.
    """

    name = 'aws'
    install_hint = 'aws'

    def configured(self) -> bool:
        return bool(self._secret_name())

    def _secret_name(self) -> str | None:
        return (
            getattr(self.config, 'aws_secret_name', None)
            or os.getenv('AWS_SECRET_NAME')
            or os.getenv('TYPO_SNIPER_AWS_SECRET_NAME')
        )

    def _load(self) -> dict[str, str]:
        name = self._secret_name()
        if not name:
            return {}

        import boto3

        region = (
            getattr(self.config, 'aws_region', None)
            or os.getenv('AWS_REGION')
            or os.getenv('AWS_DEFAULT_REGION')
        )
        client = boto3.client('secretsmanager', **({'region_name': region} if region else {}))
        response = client.get_secret_value(SecretId=name)

        raw = response.get('SecretString')
        if not raw:
            self.logger.warning('AWS secret contained no SecretString value')
            return {}

        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}


class VaultBackend(MappingBackend):
    """
    HashiCorp Vault, KV version 2.

    Talks to the REST API directly, so no ``hvac`` install is needed. The token
    comes from ``VAULT_TOKEN`` or the ``~/.vault-token`` file the CLI writes,
    which means a developer already logged in with ``vault login`` needs no
    further configuration.
    """

    name = 'vault'

    def configured(self) -> bool:
        return bool(self._addr() and self._token())

    def _addr(self) -> str | None:
        return getattr(self.config, 'vault_addr', None) or os.getenv('VAULT_ADDR')

    def _token(self) -> str | None:
        token = getattr(self.config, 'vault_token', None) or os.getenv('VAULT_TOKEN')
        if token:
            return token

        token_file = os.path.expanduser('~/.vault-token')
        if os.path.isfile(token_file):
            try:
                with open(token_file, encoding='utf-8') as handle:
                    return handle.read().strip() or None
            except OSError:
                return None
        return None

    def _load(self) -> dict[str, str]:
        addr = (self._addr() or '').rstrip('/')
        token = self._token()
        if not addr or not token:
            return {}

        path = (
            getattr(self.config, 'vault_path', None)
            or os.getenv('VAULT_PATH')
            or 'secret/data/typo-sniper'
        ).strip('/')

        headers = {'X-Vault-Token': token}
        namespace = (
            getattr(self.config, 'vault_namespace', None) or os.getenv('VAULT_NAMESPACE')
        )
        if namespace:
            headers['X-Vault-Namespace'] = namespace

        body = _https_json(f'{addr}/v1/{path}', headers)

        # KV v2 nests the payload under data.data; KV v1 puts it at data
        data = body.get('data', {})
        inner = data.get('data')
        return inner if isinstance(inner, dict) else data


class AzureKeyVaultBackend(SecretBackend):
    """
    Azure Key Vault.

    Fetched per key, because Key Vault stores one secret per name. Names there
    may only contain letters, digits, and dashes, so ``urlscan_api_key`` is
    looked up as ``urlscan-api-key``.
    """

    name = 'azure'
    install_hint = 'azure'

    def configured(self) -> bool:
        return bool(self._url())

    def _url(self) -> str | None:
        return (
            getattr(self.config, 'azure_key_vault_url', None)
            or os.getenv('AZURE_KEY_VAULT_URL')
        )

    def _client(self):
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.secrets import SecretClient

        return SecretClient(vault_url=self._url(), credential=DefaultAzureCredential())

    def _fetch(self, key: str) -> str | None:
        if not self.configured():
            return None

        from azure.core.exceptions import ResourceNotFoundError

        try:
            return self._client().get_secret(key.replace('_', '-')).value
        except ResourceNotFoundError:
            # An absent key is an ordinary outcome, not a backend failure
            return None


class GCPSecretManagerBackend(SecretBackend):
    """
    Google Cloud Secret Manager.

    Fetched per key against the ``latest`` version, trying the underscore form
    first and then the dashed form, since both conventions are common.
    """

    name = 'gcp'
    install_hint = 'gcp'

    def configured(self) -> bool:
        return bool(self._project())

    def _project(self) -> str | None:
        return (
            getattr(self.config, 'gcp_project_id', None)
            or os.getenv('GCP_PROJECT_ID')
            or os.getenv('GOOGLE_CLOUD_PROJECT')
        )

    def _fetch(self, key: str) -> str | None:
        project = self._project()
        if not project:
            return None

        from google.api_core import exceptions as gcp_exceptions
        from google.cloud import secretmanager

        client = secretmanager.SecretManagerServiceClient()
        for name in (key, key.replace('_', '-')):
            try:
                response = client.access_secret_version(
                    name=f'projects/{project}/secrets/{name}/versions/latest'
                )
                return response.payload.data.decode('utf-8')
            except (gcp_exceptions.NotFound, gcp_exceptions.PermissionDenied):
                continue
        return None


class OnePasswordBackend(SecretBackend):
    """
    1Password, through the ``op`` CLI.

    The CLI is used rather than the Connect SDK because it covers both a
    developer signed in on a laptop and a service account in CI, with the same
    configuration. Values are read as ``op://<vault>/<item>/<field>``.
    """

    name = 'onepassword'

    def configured(self) -> bool:
        return bool(self._vault() and self._item() and shutil.which('op'))

    def _vault(self) -> str | None:
        return (
            getattr(self.config, 'onepassword_vault', None)
            or os.getenv('OP_VAULT')
        )

    def _item(self) -> str | None:
        return (
            getattr(self.config, 'onepassword_item', None)
            or os.getenv('OP_ITEM')
        )

    def _fetch(self, key: str) -> str | None:
        if not self.configured():
            return None

        # Resolved to an absolute path rather than relying on PATH order at
        # call time, and run without a shell, so nothing here is interpolated
        # into a command line.
        op = shutil.which('op')
        if not op:
            return None

        reference = f'op://{self._vault()}/{self._item()}/{key}'
        result = subprocess.run(  # noqa: S603 - absolute path, no shell
            [op, 'read', '--no-newline', reference],
            capture_output=True, text=True, timeout=HTTP_TIMEOUT, check=False,
        )
        if result.returncode != 0:
            # Neither the value nor the item reference is recorded: stderr can
            # quote the reference, and the reference names a credential.
            self.logger.debug('op read did not resolve the requested field')
            return None
        return result.stdout.strip() or None


BACKENDS: dict[str, type[SecretBackend]] = {
    'env': EnvBackend,
    'doppler': DopplerBackend,
    'aws': AWSSecretsBackend,
    'vault': VaultBackend,
    'azure': AzureKeyVaultBackend,
    'gcp': GCPSecretManagerBackend,
    'onepassword': OnePasswordBackend,
}

# Consulted in this order unless the operator names a different set
DEFAULT_ORDER = ['env', 'doppler', 'aws', 'vault', 'azure', 'gcp', 'onepassword']


class SecretsManager:
    """
    Resolve secrets across every configured backend.

    Args:
        config: Optional Config object supplying backend settings
        backends: Backend names in priority order; defaults to DEFAULT_ORDER
    """

    def __init__(self, config: Any = None, backends: list[str] | None = None):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self.resolved_from: dict[str, str] = {}
        self.unknown_backends = 0

        names = backends if backends is not None else list(DEFAULT_ORDER)
        if 'env' not in names:
            # An operator can reorder or drop remote backends, but never the
            # local override: it is the escape hatch when a store is wrong.
            names = ['env', *names]

        self.backends: list[SecretBackend] = []
        for name in names:
            backend_cls = BACKENDS.get(name.strip().lower())
            if backend_cls is None:
                # The configured value is not echoed. It is operator-supplied
                # text, and a name pasted into the wrong field is exactly the
                # kind of mistake that puts a credential in a log aggregator.
                self.unknown_backends += 1
                self.logger.warning(
                    'Ignoring an unrecognised secrets backend; valid names are %s',
                    ', '.join(BACKENDS),
                )
                continue
            self.backends.append(backend_cls(config))

    def get_secret(
        self,
        key: str,
        default: str | None = None,
        aliases: tuple[str, ...] = (),
    ) -> str | None:
        """
        Resolve one secret.

        Args:
            key: Secret name, e.g. 'urlscan_api_key'
            default: Value to use when no backend holds the key
            aliases: Additional environment variable names to accept, for
                vendor-standard variables such as ANTHROPIC_API_KEY

        Returns:
            The secret value, or the default
        """
        canonical = _canonical(key)

        for backend in self.backends:
            if not backend.configured():
                continue
            value = backend.get(canonical)
            if value:
                # Recorded for --secrets-check rather than logged. Which
                # credentials a host holds is itself an inventory disclosure,
                # and a debug log goes wherever the operator ships logs.
                self.resolved_from[canonical] = backend.name
                return value

            # A vendor-standard variable is still an environment lookup, so it
            # is checked at the same point in the order as the prefixed form.
            if backend.name == 'env':
                for alias in aliases:
                    value = os.getenv(alias)
                    if value:
                        self.resolved_from[canonical] = f'env ({alias})'
                        return value

        if default:
            self.resolved_from[canonical] = 'config'
        return default

    def get_api_key(self, service: str, config_value: str | None = None) -> str | None:
        """
        Resolve an API key for one service.

        Args:
            service: Service name, e.g. 'urlscan'
            config_value: Fallback value from the config file

        Returns:
            The API key, or None
        """
        return self.get_secret(f'{service}_api_key', config_value)

    def describe(self) -> list[dict[str, str]]:
        """
        Report backend availability for diagnostics.

        Returns:
            One entry per backend with its name and status; never any value
        """
        return [
            {'backend': b.name, 'status': b.status()} for b in self.backends
        ]

    @staticmethod
    def is_doppler_cli_available() -> bool:
        """Whether the Doppler CLI is installed."""
        return DopplerBackend.cli_available()
