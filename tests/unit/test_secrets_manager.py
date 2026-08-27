"""
Tests for secret resolution across every supported backend.

Two properties matter more than any individual lookup and are asserted
throughout: a backend that fails must never stop a scan, and a secret value
must never reach a log line or a diagnostic.
"""

import subprocess
import sys
import types

import pytest

import secrets_manager
from secrets_manager import (
    BACKENDS,
    AWSSecretsBackend,
    AzureKeyVaultBackend,
    DopplerBackend,
    GCPSecretManagerBackend,
    OnePasswordBackend,
    SecretsManager,
    VaultBackend,
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Backends read the environment; no test may see the host's real values."""
    for key in (
        'TYPO_SNIPER_URLSCAN_API_KEY', 'URLSCAN_API_KEY',
        'TYPO_SNIPER_TEST_KEY', 'TEST_KEY',
        'DOPPLER_TOKEN', 'DOPPLER_PROJECT', 'DOPPLER_CONFIG',
        'AWS_SECRET_NAME', 'TYPO_SNIPER_AWS_SECRET_NAME', 'AWS_REGION',
        'AWS_DEFAULT_REGION',
        'VAULT_ADDR', 'VAULT_TOKEN', 'VAULT_PATH', 'VAULT_NAMESPACE',
        'AZURE_KEY_VAULT_URL', 'GCP_PROJECT_ID', 'GOOGLE_CLOUD_PROJECT',
        'OP_VAULT', 'OP_ITEM', 'ANTHROPIC_API_KEY',
    ):
        monkeypatch.delenv(key, raising=False)
    # A developer's ~/.vault-token must not make a Vault test pass locally
    monkeypatch.setattr(
        VaultBackend, '_token', lambda self: self.config
        and getattr(self.config, 'vault_token', None)
    )


def env_only() -> SecretsManager:
    """A manager with only the environment backend, for isolated env tests."""
    return SecretsManager(backends=['env'])


class TestEnvironmentBackend:
    def test_reads_prefixed_variable(self, monkeypatch):
        monkeypatch.setenv('TYPO_SNIPER_TEST_KEY', 'from-env')
        assert env_only().get_secret('test_key') == 'from-env'

    def test_key_case_and_dashes_are_normalised(self, monkeypatch):
        monkeypatch.setenv('TYPO_SNIPER_TEST_KEY', 'v')
        assert env_only().get_secret('TeSt-KeY') == 'v'

    def test_returns_default_when_absent(self):
        assert env_only().get_secret('missing', 'fallback') == 'fallback'
        assert env_only().get_secret('missing') is None

    def test_unprefixed_variable_needs_an_explicit_alias(self, monkeypatch):
        """An arbitrary shell variable must not be read as a Typo Sniper secret."""
        monkeypatch.setenv('TEST_KEY', 'unprefixed')
        assert env_only().get_secret('test_key') is None
        assert env_only().get_secret('test_key', aliases=('TEST_KEY',)) == 'unprefixed'

    def test_prefixed_beats_alias(self, monkeypatch):
        monkeypatch.setenv('TYPO_SNIPER_AI_API_KEY', 'ours')
        monkeypatch.setenv('ANTHROPIC_API_KEY', 'vendor')
        value = env_only().get_secret('ai_api_key', aliases=('ANTHROPIC_API_KEY',))
        assert value == 'ours'


class TestBackendOrdering:
    def test_default_order_is_env_first(self):
        assert SecretsManager().backends[0].name == 'env'

    def test_env_is_reinstated_when_omitted(self):
        """The local override is the escape hatch when a store is wrong."""
        names = [b.name for b in SecretsManager(backends=['vault']).backends]
        assert names == ['env', 'vault']

    def test_unknown_backend_is_skipped(self, caplog):
        mgr = SecretsManager(backends=['env', 'nonesuch'])
        assert [b.name for b in mgr.backends] == ['env']
        assert mgr.unknown_backends == 1
        # The valid names are named; the operator's own text is not echoed,
        # because a credential pasted into the wrong field must not be logged.
        assert 'nonesuch' not in caplog.text
        assert 'doppler' in caplog.text

    def test_every_documented_backend_is_registered(self):
        assert set(BACKENDS) == {
            'env', 'doppler', 'aws', 'vault', 'azure', 'gcp', 'onepassword',
        }

    def test_unconfigured_backends_are_not_consulted(self, monkeypatch):
        monkeypatch.setenv('TYPO_SNIPER_TEST_KEY', 'v')
        # None of the remote backends have settings, so none may be reached
        assert SecretsManager().get_secret('test_key') == 'v'

    def test_a_failing_backend_does_not_stop_resolution(self, monkeypatch):
        """A store being down must degrade, never raise."""
        class Exploding(secrets_manager.SecretBackend):
            name = 'exploding'

            def _fetch(self, key):
                raise RuntimeError('vault sealed')

        monkeypatch.setitem(BACKENDS, 'exploding', Exploding)
        monkeypatch.setenv('TYPO_SNIPER_TEST_KEY', 'still-here')
        mgr = SecretsManager(backends=['exploding', 'env'])
        assert mgr.get_secret('test_key') == 'still-here'

    def test_failure_message_carries_only_the_exception_type(self, monkeypatch, caplog):
        class Exploding(secrets_manager.SecretBackend):
            name = 'exploding'

            def _fetch(self, key):
                raise RuntimeError('token sk-secret-value leaked in message')

        monkeypatch.setitem(BACKENDS, 'exploding', Exploding)
        SecretsManager(backends=['exploding']).get_secret('test_key')
        assert 'sk-secret-value' not in caplog.text
        assert 'RuntimeError' in caplog.text


class TestDopplerBackend:
    def test_reads_cli_injected_variable(self, monkeypatch):
        """`doppler run` exports secrets under their own names."""
        monkeypatch.setenv('DOPPLER_TOKEN', 'dp.st.token')
        monkeypatch.setenv('TEST_KEY', 'from-doppler')
        assert SecretsManager(backends=['doppler']).get_secret('test_key') == 'from-doppler'

    def test_prefixed_environment_variable_takes_priority(self, monkeypatch):
        monkeypatch.setenv('DOPPLER_TOKEN', 'dp.st.token')
        monkeypatch.setenv('TYPO_SNIPER_TEST_KEY', 'prefixed')
        monkeypatch.setenv('TEST_KEY', 'doppler')
        assert SecretsManager().get_secret('test_key') == 'prefixed'

    def test_downloads_from_the_rest_api(self, monkeypatch):
        monkeypatch.setenv('DOPPLER_TOKEN', 'dp.st.token')
        seen = {}

        def fake(url, headers):
            seen['url'] = url
            seen['headers'] = headers
            return {'TEST_KEY': 'from-api', 'OTHER': 'x'}

        monkeypatch.setattr(secrets_manager, '_https_json', fake)
        assert SecretsManager(backends=['doppler']).get_secret('test_key') == 'from-api'
        assert seen['headers']['Authorization'] == 'Bearer dp.st.token'
        assert seen['url'].startswith('https://api.doppler.com/')

    def test_project_and_config_narrow_the_request(self, monkeypatch):
        monkeypatch.setenv('DOPPLER_TOKEN', 'dp.st.token')
        monkeypatch.setenv('DOPPLER_PROJECT', 'typo sniper')
        monkeypatch.setenv('DOPPLER_CONFIG', 'prd')
        seen = {}

        def fake(url, headers):
            seen['url'] = url
            return {}

        monkeypatch.setattr(secrets_manager, '_https_json', fake)
        SecretsManager(backends=['doppler']).get_secret('test_key')
        assert 'project=typo%20sniper' in seen['url']
        assert 'config=prd' in seen['url']

    def test_not_configured_without_token_or_cli(self, monkeypatch):
        monkeypatch.setattr(DopplerBackend, 'cli_available', staticmethod(lambda: False))
        assert DopplerBackend().configured() is False

    def test_cli_detection(self, monkeypatch):
        monkeypatch.setattr(secrets_manager.shutil, 'which', lambda name: '/usr/bin/doppler')
        assert SecretsManager.is_doppler_cli_available() is True
        monkeypatch.setattr(secrets_manager.shutil, 'which', lambda name: None)
        assert SecretsManager.is_doppler_cli_available() is False


def _fake_boto3(monkeypatch, secret_string, recorder=None):
    """Install a boto3 stub returning one SecretString."""
    class Client:
        def get_secret_value(self, SecretId):  # boto3's parameter name
            if recorder is not None:
                recorder['SecretId'] = SecretId
            return {'SecretString': secret_string}

    module = types.ModuleType('boto3')

    def client(service, **kwargs):
        if recorder is not None:
            recorder.update({'service': service, **kwargs})
        return Client()

    module.client = client
    monkeypatch.setitem(sys.modules, 'boto3', module)


class TestAWSBackend:
    def _manager(self, monkeypatch, secrets, recorder=None):
        monkeypatch.setenv('AWS_SECRET_NAME', 'typo-sniper/prod')
        _fake_boto3(monkeypatch, secrets, recorder)
        return SecretsManager(backends=['aws'])

    def test_reads_lowercase_key(self, monkeypatch):
        mgr = self._manager(monkeypatch, '{"test_key": "aws"}')
        assert mgr.get_secret('test_key') == 'aws'

    def test_reads_uppercase_key(self, monkeypatch):
        mgr = self._manager(monkeypatch, '{"TEST_KEY": "aws"}')
        assert mgr.get_secret('test_key') == 'aws'

    def test_absent_key_falls_back_to_default(self, monkeypatch):
        mgr = self._manager(monkeypatch, '{"other": "x"}')
        assert mgr.get_secret('test_key', 'd') == 'd'

    def test_region_is_passed_through(self, monkeypatch):
        recorder = {}
        monkeypatch.setenv('AWS_REGION', 'eu-west-1')
        self._manager(monkeypatch, '{"test_key": "v"}', recorder).get_secret('test_key')
        assert recorder['region_name'] == 'eu-west-1'

    def test_secret_is_fetched_once_for_many_keys(self, monkeypatch):
        calls = []

        class Client:
            def get_secret_value(self, SecretId):
                calls.append(SecretId)
                return {'SecretString': '{"a": "1", "b": "2"}'}

        module = types.ModuleType('boto3')
        module.client = lambda service, **kwargs: Client()
        monkeypatch.setitem(sys.modules, 'boto3', module)
        monkeypatch.setenv('AWS_SECRET_NAME', 'typo-sniper/prod')

        mgr = SecretsManager(backends=['aws'])
        assert mgr.get_secret('a') == '1'
        assert mgr.get_secret('b') == '2'
        assert len(calls) == 1

    def test_not_configured_without_a_secret_name(self):
        assert AWSSecretsBackend().configured() is False

    def test_missing_boto3_degrades_quietly(self, monkeypatch):
        monkeypatch.setenv('AWS_SECRET_NAME', 'typo-sniper/prod')
        monkeypatch.setitem(sys.modules, 'boto3', None)
        assert SecretsManager(backends=['aws']).get_secret('test_key') is None

    def test_empty_secret_string_is_handled(self, monkeypatch):
        mgr = self._manager(monkeypatch, '')
        assert mgr.get_secret('test_key') is None


class TestVaultBackend:
    def _configure(self, monkeypatch, body):
        monkeypatch.setenv('VAULT_ADDR', 'https://vault.example.com')
        monkeypatch.setattr(VaultBackend, '_token', lambda self: 'hvs.token')
        seen = {}

        def fake(url, headers):
            seen['url'] = url
            seen['headers'] = headers
            return body

        monkeypatch.setattr(secrets_manager, '_https_json', fake)
        return SecretsManager(backends=['vault']), seen

    def test_reads_kv_v2_nested_payload(self, monkeypatch):
        mgr, seen = self._configure(monkeypatch, {'data': {'data': {'test_key': 'v2'}}})
        assert mgr.get_secret('test_key') == 'v2'
        assert seen['url'].endswith('/v1/secret/data/typo-sniper')
        assert seen['headers']['X-Vault-Token'] == 'hvs.token'

    def test_reads_kv_v1_flat_payload(self, monkeypatch):
        mgr, _ = self._configure(monkeypatch, {'data': {'test_key': 'v1'}})
        assert mgr.get_secret('test_key') == 'v1'

    def test_custom_path_and_namespace(self, monkeypatch):
        monkeypatch.setenv('VAULT_PATH', '/kv/data/brand/')
        monkeypatch.setenv('VAULT_NAMESPACE', 'security')
        mgr, seen = self._configure(monkeypatch, {'data': {'data': {'test_key': 'v'}}})
        mgr.get_secret('test_key')
        assert seen['url'].endswith('/v1/kv/data/brand')
        assert seen['headers']['X-Vault-Namespace'] == 'security'

    def test_not_configured_without_address_or_token(self, monkeypatch):
        assert VaultBackend().configured() is False
        monkeypatch.setenv('VAULT_ADDR', 'https://vault.example.com')
        assert VaultBackend().configured() is False

    def test_token_file_is_read_when_no_variable_is_set(self, monkeypatch, tmp_path):
        """`vault login` writes ~/.vault-token; a signed-in operator needs no setup."""
        monkeypatch.undo()  # restore the real _token implementation
        for key in ('VAULT_TOKEN', 'VAULT_ADDR'):
            monkeypatch.delenv(key, raising=False)
        token_file = tmp_path / '.vault-token'
        token_file.write_text('hvs.from-file\n')
        monkeypatch.setattr(
            secrets_manager.os.path, 'expanduser', lambda p: str(token_file)
        )
        assert VaultBackend()._token() == 'hvs.from-file'


class TestHttpsEnforcement:
    def test_plain_http_is_refused(self):
        """A token and every secret it returns would otherwise cross in clear text."""
        with pytest.raises(ValueError, match='non-HTTPS'):
            secrets_manager._https_json('http://vault.internal/v1/secret', {})

    def test_https_is_accepted(self, monkeypatch):
        class Response:
            def read(self):
                return b'{"ok": true}'

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        monkeypatch.setattr(
            secrets_manager.urllib.request, 'urlopen',
            lambda request, timeout=None: Response(),
        )
        assert secrets_manager._https_json('https://vault.example/v1/x', {}) == {'ok': True}


def _fake_azure(monkeypatch, values, recorder=None):
    class NotFound(Exception):
        pass

    class Secret:
        def __init__(self, value):
            self.value = value

    class SecretClient:
        def __init__(self, vault_url, credential):
            if recorder is not None:
                recorder['vault_url'] = vault_url

        def get_secret(self, name):
            if recorder is not None:
                recorder['name'] = name
            if name not in values:
                raise NotFound(name)
            return Secret(values[name])

    identity = types.ModuleType('azure.identity')
    identity.DefaultAzureCredential = lambda: object()
    keyvault_secrets = types.ModuleType('azure.keyvault.secrets')
    keyvault_secrets.SecretClient = SecretClient
    core_exceptions = types.ModuleType('azure.core.exceptions')
    core_exceptions.ResourceNotFoundError = NotFound

    for name, module in (
        ('azure', types.ModuleType('azure')),
        ('azure.identity', identity),
        ('azure.keyvault', types.ModuleType('azure.keyvault')),
        ('azure.keyvault.secrets', keyvault_secrets),
        ('azure.core', types.ModuleType('azure.core')),
        ('azure.core.exceptions', core_exceptions),
    ):
        monkeypatch.setitem(sys.modules, name, module)


class TestAzureBackend:
    def test_underscores_become_dashes(self, monkeypatch):
        """Key Vault names allow only letters, digits, and dashes."""
        recorder = {}
        monkeypatch.setenv('AZURE_KEY_VAULT_URL', 'https://kv.vault.azure.net/')
        _fake_azure(monkeypatch, {'urlscan-api-key': 'azure'}, recorder)
        mgr = SecretsManager(backends=['azure'])
        assert mgr.get_secret('urlscan_api_key') == 'azure'
        assert recorder['name'] == 'urlscan-api-key'

    def test_absent_secret_returns_none(self, monkeypatch):
        monkeypatch.setenv('AZURE_KEY_VAULT_URL', 'https://kv.vault.azure.net/')
        _fake_azure(monkeypatch, {})
        assert SecretsManager(backends=['azure']).get_secret('urlscan_api_key') is None

    def test_not_configured_without_a_vault_url(self):
        assert AzureKeyVaultBackend().configured() is False


def _fake_gcp(monkeypatch, values, recorder=None):
    class NotFound(Exception):
        pass

    class PermissionDenied(Exception):
        pass

    class Payload:
        def __init__(self, data):
            self.data = data

    class Response:
        def __init__(self, data):
            self.payload = Payload(data)

    class Client:
        def access_secret_version(self, name):
            if recorder is not None:
                recorder.setdefault('names', []).append(name)
            key = name.split('/secrets/')[1].split('/')[0]
            if key not in values:
                raise NotFound(key)
            return Response(values[key].encode('utf-8'))

    secretmanager = types.ModuleType('google.cloud.secretmanager')
    secretmanager.SecretManagerServiceClient = Client
    exceptions = types.ModuleType('google.api_core.exceptions')
    exceptions.NotFound = NotFound
    exceptions.PermissionDenied = PermissionDenied

    google = sys.modules.get('google') or types.ModuleType('google')
    cloud = types.ModuleType('google.cloud')
    cloud.secretmanager = secretmanager
    api_core = types.ModuleType('google.api_core')
    api_core.exceptions = exceptions

    for name, module in (
        ('google', google),
        ('google.cloud', cloud),
        ('google.cloud.secretmanager', secretmanager),
        ('google.api_core', api_core),
        ('google.api_core.exceptions', exceptions),
    ):
        monkeypatch.setitem(sys.modules, name, module)


class TestGCPBackend:
    def test_reads_the_latest_version(self, monkeypatch):
        recorder = {}
        monkeypatch.setenv('GCP_PROJECT_ID', 'brand-security')
        _fake_gcp(monkeypatch, {'urlscan_api_key': 'gcp'}, recorder)
        mgr = SecretsManager(backends=['gcp'])
        assert mgr.get_secret('urlscan_api_key') == 'gcp'
        assert recorder['names'][0] == (
            'projects/brand-security/secrets/urlscan_api_key/versions/latest'
        )

    def test_falls_back_to_the_dashed_name(self, monkeypatch):
        recorder = {}
        monkeypatch.setenv('GCP_PROJECT_ID', 'brand-security')
        _fake_gcp(monkeypatch, {'urlscan-api-key': 'gcp'}, recorder)
        mgr = SecretsManager(backends=['gcp'])
        assert mgr.get_secret('urlscan_api_key') == 'gcp'
        assert len(recorder['names']) == 2

    def test_not_configured_without_a_project(self):
        assert GCPSecretManagerBackend().configured() is False


class TestOnePasswordBackend:
    def _configure(self, monkeypatch, returncode=0, stdout='op-value'):
        monkeypatch.setenv('OP_VAULT', 'Security')
        monkeypatch.setenv('OP_ITEM', 'typo-sniper')
        monkeypatch.setattr(secrets_manager.shutil, 'which', lambda name: '/usr/local/bin/op')
        seen = {}

        def fake_run(argv, **kwargs):
            seen['argv'] = argv
            return subprocess.CompletedProcess(argv, returncode, stdout, '')

        monkeypatch.setattr(secrets_manager.subprocess, 'run', fake_run)
        return SecretsManager(backends=['onepassword']), seen

    def test_reads_a_secret_reference(self, monkeypatch):
        mgr, seen = self._configure(monkeypatch)
        assert mgr.get_secret('urlscan_api_key') == 'op-value'
        assert seen['argv'][0] == '/usr/local/bin/op'
        assert seen['argv'][-1] == 'op://Security/typo-sniper/urlscan_api_key'

    def test_absolute_path_is_used_rather_than_bare_op(self, monkeypatch):
        """PATH order at call time must not decide which binary reads secrets."""
        mgr, seen = self._configure(monkeypatch)
        mgr.get_secret('urlscan_api_key')
        assert seen['argv'][0].startswith('/')

    def test_failed_lookup_returns_none(self, monkeypatch):
        mgr, _ = self._configure(monkeypatch, returncode=1, stdout='')
        assert mgr.get_secret('urlscan_api_key') is None

    def test_not_configured_without_the_cli(self, monkeypatch):
        monkeypatch.setenv('OP_VAULT', 'Security')
        monkeypatch.setenv('OP_ITEM', 'typo-sniper')
        monkeypatch.setattr(secrets_manager.shutil, 'which', lambda name: None)
        assert OnePasswordBackend().configured() is False


class TestDiagnostics:
    def test_describe_reports_every_backend_without_values(self, monkeypatch):
        monkeypatch.setenv('TYPO_SNIPER_URLSCAN_API_KEY', 'super-secret')
        mgr = SecretsManager()
        mgr.get_secret('urlscan_api_key')
        rendered = str(mgr.describe())
        assert 'super-secret' not in rendered
        assert {'backend': 'env', 'status': 'ready'} in mgr.describe()

    def test_unconfigured_backends_say_so(self):
        statuses = {e['backend']: e['status'] for e in SecretsManager().describe()}
        assert statuses['vault'] == 'not configured'
        assert statuses['env'] == 'ready'

    def test_resolution_logs_no_credential_names(self, monkeypatch, caplog):
        """Which credentials a host holds is itself an inventory disclosure."""
        import logging

        caplog.set_level(logging.DEBUG)
        monkeypatch.setenv('TYPO_SNIPER_SMTP_PASSWORD', 'hunter2')
        mgr = SecretsManager()
        assert mgr.get_secret('smtp_password') == 'hunter2'
        assert 'hunter2' not in caplog.text
        assert 'smtp_password' not in caplog.text

    def test_source_is_recorded_for_each_key(self, monkeypatch):
        monkeypatch.setenv('TYPO_SNIPER_URLSCAN_API_KEY', 'v')
        mgr = SecretsManager()
        mgr.get_secret('urlscan_api_key')
        assert mgr.resolved_from['urlscan_api_key'] == 'env'


class TestGetApiKey:
    def test_environment_wins_over_the_config_value(self, monkeypatch):
        monkeypatch.setenv('TYPO_SNIPER_URLSCAN_API_KEY', 'from-env')
        assert env_only().get_api_key('urlscan', 'from-config') == 'from-env'

    def test_falls_back_to_the_config_value(self):
        assert env_only().get_api_key('urlscan', 'from-config') == 'from-config'

    def test_returns_none_when_nothing_is_configured(self):
        assert env_only().get_api_key('urlscan') is None
