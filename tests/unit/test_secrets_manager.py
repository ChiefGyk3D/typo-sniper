"""Tests for secret resolution across environment, Doppler, and AWS sources."""

import pytest

from secrets_manager import SecretsManager


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for key in ('TYPO_SNIPER_URLSCAN_API_KEY', 'URLSCAN_API_KEY',
                'TYPO_SNIPER_TEST_KEY', 'TEST_KEY'):
        monkeypatch.delenv(key, raising=False)


class TestEnvironmentSource:
    def test_reads_prefixed_variable(self, monkeypatch):
        monkeypatch.setenv('TYPO_SNIPER_TEST_KEY', 'from-env')
        assert SecretsManager().get_secret('test_key') == 'from-env'

    def test_prefix_is_case_insensitive_on_the_key(self, monkeypatch):
        monkeypatch.setenv('TYPO_SNIPER_TEST_KEY', 'v')
        assert SecretsManager().get_secret('TeSt_KeY') == 'v'

    def test_returns_default_when_absent(self):
        assert SecretsManager().get_secret('missing', 'fallback') == 'fallback'
        assert SecretsManager().get_secret('missing') is None

    def test_unprefixed_variable_is_not_used_without_doppler(self, monkeypatch):
        monkeypatch.setenv('TEST_KEY', 'unprefixed')
        assert SecretsManager().get_secret('test_key') is None


class TestDopplerSource:
    def test_reads_injected_variable_when_enabled(self, monkeypatch):
        monkeypatch.setenv('TEST_KEY', 'from-doppler')
        mgr = SecretsManager()
        mgr.use_doppler = True
        mgr.doppler_available = True
        assert mgr.get_secret('test_key') == 'from-doppler'

    def test_prefixed_variable_takes_priority(self, monkeypatch):
        monkeypatch.setenv('TYPO_SNIPER_TEST_KEY', 'prefixed')
        monkeypatch.setenv('TEST_KEY', 'doppler')
        mgr = SecretsManager()
        mgr.use_doppler = True
        mgr.doppler_available = True
        assert mgr.get_secret('test_key') == 'prefixed'

    def test_missing_sdk_disables_doppler(self, monkeypatch):
        """A missing optional SDK must warn, not crash the run."""
        import builtins
        import importlib.util

        monkeypatch.setattr(importlib.util, 'find_spec', lambda name: None)
        assert SecretsManager(use_doppler=True).use_doppler is False
        assert builtins  # keep the import meaningful


class TestAwsSource:
    def _manager(self, secrets):
        mgr = SecretsManager()
        mgr.use_aws = True
        mgr.aws_available = True
        mgr.aws_secrets = secrets
        return mgr

    def test_lowercase_key(self):
        assert self._manager({'test_key': 'aws'}).get_secret('test_key') == 'aws'

    def test_uppercase_key(self):
        assert self._manager({'TEST_KEY': 'aws'}).get_secret('test_key') == 'aws'

    def test_absent_key_falls_through_to_default(self):
        assert self._manager({'other': 'x'}).get_secret('test_key', 'd') == 'd'

    def test_missing_boto3_disables_aws(self, monkeypatch):
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == 'boto3':
                raise ImportError('no boto3')
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, '__import__', fake_import)
        assert SecretsManager(use_aws=True).use_aws is False


class TestGetApiKey:
    def test_env_wins_over_config_value(self, monkeypatch):
        monkeypatch.setenv('TYPO_SNIPER_URLSCAN_API_KEY', 'from-env')
        assert SecretsManager().get_api_key('urlscan', 'from-config') == 'from-env'

    def test_falls_back_to_config_value(self):
        assert SecretsManager().get_api_key('urlscan', 'from-config') == 'from-config'

    def test_returns_none_when_nothing_configured(self):
        assert SecretsManager().get_api_key('urlscan') is None


class TestDopplerCliDetection:
    def test_reports_availability(self, monkeypatch):
        import shutil
        monkeypatch.setattr(shutil, 'which', lambda name: '/usr/bin/doppler')
        assert SecretsManager.is_doppler_cli_available() is True

        monkeypatch.setattr(shutil, 'which', lambda name: None)
        assert SecretsManager.is_doppler_cli_available() is False
