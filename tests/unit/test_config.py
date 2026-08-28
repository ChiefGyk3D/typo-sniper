"""Tests for configuration loading and validation."""

from pathlib import Path

import pytest
import yaml

from typo_sniper.config import Config


class TestPathExpansion:
    def test_tilde_is_expanded(self):
        """A literal '~' directory used to be created in the working directory."""
        cfg = Config.from_dict({'cache_dir': '~/.typo_sniper/cache'})
        assert '~' not in str(cfg.cache_dir)
        assert cfg.cache_dir.is_absolute()

    def test_env_vars_are_expanded(self, monkeypatch, tmp_path):
        monkeypatch.setenv('TS_TEST_DIR', str(tmp_path))
        cfg = Config.from_dict({'output_dir': '$TS_TEST_DIR/out'})
        assert str(cfg.output_dir) == str(tmp_path / 'out')

    def test_from_dict_does_not_mutate_caller_data(self):
        data = {'cache_dir': '~/x', 'max_workers': 5}
        Config.from_dict(data)
        assert data['cache_dir'] == '~/x'


class TestFromFile:
    def test_loads_yaml(self, tmp_path):
        path = tmp_path / 'config.yaml'
        path.write_text(yaml.dump({'max_workers': 25, 'recent_days': 45}))
        cfg = Config.from_file(path)
        assert cfg.max_workers == 25
        assert cfg.recent_days == 45

    def test_ignores_unknown_keys(self, tmp_path):
        path = tmp_path / 'config.yaml'
        path.write_text(yaml.dump({'max_workers': 3, 'not_a_real_setting': 1}))
        assert Config.from_file(path).max_workers == 3

    def test_rejects_wrong_extension(self, tmp_path):
        path = tmp_path / 'config.txt'
        path.write_text('max_workers: 5')
        with pytest.raises(ValueError, match='YAML'):
            Config.from_file(path)

    def test_rejects_missing_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            Config.from_file(tmp_path / 'nope.yaml')

    def test_rejects_directory(self, tmp_path):
        d = tmp_path / 'conf.yaml'
        d.mkdir()
        with pytest.raises(ValueError, match='regular file'):
            Config.from_file(d)

    def test_rejects_non_mapping(self, tmp_path):
        path = tmp_path / 'config.yaml'
        path.write_text('- just\n- a\n- list\n')
        with pytest.raises(ValueError, match='dictionary'):
            Config.from_file(path)

    def test_rejects_malformed_yaml(self, tmp_path):
        path = tmp_path / 'config.yaml'
        path.write_text('key: [unclosed\n')
        with pytest.raises(ValueError, match='Invalid YAML'):
            Config.from_file(path)

    def test_shipped_example_config_loads(self):
        """The example config must actually work when copied verbatim."""
        example = Path(__file__).resolve().parents[2] / 'config.yaml.example'
        cfg = Config.from_file(example)
        assert cfg.max_workers > 0
        assert '~' not in str(cfg.cache_dir)


class TestRoundTrip:
    def test_save_and_reload(self, tmp_path):
        cfg = Config()
        cfg.max_workers = 42
        path = tmp_path / 'out.yaml'
        cfg.save(path)
        assert Config.from_file(path).max_workers == 42

    def test_to_dict_stringifies_paths(self):
        data = Config().to_dict()
        assert isinstance(data['cache_dir'], str)


class TestEnvironmentIntegration:
    def test_urlscan_key_from_env(self, monkeypatch):
        monkeypatch.setenv('TYPO_SNIPER_URLSCAN_API_KEY', 'secret-key')
        assert Config().urlscan_api_key == 'secret-key'

    @pytest.mark.parametrize('value,expected', [
        ('true', True), ('1', True), ('yes', True), ('on', True),
        ('false', False), ('0', False), ('no', False),
    ])
    def test_enable_urlscan_flag_parsing(self, monkeypatch, value, expected):
        monkeypatch.setenv('ENABLE_URLSCAN', value)
        assert Config().enable_urlscan is expected

    def test_plain_env_key_does_not_auto_enable(self, monkeypatch):
        """Only managed secret stores auto-enable URLScan."""
        monkeypatch.delenv('ENABLE_URLSCAN', raising=False)
        monkeypatch.delenv('TYPO_SNIPER_ENABLE_URLSCAN', raising=False)
        monkeypatch.delenv('DOPPLER_PROJECT', raising=False)
        monkeypatch.delenv('DOPPLER_TOKEN', raising=False)
        monkeypatch.delenv('AWS_SECRET_NAME', raising=False)
        monkeypatch.setenv('URLSCAN_API_KEY', 'k')
        assert Config().enable_urlscan is False

    def test_user_agent_identifies_the_tool(self):
        assert Config().user_agent.startswith('TypoSniper/')


class TestSecretResolution:
    """Credentials must reach Config through the secrets backends, not only os.getenv."""

    @pytest.fixture(autouse=True)
    def clean_env(self, monkeypatch):
        for key in (
            'TYPO_SNIPER_URLSCAN_API_KEY', 'URLSCAN_API_KEY',
            'TYPO_SNIPER_AI_API_KEY', 'ANTHROPIC_API_KEY', 'OPENAI_API_KEY',
            'GEMINI_API_KEY', 'GOOGLE_API_KEY',
            'TYPO_SNIPER_SLACK_WEBHOOK_URL', 'SLACK_WEBHOOK_URL',
            'DOPPLER_TOKEN', 'DOPPLER_PROJECT', 'AWS_SECRET_NAME',
            'VAULT_ADDR', 'VAULT_TOKEN',
        ):
            monkeypatch.delenv(key, raising=False)

    def test_prefixed_variable_is_used(self, monkeypatch):
        monkeypatch.setenv('TYPO_SNIPER_URLSCAN_API_KEY', 'from-env')
        assert Config().urlscan_api_key == 'from-env'

    def test_vendor_standard_variable_is_accepted(self, monkeypatch):
        monkeypatch.setenv('ANTHROPIC_API_KEY', 'sk-ant-x')
        assert Config().ai_api_key == 'sk-ant-x'

    def test_a_backend_supplies_credentials(self, monkeypatch):
        """The regression this guards: backends were configured but never called."""
        from typo_sniper import secrets_manager

        monkeypatch.setenv('VAULT_ADDR', 'https://vault.example.com')
        monkeypatch.setenv('VAULT_TOKEN', 'hvs.token')
        monkeypatch.setattr(
            secrets_manager, '_https_json',
            lambda url, headers: {'data': {'data': {
                'urlscan_api_key': 'from-vault',
                'slack_webhook_url': 'https://hooks.example/from-vault',
            }}},
        )

        config = Config()
        assert config.urlscan_api_key == 'from-vault'
        assert config.slack_webhook_url == 'https://hooks.example/from-vault'
        assert config.secrets.resolved_from['urlscan_api_key'] == 'vault'

    def test_explicit_config_value_is_not_overridden(self, monkeypatch):
        """An explicit setting must not lose to a stale entry in a shared vault."""
        monkeypatch.setenv('TYPO_SNIPER_URLSCAN_API_KEY', 'from-env')
        assert Config(urlscan_api_key='from-config').urlscan_api_key == 'from-config'

    def test_backend_order_is_configurable(self):
        names = [b.name for b in Config(secrets_backends=['env', 'vault']).secrets.backends]
        assert names == ['env', 'vault']

    def test_default_leaves_every_remote_backend_unconfigured(self):
        statuses = {e['backend']: e['status'] for e in Config().secrets.describe()}
        assert statuses['env'] == 'ready'
        assert statuses['doppler'] == 'not configured'
        assert statuses['aws'] == 'not configured'

    def test_every_secret_field_exists_on_the_config(self):
        config = Config()
        for attr, _aliases in Config.SECRET_FIELDS:
            assert hasattr(config, attr), attr


class TestDirectoryOverrides:
    """
    Container deployments redirect these at runtime.

    state_dir matters most: it holds the history every delta is computed
    against. Point it at ephemeral storage and the scanner still runs, still
    reports, and silently never detects a change again.
    """

    @pytest.fixture(autouse=True)
    def clean_env(self, monkeypatch):
        for key in ('TYPO_SNIPER_CACHE_DIR', 'TYPO_SNIPER_OUTPUT_DIR',
                    'TYPO_SNIPER_STATE_DIR'):
            monkeypatch.delenv(key, raising=False)

    def test_state_dir_from_environment(self, monkeypatch):
        monkeypatch.setenv('TYPO_SNIPER_STATE_DIR', '/mnt/efs/state')
        assert Config().state_dir == Path('/mnt/efs/state')

    def test_output_dir_from_environment(self, monkeypatch):
        monkeypatch.setenv('TYPO_SNIPER_OUTPUT_DIR', '/app/results')
        assert Config().output_dir == Path('/app/results')

    def test_cache_dir_from_environment(self, monkeypatch):
        monkeypatch.setenv('TYPO_SNIPER_CACHE_DIR', '/app/cache')
        assert Config().cache_dir == Path('/app/cache')

    def test_the_environment_wins_over_a_config_value(self, monkeypatch):
        """A deployment-time override is the whole point of these."""
        monkeypatch.setenv('TYPO_SNIPER_STATE_DIR', '/mnt/efs/state')
        assert Config(state_dir=Path('/somewhere/else')).state_dir == Path('/mnt/efs/state')

    def test_overrides_are_still_expanded(self, monkeypatch):
        monkeypatch.setenv('TYPO_SNIPER_STATE_DIR', '~/from-env')
        assert '~' not in str(Config().state_dir)

    def test_defaults_are_unchanged_without_the_variables(self):
        assert '.typo_sniper' in str(Config().state_dir)


class TestUnknownKeys:
    def test_unknown_keys_are_reported(self, caplog):
        """A typo like `enable_url_scan:` must not silently run with defaults."""
        import logging

        from typo_sniper.config import Config

        with caplog.at_level(logging.WARNING):
            Config.from_dict({'enable_url_scan': True, 'max_workers': 5})

        assert any('enable_url_scan' in r.message for r in caplog.records)

    def test_known_keys_stay_quiet(self, caplog):
        import logging

        from typo_sniper.config import Config

        with caplog.at_level(logging.WARNING):
            cfg = Config.from_dict({'max_workers': 5})

        assert cfg.max_workers == 5
        assert not [r for r in caplog.records if 'unknown configuration' in r.message.lower()]


class TestSaveNeverPersistsSecrets:
    def test_resolved_credentials_are_not_written(self, tmp_path):
        """By the time save() runs, resolve_secrets() may have pulled tokens
        out of a vault; they must never land in cleartext YAML."""
        import yaml

        from typo_sniper.config import Config

        cfg = Config()
        cfg.urlscan_api_key = 'sekret-key'
        cfg.smtp_password = 'sekret-password'
        cfg.slack_webhook_url = 'https://hooks.slack.com/services/T0/B0/sekret'

        path = tmp_path / 'saved.yaml'
        cfg.save(path)
        raw = path.read_text()
        assert 'sekret' not in raw

        data = yaml.safe_load(raw)
        assert 'urlscan_api_key' not in data
        assert 'smtp_password' not in data
        # Non-secret settings still round-trip
        assert data['max_workers'] == cfg.max_workers
