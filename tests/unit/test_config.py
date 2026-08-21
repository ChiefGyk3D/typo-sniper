"""Tests for configuration loading and validation."""

from pathlib import Path

import pytest
import yaml

from config import Config


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
