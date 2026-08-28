"""Tests for CLI argument parsing and input handling."""

import pytest

from typo_sniper.cli import TypoSniper, parse_arguments


@pytest.fixture
def sniper(config):
    app = TypoSniper(config)
    yield app
    app.close()


class TestLoadDomains:
    def test_reads_and_validates(self, sniper, tmp_path):
        path = tmp_path / 'domains.txt'
        path.write_text('example.com\ngithub.com\n')
        assert sniper.load_domains(path) == ['example.com', 'github.com']

    def test_skips_comments_and_blank_lines(self, sniper, tmp_path):
        path = tmp_path / 'domains.txt'
        path.write_text('# a comment\n\nexample.com\n\n#another\n')
        assert sniper.load_domains(path) == ['example.com']

    def test_drops_invalid_entries(self, sniper, tmp_path):
        path = tmp_path / 'domains.txt'
        path.write_text('example.com\nnot a domain\nlocalhost\n')
        assert sniper.load_domains(path) == ['example.com']

    def test_strips_whitespace(self, sniper, tmp_path):
        path = tmp_path / 'domains.txt'
        path.write_text('  example.com  \n\tgithub.com\t\n')
        assert sniper.load_domains(path) == ['example.com', 'github.com']

    def test_missing_file_raises(self, sniper, tmp_path):
        with pytest.raises(FileNotFoundError):
            sniper.load_domains(tmp_path / 'nope.txt')

    def test_directory_raises(self, sniper, tmp_path):
        d = tmp_path / 'dir.txt'
        d.mkdir()
        with pytest.raises(ValueError, match='regular file'):
            sniper.load_domains(d)

    def test_wrong_extension_raises(self, sniper, tmp_path):
        path = tmp_path / 'domains.json'
        path.write_text('example.com')
        with pytest.raises(ValueError, match='text file'):
            sniper.load_domains(path)

    def test_empty_file_returns_empty_list(self, sniper, tmp_path):
        path = tmp_path / 'domains.txt'
        path.write_text('')
        assert sniper.load_domains(path) == []

    def test_shipped_example_domain_list_is_valid(self, sniper):
        from pathlib import Path
        example = (Path(__file__).resolve().parents[2]
                   / 'src' / 'typo_sniper' / 'monitored_domains.txt')
        assert len(sniper.load_domains(example)) == 3


class TestArgumentParsing:
    def test_defaults(self, monkeypatch):
        monkeypatch.setattr('sys.argv', ['typo_sniper.py'])
        args = parse_arguments()
        assert args.format == ['excel']
        # None, not the numeric defaults: an argparse default here would
        # silently overwrite the same setting from a config file. The
        # effective defaults live in Config.
        assert args.months is None
        assert args.max_workers is None
        assert args.cache_ttl is None
        assert args.output is None
        assert args.no_cache is False

    def test_explicit_flags_are_kept(self, monkeypatch):
        monkeypatch.setattr(
            'sys.argv',
            ['typo_sniper.py', '--months', '3', '--max-workers', '20',
             '--cache-ttl', '60', '-o', 'out'])
        args = parse_arguments()
        assert args.months == 3
        assert args.max_workers == 20
        assert args.cache_ttl == 60
        assert str(args.output) == 'out'

    def test_multiple_formats(self, monkeypatch):
        monkeypatch.setattr(
            'sys.argv', ['typo_sniper.py', '--format', 'json', 'html'])
        assert parse_arguments().format == ['json', 'html']

    def test_rejects_unknown_format(self, monkeypatch):
        monkeypatch.setattr('sys.argv', ['typo_sniper.py', '--format', 'pdf'])
        with pytest.raises(SystemExit):
            parse_arguments()

    def test_verbose_and_debug_flags(self, monkeypatch):
        monkeypatch.setattr('sys.argv', ['typo_sniper.py', '-v', '--debug'])
        args = parse_arguments()
        assert args.verbose is True
        assert args.debug is True


class TestExportResults:
    def test_unknown_format_is_skipped(self, sniper, tmp_path, sample_results):
        sniper.results = sample_results
        sniper.export_results(['json', 'not-a-format'], tmp_path)
        assert len(list(tmp_path.glob('*.json'))) == 1

    def test_creates_the_output_directory(self, sniper, tmp_path, sample_results):
        target = tmp_path / 'nested' / 'out'
        sniper.results = sample_results
        sniper.export_results(['json'], target)
        assert target.is_dir()


class TestPrintSummary:
    def test_runs_with_results(self, sniper, sample_results, capsys):
        sniper.results = sample_results
        sniper.print_summary()
        rendered = capsys.readouterr().out.split()
        assert 'example.com' in rendered

    def test_runs_with_no_results(self, sniper, capsys):
        sniper.print_summary()
        assert 'Scan Summary' in capsys.readouterr().out

    def test_warns_when_whois_failed(self, sniper, sample_results, capsys):
        sample_results[0]['whois_succeeded'] = 0
        sample_results[0]['whois_failed'] = 2
        sniper.results = sample_results
        sniper.print_summary()
        assert 'WHOIS data unavailable' in capsys.readouterr().out
