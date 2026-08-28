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


class TestConcurrentScanning:
    @pytest.mark.asyncio
    async def test_results_keep_input_order_under_concurrency(self, sniper):
        """Domains finish out of order; reports must not."""
        import asyncio

        sniper.config.enable_diff = False
        sniper.config.concurrent_domains = 3
        delays = {'a.com': 0.05, 'b.com': 0.0, 'c.com': 0.02}
        completion_order = []

        async def fake_scan(domain):
            await asyncio.sleep(delays[domain])
            completion_order.append(domain)
            return {'original_domain': domain, 'permutations': []}

        sniper.scanner.scan_domain = fake_scan
        await sniper.scan_domains(['a.com', 'b.com', 'c.com'])

        assert completion_order != ['a.com', 'b.com', 'c.com']  # really concurrent
        assert [r['original_domain'] for r in sniper.results] == [
            'a.com', 'b.com', 'c.com'
        ]

    @pytest.mark.asyncio
    async def test_one_failing_domain_does_not_stop_the_rest(self, sniper):
        sniper.config.enable_diff = False
        sniper.config.concurrent_domains = 2

        async def fake_scan(domain):
            if domain == 'boom.com':
                raise RuntimeError('scan exploded')
            return {'original_domain': domain, 'permutations': []}

        sniper.scanner.scan_domain = fake_scan
        await sniper.scan_domains(['ok1.com', 'boom.com', 'ok2.com'])

        assert [r['original_domain'] for r in sniper.results] == ['ok1.com', 'ok2.com']

    @pytest.mark.asyncio
    async def test_concurrency_of_one_is_sequential(self, sniper):
        import asyncio

        sniper.config.enable_diff = False
        sniper.config.concurrent_domains = 1
        active = 0
        peak = 0

        async def fake_scan(domain):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.01)
            active -= 1
            return {'original_domain': domain, 'permutations': []}

        sniper.scanner.scan_domain = fake_scan
        await sniper.scan_domains(['a.com', 'b.com', 'c.com'])
        assert peak == 1


class TestResultRetention:
    def test_prunes_oldest_scans_keeping_formats_together(self, sniper, tmp_path):
        sniper.config.results_retain = 2
        stamps = ['20260101_010101', '20260102_020202', '20260103_030303']
        for stamp in stamps:
            for ext in ('json', 'html'):
                (tmp_path / f'typo_sniper_results_{stamp}.{ext}').write_text('x')
        (tmp_path / 'unrelated.json').write_text('leave me')

        sniper._prune_old_results(tmp_path)

        remaining = sorted(p.name for p in tmp_path.iterdir())
        assert 'unrelated.json' in remaining
        assert not any(stamps[0] in name for name in remaining)
        assert sum(stamps[1] in name for name in remaining) == 2
        assert sum(stamps[2] in name for name in remaining) == 2

    def test_zero_keeps_everything(self, sniper, tmp_path):
        sniper.config.results_retain = 0
        (tmp_path / 'typo_sniper_results_20260101_010101.json').write_text('x')
        sniper._prune_old_results(tmp_path)
        assert (tmp_path / 'typo_sniper_results_20260101_010101.json').exists()
