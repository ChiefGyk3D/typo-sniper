"""Tests for the WHOIS cache."""


from cache import Cache


class TestCacheBasics:
    def test_set_and_get(self, tmp_path):
        cache = Cache(tmp_path)
        cache.set('whois:example.com', {'org': 'Example'})
        assert cache.get('whois:example.com') == {'org': 'Example'}

    def test_missing_key_returns_none(self, tmp_path):
        assert Cache(tmp_path).get('nope') is None

    def test_expired_entry_is_evicted(self, tmp_path):
        cache = Cache(tmp_path)
        cache.set('k', {'v': 1}, ttl=-1)
        assert cache.get('k') is None
        assert list(tmp_path.glob('*.json')) == []

    def test_delete(self, tmp_path):
        cache = Cache(tmp_path)
        cache.set('k', {'v': 1})
        cache.delete('k')
        assert cache.get('k') is None

    def test_keys_are_isolated(self, tmp_path):
        cache = Cache(tmp_path)
        cache.set('a', {'v': 1})
        cache.set('b', {'v': 2})
        assert cache.get('a') == {'v': 1}
        assert cache.get('b') == {'v': 2}

    def test_creates_its_directory(self, tmp_path):
        target = tmp_path / 'nested' / 'cache'
        Cache(target)
        assert target.is_dir()


class TestCacheResilience:
    def test_corrupted_entry_is_removed(self, tmp_path):
        cache = Cache(tmp_path)
        cache.set('k', {'v': 1})
        corrupted = next(tmp_path.glob('*.json'))
        corrupted.write_text('{not valid json')

        assert cache.get('k') is None
        assert not corrupted.exists()

    def test_clear_expired_only_removes_stale(self, tmp_path):
        cache = Cache(tmp_path)
        cache.set('fresh', {'v': 1}, ttl=3600)
        cache.set('stale', {'v': 2}, ttl=-1)

        assert cache.clear_expired() == 1
        assert cache.get('fresh') == {'v': 1}

    def test_clear_removes_everything(self, tmp_path):
        cache = Cache(tmp_path)
        for i in range(3):
            cache.set(f'k{i}', {'v': i})
        assert cache.clear() == 3
        assert list(tmp_path.glob('*.json')) == []


class TestCacheStats:
    def test_reports_entry_counts(self, tmp_path):
        cache = Cache(tmp_path)
        cache.set('fresh', {'v': 1}, ttl=3600)
        cache.set('stale', {'v': 2}, ttl=-1)

        stats = cache.get_stats()
        assert stats['total_entries'] == 2
        assert stats['expired_entries'] == 1
        assert stats['valid_entries'] == 1
        assert stats['total_size_bytes'] > 0
