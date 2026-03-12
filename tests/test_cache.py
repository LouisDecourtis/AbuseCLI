import pytest

from abusecli.cache import init_cache_db, cache_get, cache_set, cache_clear, cache_stats


@pytest.fixture
def cache_conn(tmp_path, monkeypatch):
    """Create a temporary cache database"""
    db_path = str(tmp_path / "cache.db")
    monkeypatch.setattr("abusecli.cache.CACHE_DB", db_path)
    monkeypatch.setattr("abusecli.cache.CACHE_DIR", str(tmp_path))
    conn = init_cache_db()
    yield conn
    conn.close()


class TestCache:
    def test_cache_set_and_get(self, cache_conn):
        data = {"data": {"ipAddress": "1.2.3.4", "abuseConfidenceScore": 50}}
        cache_set(cache_conn, "1.2.3.4", data)
        result = cache_get(cache_conn, "1.2.3.4", ttl=3600)
        assert result == data

    def test_cache_miss(self, cache_conn):
        result = cache_get(cache_conn, "9.9.9.9", ttl=3600)
        assert result is None

    def test_cache_expired(self, cache_conn):
        data = {"data": {"ipAddress": "1.2.3.4"}}
        cache_set(cache_conn, "1.2.3.4", data)
        # TTL of 0 means immediately expired
        result = cache_get(cache_conn, "1.2.3.4", ttl=0)
        assert result is None

    def test_cache_clear_all(self, cache_conn, tmp_path, monkeypatch):
        db_path = str(tmp_path / "cache.db")
        monkeypatch.setattr("abusecli.cache.CACHE_DB", db_path)
        cache_set(cache_conn, "1.1.1.1", {"data": "a"})
        cache_set(cache_conn, "2.2.2.2", {"data": "b"})
        cache_conn.close()
        deleted = cache_clear()
        assert deleted == 2

    def test_cache_stats_empty(self, tmp_path, monkeypatch):
        monkeypatch.setattr("abusecli.cache.CACHE_DB", str(tmp_path / "nonexistent.db"))
        stats = cache_stats()
        assert stats["entries"] == 0
