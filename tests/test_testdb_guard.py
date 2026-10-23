import pytest

from conftest import _test_db_url


def test_guard_refuses_non_test_database(monkeypatch):
    monkeypatch.setenv("HAKAPIK_TEST_DB", "postgresql://u:p@127.0.0.1:5432/hakapik")
    with pytest.raises(pytest.fail.Exception, match="_test"):
        _test_db_url()


def test_guard_accepts_test_database(monkeypatch):
    url = "postgresql://u:p@127.0.0.1:5432/hakapik_test"
    monkeypatch.setenv("HAKAPIK_TEST_DB", url)
    assert _test_db_url() == url


def test_guard_skips_without_env(monkeypatch):
    monkeypatch.delenv("HAKAPIK_TEST_DB", raising=False)
    with pytest.raises(pytest.skip.Exception):
        _test_db_url()
