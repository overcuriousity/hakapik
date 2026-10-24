from pathlib import Path

import pytest

from hakapik.config import load_config


def test_load_config_defaults(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text('data_dir = "/var/lib/hakapik"\ndatabase_url = "postgresql://x"\n')
    cfg = load_config(p)
    assert cfg.raw_retention_days == 7
    assert cfg.tranco_top_n == 100_000
    assert cfg.log_lists == (
        "https://www.gstatic.com/ct/log_list/v3/log_list.json",
        "https://valid.apple.com/ct/log_list/current_log_list.json",
    )


def test_load_config_types_and_overrides(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text(
        'data_dir = "/d"\ndatabase_url = "postgresql://x"\n'
        'public_apexes = ["github.io"]\nbatch_size = 10\n'
    )
    cfg = load_config(p)
    assert cfg.data_dir == Path("/d")
    assert cfg.public_apexes == ("github.io",)
    assert cfg.batch_size == 10
    assert load_config(_write(tmp_path, "")).public_apexes == ()


def _write(tmp_path, extra):
    p = tmp_path / "d.toml"
    p.write_text('data_dir = "/d"\ndatabase_url = "postgresql://x"\n' + extra)
    return p


def test_unknown_key_raises(tmp_path):
    with pytest.raises(ValueError, match="bogus"):
        load_config(_write(tmp_path, "bogus = 1\n"))


def test_example_config_loads_with_pool_cap():
    cfg = load_config(Path(__file__).parent.parent / "hakapik.example.toml")
    assert cfg.max_db_connections == 64


def _load(tmp_path, extra):
    return load_config(_write(tmp_path, extra))


def test_fetch_defaults(tmp_path):
    cfg = _load(tmp_path, "")
    assert cfg.retry_ladder_s == (0, 120, 600, 3600, 21600, 86400)
    assert cfg.fetch_per_ip_interval_s is None and cfg.fetch_daily_cap is None
    assert cfg.fetch_proxy is None and cfg.resolver_nameservers == ()
    assert cfg.fetch_workers == 2 and cfg.recheck_days == 30 and cfg.ageout_hours == 24.0


def test_ladder_must_start_at_zero_and_increase(tmp_path):
    with pytest.raises(ValueError, match="retry_ladder_s"):
        _load(tmp_path, "retry_ladder_s = [0, 600, 120]")
    with pytest.raises(ValueError, match="retry_ladder_s"):
        _load(tmp_path, "retry_ladder_s = [60, 120]")
    with pytest.raises(ValueError, match="retry_ladder_s"):
        _load(tmp_path, "retry_ladder_s = []")


def test_list_values_become_tuples(tmp_path):
    cfg = _load(tmp_path, 'resolver_nameservers = ["9.9.9.9"]')
    assert cfg.resolver_nameservers == ("9.9.9.9",)


def test_asn_mmdb_is_a_path(tmp_path):
    assert _load(tmp_path, "").asn_mmdb is None
    assert _load(tmp_path, 'asn_mmdb = "/x/a.mmdb"').asn_mmdb == Path("/x/a.mmdb")


def test_lease_must_cover_worst_case_capture(tmp_path):
    # 4 * nav_timeout_s + 60: landing, up to 3 click hops, resolve
    assert _load(tmp_path, "nav_timeout_s = 30.0\nlease_s = 180").lease_s == 180
    with pytest.raises(ValueError, match="lease_s"):
        _load(tmp_path, "nav_timeout_s = 30.0\nlease_s = 179")
    with pytest.raises(ValueError, match="lease_s"):
        _load(tmp_path, "nav_timeout_s = 200.0")


def test_fetch_workers_at_least_one(tmp_path):
    assert _load(tmp_path, "fetch_workers = 1").fetch_workers == 1
    with pytest.raises(ValueError, match="fetch_workers"):
        _load(tmp_path, "fetch_workers = 0")
