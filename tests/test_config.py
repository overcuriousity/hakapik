from pathlib import Path

import pytest

from hakapik.config import load_config


def test_load_config_defaults(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text('data_dir = "/var/lib/hakapik"\ndatabase_url = "postgresql://x"\n')
    cfg = load_config(p)
    assert cfg.bootstrap_days == 90
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
