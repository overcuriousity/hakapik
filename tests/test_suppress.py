from pathlib import Path

import pytest

from hakapik.names import normalize
from hakapik.suppress import Suppressor

FIXTURE = Path(__file__).parent / "fixtures" / "tranco_small.csv"


@pytest.fixture
def sup():
    return Suppressor.from_files(FIXTURE, top_n=5, public_apexes=["pages.dev"])


def test_tranco_suppresses_apex_and_www_only(sup):
    assert sup.reason(normalize("google.com")) == "tranco"
    assert sup.reason(normalize("www.google.com")) == "tranco"
    assert sup.reason(normalize("login-check.google.com")) is None


def test_public_apex_suppressed_but_subdomain_not(sup):
    assert sup.reason(normalize("pages.dev")) == "public_apex"
    assert sup.reason(normalize("x.pages.dev")) is None


def test_wildcard_and_invalid(sup):
    assert sup.reason(normalize("*.a.com")) == "wildcard"
    assert sup.reason(normalize("bad_!.com")) == "invalid"


def test_top_n_limits_rows(sup):
    assert sup.reason(normalize("apple.com")) == "tranco"
    assert sup.reason(normalize("example.org")) is None


def test_www_prefix_stripped_and_lowercased(tmp_path):
    csv = tmp_path / "t.csv"
    csv.write_text("1,WWW.Example.ORG\n2,other.net\n")
    s = Suppressor.from_files(csv, top_n=10, public_apexes=[])
    assert s.reason(normalize("example.org")) == "tranco"
    assert s.reason(normalize("www.example.org")) == "tranco"


def test_snapshot_private_suffixes_included_without_config():
    s = Suppressor.from_files(FIXTURE, top_n=5, public_apexes=[])
    assert s.reason(normalize("github.io")) == "public_apex"


def test_ordinary_name_is_candidate(sup):
    assert sup.reason(normalize("new-site.example.net")) is None


@pytest.mark.parametrize("name", ["*.pages.dev", "*.github.io"])
def test_wildcard_over_public_apex_is_wildcard(sup, name):
    assert sup.reason(normalize(name)) == "wildcard"
