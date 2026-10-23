from hakapik.names import normalize


def test_normalize_idn_case_and_trailing_dot():
    a = normalize("Sparkasse-Prüfung.DE.")
    b = normalize("xn--sparkasse-prfung-uzb.de")
    assert a.fqdn == b.fqdn and a.idn and a.valid


def test_private_suffix_registrable():
    r = normalize("login.microsoft-secure.pages.dev")
    assert r.registrable == "microsoft-secure.pages.dev"


def test_wildcard_stripped_and_flagged():
    r = normalize("*.example.com")
    assert r.fqdn == "example.com" and r.wildcard


def test_invalid_name_flagged():
    r = normalize("bad_label!.com")
    assert not r.valid and r.registrable == ""


def test_underscore_label_invalid():
    assert not normalize("_dmarc.example.com").valid


def test_bare_suffix_invalid():
    assert not normalize("com").valid


def test_plain_name():
    r = normalize("  WWW.Example.co.uk. ")
    assert r.fqdn == "www.example.co.uk" and r.registrable == "example.co.uk"
    assert r.valid and not r.idn and not r.wildcard


def test_empty_labels_invalid():
    for name in ("example.com..", ".example.com", "a..b.com"):
        r = normalize(name)
        assert not r.valid and r.registrable == "", name


def test_single_trailing_dot_stays_valid():
    r = normalize("example.com.")
    assert r.valid and r.fqdn == "example.com"


def test_index_key_separates_wildcard_from_apex():
    w, a = normalize("*.Example.com."), normalize("example.com")
    assert w.fqdn == a.fqdn == "example.com"
    assert w.key == "*.example.com" and a.key == "example.com"
