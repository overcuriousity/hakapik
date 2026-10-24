import io
from datetime import UTC, datetime

from warcio.archiveiterator import ArchiveIterator

from hakapik.warc import MAX_BODY, Exchange, build_warc


def _records(data):
    """(record, block bytes) pairs; a record's stream is gone once iteration moves on."""
    return [(r, r.content_stream().read()) for r in ArchiveIterator(io.BytesIO(data))]


def _ex(url, status, body, ip, response_headers=(("Content-Type", "text/html"),),
        request_headers=(("User-Agent", "test"),), body_unavailable=False):
    return Exchange(url=url, method="GET", request_headers=request_headers,
                    request_body=None, status=status, status_text="OK",
                    response_headers=response_headers, body=body, server_ip=ip,
                    at=datetime(2026, 10, 24, 12, 0, 0, tzinfo=UTC),
                    body_unavailable=body_unavailable)


def test_warc_roundtrip():
    data = build_warc([_ex("https://a.test/", 200, b"<html>hi</html>", "1.2.3.4")],
                      {"software": "hakapik"})
    assert data[:2] == b"\x1f\x8b"
    recs, blocks = zip(*_records(data))
    assert [r.rec_type for r in recs] == ["warcinfo", "request", "response"]
    info = blocks[0]
    assert b"software: hakapik" in info
    assert b"http-headers: reconstructed from the browser, not wire bytes" in info
    assert recs[0].rec_headers.protocol == "WARC/1.1"
    req, resp = recs[1], recs[2]
    assert req.rec_headers.get_header("WARC-Target-URI") == "https://a.test/"
    assert req.http_headers.get_header("User-Agent") == "test"
    assert resp.rec_headers.get_header("WARC-IP-Address") == "1.2.3.4"
    assert resp.rec_headers.get_header("WARC-Concurrent-To") == req.rec_headers.get_header("WARC-Record-ID")
    assert resp.rec_headers.get_header("WARC-Date").startswith("2026-10-24T12:00:00")
    assert resp.http_headers.protocol == "HTTP/1.1"
    assert resp.http_headers.get_statuscode() == "200"
    assert blocks[2] == b"<html>hi</html>"


def test_warc_drops_pseudo_headers_and_truncates():
    big = b"x" * (MAX_BODY + 10)
    ex = _ex("https://a.test/big", 200, big, None,
             response_headers=((":status", "200"), ("content-type", "text/plain"),
                               ("content-encoding", "gzip")),
             request_headers=((":method", "GET"), (":authority", "a.test"),
                              ("user-agent", "test")))
    recs, blocks = zip(*_records(build_warc([ex], {})))
    req, resp = recs[1], recs[2]
    assert all(not n.startswith(":") for n, _ in req.http_headers.headers)
    assert all(not n.startswith(":") for n, _ in resp.http_headers.headers)
    assert resp.rec_headers.get_header("WARC-IP-Address") is None
    assert req.http_headers.get_header("Host") == "a.test"  # restated from :authority
    assert resp.rec_headers.get_header("WARC-Truncated") == "length"
    # the browser hands over decoded bodies: the stored body is the decoded one
    assert blocks[2] == b"x" * MAX_BODY
    assert resp.http_headers.get_header("Content-Encoding") is None
    assert resp.http_headers.get_header("X-Hakapik-Orig-Content-Encoding") == "gzip"
    assert resp.http_headers.get_header("Content-Length") == str(MAX_BODY)


def test_warc_keeps_existing_host_header():
    ex = _ex("https://a.test/", 200, b"", None,
             request_headers=((":authority", "a.test"), ("host", "b.test")))
    req = _records(build_warc([ex], {}))[1][0]
    assert [v for n, v in req.http_headers.headers if n.lower() == "host"] == ["b.test"]


def test_warc_marks_unavailable_body():
    ex = _ex("https://a.test/", 200, b"", None, body_unavailable=True)
    resp = _records(build_warc([ex], {}))[2][0]
    assert resp.rec_headers.get_header("WARC-Truncated") == "unspecified"
    ok = _records(build_warc([_ex("https://a.test/", 200, b"", None)], {}))[2][0]
    assert ok.rec_headers.get_header("WARC-Truncated") is None


def test_warc_failed_request_has_no_response_record():
    ex = _ex("https://a.test/gone", 0, b"", None)
    recs = [r for r, _ in _records(build_warc([ex], {}))]
    assert [r.rec_type for r in recs] == ["warcinfo", "request"]
