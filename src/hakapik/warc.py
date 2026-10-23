"""Gzipped WARC 1.1 from the exchanges a browser saw.

Headers come from the browser's view of each request and response, not from
the wire (HTTP/2 and decoded bodies have no faithful HTTP/1.1 form), and the
warcinfo record says so. Pure: no I/O.
"""

import io
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit

from warcio.statusandheaders import StatusAndHeaders
from warcio.warcwriter import WARCWriter

MAX_BODY = 20 * 1024 * 1024

# The browser hands over decoded bodies, so these would misdescribe what is
# stored; they are kept under a prefixed name and Content-Length is restated.
_FRAMING = ("content-encoding", "transfer-encoding", "content-length")
_ORIG = "X-Hakapik-Orig-"


@dataclass(frozen=True)
class Exchange:
    """One request and its response; ``status == 0`` means no response came.

    ``body_unavailable``: a response arrived but the browser could not hand
    over its body; the record says so instead of storing a silent empty body.
    """
    url: str
    method: str
    request_headers: tuple[tuple[str, str], ...]
    request_body: bytes | None
    status: int
    status_text: str
    response_headers: tuple[tuple[str, str], ...]
    body: bytes
    server_ip: str | None
    at: datetime
    body_unavailable: bool = False


def _date(at: datetime) -> str:
    return at.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _plain(headers) -> list[tuple[str, str]]:
    return [(n, v) for n, v in headers if not n.startswith(":")]


def _request_headers(headers) -> list[tuple[str, str]]:
    """HTTP/2 carries the host as ``:authority``; HTTP/1.1 readers expect Host."""
    plain = _plain(headers)
    authority = next((v for n, v in headers if n == ":authority"), None)
    if authority and not any(n.lower() == "host" for n, _ in plain):
        plain.insert(0, ("Host", authority))
    return plain


def build_warc(exchanges: list[Exchange], info: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    w = WARCWriter(buf, gzip=True, warc_version="WARC/1.1")
    info = {**info, "http-headers": "reconstructed from the browser, not wire bytes"}
    w.write_record(w.create_warcinfo_record("hakapik.warc.gz", info))
    for ex in exchanges:
        date = _date(ex.at)
        parts = urlsplit(ex.url)
        target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        req_body = ex.request_body or b""
        req = w.create_warc_record(
            ex.url, "request", payload=io.BytesIO(req_body), length=len(req_body),
            warc_headers_dict={"WARC-Date": date},
            http_headers=StatusAndHeaders(f"{ex.method} {target} HTTP/1.1",
                                          _request_headers(ex.request_headers),
                                          is_http_request=True))
        w.write_record(req)
        if not ex.status:
            continue
        body = ex.body[:MAX_BODY]
        warc_headers = {"WARC-Date": date,
                        "WARC-Concurrent-To": req.rec_headers.get_header("WARC-Record-ID")}
        if ex.server_ip:
            warc_headers["WARC-IP-Address"] = ex.server_ip
        if len(ex.body) > MAX_BODY:
            warc_headers["WARC-Truncated"] = "length"
        elif ex.body_unavailable:
            warc_headers["WARC-Truncated"] = "unspecified"
        headers = [(_ORIG + n if n.lower() in _FRAMING else n, v)
                   for n, v in _plain(ex.response_headers)]
        headers.append(("Content-Length", str(len(body))))
        w.write_record(w.create_warc_record(
            ex.url, "response", payload=io.BytesIO(body), length=len(body),
            warc_headers_dict=warc_headers,
            http_headers=StatusAndHeaders(f"{ex.status} {ex.status_text}".rstrip(), headers,
                                          protocol="HTTP/1.1")))
    return buf.getvalue()
