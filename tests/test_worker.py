import asyncio
import base64
import json
import time

from hakapik.blobstore import BlobStore
from hakapik.browser import Capture, ClickCapture
from hakapik.protocol import DnsAnswer, Job, NodeKey, PageResult, open_envelope
from hakapik.worker import IpSpacer, run_job

T = "2026-10-24T10:00:00.000000Z"
JOB = Job(job_id=7, candidate_id=3, fqdn="a.example.com", registrable="example.com",
          step=0, url="https://a.example.com/")


def dns(rcode="NOERROR", ips=("192.0.2.1",)):
    return (DnsAnswer("a.example.com", "A", rcode, 60, tuple(ips), "fake", T),)


class FakeResolver:
    def __init__(self, answers):
        self.answers = answers

    async def resolve(self, fqdn, registrable):
        return self.answers


def page(profile, outcome="live"):
    return PageResult(profile, outcome, 200 if outcome == "live" else 500,
                      "https://a.example.com/", "192.0.2.1", (), None, T, T)


class FakeBrowser:
    def __init__(self, mobile="live", exc=None):
        self.calls = []
        self.mobile = mobile
        self.exc = exc

    async def capture(self, url, profile, *, click_through=False):
        self.calls.append((url, profile, click_through))
        if self.exc and profile == "desktop":
            raise self.exc
        if profile == "mobile":
            return Capture(page(profile, self.mobile), b"png-m", b"<m>", b"warc-m",
                           (b"der1", b"der2"), ())
        click = ClickCapture("Log in", page("desktop-click1"), b"png-c", None)
        return Capture(page(profile), b"png-d", b"<d>", b"warc-d", (), (click,))


async def run(tmp_path, resolver, browser):
    key = NodeKey.load_or_create(tmp_path / "key")
    bs = BlobStore(tmp_path / "blobs")
    env = await run_job(JOB, resolver=resolver, browser=browser, bs=bs, key=key,
                        egress_address="198.51.100.9", spacer=IpSpacer(None))
    return open_envelope(env, {key.node_id: key.public_key}.get), bs


async def test_dns_fail_skips_browser(tmp_path):
    b = FakeBrowser()
    r, _ = await run(tmp_path, FakeResolver(dns("NXDOMAIN", ())), b)
    assert r.outcome == "dns_fail" and b.calls == [] and r.pages == () and r.blobs == ()
    assert r.dns and r.job_id == 7 and r.egress_address == "198.51.100.9"


async def test_live_runs_desktop_with_clicks(tmp_path):
    b = FakeBrowser()
    r, bs = await run(tmp_path, FakeResolver(dns()), b)
    assert b.calls == [(JOB.url, "mobile", False), (JOB.url, "desktop", True)]
    assert r.outcome == "live" and r.error is None
    assert [p.profile for p in r.pages] == ["mobile", "desktop", "desktop-click1"]
    got = {(x.profile, x.kind) for x in r.blobs}
    assert got == {("mobile", "warc"), ("mobile", "screenshot"), ("mobile", "dom"),
                   ("mobile", "certchain"), ("desktop", "warc"),
                   ("desktop", "screenshot"), ("desktop", "dom"),
                   ("desktop-click1", "screenshot")}
    assert all(bs.path(x.sha256).stat().st_size == x.size for x in r.blobs)
    cert = next(x for x in r.blobs if x.kind == "certchain")
    assert cert.media_type == "application/json"
    assert json.loads(bs.path(cert.sha256).read_bytes()) == [
        base64.b64encode(b"der1").decode(), base64.b64encode(b"der2").decode()]
    media = {x.kind: x.media_type for x in r.blobs}
    assert media["warc"] == "application/warc+gzip" and media["screenshot"] == "image/png"
    assert media["dom"] == "text/html; charset=utf-8"


async def test_non_live_mobile_skips_desktop(tmp_path):
    b = FakeBrowser(mobile="http_error")
    r, _ = await run(tmp_path, FakeResolver(dns()), b)
    assert r.outcome == "http_error" and [p.profile for p in r.pages] == ["mobile"]
    assert len(b.calls) == 1


async def test_browser_exception_becomes_error_result(tmp_path):
    b = FakeBrowser(exc=RuntimeError("boom"))
    r, bs = await run(tmp_path, FakeResolver(dns()), b)
    assert r.outcome == "error" and r.error == repr(RuntimeError("boom"))
    assert [p.profile for p in r.pages] == ["mobile"] and r.dns
    assert {(x.profile, x.kind) for x in r.blobs} >= {("mobile", "warc")}
    assert all(bs.path(x.sha256).exists() for x in r.blobs)


async def test_ip_spacer_waits():
    s = IpSpacer(0.2)
    t = time.monotonic()
    await s.wait("1.1.1.1")
    await s.wait("2.2.2.2")
    assert time.monotonic() - t < 0.1
    await s.wait("1.1.1.1")
    assert time.monotonic() - t >= 0.2


async def test_ip_spacer_concurrent_waits_are_spaced():
    s = IpSpacer(0.2)
    done = []

    async def w():
        await s.wait("1.1.1.1")
        done.append(time.monotonic())

    t = time.monotonic()
    await asyncio.gather(w(), w(), w())
    done.sort()
    assert done[1] - done[0] >= 0.19 and done[2] - done[1] >= 0.19
    assert done[2] - t >= 0.39


async def test_ip_spacer_none_returns_at_once():
    s = IpSpacer(None)
    t = time.monotonic()
    await asyncio.gather(s.wait("1.1.1.1"), s.wait("1.1.1.1"))
    assert time.monotonic() - t < 0.05
