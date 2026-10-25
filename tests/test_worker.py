import asyncio
import base64
import json

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
    def __init__(self, mobile="live", exc=None, exc_profile="desktop"):
        self.calls = []
        self.mobile = mobile
        self.exc = exc
        self.exc_profile = exc_profile

    async def capture(self, url, profile, *, click_through=False):
        self.calls.append((url, profile, click_through))
        if self.exc and profile == self.exc_profile:
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


async def test_desktop_exception_keeps_mobile_outcome(tmp_path):
    b = FakeBrowser(exc=RuntimeError("boom"))
    r, bs = await run(tmp_path, FakeResolver(dns()), b)
    assert r.outcome == "live" and r.error == repr(RuntimeError("boom"))
    assert [p.profile for p in r.pages] == ["mobile"] and r.dns
    assert {(x.profile, x.kind) for x in r.blobs} == {
        ("mobile", "warc"), ("mobile", "screenshot"), ("mobile", "dom"),
        ("mobile", "certchain")}
    assert all(bs.path(x.sha256).exists() for x in r.blobs)


async def test_mobile_exception_becomes_error_result(tmp_path):
    b = FakeBrowser(exc=RuntimeError("boom"), exc_profile="mobile")
    r, _ = await run(tmp_path, FakeResolver(dns()), b)
    assert r.outcome == "error" and r.error == repr(RuntimeError("boom"))
    assert r.pages == () and r.blobs == () and r.dns


class FakeClock:
    """A monotonic clock that only moves when a sleep is awaited."""

    def __init__(self):
        self.t = 1000.0
        self.sleeps = []

    def __call__(self):
        return self.t

    async def sleep(self, d):
        self.sleeps.append(round(d, 6))
        await asyncio.sleep(0)
        self.t += d


async def test_ip_spacer_waits():
    c = FakeClock()
    s = IpSpacer(0.2, clock=c, sleep=c.sleep)
    await s.wait("1.1.1.1")
    await s.wait("2.2.2.2")
    assert c.sleeps == []
    await s.wait("1.1.1.1")
    assert c.sleeps == [0.2]
    c.t += 1.0
    await s.wait("1.1.1.1")
    assert c.sleeps == [0.2]


async def test_ip_spacer_concurrent_waits_are_spaced():
    c = FakeClock()
    s = IpSpacer(0.2, clock=c, sleep=c.sleep)
    await asyncio.gather(s.wait("1.1.1.1"), s.wait("1.1.1.1"), s.wait("1.1.1.1"))
    assert c.sleeps == [0.2, 0.4]


async def test_ip_spacer_none_returns_at_once():
    c = FakeClock()
    s = IpSpacer(None, clock=c, sleep=c.sleep)
    await asyncio.gather(s.wait("1.1.1.1"), s.wait("1.1.1.1"))
    assert c.sleeps == []


async def test_ip_spacer_forgets_passed_slots():
    c = FakeClock()
    s = IpSpacer(0.2, clock=c, sleep=c.sleep)
    for i in range(50):
        await s.wait(f"192.0.2.{i}")
    c.t += 0.2
    await s.wait("198.51.100.1")
    assert list(s._next) == ["198.51.100.1"]


async def test_ip_spacer_cancelled_waiter_keeps_its_slot():
    c = FakeClock()
    sleeps = []

    async def blocking_sleep(d):
        sleeps.append(round(d, 6))
        await asyncio.Event().wait()

    s = IpSpacer(0.2, clock=c, sleep=blocking_sleep)
    await s.wait("1.1.1.1")  # first slot, no sleep
    waiter = asyncio.create_task(s.wait("1.1.1.1"))
    await asyncio.sleep(0)
    waiter.cancel()
    await asyncio.gather(waiter, return_exceptions=True)
    late = asyncio.create_task(s.wait("1.1.1.1"))
    await asyncio.sleep(0)
    late.cancel()
    await asyncio.gather(late, return_exceptions=True)
    # The cancelled waiter's slot (0.2..0.4) stays reserved: spacing only lengthens.
    assert sleeps == [0.2, 0.4]


class RecordingSpacer(IpSpacer):
    def __init__(self):
        super().__init__(None)
        self.ips = []

    async def wait(self, ip):
        self.ips.append(ip)


async def test_spacer_waits_on_the_first_address(tmp_path):
    answers = (DnsAnswer("a.example.com", "AAAA", "NOERROR", 60, ("2001:db8::1",), "fake", T),
               DnsAnswer("a.example.com", "A", "NOERROR", 60, ("192.0.2.5", "192.0.2.1"),
                         "fake", T))
    key = NodeKey.load_or_create(tmp_path / "key")
    spacer = RecordingSpacer()
    await run_job(JOB, resolver=FakeResolver(answers), browser=FakeBrowser(),
                  bs=BlobStore(tmp_path / "blobs"), key=key, egress_address=None,
                  spacer=spacer)
    # addresses() lists A before AAAA, in answer order.
    assert spacer.ips == ["192.0.2.5"]


async def test_resolver_exception_becomes_error_result(tmp_path):
    class Broken:
        async def resolve(self, fqdn, registrable):
            raise RuntimeError("resolver down")

    b = FakeBrowser()
    r, _ = await run(tmp_path, Broken(), b)
    assert r.outcome == "error" and r.error == repr(RuntimeError("resolver down"))
    assert r.dns == () and r.pages == () and r.blobs == () and b.calls == []


class FailingStore(BlobStore):
    """A blob store whose put of one given payload raises."""

    def __init__(self, root, fail_on):
        super().__init__(root)
        self.fail_on = fail_on

    def put(self, data, media_type):
        if data == self.fail_on:
            raise OSError("disk full")
        return super().put(data, media_type)


async def _run_store(tmp_path, bs, browser):
    key = NodeKey.load_or_create(tmp_path / "key")
    env = await run_job(JOB, resolver=FakeResolver(dns()), browser=browser, bs=bs, key=key,
                        egress_address=None, spacer=IpSpacer(None))
    return open_envelope(env, {key.node_id: key.public_key}.get)


async def test_failed_mobile_blob_write_records_no_mobile_page(tmp_path):
    # The screenshot write fails after the WARC was written: the mobile pass is
    # not recorded at all, so no page claims an outcome its artefacts miss.
    r = await _run_store(tmp_path, FailingStore(tmp_path / "blobs", b"png-m"), FakeBrowser())
    assert r.outcome == "error" and r.error == repr(OSError("disk full"))
    assert r.pages == () and r.blobs == () and r.dns


async def test_failed_desktop_blob_write_keeps_the_whole_mobile_pass(tmp_path):
    r = await _run_store(tmp_path, FailingStore(tmp_path / "blobs", b"<d>"), FakeBrowser())
    assert r.outcome == "live" and r.error == repr(OSError("disk full"))
    assert [p.profile for p in r.pages] == ["mobile"]
    assert {(x.profile, x.kind) for x in r.blobs} == {
        ("mobile", "warc"), ("mobile", "screenshot"), ("mobile", "dom"),
        ("mobile", "certchain")}


async def test_failed_click_blob_write_drops_the_desktop_pass(tmp_path):
    # The click screenshot is the desktop capture's last write: the whole
    # desktop pass (its page, its click page and their blobs) is dropped.
    r = await _run_store(tmp_path, FailingStore(tmp_path / "blobs", b"png-c"), FakeBrowser())
    assert r.outcome == "live" and r.error == repr(OSError("disk full"))
    assert [p.profile for p in r.pages] == ["mobile"]
    assert {x.profile for x in r.blobs} == {"mobile"}
