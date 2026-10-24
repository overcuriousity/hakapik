import asyncio
import gzip
import io
import json
import time

import pytest
from warcio.archiveiterator import ArchiveIterator

from hakapik.blobstore import BlobStore
from hakapik.browser import PROFILES, Browser, classify
from hakapik.protocol import DnsAnswer, Job, NodeKey
from hakapik.recorder import Recorder
from hakapik.worker import IpSpacer, run_job

# The shared browser fixture lives on the module loop; tests using it must too.
module_loop = pytest.mark.asyncio(loop_scope="module")


def test_classify_table():
    assert classify("net::ERR_NAME_NOT_RESOLVED at https://x/", None) == "dns_fail"
    assert classify("net::ERR_CONNECTION_REFUSED", None) == "connect_fail"
    assert classify("net::ERR_ADDRESS_UNREACHABLE", None) == "connect_fail"
    assert classify("net::ERR_TIMED_OUT", None) == "connect_fail"
    assert classify("net::ERR_CERT_DATE_INVALID", None) == "tls_error"
    assert classify("net::ERR_SSL_PROTOCOL_ERROR", None) == "tls_error"
    assert classify("TimeoutError: Timeout 10000ms exceeded.", None) == "timeout"
    assert classify("Download is starting", None) == "download"
    assert classify("something odd", None) == "error"
    assert classify(None, 404) == "http_error" and classify(None, 200) == "live"


def test_profiles():
    assert set(PROFILES) == {"mobile", "desktop"}
    assert PROFILES["mobile"]["is_mobile"] and PROFILES["mobile"]["has_touch"]
    assert "Android 10; K" in PROFILES["mobile"]["user_agent"]
    d = PROFILES["desktop"]
    assert d["viewport"] == {"width": 1366, "height": 768}
    assert not d["has_touch"] and "Windows" in d["user_agent"]


@module_loop
async def test_capture_live_page(site, browser):
    c = await browser.capture(site.url("/redirect"), "mobile")
    assert c.page.outcome == "live" and c.page.http_status == 200
    assert c.page.profile == "mobile" and c.page.error is None
    assert c.page.final_url == site.url("/") and site.url("/redirect") in c.page.redirects
    assert c.screenshot.startswith(b"\x89PNG") and b"Sign in" in c.dom
    assert c.page.server_ip == "127.0.0.1"
    assert c.page.started_at.endswith("Z") and c.page.finished_at >= c.page.started_at
    assert c.cert_chain == () and c.clicks == ()
    recs = [(r.rec_type, r.rec_headers.get_header("WARC-Target-URI"),
             r.http_headers.get_statuscode() if r.rec_type == "response" else None)
            for r in ArchiveIterator(io.BytesIO(c.warc))]
    assert ("response", site.url("/redirect"), "302") in recs
    assert ("response", site.url("/"), "200") in recs
    assert b"WARC/1.1" in gzip.decompress(c.warc)
    assert "/favicon.ico" not in site.paths_requested and "/robots.txt" not in site.paths_requested


def _major(browser):
    return browser.version.split(".")[0]


@module_loop
async def test_mobile_profile_claims_matching_browser(site, browser):
    await browser.capture(site.url("/"), "mobile")
    h = site.headers[-1]
    # real Chrome's reduced UA, with client hints that agree with it
    assert "Android 10; K" in h["user-agent"]
    assert f"Chrome/{_major(browser)}.0.0.0 " in h["user-agent"]
    assert h["sec-ch-ua-mobile"] == "?1" and h["sec-ch-ua-platform"] == '"Android"'
    assert f'"Chromium";v="{_major(browser)}"' in h["sec-ch-ua"]
    assert "Google Chrome" not in h["sec-ch-ua"] and "Headless" not in h["sec-ch-ua"]


@module_loop
async def test_mobile_high_entropy_hints(site, browser):
    c = await browser.capture(site.url("/uad"), "mobile")
    text = c.dom.decode().split("<body>")[1].split("</body>")[0]
    v = json.loads(text)
    assert v["model"] == "K" and v["architecture"] == "" and v["platform"] == "Android"
    assert v["mobile"] is True and v["platformVersion"]
    assert {"brand": "Chromium", "version": browser.version} in v["fullVersionList"]


@module_loop
async def test_desktop_profile(site, browser):
    c = await browser.capture(site.url("/"), "desktop")
    assert c.page.outcome == "live" and c.page.profile == "desktop"
    h = site.headers[-1]
    assert "Windows NT 10.0; Win64; x64" in h["user-agent"]
    assert f"Chrome/{_major(browser)}.0.0.0 " in h["user-agent"]
    assert h["sec-ch-ua-mobile"] == "?0" and h["sec-ch-ua-platform"] == '"Windows"'
    c = await browser.capture(site.url("/uad"), "desktop")
    v = json.loads(c.dom.decode().split("<body>")[1].split("</body>")[0])
    assert v["model"] == "" and v["architecture"] == "x86" and v["platform"] == "Windows"


@module_loop
async def test_js_redirect_followed(site, browser):
    c = await browser.capture(site.url("/js"), "mobile")
    assert c.page.outcome == "live"
    assert c.page.final_url == site.url("/")
    assert site.url("/js") in c.page.redirects


@module_loop
async def test_meta_refresh_loop_terminates(site, browser):
    t0 = time.monotonic()
    c = await browser.capture(site.url("/loop"), "mobile")
    assert time.monotonic() - t0 < browser.nav_timeout_s + browser.settle_s + 5
    assert len(c.page.redirects) <= 50
    # the page is frozen after settling, so it still yields evidence
    assert c.screenshot.startswith(b"\x89PNG") and b"loop" in c.dom


@module_loop
async def test_download_is_refused(site, browser):
    c = await browser.capture(site.url("/apk"), "mobile")
    assert c.page.outcome == "download" and c.screenshot is None


@module_loop
async def test_http_error_and_dns_fail(site, browser):
    c = await browser.capture(site.url("/404"), "mobile")
    assert c.page.outcome == "http_error" and c.page.http_status == 404
    c = await browser.capture("http://nonexistent.invalid/", "mobile")
    assert c.page.outcome == "dns_fail" and c.page.http_status is None
    assert c.screenshot is None and "ERR_NAME_NOT_RESOLVED" in c.page.error


@module_loop
async def test_load_timeout_with_committed_document(site, browser):
    # a dead tracker keeps "load" from firing; the document itself arrived
    async with Browser(proxy=None, nav_timeout_s=2, settle_s=0.5) as b:
        c = await b.capture(site.url("/stall"), "mobile")
    assert c.page.outcome == "live" and c.page.http_status == 200
    assert "load timeout" in c.page.error
    assert c.screenshot.startswith(b"\x89PNG") and b"stalled" in c.dom


@module_loop
async def test_status_belongs_to_final_url(site, browser):
    # pushState moves the URL without a response: no other document's status
    c = await browser.capture(site.url("/push"), "mobile")
    assert c.page.final_url == site.url("/pushed")
    assert c.page.http_status is None and c.page.server_ip is None


@module_loop
async def test_click_through_reaches_login_form(site, browser):
    c = await browser.capture(site.url("/"), "desktop", click_through=True)
    assert len(c.clicks) == 1 and c.clicks[0].label.lower() == "sign in"
    click = c.clicks[0]
    assert click.page.final_url == site.url("/login") and b'type="password"' in click.dom
    assert click.page.profile == "desktop-click1" and click.page.outcome == "live"
    assert click.page.http_status == 200 and click.screenshot.startswith(b"\x89PNG")
    # the landing page itself is unchanged, and the click's exchanges share its WARC
    assert c.page.final_url == site.url("/") and b"Welcome" in c.dom
    uris = [r.rec_headers.get_header("WARC-Target-URI")
            for r in ArchiveIterator(io.BytesIO(c.warc)) if r.rec_type == "response"]
    assert site.url("/login") in uris


@module_loop
async def test_click_through_capped_at_three(site, browser):
    c = await browser.capture(site.url("/many"), "desktop", click_through=True)
    assert [k.page.profile for k in c.clicks] == ["desktop-click1", "desktop-click2",
                                                  "desktop-click3"]
    assert [k.page.final_url for k in c.clicks] == [site.url(f"/login?n={i}") for i in range(3)]
    assert all(k.label == "Log in" for k in c.clicks)


@module_loop
async def test_click_through_follows_popup(site, browser):
    c = await browser.capture(site.url("/popup"), "desktop", click_through=True)
    assert len(c.clicks) == 1 and c.clicks[0].page.final_url == site.url("/login")
    assert b'type="password"' in c.clicks[0].dom


@module_loop
async def test_no_click_through_by_default(site, browser):
    c = await browser.capture(site.url("/"), "desktop")
    assert c.clicks == ()
    assert "/login" not in site.paths_requested


@module_loop
async def test_click_through_element_gone_is_error(site, browser):
    # the login link is only there on the first visit of this context
    c = await browser.capture(site.url("/once"), "desktop", click_through=True)
    assert len(c.clicks) == 1 and c.clicks[0].label == "Login"
    assert c.clicks[0].page.outcome == "error"
    assert c.clicks[0].page.error == "click failed: element changed"
    assert c.clicks[0].dom is None


@module_loop
async def test_click_through_to_dead_host(site, browser):
    c = await browser.capture(site.url("/dead"), "desktop", click_through=True)
    assert c.clicks[0].page.outcome == "dns_fail" and c.clicks[0].page.final_url is None
    assert "ERR_NAME_NOT_RESOLVED" in c.clicks[0].page.error


@module_loop
async def test_click_through_after_landing_load_timeout(site, browser):
    # a dead tracker keeps "load" from firing on the landing page and every replay
    async with Browser(proxy=None, nav_timeout_s=2, settle_s=0.5) as b:
        c = await b.capture(site.url("/stall-login"), "desktop", click_through=True)
    assert c.page.outcome == "live" and "load timeout" in c.page.error
    assert c.clicks[0].page.outcome == "live" and c.clicks[0].page.final_url == site.url("/login")
    assert b'type="password"' in c.clicks[0].dom


@module_loop
async def test_click_through_label_changed_is_error(site, browser):
    c = await browser.capture(site.url("/relabel"), "desktop", click_through=True)
    assert c.clicks[0].label == "Sign in" and c.clicks[0].page.outcome == "error"
    assert c.clicks[0].page.error == "click failed: element changed"


@module_loop
async def test_click_through_finds_moved_label(site, browser):
    c = await browser.capture(site.url("/swap"), "desktop", click_through=True)
    assert [(k.label, k.page.final_url) for k in c.clicks] == [
        ("Log in", site.url("/login?via=log")), ("Sign in", site.url("/login?via=sign"))]


@module_loop
async def test_click_hop_failure_is_isolated(site, browser, monkeypatch):
    real = browser._click

    async def flaky(context, rec, url, profile, n, label, deadline):
        if n == 0:
            raise RuntimeError("boom")
        return await real(context, rec, url, profile, n, label, deadline)

    monkeypatch.setattr(browser, "_click", flaky)
    c = await browser.capture(site.url("/many"), "desktop", click_through=True)
    assert c.page.outcome == "live" and c.page.error is None
    assert [k.page.outcome for k in c.clicks] == ["error", "live", "live"]
    assert c.clicks[0].page.error == "click failed: RuntimeError: boom"
    assert c.clicks[0].page.profile == "desktop-click1" and c.clicks[0].label == "Log in"


@module_loop
async def test_freeze_holds_against_later_meta_refresh(site, browser):
    # a refresh already scheduled at the freeze must not fire afterwards
    context = await browser._browser.new_context()
    rec = Recorder()
    try:
        rec.watch(context)
        page = await context.new_page()
        cdp = await browser.prepare_page(context, page, "mobile")
        await page.goto(site.url("/late"), wait_until="load")
        await browser._freeze(page, cdp, rec, asyncio.get_running_loop().time() + 5)
        await asyncio.sleep(2)
        assert page.url == site.url("/late") and "/late-done" not in site.paths_requested
        assert (await page.screenshot(type="png", timeout=5000)).startswith(b"\x89PNG")
    finally:
        await rec.exchanges(1)
        await context.close()


@module_loop
async def test_freeze_stops_a_refresh_loop(site, browser):
    # The /loop flake: Page.stopLoading landing between a commit and the
    # document's load let its 0-second refresh be scheduled after the freeze,
    # so the page kept reloading and the screenshot hung until the deadline.
    # The race hits about every second freeze; five in a row must all hold.
    for _ in range(5):
        context = await browser._browser.new_context()
        rec = Recorder()
        try:
            rec.watch(context)
            page = await context.new_page()
            cdp = await browser.prepare_page(context, page, "mobile")
            await page.goto(site.url("/loop"), wait_until="load")
            await asyncio.sleep(0.3)
            await browser._freeze(page, cdp, rec, asyncio.get_running_loop().time() + 5)
            await asyncio.sleep(0.2)  # anything in flight at the freeze lands
            before = len(site.paths_requested)
            await asyncio.sleep(0.5)
            assert len(site.paths_requested) == before
            assert (await page.screenshot(type="png", timeout=3000)).startswith(b"\x89PNG")
        finally:
            await rec.exchanges(1)
            await context.close()


class _LocalResolver:
    async def resolve(self, fqdn, registrable):
        return (DnsAnswer(fqdn, "A", "NOERROR", 60, ("127.0.0.1",), "local",
                          "2026-10-24T10:00:00Z"),)


@module_loop
async def test_job_timeout_cancels_a_hanging_capture_and_the_browser_still_works(
        site, browser, tmp_path):
    # The fetch loop's bound: asyncio.timeout around run_job. The landing
    # never answers; the cancelled capture drains (up to nav_timeout_s) and
    # closes its context; the same Browser then captures a normal page.
    job = Job(1, 1, "127.0.0.1", "127.0.0.1", 0, site.url("/hang"))
    t = time.monotonic()
    with pytest.raises(TimeoutError):
        async with asyncio.timeout(1.0):
            await run_job(job, resolver=_LocalResolver(), browser=browser,
                          bs=BlobStore(tmp_path / "blobs"),
                          key=NodeKey.load_or_create(tmp_path / "key"),
                          egress_address=None, spacer=IpSpacer(None))
    # job_timeout + at most one drain (nav_timeout_s = 10, settle 1) + margin
    assert time.monotonic() - t < 1.0 + 10 + 1 + 5
    assert "/hang" in site.paths_requested
    assert browser._browser.contexts == []  # the cancelled capture's context is closed
    c = await browser.capture(site.url("/"), "mobile")
    assert c.page.outcome == "live" and c.page.http_status == 200
