import gzip
import io
import json
import time

import pytest
from warcio.archiveiterator import ArchiveIterator

from hakapik.browser import PROFILES, Browser, classify

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
