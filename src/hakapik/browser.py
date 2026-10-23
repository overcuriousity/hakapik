"""Playwright capture of one URL as forensic evidence (spec 5.5).

One Chromium serves many captures; each capture gets a fresh context (no
shared cookies or cache). A capture records the main-frame URL chain, the
final status and server address, a viewport screenshot, the DOM, the served
certificate chain and a WARC of every exchange. With click-through it also
follows up to three login elements one hop deep (PhishIntention found 7% of
phishing only behind such a click). Nothing a page does makes ``capture``
raise or hang: every page-facing step is bounded and failures become the
outcome.
"""

import asyncio
import base64
import functools
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urldefrag, urlsplit

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeout
from playwright.async_api import async_playwright

from hakapik.protocol import PageResult
from hakapik.warc import Exchange, build_warc

log = logging.getLogger(__name__)

# Real Chrome's reduced UAs; "0" is replaced by the running browser's major
# version so the claimed client matches the real one (TLS fingerprint
# included). Client hints are set to agree, see _HINTS and prepare_page.
PROFILES: dict[str, dict] = {
    # viewport and touch from playwright devices["Pixel 7"]
    "mobile": {
        "user_agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/0.0.0.0 Mobile Safari/537.36",
        "viewport": {"width": 412, "height": 839},
        "device_scale_factor": 2.625,
        "is_mobile": True,
        "has_touch": True,
    },
    "desktop": {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/0.0.0.0 Safari/537.36",
        "viewport": {"width": 1366, "height": 768},
        "device_scale_factor": 1,
        "is_mobile": False,
        "has_touch": False,
    },
}

# UA-CH metadata per profile; brands and full versions come from Chromium.
_HINTS: dict[str, dict] = {
    "mobile": {"platform": "Android", "platformVersion": "14.0.0", "architecture": "",
               "model": "K", "mobile": True, "bitness": "", "wow64": False},
    "desktop": {"platform": "Windows", "platformVersion": "15.0.0", "architecture": "x86",
                "model": "", "mobile": False, "bitness": "64", "wow64": False},
}

MAX_CHAIN = 50
MAX_CLICKS = 3
MAX_LABEL = 200
LOGIN_PATTERN = re.compile(r"log ?in|sign ?in|anmelden|einloggen|connexion|se connecter|"
                           r"iniciar sesi[oó]n|accedi|inloggen", re.IGNORECASE)
DRAIN_FLOOR_S = 2.0  # minimum wait for in-flight exchanges, however late
_BLANK = ("about:blank", "chrome-error:")

# Visible login elements in document order: with n < 0 their labels, else
# the n-th element itself (null if there is none).
_LOGIN_JS = """([pattern, n]) => {
  const re = new RegExp(pattern, "i");
  const found = [];
  for (const el of document.querySelectorAll("a, button, input[type=submit], [role=button]")) {
    if (!el.getClientRects().length
        || !el.checkVisibility({checkOpacity: true, checkVisibilityCSS: true})) continue;
    const text = String((el.tagName === "INPUT" ? el.value : el.innerText) || "")
      .replace(/\\s+/g, " ").trim();
    if (re.test(text)) found.push([el, text.slice(0, %d)]);
  }
  if (n < 0) return found.slice(0, %d).map(f => f[1]);
  return n < found.length ? found[n][0] : null;
}""" % (MAX_LABEL, MAX_CLICKS)


@dataclass(frozen=True)
class ClickCapture:
    label: str
    page: PageResult
    screenshot: bytes | None
    dom: bytes | None


@dataclass(frozen=True)
class Capture:
    page: PageResult
    screenshot: bytes | None
    dom: bytes | None
    warc: bytes
    cert_chain: tuple[bytes, ...]
    clicks: tuple[ClickCapture, ...]


def _now() -> datetime:
    return datetime.now(UTC)


def _rfc3339(t: datetime) -> str:
    return t.isoformat(timespec="microseconds").replace("+00:00", "Z")


def classify(error: str | None, status: int | None) -> str:
    if error:
        if "Download is starting" in error:
            return "download"
        if "ERR_NAME_NOT_RESOLVED" in error:
            return "dns_fail"
        if re.search(r"ERR_(CONNECTION_|ADDRESS_|TIMED_OUT)", error):
            return "connect_fail"
        if re.search(r"ERR_(CERT|SSL)_", error):
            return "tls_error"
        if error.startswith("TimeoutError"):
            return "timeout"
        return "error"
    if status is not None and status >= 400:
        return "http_error"
    return "live"


def _error_text(e: Exception) -> str:
    """One line; playwright appends a multi-line call log we do not keep."""
    msg = (e.message if isinstance(e, PlaywrightError) else str(e)).split("\n")[0]
    if isinstance(e, PlaywrightTimeout):
        return f"TimeoutError: {msg}"
    return msg if isinstance(e, PlaywrightError) else f"{type(e).__name__}: {msg}"


def _safe(fn, *args):
    """An event handler; an exception in it would surface inside playwright's
    dispatcher."""
    def handler(x):
        try:
            fn(*args, x)
        except Exception:
            log.warning("event handler %s failed", fn.__name__, exc_info=True)
    return handler


class _Nav:
    """One page's main-frame URL chain and document responses."""

    def __init__(self):
        self.chain: list[str] = []
        self.responses: dict = {}  # URL -> last non-redirect main-frame response
        self.failure: str | None = None  # error of the last failed navigation

    def add(self, url: str):
        if len(self.chain) < MAX_CHAIN and not url.startswith(_BLANK):
            self.chain.append(url)

    def response_for(self, url: str | None):
        """The document response for ``url``, never another document's."""
        return self.responses.get(urldefrag(url).url) if url else None


class _Recorder:
    """Collects one context's exchanges and each of its pages' navigations."""

    def __init__(self):
        self.tasks: list[asyncio.Task] = []
        self.blocked: set = set()
        self.navs: dict = {}  # page -> _Nav
        self.open = True

    def watch(self, context):
        context.on("requestfinished", _safe(self._spawn, False))
        context.on("requestfailed", _safe(self._spawn, True))
        context.on("requestfailed", _safe(self._on_failed))
        context.on("request", _safe(self._on_request))
        context.on("response", _safe(self._on_response))

    def nav(self, page) -> _Nav:
        """``page``'s navigations; pages the site opens are tracked on their own."""
        if page not in self.navs:
            self.navs[page] = _Nav()
            page.on("framenavigated", _safe(self._on_navigated, page))
        return self.navs[page]

    def _main_nav(self, req) -> _Nav | None:
        if not req.is_navigation_request():
            return None
        frame = req.frame
        return self.nav(frame.page) if frame.parent_frame is None else None

    def _on_request(self, req):
        if nav := self._main_nav(req):
            nav.add(req.url)  # every hop, HTTP redirects included

    def _on_failed(self, req):
        if nav := self._main_nav(req):
            nav.failure = req.failure

    def _on_navigated(self, page, frame):
        # Same-document navigations have no request of their own.
        nav = self.navs[page]
        if frame == page.main_frame and (not nav.chain or nav.chain[-1] != frame.url):
            nav.add(frame.url)

    def _on_response(self, resp):
        if ((nav := self._main_nav(resp.request))
                and not (300 <= resp.status < 400 and "location" in resp.headers)):
            nav.responses[urldefrag(resp.url).url] = resp

    def _spawn(self, failed: bool, req):
        if self.open and req not in self.blocked:
            self.tasks.append(asyncio.ensure_future(self._exchange(req, failed)))

    async def _exchange(self, req, failed: bool) -> Exchange:
        start = req.timing.get("startTime", -1)
        at = datetime.fromtimestamp(start / 1000, UTC) if start > 0 else _now()
        resp = None if failed else await req.response()
        req_headers = tuple((h["name"], h["value"]) for h in await req.headers_array())
        status, status_text, resp_headers, body, ip = 0, "", (), b"", None
        unavailable = False
        if resp is not None:
            status, status_text = resp.status, resp.status_text
            resp_headers = tuple((h["name"], h["value"]) for h in await resp.headers_array())
            try:
                body = await resp.body()
            except PlaywrightError:  # redirects have none; evicted bodies are marked
                unavailable = not (300 <= status < 400 and "location" in resp.headers)
            ip = ((await resp.server_addr()) or {}).get("ipAddress")
        return Exchange(url=req.url, method=req.method, request_headers=req_headers,
                        request_body=req.post_data_buffer, status=status,
                        status_text=status_text, response_headers=resp_headers,
                        body=body, server_ip=ip, at=at, body_unavailable=unavailable)

    async def exchanges(self, timeout_s: float) -> list[Exchange]:
        """Stop recording and return what finished within ``timeout_s``."""
        self.open = False
        if not self.tasks:
            return []
        await asyncio.wait(self.tasks, timeout=timeout_s)
        for t in self.tasks:
            t.cancel()
        results = await asyncio.gather(*self.tasks, return_exceptions=True)
        out = []
        for r in results:
            if isinstance(r, Exchange):
                out.append(r)
            elif not isinstance(r, asyncio.CancelledError):
                log.debug("exchange not recorded: %r", r)
        return out


class Browser:
    def __init__(self, *, proxy: str | None, nav_timeout_s: float, settle_s: float = 3.0):
        self.proxy = proxy
        self.nav_timeout_s = nav_timeout_s
        self.settle_s = settle_s
        self.version: str | None = None
        self._pw = None
        self._browser = None
        self._brands: list[dict] = []
        self._full_versions: list[dict] = []

    async def __aenter__(self) -> "Browser":
        self._pw = await async_playwright().start()
        try:
            self._browser = await self._pw.chromium.launch(
                channel="chromium",
                args=["--disable-blink-features=AutomationControlled"],
                proxy={"server": self.proxy} if self.proxy else None)
        except BaseException:
            await self._pw.stop()
            raise
        self.version = self._browser.version
        try:
            self._brands, self._full_versions = await self._chromium_brands()
        except BaseException:
            await self.__aexit__(None, None, None)
            raise
        return self

    async def _chromium_brands(self) -> tuple[list[dict], list[dict]]:
        """Chromium's own brand lists (GREASE included), as navigator.userAgentData
        reports them. userAgentData needs a secure context: a routed https page,
        no network involved."""
        context = await self._browser.new_context()
        try:
            async def blank(route):
                await route.fulfill(body="", content_type="text/html")

            await context.route("https://brands.invalid/", blank)
            page = await context.new_page()
            await page.goto("https://brands.invalid/")
            v = await page.evaluate(
                "navigator.userAgentData.getHighEntropyValues(['fullVersionList'])")
            return v["brands"], v["fullVersionList"]
        finally:
            await context.close()

    async def __aexit__(self, *exc):
        try:
            await self._browser.close()
        finally:
            await self._pw.stop()

    def _profile(self, profile: str) -> dict:
        p = dict(PROFILES[profile])
        major = self.version.split(".")[0]
        p["user_agent"] = re.sub(r"Chrome/[\d.]+", f"Chrome/{major}.0.0.0", p["user_agent"])
        return p

    async def prepare_page(self, context, page, profile: str):
        """CDP session for ``page`` with network events on and client hints
        that agree with the profile's UA. Call before the page navigates.

        Playwright already overrides the UA for every page of the context, but
        its UA-CH metadata has no brands and guesses the rest from the UA.
        """
        cdp = await context.new_cdp_session(page)
        await cdp.send("Network.enable")
        await cdp.send("Emulation.setUserAgentOverride", {
            "userAgent": self._profile(profile)["user_agent"],
            "userAgentMetadata": {"brands": self._brands,
                                  "fullVersionList": self._full_versions,
                                  "fullVersion": self.version, **_HINTS[profile]}})
        return cdp

    @staticmethod
    async def _bounded(coro, deadline: float):
        """Await a page-facing step; None if it fails or runs past ``deadline``.

        All steps after navigation share one deadline, so a page that hangs
        its renderer costs at most nav_timeout_s once, not once per step.
        """
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            coro.close()
            return None
        try:
            return await asyncio.wait_for(coro, remaining)
        except (PlaywrightError, TimeoutError) as e:
            log.debug("capture step failed: %s", e)
            return None

    async def _click(self, context, rec: _Recorder, url: str, profile: str, n: int,
                     label: str, deadline: float) -> ClickCapture:
        """Hop ``n`` (from 0): a new page goes to ``url``, settles, clicks its
        n-th login element and captures where that leads, all by ``deadline``.

        The landing page is frozen, hence the new page. If the click opened a
        popup, the first popup is captured instead of the page. Nothing on the
        clicked page is clicked. A failed click is outcome "error".
        """
        loop = asyncio.get_running_loop()
        started = _now()
        bounded = functools.partial(self._bounded, deadline=deadline)

        def left() -> float:
            return max(deadline - loop.time(), 0.001)

        error = status = server_ip = final_url = None
        load_timeout = clicked = False
        screenshot = dom = None
        nav = _Nav()
        try:
            page = await asyncio.wait_for(context.new_page(), left())
            nav = rec.nav(page)
            popups: list = []
            page.on("popup", lambda p: popups.append(p))
            cdp = await asyncio.wait_for(self.prepare_page(context, page, profile), left())
            try:
                await page.goto(url, wait_until="load", timeout=left() * 1000)
            except PlaywrightTimeout:
                if not nav.responses:
                    raise
            await asyncio.sleep(min(self.settle_s, left()))
            handle = await asyncio.wait_for(
                page.evaluate_handle(_LOGIN_JS, [LOGIN_PATTERN.pattern, n]), left())
            if (element := handle.as_element()) is None:
                raise LookupError(f"login element {n + 1} not found again")
            await asyncio.wait_for(element.click(timeout=left() * 1000), left())
            clicked = True
        except Exception as e:  # anything the page does; the hop's budget included
            error = f"click failed: {_error_text(e)}"
        if clicked:
            target = page
            try:
                await asyncio.wait_for(
                    page.wait_for_load_state("load", timeout=left() * 1000), left())
                await asyncio.sleep(min(self.settle_s, left()))
                if popups:
                    # both or neither: the freeze must reach the captured page
                    target, cdp = popups[0], await asyncio.wait_for(
                        context.new_cdp_session(popups[0]), left())
                    await asyncio.wait_for(
                        target.wait_for_load_state("load", timeout=left() * 1000), left())
            except (PlaywrightError, TimeoutError):
                load_timeout = True  # evidence all the same, as on the landing page
                error = "load timeout"
            nav = rec.nav(target)
            if target.url.startswith("chrome-error:"):
                error = nav.failure or "navigation failed"
                load_timeout = False
            else:
                await bounded(cdp.send("Emulation.setScriptExecutionDisabled", {"value": True}))
                await bounded(cdp.send("Page.stopLoading"))
                screenshot = await bounded(target.screenshot(type="png", timeout=left() * 1000))
            if not target.url.startswith(_BLANK):
                final_url = target.url
            if (resp := nav.response_for(final_url)) is not None:
                status = resp.status
                server_ip = ((await bounded(resp.server_addr())) or {}).get("ipAddress")
            content = await bounded(target.content())
            dom = content.encode("utf-8") if content is not None else None
            outcome = classify(None if load_timeout else error, status)
        else:
            outcome = "error"
        return ClickCapture(label=label, screenshot=screenshot, dom=dom, page=PageResult(
            profile=f"{profile}-click{n + 1}", outcome=outcome, http_status=status,
            final_url=final_url, server_ip=server_ip, redirects=tuple(nav.chain),
            error=error, started_at=_rfc3339(started), finished_at=_rfc3339(_now())))

    async def capture(self, url: str, profile: str, *, click_through: bool = False) -> Capture:
        settings = self._profile(profile)
        started = _now()
        loop = asyncio.get_running_loop()
        context = await self._browser.new_context(**settings, accept_downloads=False)
        rec = _Recorder()
        nav = _Nav()  # replaced by the page's once it exists
        popups: list[asyncio.Task] = []
        error = status = server_ip = final_url = deadline = None
        load_timeout = False
        screenshot = dom = None
        cert_chain: tuple[bytes, ...] = ()
        exchanges: list[Exchange] = []
        clicks: list[ClickCapture] = []
        try:
            async def no_favicon(route):  # spec 5.5: the site never sees one
                rec.blocked.add(route.request)
                await route.abort()

            await context.route("**/favicon.ico", no_favicon)
            rec.watch(context)
            page = await context.new_page()
            nav = rec.nav(page)
            cdp = await self.prepare_page(context, page, profile)
            # Pages the site opens itself get the same client hints (best effort:
            # a popup's first request may leave before this lands). Our own click
            # pages get them twice, with the same values.
            context.on("page", lambda p: popups.append(
                asyncio.ensure_future(self.prepare_page(context, p, profile))))
            try:
                await page.goto(url, wait_until="load", timeout=self.nav_timeout_s * 1000)
            except PlaywrightTimeout as e:
                # Kits often hang on dead trackers: if the document arrived, it is
                # evidence like any other, only "load" never fired.
                load_timeout = bool(nav.responses)
                error = "load timeout" if load_timeout else _error_text(e)
            except Exception as e:  # anything the page or network does
                error = _error_text(e)
            navigated = error is None or load_timeout
            if navigated:
                await asyncio.sleep(self.settle_s)  # JS and meta-refresh redirects
            deadline = loop.time() + self.nav_timeout_s
            bounded = functools.partial(self._bounded, deadline=deadline)
            if navigated:
                # Freeze: a page that keeps navigating never yields a frame or DOM.
                await bounded(cdp.send("Emulation.setScriptExecutionDisabled", {"value": True}))
                await bounded(cdp.send("Page.stopLoading"))
            if not page.url.startswith(_BLANK):
                final_url = page.url
            if (resp := nav.response_for(final_url)) is not None:
                status = resp.status
                addr = await bounded(resp.server_addr())
                server_ip = (addr or {}).get("ipAddress")
            if navigated:
                screenshot = await bounded(page.screenshot(
                    type="png", timeout=self.nav_timeout_s * 1000))
            content = await bounded(page.content())
            dom = content.encode("utf-8") if content is not None else None
            if final_url and urlsplit(final_url).scheme == "https":
                origin = f"https://{urlsplit(final_url).netloc}"
                cert = await bounded(cdp.send("Network.getCertificate", {"origin": origin}))
                cert_chain = tuple(base64.b64decode(c) for c in (cert or {}).get("tableNames", ()))
            labels = []
            if click_through and navigated and dom is not None:
                found = await bounded(page.evaluate(_LOGIN_JS, [LOGIN_PATTERN.pattern, -1]))
                labels = [str(x)[:MAX_LABEL] for x in found[:MAX_CLICKS]] if isinstance(
                    found, list) else []
            for n, label in enumerate(labels):
                # Each hop has its own budget; the drain below gets what is
                # left of the last one.
                deadline = loop.time() + self.nav_timeout_s + self.settle_s
                clicks.append(await self._click(context, rec, url, profile, n, label, deadline))
        except Exception as e:  # a crashed page or target; still a result
            log.warning("capture of %s failed", url, exc_info=True)
            error = error or _error_text(e)
        finally:
            # In-flight exchanges get what is left of the post-navigation
            # deadline, but at least DRAIN_FLOOR_S: their bodies come from the
            # network side, so a hung renderer does not stall them.
            drain = (self.nav_timeout_s if deadline is None
                     else max(deadline - loop.time(), DRAIN_FLOOR_S))
            exchanges = await rec.exchanges(drain)
            for t in popups:
                t.cancel()
            await asyncio.gather(*popups, return_exceptions=True)
            try:
                await context.close()
            except PlaywrightError:
                log.debug("context close failed", exc_info=True)
        finished = _now()
        outcome = classify(None if load_timeout else error, status)
        page_result = PageResult(
            profile=profile, outcome=outcome, http_status=status,
            final_url=final_url, server_ip=server_ip, redirects=tuple(nav.chain),
            error=error, started_at=_rfc3339(started), finished_at=_rfc3339(finished))
        warc = build_warc(exchanges, {
            "software": "hakapik", "url": url, "profile": profile,
            "browser": f"Chromium {self.version}", "user-agent": settings["user_agent"]})
        return Capture(page=page_result, screenshot=screenshot, dom=dom, warc=warc,
                       cert_chain=cert_chain, clicks=tuple(clicks))
