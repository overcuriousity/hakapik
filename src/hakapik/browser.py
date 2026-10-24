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
from urllib.parse import urlsplit

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeout
from playwright.async_api import async_playwright

from hakapik.protocol import PageResult
from hakapik.recorder import BLANK, Nav, Recorder
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

MAX_CLICKS = 3
MAX_LABEL = 200
LOGIN_PATTERN = re.compile(r"log ?in|sign ?in|anmelden|einloggen|connexion|se connecter|"
                           r"iniciar sesi[oó]n|accedi|inloggen", re.IGNORECASE)
DRAIN_FLOOR_S = 2.0  # minimum wait for in-flight exchanges, however late

# Visible login elements in document order: with n < 0 their labels, else
# the n-th element if its label is still ``label``, else the first element
# with that label, else null.
_LOGIN_JS = """([pattern, n, label]) => {
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
  if (n < found.length && found[n][1] === label) return found[n][0];
  const same = found.find(f => f[1] === label);
  return same ? same[0] : null;
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
        if error.startswith(("TimeoutError", "load timeout")):
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


class _ClickFailed(Exception):
    """A click hop that cannot click; its message is the reason."""


class Browser:
    LAUNCH_ARGS: tuple[str, ...] = ("--disable-blink-features=AutomationControlled",)

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
                args=list(self.LAUNCH_ARGS),
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

    @classmethod
    async def _freeze(cls, page, cdp, rec: Recorder, deadline: float):
        """Stop ``page`` where it is: a page that keeps navigating never yields
        a frame or DOM. ``cdp`` may be None (then only navigations are held).

        Page.stopLoading cancels only what is scheduled when it lands: between
        a commit and that document's load, a meta refresh is not scheduled yet
        and fires afterwards. So new main-frame navigations are aborted first,
        with ERR_ABORTED, which Chromium drops without an error page.
        """
        bounded = functools.partial(cls._bounded, deadline=deadline)

        async def hold(route):
            req = route.request
            try:
                if req.is_navigation_request() and req.frame == page.main_frame:
                    rec.blocked.add(req)  # our doing, not the site's: kept out of the WARC
                    await route.abort("aborted")
                else:
                    await route.fallback()
            except PlaywrightError:  # page or context gone
                log.debug("navigation hold failed", exc_info=True)

        await bounded(page.route("**/*", hold))
        if cdp is not None:
            await bounded(cdp.send("Emulation.setScriptExecutionDisabled", {"value": True}))
            await bounded(cdp.send("Page.stopLoading"))

    async def _click(self, context, rec: Recorder, url: str, profile: str, n: int,
                     label: str, deadline: float) -> ClickCapture:
        """Hop ``n`` (from 0): a new page goes to ``url``, settles, clicks the
        login element labelled ``label`` (the n-th, unless the page moved it)
        and captures where that leads, all by ``deadline``.

        The landing page is frozen, hence the new page. Navigation steps leave
        a third of nav_timeout_s for the evidence; the replay of ``url`` waits
        for DOMContentLoaded only, at most a third of nav_timeout_s, so a dead
        tracker cannot use up the hop. If the click opened a popup, the first
        one is captured instead of the page. Nothing on the clicked page is
        clicked. A failed click is outcome "error".
        """
        loop = asyncio.get_running_loop()
        started = _now()
        bounded = functools.partial(self._bounded, deadline=deadline)
        reserve = self.nav_timeout_s / 3

        def left() -> float:  # for navigation steps: the evidence keeps its reserve
            return max(deadline - reserve - loop.time(), 0.001)

        notes: list[str] = []  # evidence kept all the same, as on the landing page
        nav_error = status = server_ip = final_url = None
        clicked = False
        screenshot = dom = None
        nav = Nav()
        try:
            page = await asyncio.wait_for(context.new_page(), left())
            nav = rec.nav(page)
            popups: list = []
            page.on("popup", lambda p: popups.append(p))
            cdp = await asyncio.wait_for(self.prepare_page(context, page, profile), left())
            try:
                await page.goto(url, wait_until="domcontentloaded",
                                timeout=min(left(), reserve) * 1000)
            except PlaywrightTimeout:
                if not nav.responses:
                    raise
            await asyncio.sleep(min(self.settle_s, left()))
            handle = await asyncio.wait_for(
                page.evaluate_handle(_LOGIN_JS, [LOGIN_PATTERN.pattern, n, label]), left())
            if (element := handle.as_element()) is None:
                raise _ClickFailed("element changed")
            popups.clear()  # only a popup of the click counts, not the landing's own
            await asyncio.wait_for(element.click(timeout=left() * 1000), left())
            clicked = True
        except _ClickFailed as e:
            nav_error = f"click failed: {e}"
        except Exception as e:  # anything the page does; the hop's budget included
            nav_error = f"click failed: {_error_text(e)}"
        if clicked:
            target = page
            try:
                await asyncio.wait_for(
                    page.wait_for_load_state("load", timeout=left() * 1000), left())
            except (PlaywrightError, TimeoutError):
                notes.append("load timeout")
            await asyncio.sleep(min(self.settle_s, left()))
            if popups:
                target = popups[0]
                try:
                    cdp = await asyncio.wait_for(context.new_cdp_session(target), left())
                except (PlaywrightError, TimeoutError) as e:
                    cdp = None
                    notes.append(f"popup not frozen: {_error_text(e)}")
                try:
                    await asyncio.wait_for(
                        target.wait_for_load_state("load", timeout=left() * 1000), left())
                except (PlaywrightError, TimeoutError):
                    notes.append("popup load timeout")
            nav = rec.nav(target)
            if target.url.startswith("chrome-error:"):
                nav_error = nav.failure or "navigation failed"
            else:
                await self._freeze(target, cdp, rec, deadline)
                screenshot = await bounded(target.screenshot(
                    type="png", timeout=max(deadline - loop.time(), 0.001) * 1000))
            if not target.url.startswith(BLANK):
                final_url = target.url
            elif not nav_error:  # e.g. a popup that never got a document
                nav_error = "no document"
            if (resp := nav.response_for(final_url)) is not None:
                status = resp.status
                server_ip = ((await bounded(resp.server_addr())) or {}).get("ipAddress")
            content = await bounded(target.content())
            dom = content.encode("utf-8") if content is not None else None
            outcome = classify(nav_error, status)
        else:
            outcome = "error"
        error = "; ".join(([nav_error] if nav_error else []) + notes) or None
        return ClickCapture(label=label, screenshot=screenshot, dom=dom, page=PageResult(
            profile=f"{profile}-click{n + 1}", outcome=outcome, http_status=status,
            final_url=final_url, server_ip=server_ip, redirects=tuple(nav.chain),
            error=error, started_at=_rfc3339(started), finished_at=_rfc3339(_now())))

    async def capture(self, url: str, profile: str, *, click_through: bool = False) -> Capture:
        settings = self._profile(profile)
        started = _now()
        loop = asyncio.get_running_loop()
        setup_by = loop.time() + self.nav_timeout_s

        async def setup(coro):
            """A step before navigation: only a wedged browser takes long."""
            try:
                return await asyncio.wait_for(coro, max(setup_by - loop.time(), 0.001))
            except TimeoutError:
                raise TimeoutError("browser setup took over nav_timeout_s") from None

        # Raises if the browser is wedged: there is no page yet to blame.
        context = await setup(self._browser.new_context(**settings, accept_downloads=False))
        rec = Recorder()
        nav = Nav()  # replaced by the page's once it exists
        hint_tasks: list[asyncio.Task] = []  # prepare_page of pages the site opens
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

            await setup(context.route("**/favicon.ico", no_favicon))
            rec.watch(context)
            page = await setup(context.new_page())
            nav = rec.nav(page)
            cdp = await setup(self.prepare_page(context, page, profile))
            # Pages the site opens itself get the same client hints (best effort:
            # a popup's first request may leave before this lands). Our own click
            # pages get them twice, with the same values.
            context.on("page", lambda p: hint_tasks.append(
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
                if page.url.startswith("chrome-error:"):
                    # It moved on to a navigation that failed: that is the outcome.
                    error, load_timeout, navigated = nav.failure or "navigation failed", False, False
            deadline = loop.time() + self.nav_timeout_s
            bounded = functools.partial(self._bounded, deadline=deadline)
            if navigated:
                await self._freeze(page, cdp, rec, deadline)
            if not page.url.startswith(BLANK):
                final_url = page.url
            doc_url = final_url
            if doc_url is None and classify(error, None) == "download" and nav.chain:
                doc_url = nav.chain[-1]  # the page stayed blank; the response is the download's
            if (resp := nav.response_for(doc_url)) is not None:
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
                found = await bounded(
                    page.evaluate(_LOGIN_JS, [LOGIN_PATTERN.pattern, -1, None]))
                labels = [str(x)[:MAX_LABEL] for x in found[:MAX_CLICKS]] if isinstance(
                    found, list) else []
            for n, label in enumerate(labels):
                # Each hop has its own budget; the drain below gets what is
                # left of the last one.
                deadline = loop.time() + self.nav_timeout_s + self.settle_s
                hop_started = _now()
                try:
                    click = await self._click(context, rec, url, profile, n, label, deadline)
                except Exception as e:  # one hop's bug never costs the landing or other hops
                    log.warning("click hop %d of %s failed", n + 1, url, exc_info=True)
                    click = ClickCapture(label=label, screenshot=None, dom=None, page=PageResult(
                        profile=f"{profile}-click{n + 1}", outcome="error", http_status=None,
                        final_url=None, server_ip=None, redirects=(),
                        error=f"click failed: {_error_text(e)}",
                        started_at=_rfc3339(hop_started), finished_at=_rfc3339(_now())))
                clicks.append(click)
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
            for t in hint_tasks:
                t.cancel()
            await asyncio.gather(*hint_tasks, return_exceptions=True)
            try:
                await asyncio.wait_for(context.close(), self.nav_timeout_s)
            except TimeoutError:  # a wedged browser; the context stays open
                log.warning("context of %s did not close within nav_timeout_s", url)
            except PlaywrightError:
                log.debug("context close failed", exc_info=True)
        finished = _now()
        # A load timeout is still "live" when the final URL's document arrived;
        # without that document it is a timeout.
        outcome = classify(None if load_timeout and status is not None else error, status)
        page_result = PageResult(
            profile=profile, outcome=outcome, http_status=status,
            final_url=final_url, server_ip=server_ip, redirects=tuple(nav.chain),
            error=error, started_at=_rfc3339(started), finished_at=_rfc3339(finished))
        warc = build_warc(exchanges, {
            "software": "hakapik", "url": url, "profile": profile,
            "browser": f"Chromium {self.version}", "user-agent": settings["user_agent"]})
        return Capture(page=page_result, screenshot=screenshot, dom=dom, warc=warc,
                       cert_chain=cert_chain, clicks=tuple(clicks))
