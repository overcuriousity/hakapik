"""The exchange recorder behind a browser capture.

A ``Recorder`` watches one browser context: every request the context makes
becomes an ``Exchange`` for the WARC, and each page's main-frame navigations
become its ``Nav`` (URL chain and document responses). It only listens;
``browser.Browser`` decides what to navigate, freeze and capture.
"""

import asyncio
import logging
from datetime import UTC, datetime
from urllib.parse import urldefrag

from playwright.async_api import Error as PlaywrightError

from hakapik.warc import Exchange

log = logging.getLogger(__name__)

MAX_CHAIN = 50
BLANK = ("about:blank", "chrome-error:")


def _safe(fn, *args):
    """An event handler; an exception in it would surface inside playwright's
    dispatcher."""
    def handler(x):
        try:
            fn(*args, x)
        except Exception:
            log.warning("event handler %s failed", fn.__name__, exc_info=True)
    return handler


class Nav:
    """One page's main-frame URL chain and document responses."""

    def __init__(self):
        self.chain: list[str] = []
        self.responses: dict = {}  # URL -> last non-redirect main-frame response
        self.failure: str | None = None  # error of the last failed navigation
        self.unanswered: set = set()  # navigation requests with no response or failure yet

    def add(self, url: str):
        if len(self.chain) < MAX_CHAIN and not url.startswith(BLANK):
            self.chain.append(url)

    def response_for(self, url: str | None):
        """The document response for ``url``, never another document's."""
        return self.responses.get(urldefrag(url).url) if url else None


class Recorder:
    """Collects one context's exchanges and each of its pages' navigations."""

    def __init__(self):
        self.tasks: list[asyncio.Task] = []
        self.blocked: set = set()
        self.navs: dict = {}  # page -> Nav
        self.waiting: list = []  # (handler, event) whose page did not exist yet
        self.open = True

    def watch(self, context):
        context.on("requestfinished", _safe(self._spawn, False))
        context.on("requestfailed", _safe(self._spawn, True))
        context.on("requestfailed", _safe(self._on_failed))
        context.on("request", _safe(self._on_request))
        context.on("response", _safe(self._on_response))
        context.on("page", _safe(self._on_page))

    def nav(self, page) -> Nav:
        """``page``'s navigations; pages the site opens are tracked on their own."""
        if page not in self.navs:
            self.navs[page] = Nav()
            page.on("framenavigated", _safe(self._on_navigated, page))
        return self.navs[page]

    def _main_nav(self, req, handler, event) -> Nav | None:
        """``req``'s page's Nav if it is a main-frame navigation. A popup's
        first request comes before playwright has its page: then ``handler``
        runs again with ``event`` once the page exists."""
        if not req.is_navigation_request():
            return None
        try:
            frame = req.frame
        except PlaywrightError:  # frame not attached to a page yet
            self.waiting.append((handler, event))
            return None
        return self.nav(frame.page) if frame.parent_frame is None else None

    def _on_page(self, page):
        waiting, self.waiting = self.waiting, []
        for handler, event in waiting:  # in arrival order
            handler(event)

    def _on_request(self, req):
        if nav := self._main_nav(req, self._on_request, req):
            nav.add(req.url)  # every hop, HTTP redirects included
            nav.unanswered.add(req)

    def _on_failed(self, req):
        if nav := self._main_nav(req, self._on_failed, req):
            nav.failure = req.failure
            nav.unanswered.discard(req)

    def _on_navigated(self, page, frame):
        # Same-document navigations have no request of their own.
        nav = self.navs[page]
        if frame == page.main_frame and (not nav.chain or nav.chain[-1] != frame.url):
            nav.add(frame.url)

    def _on_response(self, resp):
        if nav := self._main_nav(resp.request, self._on_response, resp):
            nav.unanswered.discard(resp.request)
            if not (300 <= resp.status < 400 and "location" in resp.headers):
                nav.responses[urldefrag(resp.url).url] = resp

    def _spawn(self, failed: bool, req):
        if self.open and req not in self.blocked:
            self.tasks.append(asyncio.ensure_future(self._exchange(req, failed)))

    async def _exchange(self, req, failed: bool) -> Exchange:
        start = req.timing.get("startTime", -1)
        at = datetime.fromtimestamp(start / 1000, UTC) if start > 0 else datetime.now(UTC)
        resp = None if failed else await req.response()
        req_headers = tuple((h["name"], h["value"]) for h in await req.headers_array())
        status, status_text, resp_headers, body, ip = 0, "", (), b"", None
        unavailable = False
        if resp is not None:
            status, status_text = resp.status, resp.status_text
            resp_headers = tuple((h["name"], h["value"]) for h in await resp.headers_array())
            # The body is read whole, but Chromium hands over a body only up
            # to its DevTools buffer (about 15 MB in Chromium 156: playwright
            # enables Network with Chromium's defaults), below warc.MAX_BODY;
            # a larger one fails here and is marked unavailable. So no body
            # over MAX_BODY is ever held (test_a_body_over_max_body_is_never_read).
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
