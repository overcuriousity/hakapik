"""Worker role: one fetch Job in, one Ed25519-sealed AttemptResult out.

Resolves the name, renders it on mobile and (if live) on desktop with login
click-through, stores every artefact in the blob store. Later a remote node
runs exactly this; in the PoC the head does.
"""

import asyncio
import base64
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Protocol

from hakapik.blobstore import BlobStore
from hakapik.browser import Capture
from hakapik.protocol import (
    AttemptResult,
    BlobRef,
    DnsAnswer,
    Job,
    NodeKey,
    PageResult,
    canonical_json,
    seal,
)
from hakapik.resolve import addresses

WARC = "application/warc+gzip"
PNG = "image/png"
DOM = "text/html; charset=utf-8"
JSON = "application/json"


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


class ResolverLike(Protocol):
    async def resolve(self, fqdn: str, registrable: str) -> tuple[DnsAnswer, ...]: ...


class BrowserLike(Protocol):
    async def capture(self, url: str, profile: str, *,
                      click_through: bool = False) -> Capture: ...


class IpSpacer:
    """Keeps at least interval_s between starts against one IP.

    Each wait reserves the next free slot synchronously (no await between
    reading and writing the slot), so concurrent waits on one IP are spaced.
    Slots already passed are forgotten, so the map holds only IPs with a
    future slot. A waiter cancelled while sleeping keeps its slot: spacing
    can only lengthen, never shorten.
    """

    def __init__(self, interval_s: float | None, *,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], Awaitable[None]] = asyncio.sleep) -> None:
        self.interval_s = interval_s
        self._clock = clock
        self._sleep = sleep
        self._next: dict[str, float] = {}

    async def wait(self, ip: str) -> None:
        if self.interval_s is None:
            return
        now = self._clock()
        for passed in [k for k, t in self._next.items() if t <= now]:
            del self._next[passed]
        start = max(now, self._next.get(ip, now))
        self._next[ip] = start + self.interval_s
        if start > now:
            await self._sleep(start - now)


def _store(bs: BlobStore, blobs: list[BlobRef], profile: str, kind: str,
           data: bytes | None, media_type: str) -> None:
    if data is None:
        return
    blobs.append(BlobRef(profile, kind, bs.put(data, media_type), len(data), media_type))


def _record(bs: BlobStore, cap: Capture, pages: list[PageResult],
            blobs: list[BlobRef]) -> None:
    """Write a capture's blobs, then record its pages and blobs together.

    If any write fails, nothing of this capture is recorded: a recorded page
    always comes with every artefact it produced. Blobs written before the
    failure stay unreferenced in the store until the orphan sweep removes them.
    """
    profile = cap.page.profile
    new_pages, new_blobs = [cap.page], []
    _store(bs, new_blobs, profile, "warc", cap.warc, WARC)
    _store(bs, new_blobs, profile, "screenshot", cap.screenshot, PNG)
    _store(bs, new_blobs, profile, "dom", cap.dom, DOM)
    if cap.cert_chain:
        chain = canonical_json([base64.b64encode(c).decode("ascii")
                                for c in cap.cert_chain])
        _store(bs, new_blobs, profile, "certchain", chain, JSON)
    for click in cap.clicks:
        new_pages.append(click.page)
        _store(bs, new_blobs, click.page.profile, "screenshot", click.screenshot, PNG)
        _store(bs, new_blobs, click.page.profile, "dom", click.dom, DOM)
    pages.extend(new_pages)
    blobs.extend(new_blobs)


async def run_job(job: Job, *, resolver: ResolverLike, browser: BrowserLike,
                  bs: BlobStore, key: NodeKey,
                  egress_address: str | None, spacer: IpSpacer) -> bytes:
    started = _now()
    dns: tuple[DnsAnswer, ...] = ()
    pages: list[PageResult] = []
    blobs: list[BlobRef] = []
    outcome, error = "error", None
    try:
        dns = await resolver.resolve(job.fqdn, job.registrable)
        ips = addresses(dns, job.fqdn)
        if not ips:
            outcome = "dns_fail"
        else:
            await spacer.wait(ips[0])
            mobile = await browser.capture(job.url, "mobile")
            _record(bs, mobile, pages, blobs)
            outcome = mobile.page.outcome
            if outcome == "live":
                desktop = await browser.capture(job.url, "desktop", click_through=True)
                _record(bs, desktop, pages, blobs)
    except Exception as e:
        # A recorded mobile pass (all its blobs written) keeps its outcome; the
        # error says what failed after it.
        mobile_page = next((p for p in pages if p.profile == "mobile"), None)
        outcome = mobile_page.outcome if mobile_page else "error"
        error = repr(e)
    return seal(AttemptResult(
        job_id=job.job_id, step=job.step, node_id=key.node_id,
        egress_address=egress_address, started_at=started, finished_at=_now(),
        outcome=outcome, error=error, dns=tuple(dns), pages=tuple(pages),
        blobs=tuple(blobs)), key)
