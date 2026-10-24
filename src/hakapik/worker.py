"""Worker role: one fetch Job in, one Ed25519-sealed AttemptResult out.

Resolves the name, renders it on mobile and (if live) on desktop with login
click-through, stores every artefact in the blob store. Later a remote node
runs exactly this; in the PoC the head does.
"""

import asyncio
import base64
import time
from datetime import UTC, datetime

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


class IpSpacer:
    """Keeps at least interval_s between starts against one IP.

    Each wait reserves the next free slot synchronously (no await between
    reading and writing the slot), so concurrent waits on one IP are spaced.
    """

    def __init__(self, interval_s: float | None) -> None:
        self.interval_s = interval_s
        self._next: dict[str, float] = {}

    async def wait(self, ip: str) -> None:
        if self.interval_s is None:
            return
        now = time.monotonic()
        start = max(now, self._next.get(ip, now))
        self._next[ip] = start + self.interval_s
        if start > now:
            await asyncio.sleep(start - now)


def _store(bs: BlobStore, blobs: list[BlobRef], profile: str, kind: str,
           data: bytes | None, media_type: str) -> None:
    if data is None:
        return
    blobs.append(BlobRef(profile, kind, bs.put(data, media_type), len(data), media_type))


def _record(bs: BlobStore, cap: Capture, pages: list[PageResult],
            blobs: list[BlobRef]) -> None:
    profile = cap.page.profile
    pages.append(cap.page)
    _store(bs, blobs, profile, "warc", cap.warc, WARC)
    _store(bs, blobs, profile, "screenshot", cap.screenshot, PNG)
    _store(bs, blobs, profile, "dom", cap.dom, DOM)
    if cap.cert_chain:
        chain = canonical_json([base64.b64encode(c).decode("ascii")
                                for c in cap.cert_chain])
        _store(bs, blobs, profile, "certchain", chain, JSON)
    for click in cap.clicks:
        pages.append(click.page)
        _store(bs, blobs, click.page.profile, "screenshot", click.screenshot, PNG)
        _store(bs, blobs, click.page.profile, "dom", click.dom, DOM)


async def run_job(job: Job, *, resolver, browser, bs: BlobStore, key: NodeKey,
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
        outcome, error = "error", repr(e)
    return seal(AttemptResult(
        job_id=job.job_id, step=job.step, node_id=key.node_id,
        egress_address=egress_address, started_at=started, finished_at=_now(),
        outcome=outcome, error=error, dns=tuple(dns), pages=tuple(pages),
        blobs=tuple(blobs)), key)
