"""A small local test site and a shared Browser, as pytest fixtures."""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import pytest_asyncio

from hakapik.browser import Browser

PAGES = {
    "/": (200, [], b'<html><head><title>Home</title></head><body><h1>Welcome</h1>'
                   b'<a href="/login">Sign in</a></body></html>'),
    "/login": (200, [], b'<html><body><form method="post" action="/login">'
                        b'<input name="user"><input type="password" name="pw">'
                        b'<button>Log in</button></form></body></html>'),
    "/redirect": (302, [("Location", "/")], b""),
    "/js": (200, [], b'<html><body><script>location.href = "/";</script></body></html>'),
    "/loop": (200, [], b'<html><head><meta http-equiv="refresh" content="0;url=/loop">'
                       b'</head><body>loop</body></html>'),
    "/stall": (200, [], b'<html><body>stalled<img src="/never"></body></html>'),
    "/push": (200, [], b'<html><body>push<script>history.pushState({}, "", "/pushed");'
                       b'</script></body></html>'),
    "/uad": (200, [], b'<html><body>wait<script>navigator.userAgentData.getHighEntropyValues('
                      b'["architecture", "model", "platformVersion", "fullVersionList"])'
                      b'.then(v => { document.body.textContent = JSON.stringify(v); });'
                      b'</script></body></html>'),
    "/many": (200, [], b'<html><body>' + b''.join(
        b'<p><a href="/login?n=%d">Log in</a></p>' % i for i in range(5)) + b'</body></html>'),
    "/popup": (200, [], b'<html><body><a href="/login" target="_blank">Login</a></body></html>'),
    "/once": (200, [], b'<html><body><script>if (!document.cookie.includes("seen")) {'
                       b'document.cookie = "seen=1"; document.write(\'<a href="/login">Login</a>\');'
                       b'}</script></body></html>'),
    "/dead": (200, [], b'<html><body><a href="http://nonexistent.invalid/">Sign in</a></body></html>'),
    "/apk": (200, [("Content-Type", "application/vnd.android.package-archive"),
                   ("Content-Disposition", 'attachment; filename="app.apk"')], b"PK\x03\x04" * 64),
}


class Site:
    def __init__(self, port: int):
        self.port = port
        self.paths_requested: list[str] = []
        self.user_agents: list[str] = []
        self.headers: list[dict[str, str]] = []  # lower-cased names, per request
        self.release = threading.Event()  # lets /never return

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"


def _handler(site: Site):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            site.paths_requested.append(self.path)
            site.user_agents.append(self.headers.get("User-Agent", ""))
            site.headers.append({k.lower(): v for k, v in self.headers.items()})
            if self.path == "/never":  # a dead tracker: no answer until teardown
                site.release.wait(30)
                return
            status, headers, body = PAGES.get(self.path.split("?")[0], (404, [], b"<html>not found</html>"))
            self.send_response(status)
            if not any(n == "Content-Type" for n, _ in headers):
                self.send_header("Content-Type", "text/html; charset=utf-8")
            for name, value in headers:
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_POST = do_GET

        def log_message(self, *args):
            pass

    return Handler


@pytest.fixture
def site():
    server = ThreadingHTTPServer(("127.0.0.1", 0), None)
    s = Site(server.server_address[1])
    server.RequestHandlerClass = _handler(s)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield s
    finally:
        s.release.set()
        server.shutdown()
        server.server_close()
        thread.join()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def browser():
    """One Chromium per test module; tests using it need loop_scope="module"."""
    b = Browser(proxy=None, nav_timeout_s=10, settle_s=1)
    try:
        await b.__aenter__()
    except Exception as e:  # no Chromium installed, no display libs, ...
        pytest.skip(f"cannot launch Chromium: {e}")
    try:
        yield b
    finally:
        await b.__aexit__(None, None, None)
