"""A small local test site (plain and TLS) and a shared Browser, as pytest fixtures."""

import base64
import datetime
import hashlib
import ipaddress
import ssl
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from hakapik.browser import Browser
from hakapik.warc import MAX_BODY

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
    "/late": (200, [], b'<html><head><meta http-equiv="refresh" content="1;url=/late-done">'
                       b'</head><body>late</body></html>'),
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
    "/stall-login": (200, [], b'<html><body><a href="/login">Sign in</a><img src="/never">'
                              b'</body></html>'),
    # the first visit of a context shows one label, later visits another
    "/relabel": (200, [], b'<html><body><script>document.write(document.cookie.includes("seen")'
                          b' ? \'<a href="/login">Log in</a>\' : \'<a href="/login">Sign in</a>\');'
                          b'document.cookie = "seen=1";</script></body></html>'),
    # later visits swap the order of the two login links
    "/swap": (200, [], b'<html><body><script>const a = \'<a href="/login?via=log">Log in</a>\','
                       b' b = \'<a href="/login?via=sign">Sign in</a>\';'
                       b'document.write(document.cookie.includes("seen") ? b + a : a + b);'
                       b'document.cookie = "seen=1";</script></body></html>'),
    # load never fires and the URL moves without a response of its own
    "/stall-push": (200, [], b'<html><body>stalled push<img src="/never"><script>'
                             b'history.pushState({}, "", "/pushed");</script></body></html>'),
    # loads, then sends itself to a host that does not resolve
    "/to-dead": (200, [], b'<html><body>going<script>setTimeout(() => { location.href = '
                          b'"http://nonexistent.invalid/"; }, 100);</script></body></html>'),
    "/fetch-big": (200, [], b'<html><body>big<script>fetch("/big");</script></body></html>'),
    # a favicon the page asks for itself, as a link and as an image
    "/icons": (200, [], b'<html><head><link rel="icon" href="/favicon.ico"></head>'
                        b'<body>icons<img src="/favicon.ico"></body></html>'),
    "/apk": (200, [("Content-Type", "application/vnd.android.package-archive"),
                   ("Content-Disposition", 'attachment; filename="app.apk"')], b"PK\x03\x04" * 64),
}


class Site:
    def __init__(self, port: int, scheme: str = "http"):
        self.port = port
        self.scheme = scheme
        self.paths_requested: list[str] = []
        self.user_agents: list[str] = []
        self.headers: list[dict[str, str]] = []  # lower-cased names, per request
        self.release = threading.Event()  # lets /never return

    def url(self, path: str) -> str:
        return f"{self.scheme}://127.0.0.1:{self.port}{path}"


def _handler(site: Site):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            site.paths_requested.append(self.path)
            site.user_agents.append(self.headers.get("User-Agent", ""))
            site.headers.append({k.lower(): v for k, v in self.headers.items()})
            # /never: a dead tracker; /hang: a page that never answers. Both
            # hold the request until teardown.
            if self.path in ("/never", "/hang"):
                site.release.wait(30)
                return
            if self.path == "/big":  # one byte over the WARC's cap, made per request
                status, headers, body = 200, [("Content-Type", "application/octet-stream")], \
                    b"x" * (MAX_BODY + 1)
            else:
                status, headers, body = PAGES.get(self.path.split("?")[0],
                                                  (404, [], b"<html>not found</html>"))
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


def _serve(tls: ssl.SSLContext | None = None):
    server = ThreadingHTTPServer(("127.0.0.1", 0), None)
    if tls is not None:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    s = Site(server.server_address[1], "https" if tls else "http")
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


@pytest.fixture
def site():
    yield from _serve()


@dataclass(frozen=True)
class SiteCert:
    der: bytes
    cert_file: str
    key_file: str
    spki_sha256: str  # base64, the form --ignore-certificate-errors-spki-list takes


@pytest.fixture(scope="session")
def site_cert(tmp_path_factory) -> SiteCert:
    """A self-signed certificate for 127.0.0.1, made for this test session."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=7))
            .add_extension(x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .sign(key, hashes.SHA256()))
    d = tmp_path_factory.mktemp("tls")
    (d / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / "key.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    spki = cert.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
    return SiteCert(der=cert.public_bytes(serialization.Encoding.DER),
                    cert_file=str(d / "cert.pem"), key_file=str(d / "key.pem"),
                    spki_sha256=base64.b64encode(hashlib.sha256(spki).digest()).decode())


@pytest.fixture
def tls_site(site_cert):
    """The same site over HTTPS with ``site_cert``."""
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(site_cert.cert_file, site_cert.key_file)
    yield from _serve(tls)


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def browser(site_cert):
    """One Chromium per test session; tests using it need loop_scope="session".

    It trusts ``site_cert`` by its key (a test-only launch argument); every
    other certificate is checked as in production.
    """
    class TrustingBrowser(Browser):
        LAUNCH_ARGS = (*Browser.LAUNCH_ARGS,
                       f"--ignore-certificate-errors-spki-list={site_cert.spki_sha256}")

    b = TrustingBrowser(proxy=None, nav_timeout_s=10, settle_s=1)
    try:
        await b.__aenter__()
    except Exception as e:  # no Chromium installed, no display libs, ...
        pytest.skip(f"cannot launch Chromium: {e}")
    try:
        yield b
    finally:
        await b.__aexit__(None, None, None)
