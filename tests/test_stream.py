# SPDX-License-Identifier: Apache-2.0

"""chip-tool-gw's stream client (chip-tool-gw/gateway),
against a scripted fake gateway written from core/mgw_proto.h, through a CONNECT
proxy, and against mgw-host (the gateway's server and relay, on the host). No
device.

Needs a chip-tool-gw build: set CHIP_TOOL_GW_OUT to build.sh's OUT_DIR (with
chip-tool-gw and mgw-host in it). Needs Python 3.13 or later, for ssl's PSK
callbacks. Skips without either. test_dead_stream takes about 65 s."""

from __future__ import annotations

import base64
import hashlib
import hmac
import itertools
import json
import os
from pathlib import Path
import queue
import re
import select
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROTO = (ROOT / "components/esp32_matter_gateway/core/mgw_proto.h").read_text()
OUT = Path(os.environ.get("CHIP_TOOL_GW_OUT", ""))
CLIENT = OUT / "chip-tool-gw"
HOST_BIN = OUT / "mgw-host"


def proto_const(name: str) -> int:
    return int(re.search(rf"\b{name}\s*=\s*(\d+)", PROTO).group(1))


def proto_string(name: str) -> str:
    return re.search(rf'\b{name}\[\]\s*=\s*"([^"]+)"', PROTO).group(1)


ALPN = proto_string("kAlpn")
IDENTITY_NAME = proto_string("kIdentityName")
LABEL = ALPN.split("/")[0]
OP_OPEN, OP_OPEN_ERR, OP_PING, OP_PONG, OP_ERROR, OP_CALL, OP_RESULT, OP_SIGN, OP_SIGNED, OP_EVENT = (
    proto_const(n) for n in ("kOpOpen", "kOpOpenErr", "kOpPing", "kOpPong", "kOpError", "kOpCall", "kOpResult",
                             "kOpSign", "kOpSigned", "kOpEvent"))
ERR_BAD_NODE, ERR_BAD_FRAME, ERR_ATTESTATION, ERR_SIGNER = (
    proto_const(n) for n in ("kErrBadNode", "kErrBadFrame", "kErrAttestation", "kErrSigner"))
EVENT_ICD_ACTIVE = proto_const("kEventIcdActive")

SECRET = bytes(range(32))
CONNECT_FILES = itertools.count()
TMP = Path(tempfile.mkdtemp(prefix="mgw-stream-"))


def tls_psk(secret: bytes) -> bytes:
    return hmac.new(secret, (LABEL + " tls psk").encode(), hashlib.sha256).digest()


def tls_identity(secret: bytes) -> str:
    # the same in every protocol version: only the ALPN says which one
    return IDENTITY_NAME + ":" + hmac.new(secret, (LABEL + " psk id").encode(), hashlib.sha256).digest()[:8].hex()


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def connect_file(name: str, payload: dict) -> str:
    p = TMP / name
    p.write_text(json.dumps(payload))
    p.chmod(0o600)
    return str(p)


class Conn:
    """A TLS connection served from several threads: reads on one, frames
    written whole from any (one SSL object: every call under one lock)."""

    def __init__(self, sock: ssl.SSLSocket):
        self.s = sock
        self.lock = threading.Lock()   # the SSL object
        self.wlock = threading.Lock()  # one frame at a time
        self.buf = b""
        sock.setblocking(False)

    def _recv(self) -> bytes:
        while True:
            with self.lock:
                try:
                    d = self.s.recv(65536)
                    if not d:
                        raise ConnectionError("closed")
                    return d
                except (ssl.SSLWantReadError, BlockingIOError):
                    pass
                except ssl.SSLZeroReturnError:
                    raise ConnectionError("closed")
            select.select([self.s], [], [], 0.2)

    def recv_exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            self.buf += self._recv()
        b, self.buf = self.buf[:n], self.buf[n:]
        return b

    def read(self) -> tuple[int, bytes]:
        (length,) = struct.unpack(">H", self.recv_exact(2))
        frame = self.recv_exact(length)  # [type][op][fields] for control frames
        if frame[0] != 0:
            return -1, frame[1:]  # a Matter frame
        return frame[1], frame[2:]

    def send(self, body: bytes, ftype: int = 0) -> None:
        data = struct.pack(">HB", len(body) + 1, ftype) + body
        with self.wlock:
            while data:
                with self.lock:
                    try:
                        data = data[self.s.send(data):]
                        continue
                    except (ssl.SSLWantWriteError, ssl.SSLWantReadError, BlockingIOError):
                        pass
                select.select([], [self.s], [], 0.2)

    def shutdown(self) -> None:
        socket.socket.shutdown(self.s, socket.SHUT_RDWR)  # the TCP socket under TLS


class FakeGateway:
    """One listening socket; each connection: TLS 1.2 ECDHE-PSK with the PSK
    from secret (mgw_proto.h), then frames.

    on_call(conn, name, params) -> result dict (sent as the call's result) or
    None (never answered). pong=False: ignore the client's pings. tls=False:
    a gateway without TLS (it answers the ClientHello with bad_frame). alpn:
    the protocol the gateway speaks. close_on_open: drop the stream on a
    session request instead of refusing it."""

    def __init__(self, secret: bytes = SECRET, on_call=None, pong: bool = True, close_after_result: bool = False,
                 tls: bool = True, alpn: str = ALPN, close_on_open: bool = False):
        self.secret, self.on_call, self.pong, self.close_after = secret, on_call, pong, close_after_result
        self.tls, self.close_on_open = tls, close_on_open
        self.ls = socket.socket()
        self.ls.bind(("127.0.0.1", 0))
        self.ls.listen()
        self.port = self.ls.getsockname()[1]
        self.conns = 0
        self.opens: list[tuple[int, int]] = []  # (node, cloud lsid)
        self.signed: queue.Queue = queue.Queue()
        self.auth_failures = 0
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.minimum_version = self.ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        self.ctx.set_ciphers("ECDHE-PSK-AES128-CBC-SHA256")
        self.ctx.set_ecdh_curve("prime256v1")
        self.ctx.set_alpn_protocols([alpn])
        self.ctx.options |= ssl.OP_NO_TICKET
        self.ctx.set_psk_server_callback(self.psk)
        threading.Thread(target=self.accept, daemon=True).start()

    def psk(self, identity: str | None) -> bytes:
        if identity == tls_identity(self.secret):
            return tls_psk(self.secret)
        self.auth_failures += 1
        return b""  # no PSK in common: the handshake fails

    def close(self):
        self.ls.close()

    def accept(self):
        while True:
            try:
                s, _ = self.ls.accept()
            except OSError:
                return
            threading.Thread(target=self.serve, args=(s,), daemon=True).start()

    def serve(self, raw: socket.socket):
        if not self.tls:
            raw.recv(5)  # a ClientHello's record header: "frame length" 0x1603
            raw.sendall(bytes([0, 3, 0, OP_ERROR]) + struct.pack(">H", ERR_BAD_FRAME))
            raw.close()
            return
        try:
            raw.settimeout(10)
            c = Conn(self.ctx.wrap_socket(raw, server_side=True))
        except (ssl.SSLError, OSError):
            raw.close()
            return
        self.conns += 1
        try:
            while True:
                op, b = c.read()
                if op == OP_PING and self.pong:
                    c.send(bytes([OP_PONG]) + b)
                elif op == OP_OPEN:
                    req, node, lsid = struct.unpack(">HQH", b[:12])
                    self.opens.append((node, lsid))
                    if self.close_on_open:
                        c.shutdown()
                        return
                    c.send(bytes([OP_OPEN_ERR]) + struct.pack(">HH", req, ERR_BAD_NODE))
                elif op == OP_SIGNED:
                    self.signed.put(b)
                elif op == OP_CALL:
                    req, n = struct.unpack(">HB", b[:3])
                    name, params = b[3:3 + n].decode(), json.loads(b[3 + n:] or b"{}")
                    threading.Thread(target=self.call, args=(c, req, name, params), daemon=True).start()
        except (ConnectionError, OSError, AssertionError):
            pass
        finally:
            c.s.close()

    def call(self, c: Conn, req: int, name: str, params: dict):
        r = self.on_call(c, name, params) if self.on_call else {"ok": True, "payload": {"name": name}}
        if r is None:
            return
        c.send(bytes([OP_RESULT]) + struct.pack(">H", req) + json.dumps(r, separators=(",", ":")).encode())
        if self.close_after:
            time.sleep(0.2)
            try:
                c.shutdown()
            except OSError:
                pass  # the client was quicker

    def sign(self, c: Conn, kind: int, a: int, b: int, fields: list[bytes], timeout: float = 30) -> bytes:
        body = bytes([OP_SIGN]) + struct.pack(">HBQQ", 7, kind, a, b)
        for f in fields:
            body += struct.pack(">H", len(f)) + f
        c.send(body)
        return self.signed.get(timeout=timeout)


class ConnectProxy:
    """An HTTP CONNECT proxy on loopback, standing in for the VM's: a CONNECT
    without the Basic credentials `auth` (user:pass) gets 407."""

    def __init__(self, auth: str):
        self.expect = "Basic " + base64.b64encode(auth.encode()).decode()
        self.ls = socket.socket()
        self.ls.bind(("127.0.0.1", 0))
        self.ls.listen()
        self.port = self.ls.getsockname()[1]
        threading.Thread(target=self.accept, daemon=True).start()

    def close(self):
        self.ls.close()

    def accept(self):
        while True:
            try:
                c, _ = self.ls.accept()
            except OSError:
                return
            threading.Thread(target=self.serve, args=(c,), daemon=True).start()

    def serve(self, c: socket.socket):
        head = b""
        while b"\r\n\r\n" not in head:  # the client sends nothing more before the answer
            d = c.recv(4096)
            if not d:
                c.close()
                return
            head += d
        lines = head.decode(errors="replace").split("\r\n")
        method, target = (lines[0].split() + ["", ""])[:2]
        given = [l.split(":", 1)[1].strip() for l in lines[1:] if l.lower().startswith("proxy-authorization:")]
        if method != "CONNECT":
            c.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
        elif given != [self.expect]:
            c.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                      b"Proxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\n\r\n")
        else:
            host, _, port = target.rpartition(":")
            try:
                up = socket.create_connection((host.strip("[]"), int(port)), timeout=15)
            except (OSError, ValueError):
                c.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            else:
                up.settimeout(None)
                c.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                threading.Thread(target=self.pipe, args=(up, c), daemon=True).start()
                self.pipe(c, up)
                return
        c.close()

    @staticmethod
    def pipe(src: socket.socket, dst: socket.socket):
        try:
            while d := src.recv(65536):
                dst.sendall(d)
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def client(args: str, gw: str, secret: bytes, timeout: float = 60, env: dict | None = None,
           stdin: str | None = None) -> tuple[int, str, float]:
    """chip-tool-gw with a connect file for gw (host:port, or proxy:host:port) and secret."""
    via_proxy = gw.startswith("proxy:")
    conn = connect_file(f"connect-{next(CONNECT_FILES)}.json",
                        {"endpoint": gw.removeprefix("proxy:"), "secret": secret.hex()})
    e = dict(os.environ, MATTER_GW_CONNECT_FILE=conn, **(env or {}))
    e.pop("MATTER_GW", None)
    if via_proxy:
        e["MATTER_GW"] = "proxy"
    for k in ("MATTER_GW_PROXY", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        if k not in (env or {}):
            e.pop(k, None)
    store = TMP / "cloud"
    store.mkdir(exist_ok=True)
    t0 = time.time()
    p = subprocess.run([str(CLIENT), *args.split(), "--storage-directory", str(store)], env=e, input=stdin,
                       capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout + p.stderr, time.time() - t0


def results(out: str) -> list[dict]:
    # interactive mode prefixes lines with terminal escapes
    return [json.loads(l[l.index('{"ok"'):]) for l in out.splitlines() if '{"ok"' in l]


def call_line(out: str) -> dict:
    r = results(out)
    if not r:
        raise AssertionError(f"no result line: {out[-1500:]}")
    return r[0]


def setUpModule():
    if not hasattr(ssl.SSLContext, "set_psk_server_callback"):
        raise unittest.SkipTest("needs Python 3.13+ (ssl PSK callbacks)")
    if not os.environ.get("CHIP_TOOL_GW_OUT"):
        raise unittest.SkipTest("set CHIP_TOOL_GW_OUT to a chip-tool-gw build (chip-tool-gw/build.sh)")
    for b in (CLIENT, HOST_BIN):
        if not os.access(b, os.X_OK):
            raise unittest.SkipTest(f"{b} not built (chip-tool-gw/build.sh)")


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


class Stream(unittest.TestCase):
    def setUp(self):
        self.gw = None

    def tearDown(self):
        if self.gw:
            self.gw.close()

    def start(self, **kw) -> str:
        self.gw = FakeGateway(**kw)
        return f"127.0.0.1:{self.gw.port}"

    def test_call(self):
        gw = self.start(on_call=lambda c, n, p: {"ok": True, "payload": {"name": n, "params": p}})
        rc, out, _ = client('gateway call matter.gateway_status --params {"a":1}', gw, SECRET)
        self.assertEqual(rc, 0, out[-1500:])
        self.assertEqual(call_line(out)["payload"], {"name": "matter.gateway_status", "params": {"a": 1}})
        self.assertNotIn(SECRET.hex(), out)

    def test_error_result_fails_the_command(self):
        gw = self.start(on_call=lambda c, n, p: {"ok": False, "error": {"code": "busy", "message": "x"}})
        rc, out, _ = client("gateway call matter.nodes", gw, SECRET)
        self.assertNotEqual(rc, 0)
        self.assertEqual(call_line(out)["error"]["code"], "busy")

    def test_call_without_an_answer(self):
        # the stream stays up (pongs), the call alone times out and says so
        gw = self.start(on_call=lambda c, n, p: None)
        rc, out, t = client("gateway call matter.nodes --call-timeout 3", gw, SECRET)
        self.assertNotEqual(rc, 0)
        self.assertIn("gateway call matter.nodes: no answer from the gateway in time", out)
        self.assertLess(t, 30)

    def test_stream_dropped_during_a_call(self):
        def on_call(c, name, params):
            c.shutdown()
            return None

        gw = self.start(on_call=on_call)
        rc, out, t = client("gateway call matter.nodes", gw, SECRET)
        self.assertNotEqual(rc, 0)
        self.assertIn("gateway call matter.nodes: the stream dropped", out)
        self.assertLess(t, 30)

    def test_wrong_secret(self):
        gw = self.start()
        rc, out, t = client("gateway call matter.gateway_status", gw, bytes(32))
        self.assertNotEqual(rc, 0)
        self.assertIn("the gateway does not know this secret", out)
        self.assertIn("get the gateway's current endpoint and secret again", out)  # the hint
        self.assertEqual(self.gw.conns, 0)
        self.assertEqual(self.gw.auth_failures, 1)
        self.assertLess(t, 20)

    def test_gateway_without_tls(self):
        gw = self.start(tls=False)
        rc, out, t = client("gateway call matter.gateway_status", gw, SECRET)
        self.assertNotEqual(rc, 0)
        self.assertIn("firmware without TLS", out)
        self.assertIn("update the older one", out)
        self.assertLess(t, 20)

    def test_other_protocol_version(self):
        # a gateway of another version: the same secret and PSK identity, so
        # only the ALPN differs, and the client says so (not "unknown secret")
        gw = self.start(alpn=LABEL + "/99")
        rc, out, _ = client("gateway call matter.gateway_status", gw, SECRET)
        self.assertNotEqual(rc, 0)
        self.assertIn("the gateway speaks another protocol version", out)
        self.assertIn("update the older one", out)  # the hint
        self.assertNotIn("does not know this secret", out)
        self.assertEqual(self.gw.auth_failures, 0)
        self.assertEqual(self.gw.conns, 1)  # TLS itself worked

    def test_bad_settings(self):
        rc, out, _ = client("gateway call matter.gateway_status", "tailcat:x", SECRET)
        self.assertIn("must be host:port", out)
        rc, out, t = client("gateway call matter.gateway_status", f"127.0.0.1:{free_port()}", SECRET)
        self.assertIn("can't connect to the gateway", out)
        self.assertIn("get its current endpoint and secret again and rewrite connect.json", out)  # the hint

    def test_open_refused_fails_fast(self):
        gw = self.start()
        rc, out, t = client("onoff read on-off 77 1", gw, SECRET, timeout=90)
        self.assertNotEqual(rc, 0, out[-1500:])
        self.assertEqual([n for n, _ in self.gw.opens][:1], [77])
        self.assertLess(t, 20, "the lookup hook should fail the session at once")

    def test_stream_dropped_during_a_session_request(self):
        gw = self.start(close_on_open=True)
        rc, out, t = client("onoff read on-off 77 1", gw, SECRET, timeout=90)
        self.assertNotEqual(rc, 0, out[-1500:])
        self.assertIn("session request: the stream dropped", out)
        self.assertLess(t, 20)

    def sign_case(self, kind: int, a: int, b: int, fields: list[bytes]) -> tuple[bytes, str]:
        got: dict = {}

        def on_call(c, name, params):
            got["signed"] = self.gw.sign(c, kind, a, b, fields)
            return {"ok": True, "payload": {}}

        gw = self.start(on_call=on_call)
        rc, out, _ = client("gateway call matter.commission", gw, SECRET)
        self.assertIn("signed", got, out[-1500:])
        return got["signed"], out

    def test_sign_unknown_kind_refused(self):
        signed, out = self.sign_case(99, 1, 1, [b""] * 6)
        req, status = struct.unpack(">HH", signed[:4])
        self.assertEqual((req, status, len(signed)), (7, ERR_SIGNER, 4))
        self.assertIn("unknown request kind 99", out)

    def test_sign_attest_parses_and_refuses_garbage(self):
        # kind 3: VID, PID, then elements, challenge, signature, PAI, DAC, nonce
        fields = [b"\x15\x18", os.urandom(16), os.urandom(64), b"\x30\x00", b"\x30\x00", os.urandom(32)]
        signed, out = self.sign_case(3, 0xFFF1, 0x8000, fields)
        req, status, result = struct.unpack(">HHH", signed)
        self.assertEqual((req, status), (7, ERR_ATTESTATION))
        self.assertNotEqual(result, 0)
        self.assertIn("Gateway attestation: device VID 0xfff1 PID 0x8000", out)
        self.assertIn(f"Gateway attestation: refused ({result})", out)

    def test_sign_device_needs_a_verified_attestation(self):
        signed, out = self.sign_case(1, 5, 1, [b"x", b"y", os.urandom(32), os.urandom(32), b"\x30\x00", b"\x30\x00"])
        self.assertEqual(struct.unpack(">HH", signed), (7, ERR_ATTESTATION))
        self.assertIn("no verified attestation for this device", out)
        self.assertNotIn("Gateway signer: signed", out)

    def test_short_sign_request_answered(self):
        signed, out = self.sign_case(1, 5, 1, [b"x"])  # five fields missing
        self.assertEqual(struct.unpack(">HH", signed), (7, ERR_SIGNER))

    def test_event(self):
        def on_call(c, name, params):
            c.send(bytes([OP_EVENT, EVENT_ICD_ACTIVE]) + struct.pack(">Q", 0x1234))
            c.send(bytes([OP_EVENT, 200]) + struct.pack(">Q", 1))  # unknown kind: ignored
            time.sleep(1)
            return {"ok": True, "payload": {}}

        gw = self.start(on_call=on_call)
        rc, out, _ = client("gateway call matter.gateway_status", gw, SECRET)
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("checked in (sleepy device awake)", out)

    def test_reconnect_after_the_gateway_closes(self):
        gw = self.start(close_after_result=True)
        script = "gateway call matter.gateway_status\ndelay sleep 1000\ngateway call matter.nodes\nquit\n"
        rc, out, _ = client("interactive start", gw, SECRET, stdin=script)
        names = [r["payload"]["name"] for r in results(out)]
        self.assertEqual(names, ["matter.gateway_status", "matter.nodes"], out[-2000:])
        self.assertEqual(self.gw.conns, 2)

    def test_dead_stream(self):
        gw = self.start(on_call=lambda c, n, p: None, pong=False)
        rc, out, t = client("gateway call matter.gateway_status --call-timeout 200", gw, SECRET,
                            timeout=150)
        self.assertNotEqual(rc, 0)
        self.assertIn("no answer for 60 s; dropping the stream", out)
        self.assertTrue(55 < t < 100, t)


class Proxy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gw = FakeGateway()
        cls.proxy = ConnectProxy("agent:pw-123")

    @classmethod
    def tearDownClass(cls):
        cls.proxy.close()
        cls.gw.close()

    def run_via(self, url: str, var: str = "MATTER_GW_PROXY"):
        return client("gateway call matter.gateway_status", f"proxy:127.0.0.1:{self.gw.port}",
                      SECRET, env={var: url})

    def test_connect_with_basic_auth(self):
        rc, out, _ = self.run_via(f"http://agent:pw-123@127.0.0.1:{self.proxy.port}")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("through the CONNECT proxy", out)
        self.assertNotIn("pw-123", out)

    def test_https_proxy_fallback(self):
        rc, out, _ = self.run_via(f"http://agent:pw-123@127.0.0.1:{self.proxy.port}", "HTTPS_PROXY")
        self.assertEqual(rc, 0, out[-1500:])

    def test_407(self):
        rc, out, _ = self.run_via(f"http://agent:nope@127.0.0.1:{self.proxy.port}")
        self.assertNotEqual(rc, 0)
        self.assertIn(f"the CONNECT proxy refused 127.0.0.1:{self.gw.port}: 407", out)
        self.assertIn("HTTPS_PROXY or MATTER_GW_PROXY", out)  # the hint
        self.assertNotIn("nope", out)

    def test_no_proxy_configured(self):
        rc, out, _ = client("gateway call matter.gateway_status", f"proxy:127.0.0.1:{self.gw.port}",
                            SECRET)
        self.assertIn("no CONNECT proxy configured", out)


def run_env(cmd: list[str], env: dict, timeout: float = 60) -> tuple[int, str]:
    """cmd with only env's gateway and proxy settings."""
    e = {k: v for k, v in os.environ.items()
         if not k.startswith("MATTER_GW") and not k.startswith("MGW_") and k.lower() not in ("https_proxy", "http_proxy")}
    e.update(env)
    p = subprocess.run(cmd, env=e, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout + p.stderr


class ConnectFile(unittest.TestCase):
    """MATTER_GW_CONNECT_FILE: the gateway's connect payload gives the endpoint and
    the secret, alone or with MATTER_GW=proxy; and mgw.sh, which uses it."""

    @classmethod
    def setUpClass(cls):
        cls.gw = FakeGateway(on_call=lambda c, n, p: {"ok": True, "payload": {"name": n}})
        cls.proxy = ConnectProxy("agent:pw-123")
        cls.payload = {"endpoint": f"127.0.0.1:{cls.gw.port}", "secret": SECRET.hex(), "client": "v0.1.0"}

    @classmethod
    def tearDownClass(cls):
        cls.proxy.close()
        cls.gw.close()

    def call(self, env: dict) -> tuple[int, str]:
        store = TMP / "cloud"
        store.mkdir(exist_ok=True)
        return run_env([str(CLIENT), "gateway", "call", "matter.gateway_status", "--storage-directory", str(store)],
                       env)

    def test_endpoint_and_secret_from_the_file(self):
        rc, out = self.call({"MATTER_GW_CONNECT_FILE": connect_file("c.json", self.payload)})
        self.assertEqual(rc, 0, out[-1500:])
        self.assertEqual(call_line(out)["payload"], {"name": "matter.gateway_status"})
        self.assertNotIn(SECRET.hex(), out)

    def test_through_the_proxy(self):
        rc, out = self.call({"MATTER_GW_CONNECT_FILE": connect_file("c.json", self.payload), "MATTER_GW": "proxy",
                             "MATTER_GW_PROXY": f"http://agent:pw-123@127.0.0.1:{self.proxy.port}"})
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("through the CONNECT proxy", out)

    def test_gateway_needs_the_file(self):
        # not plain chip-tool behind the user's back
        rc, out = self.call({"MATTER_GW": self.payload["endpoint"]})
        self.assertEqual(rc, 2, out[-1500:])
        self.assertIn("MATTER_GW needs MATTER_GW_CONNECT_FILE", out)

    def test_another_address(self):
        rc, out = self.call({"MATTER_GW_CONNECT_FILE": connect_file("c.json", {**self.payload, "endpoint": "127.0.0.1:1"}),
                             "MATTER_GW": self.payload["endpoint"]})
        self.assertEqual(rc, 0, out[-1500:])

    def test_malformed_file_refused(self):
        for name, text in (("no-secret.json", json.dumps({"endpoint": self.payload["endpoint"]})),
                           ("not-hex.json", json.dumps({**self.payload, "secret": "x" * 64})),
                           ("not-json.json", "endpoint=127.0.0.1:1")):
            (TMP / name).write_text(text)
            rc, out = self.call({"MATTER_GW_CONNECT_FILE": str(TMP / name)})
            self.assertEqual(rc, 2, f"{name}: {out[-1500:]}")
            self.assertIn("MATTER_GW_CONNECT_FILE", out, name)
        rc, out = self.call({"MATTER_GW_CONNECT_FILE": str(TMP / "missing.json")})
        self.assertEqual(rc, 2, out[-1500:])
        self.assertIn("can't read MATTER_GW_CONNECT_FILE", out)

    def test_mgw_sh(self):
        # The release layout: bin/chip-tool-gw, mgw.sh, connect.json; mgw.sh
        # makes no copy of the secret.
        d = TMP / "mgw"
        (d / "bin").mkdir(parents=True, exist_ok=True)
        if not (d / "bin/chip-tool-gw").exists():
            (d / "bin/chip-tool-gw").symlink_to(CLIENT)
        shutil.copy(ROOT / "chip-tool-gw/mgw.sh", d / "mgw.sh")
        connect_file("mgw/connect.json", self.payload)
        for env in ({"MGW_VIA_PROXY": "0"},
                    {"HTTPS_PROXY": f"http://agent:pw-123@127.0.0.1:1", "MGW_PROXY_PORT": str(self.proxy.port)}):
            rc, out = run_env([str(d / "mgw.sh"), "gateway", "call", "matter.gateway_status"], env)
            self.assertEqual(rc, 0, out[-1500:])
            self.assertEqual(call_line(out)["payload"], {"name": "matter.gateway_status"})
            self.assertNotIn(SECRET.hex(), out)
            self.assertNotIn("pw-123", out)
        self.assertEqual(sorted(p.name for p in d.iterdir()), ["bin", "connect.json", "mgw.sh", "storage"])


class NotOffered(unittest.TestCase):
    """Through a gateway, chip-tool's pairing, discover, dcl and groupsettings
    sets don't exist (they can't work through it), in interactive mode too;
    plain chip-tool still has them. Nothing reaches the gateway."""

    @classmethod
    def setUpClass(cls):
        cls.gw = FakeGateway(on_call=lambda c, n, p: {"ok": True, "payload": {}})
        cls.conn = connect_file("not-offered.json", {"endpoint": f"127.0.0.1:{cls.gw.port}", "secret": SECRET.hex()})

    @classmethod
    def tearDownClass(cls):
        cls.gw.close()

    def run_line(self, line: str, gateway: bool = True, stdin: str | None = None) -> tuple[int, str]:
        store = TMP / "cloud"
        store.mkdir(exist_ok=True)
        e = {k: v for k, v in os.environ.items() if not k.startswith("MATTER_GW")}
        if gateway:
            e["MATTER_GW_CONNECT_FILE"] = self.conn
        p = subprocess.run([str(CLIENT), *line.split(), "--storage-directory", str(store)], env=e, input=stdin,
                           capture_output=True, text=True, timeout=60)
        return p.returncode, p.stdout + p.stderr

    def test_sets_not_offered(self):
        for line in ("pairing code 1 MT:Y.K9042C00KA0648G00", "pairing unpair 77", "discover commissionables",
                     "dcl model 65521 32768", "groupsettings add-group 1 x"):
            rc, out = self.run_line(line)
            self.assertNotEqual(rc, 0, f"{line}: {out[-1500:]}")
            self.assertIn(f"Unknown cluster or command set: {line.split()[0]}", out, line)
        self.assertEqual(self.gw.conns, 0)

    def test_not_offered_in_interactive_mode(self):
        rc, out = self.run_line("interactive start", stdin="pairing unpair 77\nquit\n")
        self.assertIn("Unknown cluster or command set: pairing", out, out[-1500:])
        self.assertEqual(self.gw.opens, [])

    def test_offered_without_a_gateway(self):
        # plain chip-tool: pairing exists (and checks its own arguments)
        rc, out = self.run_line("pairing code", gateway=False)
        self.assertEqual(rc, 1, out[-1500:])
        self.assertIn("InitArgs: ", out)
        self.assertNotIn("Unknown cluster or command set", out)


class MgwHost(unittest.TestCase):
    """chip-tool-gw against the gateway's server (core/) in mgw-host."""

    @classmethod
    def setUpClass(cls):
        cls.port = free_port()
        store = TMP / "host"
        store.mkdir(exist_ok=True)
        cls.log = open(TMP / "mgw-host.log", "w+")
        conn = connect_file("host.json", {"endpoint": f"127.0.0.1:{cls.port}", "secret": SECRET.hex()})
        cls.p = subprocess.Popen([str(HOST_BIN), "gateway", "serve", conn, "--stats-interval", "0",
                                  "--storage-directory", str(store)], stdout=cls.log, stderr=subprocess.STDOUT)
        deadline = time.time() + 30
        while "gateway serve: fabric index" not in (TMP / "mgw-host.log").read_text():
            if time.time() > deadline or cls.p.poll() is not None:
                raise RuntimeError("mgw-host did not start: " + (TMP / "mgw-host.log").read_text()[-1500:])
            time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        cls.p.terminate()
        cls.p.wait()
        cls.log.close()

    def server_log(self) -> str:
        self.log.flush()
        return (TMP / "mgw-host.log").read_text(errors="replace")

    def test_handshake_and_call(self):
        # mgw-host relays sessions only: no gateway commands
        rc, out, _ = client("gateway call matter.gateway_status", f"127.0.0.1:{self.port}", SECRET)
        self.assertEqual(call_line(out)["error"]["code"], "unsupported", out[-1500:])

    def test_refuses_a_bad_connect_file(self):
        store = TMP / "host-bad"
        store.mkdir(exist_ok=True)
        for name, text, want in (
                ("host-missing.json", None, "can't read the connect file"),
                ("host-no-port.json", json.dumps({"endpoint": "127.0.0.1", "secret": SECRET.hex()}),
                 "the connect file's endpoint must be host:port"),
                ("host-short.json", json.dumps({"endpoint": "127.0.0.1:1", "secret": "00" * 8}),
                 "the secret in the connect file must be 32-128 hex digits")):
            if text is not None:
                (TMP / name).write_text(text)
            rc, out = run_env([str(HOST_BIN), "gateway", "serve", str(TMP / name), "--stats-interval", "0",
                               "--storage-directory", str(store)], {})
            self.assertNotEqual(rc, 0, f"{name}: {out[-1500:]}")
            self.assertIn(want, out, name)
            self.assertNotIn(SECRET.hex(), out, name)

    def test_wrong_secret(self):
        rc, out, _ = client("gateway call matter.gateway_status", f"127.0.0.1:{self.port}",
                            bytes(32))
        self.assertIn("the gateway does not know this secret", out)
        self.assertIn("a client with an unknown secret", self.server_log())

    def test_slow_handshake_dropped(self):
        # a peer that sends a handshake record a byte a second never finishes
        # TLS: dropped at 10 s
        with socket.create_connection(("127.0.0.1", self.port)) as s:
            s.settimeout(1.2)
            s.send(bytes([0x16, 3, 1, 1, 0]))  # a 256-byte handshake record follows
            t0, closed = time.time(), False
            while time.time() - t0 < 30 and not closed:
                try:
                    s.send(b"\x00")
                    closed = s.recv(64) == b""
                except socket.timeout:
                    pass
                except OSError:
                    closed = True
            self.assertTrue(closed, "still open after 30 s")
            self.assertTrue(8 < time.time() - t0 < 16, time.time() - t0)

    def test_over_the_limit_closed(self):
        # connections that never handshake hold every slot (mgw-host: 4)
        held = [socket.create_connection(("127.0.0.1", self.port)) for _ in range(4)]
        try:
            time.sleep(0.5)
            rc, out, t = client("gateway call matter.gateway_status", f"127.0.0.1:{self.port}",
                                SECRET)
            self.assertNotEqual(rc, 0)
            self.assertIn("closed the connection during the TLS handshake (busy", out)
            self.assertLess(t, 8)
        finally:
            for h in held:
                h.close()
        time.sleep(0.5)
        rc, out, _ = client("gateway call matter.gateway_status", f"127.0.0.1:{self.port}", SECRET)
        self.assertEqual(call_line(out)["error"]["code"], "unsupported", out[-1500:])

    def test_unknown_node_fails(self):
        # mgw-host has no node policy (the gateway refuses at open): the open
        # succeeds and the relay's CASE to the absent node times out
        rc, out, t = client("onoff read on-off 4242 1", f"127.0.0.1:{self.port}", SECRET,
                            timeout=120)
        self.assertNotEqual(rc, 0)
        self.assertIn("Gateway: connected to", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
