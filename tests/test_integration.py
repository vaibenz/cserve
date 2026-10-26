"""End to end tests: start the real server binary and talk to it over TCP.

Usage: python3 tests/test_integration.py ./cserve-asan
Uses only the Python standard library.
"""
import hashlib
import http.client
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

BINARY = os.path.abspath(sys.argv.pop(1) if len(sys.argv) > 1 else "./cserve")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class RawConn:
    """A tiny HTTP client over a raw socket, so tests control every byte."""

    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.buf = b""

    def send(self, data):
        self.sock.sendall(data)

    def _fill(self):
        chunk = self.sock.recv(65536)
        if not chunk:
            raise ConnectionError("closed")
        self.buf += chunk

    def response(self, head_only=False):
        while b"\r\n\r\n" not in self.buf:
            self._fill()
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        lines = head.decode().split("\r\n")
        status = int(lines[0].split()[1])
        headers = {k.lower(): v.strip() for k, v in (l.split(":", 1) for l in lines[1:])}
        length = 0 if head_only else int(headers.get("content-length", 0))
        while len(self.buf) < length:
            self._fill()
        body, self.buf = self.buf[:length], self.buf[length:]
        return status, headers, body

    def is_closed(self, wait=2.0):
        self.sock.settimeout(wait)
        try:
            return self.sock.recv(1) == b""
        except (ConnectionResetError, BrokenPipeError):
            return True
        except socket.timeout:
            return False

    def close(self):
        self.sock.close()


def start_server(root, extra):
    port = free_port()
    proc = subprocess.Popen([BINARY, "-p", str(port), "-r", root, "-t", "2", "-i", "2", "-q"] + extra,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.1).close()
            return port, proc
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("server did not start")


def stop_server(proc):
    proc.terminate()
    _, err = proc.communicate(timeout=10)
    # Any AddressSanitizer or UBSan report lands on stderr.
    if b"ERROR: AddressSanitizer" in err or b"runtime error" in err:
        raise AssertionError("sanitizer report:\n" + err.decode(errors="replace"))
    assert proc.returncode == 0, err.decode(errors="replace")


def get(port, path="/hello.txt"):
    return f"GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode()


class ServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        base = cls.tmp.name
        root = os.path.join(base, "www")
        os.makedirs(os.path.join(root, "docs"))
        with open(os.path.join(root, "index.html"), "w") as f:
            f.write("<h1>home</h1>")
        with open(os.path.join(root, "hello.txt"), "w") as f:
            f.write("hello world\n")
        with open(os.path.join(root, "docs", "index.html"), "w") as f:
            f.write("<h1>docs</h1>")
        with open(os.path.join(root, "space name.txt"), "w") as f:
            f.write("spaced")
        cls.big = os.urandom(8 * 1024 * 1024)
        with open(os.path.join(root, "big.bin"), "wb") as f:
            f.write(cls.big)
        with open(os.path.join(base, "secret.txt"), "w") as f:
            f.write("TOP SECRET")
        os.symlink(os.path.join(base, "secret.txt"), os.path.join(root, "escape.txt"))

        cls.root = root
        cls.port, cls.proc = start_server(root, cls.extra_args())

    @classmethod
    def extra_args(cls):
        return []

    @classmethod
    def tearDownClass(cls):
        stop_server(cls.proc)
        cls.tmp.cleanup()

    def client(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        self.addCleanup(c.close)
        return c

    def raw(self):
        conn = RawConn(self.port)
        self.addCleanup(conn.close)
        return conn

    def test_index_and_file(self):
        c = self.client()
        c.request("GET", "/")
        r = c.getresponse()
        self.assertEqual(r.status, 200)
        self.assertTrue(r.getheader("Content-Type").startswith("text/html"))
        self.assertEqual(r.read(), b"<h1>home</h1>")
        c.request("GET", "/hello.txt")
        r = c.getresponse()
        self.assertEqual((r.status, r.read()), (200, b"hello world\n"))
        self.assertTrue(r.getheader("Date"))

    def test_directory_index_and_percent_decoding(self):
        c = self.client()
        c.request("GET", "/docs/")
        r = c.getresponse()
        self.assertEqual((r.status, r.read()), (200, b"<h1>docs</h1>"))
        c.request("GET", "/docs")
        r = c.getresponse()
        self.assertEqual((r.status, r.read()), (200, b"<h1>docs</h1>"))
        c.request("GET", "/space%20name.txt?cache=1")
        r = c.getresponse()
        self.assertEqual((r.status, r.read()), (200, b"spaced"))

    def test_not_found(self):
        c = self.client()
        c.request("GET", "/nope.txt")
        r = c.getresponse()
        r.read()
        self.assertEqual(r.status, 404)

    def test_traversal_is_blocked(self):
        for path in ["/../secret.txt", "/%2e%2e/secret.txt", "/docs/../../secret.txt", "/escape.txt"]:
            conn = self.raw()
            conn.send(get(self.port, path))
            status, _, body = conn.response()
            self.assertEqual(status, 403, path)
            self.assertNotIn(b"SECRET", body)
            conn.close()

    def test_head_has_no_body(self):
        conn = self.raw()
        conn.send(b"HEAD /hello.txt HTTP/1.1\r\nHost: x\r\n\r\n")
        status, headers, _ = conn.response(head_only=True)
        self.assertEqual((status, headers["content-length"]), (200, "12"))
        conn.send(get(self.port))  # a body leak would corrupt this next response
        status, _, body = conn.response()
        self.assertEqual((status, body), (200, b"hello world\n"))
        conn.close()

    def test_keep_alive_many_requests(self):
        conn = self.raw()
        for _ in range(200):
            conn.send(get(self.port))
            status, headers, body = conn.response()
            self.assertEqual((status, body, headers["connection"]), (200, b"hello world\n", "keep-alive"))
        conn.close()

    def test_pipelining(self):
        conn = self.raw()
        conn.send(get(self.port, "/hello.txt") + get(self.port, "/") + get(self.port, "/missing"))
        self.assertEqual([conn.response()[0] for _ in range(3)], [200, 200, 404])
        conn.close()

    def test_request_split_across_packets(self):
        conn = self.raw()
        for b in get(self.port):
            conn.send(bytes([b]))
            time.sleep(0.001)
        self.assertEqual(conn.response()[0], 200)
        conn.close()

    def test_malformed_request_closes(self):
        conn = self.raw()
        conn.send(b"GARBAGE\r\n\r\n")
        self.assertEqual(conn.response()[0], 400)
        self.assertTrue(conn.is_closed())

    def test_http2_version(self):
        conn = self.raw()
        conn.send(b"GET / HTTP/2.0\r\nHost: x\r\n\r\n")
        self.assertEqual(conn.response()[0], 505)

    def test_method_not_allowed(self):
        conn = self.raw()
        conn.send(b"DELETE /hello.txt HTTP/1.1\r\nHost: x\r\n\r\n")
        status, headers, _ = conn.response()
        self.assertEqual((status, headers["allow"]), (405, "GET, HEAD"))

    def test_header_too_large(self):
        conn = self.raw()
        conn.send(b"GET / HTTP/1.1\r\nHost: x\r\nX-Big: " + b"a" * 10000 + b"\r\n\r\n")
        self.assertEqual(conn.response()[0], 431)

    def test_http10_closes_by_default(self):
        conn = self.raw()
        conn.send(b"GET /hello.txt HTTP/1.0\r\n\r\n")
        status, headers, _ = conn.response()
        self.assertEqual((status, headers["connection"]), (200, "close"))
        self.assertTrue(conn.is_closed())

    def test_large_file_integrity(self):
        c = self.client()
        c.request("GET", "/big.bin")
        r = c.getresponse()
        data = r.read()
        self.assertEqual(r.status, 200)
        self.assertEqual(hashlib.sha256(data).digest(), hashlib.sha256(self.big).digest())

    def test_slow_reader_large_file(self):
        conn = self.raw()
        conn.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        conn.send(get(self.port, "/big.bin"))
        got = 0
        while got < 512 * 1024:  # drip read so the server hits EAGAIN and waits on EPOLLOUT
            got += len(conn.sock.recv(4096))
        conn.close()

    def test_concurrent_clients(self):
        errors = []

        def worker():
            try:
                c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
                for _ in range(25):
                    c.request("GET", "/hello.txt")
                    r = c.getresponse()
                    if (r.status, r.read()) != (200, b"hello world\n"):
                        errors.append("bad response")
                c.close()
            except Exception as e:  # noqa: BLE001
                errors.append(repr(e))

        threads = [threading.Thread(target=worker) for _ in range(64)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])

    def test_slow_but_steady_reader_is_not_reaped(self):
        # Regression test, on its own server with a 1 s idle timeout. A client that downloads 8 MB at
        # about 800 KB/s goes longer than 1 s without the server seeing an event: the kernel send buffer
        # autotunes to about 4 MB and EPOLLOUT only fires again after a large part of it has drained.
        # It used to be closed as idle, about 4 MB in, every time. Now bytes acknowledged keep it alive.
        port, proc = start_server(self.root, ["-t", "1", "-i", "1"])
        self.addCleanup(stop_server, proc)
        conn = RawConn(port)
        self.addCleanup(conn.close)
        conn.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16384)
        conn.send(get(port, "/big.bin"))
        data = b""
        while b"\r\n\r\n" not in data:
            data += conn.sock.recv(16384)
        body = data.split(b"\r\n\r\n", 1)[1]
        while len(body) < len(self.big):
            chunk = conn.sock.recv(16384)
            self.assertTrue(chunk, "closed as idle after %d of %d bytes" % (len(body), len(self.big)))
            body += chunk
            time.sleep(0.02)
        self.assertEqual(hashlib.sha256(body).digest(), hashlib.sha256(self.big).digest())

    def test_stalled_reader_is_still_reaped(self):
        # The other side of the same rule: a client that stops reading mid download acknowledges
        # nothing, so it is closed once the idle timeout passes.
        conn = self.raw()
        conn.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16384)
        conn.send(get(self.port, "/big.bin"))
        conn.sock.recv(16384)
        time.sleep(7.0)  # server runs with -i 2: closed by the second check with nothing acknowledged
        # The server has closed its socket, so anything we send now is answered with a reset.
        conn.sock.settimeout(5.0)
        with self.assertRaises((ConnectionResetError, BrokenPipeError)):
            for _ in range(50):
                conn.sock.send(get(self.port))
                conn.sock.recv(16384)
                time.sleep(0.1)

    def test_idle_connection_is_reaped(self):
        conn = self.raw()
        conn.send(get(self.port))
        conn.response()
        self.assertTrue(conn.is_closed(wait=5.0))  # server runs with -i 2


if __name__ == "__main__":
    unittest.main(verbosity=2)
