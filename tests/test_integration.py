"""End to end tests: start the real server binary and talk to it over TCP.

Usage: python3 tests/test_integration.py ./cserve-asan
Uses only the Python standard library.
"""
import email.utils
import hashlib
import http.client
import os
import resource
import socket
import ssl
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

    def is_gone(self, wait=2.0):
        """Closed by the server, after whatever it sent last (a 408, say) has been read."""
        self.sock.settimeout(wait)
        try:
            while self.sock.recv(65536):
                pass
            return True
        except (ConnectionResetError, BrokenPipeError):
            return True
        except socket.timeout:
            return False

    def close(self):
        self.sock.close()


def start_server(root, extra, max_fds=None):
    port = free_port()
    limit = (lambda: resource.setrlimit(resource.RLIMIT_NOFILE, (max_fds, max_fds))) if max_fds else None
    proc = subprocess.Popen([BINARY, "-p", str(port), "-r", root, "-t", "2", "-i", "2", "-q"] + extra,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=limit)
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

    def fetch(self, path, **headers):
        c = self.client()
        c.request("GET", path, headers=headers)
        r = c.getresponse()
        return r, r.read()

    def test_validators_on_every_file(self):
        r, _ = self.fetch("/hello.txt")
        self.assertEqual(r.getheader("Accept-Ranges"), "bytes")
        self.assertTrue(r.getheader("ETag").startswith('"'))
        mtime = os.stat(os.path.join(self.root, "hello.txt")).st_mtime
        self.assertEqual(r.getheader("Last-Modified"), email.utils.formatdate(int(mtime), usegmt=True))

    def test_range_forms(self):
        cases = {"bytes=0-4": (0, 4), "bytes=6-": (6, 11), "bytes=-3": (9, 11), "bytes=6-1000": (6, 11)}
        for spec, (a, b) in cases.items():
            r, body = self.fetch("/hello.txt", Range=spec)
            self.assertEqual(r.status, 206, spec)
            self.assertEqual(body, b"hello world\n"[a:b + 1], spec)
            self.assertEqual(r.getheader("Content-Range"), "bytes %d-%d/12" % (a, b), spec)

    def test_range_in_a_large_file(self):
        a, b = 3_000_001, 7_654_320
        r, body = self.fetch("/big.bin", Range="bytes=%d-%d" % (a, b))
        self.assertEqual(r.status, 206)
        self.assertEqual(body, self.big[a:b + 1])

    def test_unsatisfiable_range(self):
        r, _ = self.fetch("/hello.txt", Range="bytes=12-")
        self.assertEqual(r.status, 416)
        self.assertEqual(r.getheader("Content-Range"), "bytes */12")

    def test_ignored_ranges_send_the_whole_file(self):
        for spec in ("bytes=0-1,4-5", "bytes=5-2", "lines=1-2", "bytes=x"):
            r, body = self.fetch("/hello.txt", Range=spec)
            self.assertEqual((r.status, body), (200, b"hello world\n"), spec)

    def test_if_none_match(self):
        r, _ = self.fetch("/hello.txt")
        etag = r.getheader("ETag")
        r, body = self.fetch("/hello.txt", **{"If-None-Match": etag})
        self.assertEqual((r.status, body), (304, b""))
        self.assertEqual(r.getheader("ETag"), etag)
        r, _ = self.fetch("/hello.txt", **{"If-None-Match": '"stale", W/' + etag})
        self.assertEqual(r.status, 304)  # weak comparison, any entry in the list
        r, _ = self.fetch("/hello.txt", **{"If-None-Match": '"stale"'})
        self.assertEqual(r.status, 200)

    def test_if_modified_since(self):
        r, _ = self.fetch("/hello.txt")
        lm = r.getheader("Last-Modified")
        self.assertEqual(self.fetch("/hello.txt", **{"If-Modified-Since": lm})[0].status, 304)
        earlier = email.utils.formatdate(email.utils.parsedate_to_datetime(lm).timestamp() - 1, usegmt=True)
        self.assertEqual(self.fetch("/hello.txt", **{"If-Modified-Since": earlier})[0].status, 200)
        self.assertEqual(self.fetch("/hello.txt", **{"If-Modified-Since": "yesterday"})[0].status, 200)
        # If-None-Match takes precedence: a stale ETag means 200 even with a current date.
        r, _ = self.fetch("/hello.txt", **{"If-None-Match": '"stale"', "If-Modified-Since": lm})
        self.assertEqual(r.status, 200)

    def test_if_range(self):
        r, _ = self.fetch("/hello.txt")
        etag, lm = r.getheader("ETag"), r.getheader("Last-Modified")
        self.assertEqual(self.fetch("/hello.txt", Range="bytes=0-4", **{"If-Range": etag})[0].status, 206)
        self.assertEqual(self.fetch("/hello.txt", Range="bytes=0-4", **{"If-Range": lm})[0].status, 206)
        r, body = self.fetch("/hello.txt", Range="bytes=0-4", **{"If-Range": '"old"'})
        self.assertEqual((r.status, body), (200, b"hello world\n"))  # changed since: whole file

    def test_etag_changes_when_the_file_does(self):
        path = os.path.join(self.root, "changing.txt")
        with open(path, "w") as f:
            f.write("one")
        e1 = self.fetch("/changing.txt")[0].getheader("ETag")
        with open(path, "w") as f:
            f.write("two")  # same size, so only the nanosecond mtime tells them apart
        os.utime(path, ns=(os.stat(path).st_atime_ns, os.stat(path).st_mtime_ns + 1))
        r, body = self.fetch("/changing.txt", **{"If-None-Match": e1})
        self.assertEqual((r.status, body), (200, b"two"))

    def test_head_with_range(self):
        c = self.client()
        c.request("HEAD", "/big.bin", headers={"Range": "bytes=10-19"})
        r = c.getresponse()
        self.assertEqual((r.status, r.getheader("Content-Length"), r.read()), (206, "10", b""))

    def test_resume_a_download_over_keep_alive(self):
        # How a download manager resumes: the first part, then the rest, on one connection.
        c = self.client()
        c.request("GET", "/big.bin", headers={"Range": "bytes=0-1048575"})
        r = c.getresponse()
        part1, etag = r.read(), r.getheader("ETag")
        c.request("GET", "/big.bin", headers={"Range": "bytes=1048576-", "If-Range": etag})
        part2 = c.getresponse().read()
        self.assertEqual(part1 + part2, self.big)

    def test_idle_connection_is_reaped(self):
        conn = self.raw()
        conn.send(get(self.port))
        conn.response()
        self.assertTrue(conn.is_closed(wait=5.0))  # server runs with -i 2


class AttackTest(unittest.TestCase):
    """Resource exhaustion: Slowloris, slow reads, and running out of connections.

    The server runs with a 2 s header deadline, a 30 s idle timeout (so only the
    defence under test can close a connection), one worker and at most 64
    connections.
    """

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = os.path.join(cls.tmp.name, "www")
        os.makedirs(root)
        with open(os.path.join(root, "hello.txt"), "w") as f:
            f.write("hello world\n")
        with open(os.path.join(root, "big.bin"), "wb") as f:
            f.write(os.urandom(8 * 1024 * 1024))
        cls.port, cls.proc = start_server(root, ["-t", "1", "-i", "30", "-H", "2", "-m", "64"])

    @classmethod
    def tearDownClass(cls):
        stop_server(cls.proc)
        cls.tmp.cleanup()

    def raw(self):
        conn = RawConn(self.port)
        self.addCleanup(conn.close)
        return conn

    def served(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            c.request("GET", "/hello.txt")
            r = c.getresponse()
            return r.status == 200 and r.read() == b"hello world\n"
        finally:
            c.close()

    def test_slowloris_gets_408_at_the_deadline(self):
        # One header byte every 0.25 s keeps the connection busy forever as far as an idle
        # timeout can tell. The head deadline does not move, so it ends at about 2 s.
        conn = self.raw()
        conn.send(b"GET /hello.txt HTTP/1.1\r\nHost: a\r\n")
        start = time.time()
        with self.assertRaises((ConnectionError, BrokenPipeError)):
            for _ in range(40):
                conn.send(b"X")
                time.sleep(0.25)
        self.assertLess(time.time() - start, 4.5)

    def test_slowloris_response_is_408(self):
        conn = self.raw()
        conn.send(b"GET /hello.txt HTTP/1.1\r\nHost: a\r\n")
        time.sleep(3.5)
        status, _, _ = conn.response()
        self.assertEqual(status, 408)
        self.assertTrue(conn.is_closed())

    def test_silent_connection_is_closed_at_the_deadline(self):
        conn = self.raw()
        start = time.time()
        self.assertEqual(conn.response()[0], 408)
        self.assertTrue(conn.is_closed())
        self.assertLess(time.time() - start, 4.0)

    def test_deadline_is_per_request_not_per_connection(self):
        # A keep alive client that pauses between requests is governed by the idle timeout:
        # each new head gets a fresh 2 s from its first byte.
        conn = self.raw()
        for _ in range(3):
            conn.send(get(self.port))
            self.assertEqual(conn.response()[0], 200)
            time.sleep(2.5)

    def test_attack_does_not_stop_service(self):
        # 50 Slowloris connections at once: real clients are still served throughout, and every
        # attacker is gone shortly after the deadline.
        attackers = [RawConn(self.port) for _ in range(50)]
        for a in attackers:
            self.addCleanup(a.close)
            a.send(b"GET / HTTP/1.1\r\n")
        for _ in range(6):
            for a in attackers:
                try:
                    a.send(b"X")
                except OSError:
                    pass
            self.assertTrue(self.served())
            time.sleep(0.5)
        self.assertTrue(all(a.is_gone(wait=2.0) for a in attackers))

    def test_full_server_evicts_the_longest_idle_connection(self):
        idle = []
        for _ in range(64):  # fill every slot with an idle keep alive connection
            conn = self.raw()
            conn.send(get(self.port))
            self.assertEqual(conn.response()[0], 200)
            idle.append(conn)
            time.sleep(0.002)
        self.assertTrue(self.served())  # room is made rather than the newcomer refused
        self.assertTrue(idle[0].is_closed(wait=2.0))  # the oldest one went
        self.assertFalse(idle[-1].is_closed(wait=0.2))

    def test_full_server_of_busy_connections_refuses(self):
        # When every slot holds a connection mid request, nothing can be evicted: the newcomer is
        # refused, and served again once the deadline has cleared the attackers.
        busy = []
        for _ in range(64):
            conn = self.raw()
            conn.send(b"GET / HTTP/1.1\r\n")
            busy.append(conn)
        time.sleep(0.2)
        with self.assertRaises((ConnectionError, OSError, http.client.HTTPException)):
            self.served()
        time.sleep(2.5)
        self.assertTrue(self.served())

    def test_out_of_descriptors_does_not_spin(self):
        # With 64 descriptors and 100 clients the server runs out. The listener is level triggered,
        # so a naive accept loop would be woken for the waiting connections forever, at 100% CPU.
        port, proc = start_server(self.tmp.name + "/www", ["-t", "1"], max_fds=64)
        self.addCleanup(stop_server, proc)

        def cpu_ticks():
            with open("/proc/%d/stat" % proc.pid) as f:
                fields = f.read().rsplit(")", 1)[1].split()
            return int(fields[11]) + int(fields[12])

        held = [socket.create_connection(("127.0.0.1", port), timeout=5) for _ in range(100)]
        time.sleep(0.5)
        before = cpu_ticks()
        time.sleep(2.0)
        used = (cpu_ticks() - before) / os.sysconf("SC_CLK_TCK") / 2.0
        self.assertLess(used, 0.2, "server used %.0f%% CPU while out of descriptors" % (used * 100))
        for s in held:
            s.close()
        time.sleep(0.5)
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        self.addCleanup(c.close)
        c.request("GET", "/hello.txt")
        self.assertEqual(c.getresponse().status, 200)  # and it recovers once they are released

    def test_slow_read_is_reaped(self):
        # The reverse attack: request a large file and take it a trickle at a time, 4 KB every 6 s
        # (under 700 B/s), below the 1 KB/s floor. The small receive window is set before
        # connecting, so every 4 KB read reopens it and the server sees new bytes acknowledged
        # within each 8 s idle interval: "any progress" would keep this connection forever.
        port, proc = start_server(self.tmp.name + "/www", ["-t", "1", "-i", "8"])
        self.addCleanup(stop_server, proc)
        sock = socket.socket()
        self.addCleanup(sock.close)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        sock.connect(("127.0.0.1", port))
        sock.settimeout(5)
        sock.sendall(get(port, "/big.bin"))
        start = time.time()
        with self.assertRaises((ConnectionResetError, BrokenPipeError)):
            while time.time() - start < 40:
                got = 0
                while got < 4096:
                    chunk = sock.recv(4096 - got)
                    self.assertTrue(chunk)
                    got += len(chunk)
                time.sleep(6.0)
                # Once the server has closed its socket, a byte sent to it is answered with a reset.
                # (Reading alone cannot tell: the kernel still delivers what was queued before.)
                sock.send(b"G")
        self.assertLess(time.time() - start, 30)


class TlsTest(unittest.TestCase):
    """The same server over TLS, with a throwaway certificate made by the openssl tool."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        base = cls.tmp.name
        root = os.path.join(base, "www")
        os.makedirs(root)
        with open(os.path.join(root, "hello.txt"), "w") as f:
            f.write("hello world\n")
        cls.big = os.urandom(8 * 1024 * 1024 + 12345)  # not a multiple of the 16 KB record size
        with open(os.path.join(root, "big.bin"), "wb") as f:
            f.write(cls.big)
        cls.cert, cls.key = os.path.join(base, "cert.pem"), os.path.join(base, "key.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-nodes", "-keyout", cls.key, "-out", cls.cert, "-days", "1", "-subj", "/CN=localhost",
                        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                       check=True, capture_output=True)
        cls.port, cls.proc = start_server(root, ["-c", cls.cert, "-k", cls.key])

    @classmethod
    def tearDownClass(cls):
        stop_server(cls.proc)
        cls.tmp.cleanup()

    def context(self):
        ctx = ssl.create_default_context(cafile=self.cert)
        ctx.set_alpn_protocols(["http/1.1"])
        return ctx

    def https(self):
        c = http.client.HTTPSConnection("localhost", self.port, timeout=5, context=self.context())
        self.addCleanup(c.close)
        return c

    def tls_socket(self, ctx=None):
        raw = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        s = (ctx or self.context()).wrap_socket(raw, server_hostname="localhost")
        self.addCleanup(s.close)
        return s

    def test_handshake_verifies_and_negotiates(self):
        s = self.tls_socket()
        self.assertIn(s.version(), ("TLSv1.2", "TLSv1.3"))
        self.assertEqual(s.selected_alpn_protocol(), "http/1.1")

    def test_keep_alive_over_tls(self):
        c = self.https()
        for _ in range(100):
            c.request("GET", "/hello.txt")
            r = c.getresponse()
            self.assertEqual((r.status, r.read()), (200, b"hello world\n"))

    def test_pipelining_over_tls(self):
        s = self.tls_socket()
        s.sendall(get(self.port) * 3)
        data = b""
        while data.count(b"hello world\n") < 3:
            chunk = s.recv(65536)
            self.assertTrue(chunk, "closed early")
            data += chunk
        self.assertEqual(data.count(b"HTTP/1.1 200 OK"), 3)

    def test_large_file_integrity_over_tls(self):
        c = self.https()
        c.request("GET", "/big.bin")
        r = c.getresponse()
        self.assertEqual(r.status, 200)
        self.assertEqual(hashlib.sha256(r.read()).digest(), hashlib.sha256(self.big).digest())

    def test_range_over_tls(self):
        # The TLS path reads the file itself in record sized chunks, so it must start at the range.
        a, b = 16383, 5_000_000
        c = self.https()
        c.request("GET", "/big.bin", headers={"Range": "bytes=%d-%d" % (a, b)})
        r = c.getresponse()
        self.assertEqual((r.status, r.read()), (206, self.big[a:b + 1]))

    def test_slow_reader_over_tls(self):
        # Partial and would-block TLS writes must resume with exactly the bytes that were pending.
        s = self.tls_socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        s.sendall(get(self.port, "/big.bin"))
        data = b""
        while b"\r\n\r\n" not in data:
            data += s.recv(4096)
        head, body = data.split(b"\r\n\r\n", 1)
        while len(body) < 768 * 1024:
            chunk = s.recv(4096)
            self.assertTrue(chunk)
            body += chunk
        self.assertEqual(body, self.big[:len(body)])

    def test_concurrent_tls_clients(self):
        errors = []

        def worker():
            try:
                c = http.client.HTTPSConnection("localhost", self.port, timeout=10, context=self.context())
                for _ in range(10):
                    c.request("GET", "/hello.txt")
                    r = c.getresponse()
                    if (r.status, r.read()) != (200, b"hello world\n"):
                        errors.append("bad response")
                c.close()
            except Exception as e:  # noqa: BLE001
                errors.append(repr(e))

        threads = [threading.Thread(target=worker) for _ in range(32)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])

    def test_plaintext_client_is_dropped(self):
        conn = RawConn(self.port)
        self.addCleanup(conn.close)
        conn.send(get(self.port))
        self.assertTrue(conn.is_closed(wait=3.0))

    def test_client_that_only_speaks_h2_is_refused(self):
        ctx = ssl.create_default_context(cafile=self.cert)
        ctx.set_alpn_protocols(["h2"])
        with self.assertRaises(ssl.SSLError):
            self.tls_socket(ctx)

    def test_stalled_handshake_is_reaped(self):
        conn = RawConn(self.port)  # TCP connects, then never sends a ClientHello
        self.addCleanup(conn.close)
        self.assertTrue(conn.is_closed(wait=5.0))  # server runs with -i 2


if __name__ == "__main__":
    unittest.main(verbosity=2)
