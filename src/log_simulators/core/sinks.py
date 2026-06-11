"""Output sinks: stdout, rotating files (gzip), and TCP/UDP senders.

A sink accepts one *event* per ``write`` call. Events may span multiple
lines (Windows XML, stack traces); the sink appends the trailing newline.
"""

from __future__ import annotations

import contextlib
import errno
import gzip
import os
import shutil
import socket
import sys
from dataclasses import dataclass, field
from types import TracebackType
from urllib.parse import urlparse


@dataclass
class Stats:
    target_eps: float = 0.0
    events: int = 0
    lines: int = 0
    bytes: int = 0
    elapsed: float = 0.0
    _achieved: float = field(default=0.0, repr=False)

    def record(self, nbytes: int, event: str) -> None:
        self.events += 1
        self.lines += event.count("\n") + 1
        self.bytes += nbytes

    def finish(self, elapsed: float) -> None:
        self.elapsed = elapsed
        self._achieved = self.events / elapsed if elapsed > 0 else 0.0

    @property
    def achieved_eps(self) -> float:
        return self._achieved

    def summary(self) -> str:
        return (
            f"[logsim] events={self.events} lines={self.lines} bytes={self.bytes} "
            f"elapsed={self.elapsed:.1f}s achieved_eps={self._achieved:.1f} "
            f"target_eps={self.target_eps:g}"
        )


class Sink:
    def write(self, event: str) -> int:  # returns bytes written
        raise NotImplementedError

    def __enter__(self) -> Sink:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        pass


class StdoutSink(Sink):
    def write(self, event: str) -> int:
        data = event + "\n"
        sys.stdout.write(data)
        sys.stdout.flush()
        return len(data.encode("utf-8", errors="replace"))


class FileSink(Sink):
    """Append to a file with optional size-based rotation.

    On rotation: ``app.log`` -> ``app.log.1.gz``; older backups shift up to
    ``keep`` generations (``app.log.2.gz``, ...), oldest is deleted.
    """

    def __init__(self, path: str, rotate_mb: int = 0, keep: int = 5) -> None:
        self.path = path
        self.rotate_bytes = rotate_mb * 1024 * 1024
        self.keep = keep
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        self._fh = open(path, "a", encoding="utf-8")  # noqa: SIM115 - long-lived handle
        self._size = self._fh.tell()

    def write(self, event: str) -> int:
        data = event + "\n"
        self._fh.write(data)
        nbytes = len(data.encode("utf-8", errors="replace"))
        self._size += nbytes
        if self.rotate_bytes and self._size >= self.rotate_bytes:
            self._rotate()
        return nbytes

    def _rotate(self) -> None:
        self._fh.close()
        oldest = f"{self.path}.{self.keep}.gz"
        if os.path.exists(oldest):
            os.remove(oldest)
        for i in range(self.keep - 1, 0, -1):
            src = f"{self.path}.{i}.gz"
            if os.path.exists(src):
                os.replace(src, f"{self.path}.{i + 1}.gz")
        with open(self.path, "rb") as raw, gzip.open(f"{self.path}.1.gz", "wb") as gz:
            shutil.copyfileobj(raw, gz)
        self._fh = open(self.path, "w", encoding="utf-8")  # noqa: SIM115
        self._size = 0

    def close(self) -> None:
        self._fh.flush()
        self._fh.close()


class UdpSink(Sink):
    _MAX_DATAGRAM = 65_000  # stay under the UDP payload ceiling

    def __init__(self, host: str, port: int) -> None:
        self._addr = (host, port)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        with contextlib.suppress(OSError):  # macOS defaults to a 9 KiB send buffer
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)
        self._warned = False

    def _warn_truncated(self) -> None:
        if not self._warned:
            self._warned = True
            print(
                "[logsim] warning: event exceeded the UDP datagram limit and was "
                "truncated (further truncations are silent)",
                file=sys.stderr,
            )

    def write(self, event: str) -> int:
        data = event.encode("utf-8", errors="replace")
        if len(data) > self._MAX_DATAGRAM:
            data = data[: self._MAX_DATAGRAM]
            self._warn_truncated()
        while True:
            try:
                self._sock.sendto(data, self._addr)
                break
            except OSError as exc:
                if exc.errno != errno.EMSGSIZE or len(data) <= 1024:
                    raise
                # OS datagram ceiling below the protocol limit: halve and retry
                data = data[: len(data) // 2]
                self._warn_truncated()
        return len(data)

    def close(self) -> None:
        self._sock.close()


class TcpSink(Sink):
    def __init__(self, host: str, port: int) -> None:
        self._addr = (host, port)
        try:
            self._sock = self._connect()
        except OSError as exc:
            raise SystemExit(f"cannot connect to tcp://{host}:{port}: {exc}") from exc

    def _connect(self) -> socket.socket:
        sock = socket.create_connection(self._addr, timeout=10)
        sock.settimeout(10)
        return sock

    def write(self, event: str) -> int:
        data = (event + "\n").encode("utf-8", errors="replace")
        try:
            self._sock.sendall(data)
        except OSError:
            # One reconnect attempt, then propagate. A failure mid-send can
            # resend the whole event - acceptable duplication for a simulator.
            self._sock.close()
            self._sock = self._connect()
            self._sock.sendall(data)
        return len(data)

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self._sock.close()


def open_sink(output: str, rotate_mb: int = 0) -> Sink:
    if rotate_mb and (output == "-" or output.startswith(("tcp://", "udp://"))):
        print("[logsim] warning: --rotate-mb only applies to file output; ignored", file=sys.stderr)
    if output == "-":
        return StdoutSink()
    if output.startswith(("tcp://", "udp://")):
        parsed = urlparse(output)
        if not parsed.hostname or not parsed.port:
            raise SystemExit(f"invalid network destination: {output!r} (need host:port)")
        if parsed.scheme == "udp":
            return UdpSink(parsed.hostname, parsed.port)
        return TcpSink(parsed.hostname, parsed.port)
    return FileSink(output, rotate_mb=rotate_mb)
