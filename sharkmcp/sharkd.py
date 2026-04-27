"""Thin JSON-RPC client over a per-PCAP sharkd subprocess."""

import json
import os
import selectors
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_TIMEOUT = float(os.environ.get("SHARKMCP_TIMEOUT", "300"))
SHARKD_BIN = os.environ.get("SHARKMCP_SHARKD_BIN", "sharkd")


class SharkdError(RuntimeError):
    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(f"sharkd error {code}: {message}")
        self.code = code
        self.data = data


def _readline_with_timeout(stream, timeout: float) -> str:
    sel = selectors.DefaultSelector()
    sel.register(stream, selectors.EVENT_READ)
    if not sel.select(timeout):
        raise TimeoutError(f"sharkd response timed out after {timeout}s")
    return stream.readline()


@dataclass
class Session:
    alias: str
    path: str
    proc: subprocess.Popen
    lock: threading.Lock = field(default_factory=threading.Lock)
    _next_id: int = 1

    def call(
        self,
        method: str,
        params: dict | None = None,
        timeout: float | None = None,
    ) -> Any:
        if timeout is None:
            timeout = DEFAULT_TIMEOUT
        with self.lock:
            if self.proc.poll() is not None:
                raise SharkdError(-1, f"sharkd exited (rc={self.proc.returncode})")
            req_id = self._next_id
            self._next_id += 1
            req: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
            if params:
                req["params"] = params
            assert self.proc.stdin is not None and self.proc.stdout is not None
            self.proc.stdin.write(json.dumps(req) + "\n")
            self.proc.stdin.flush()
            line = _readline_with_timeout(self.proc.stdout, timeout)
            if not line:
                raise SharkdError(-1, "sharkd closed the connection")
            resp = json.loads(line)
            if "error" in resp:
                err = resp["error"]
                raise SharkdError(
                    err.get("code", -1),
                    err.get("message", "unknown"),
                    err.get("data"),
                )
            return resp.get("result")

    def close(self) -> None:
        try:
            self.call("bye", timeout=5)
        except Exception:
            pass
        for stream in (self.proc.stdin, self.proc.stdout):
            try:
                if stream:
                    stream.close()
            except Exception:
                pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=2)


class SessionPool:
    def __init__(self, sharkd_path: str = SHARKD_BIN):
        self.sharkd_path = sharkd_path
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def load(self, path: str, alias: str | None = None) -> Session:
        p = Path(path).expanduser()
        if not p.is_file():
            raise FileNotFoundError(f"no such file: {p}")
        resolved = str(p.resolve())
        if alias is None:
            alias = p.name
        with self._lock:
            if alias in self._sessions:
                raise ValueError(f"alias {alias!r} already loaded; unload first")
            proc = subprocess.Popen(
                [self.sharkd_path, "-"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
            sess = Session(alias=alias, path=resolved, proc=proc)
            try:
                result = sess.call("load", {"file": resolved})
                if not isinstance(result, dict) or result.get("status") != "OK":
                    raise SharkdError(-1, f"load failed: {result!r}")
            except Exception:
                sess.close()
                raise
            self._sessions[alias] = sess
            return sess

    def get(self, alias: str) -> Session:
        try:
            return self._sessions[alias]
        except KeyError:
            raise KeyError(f"unknown alias {alias!r}; load it first") from None

    def unload(self, alias: str) -> None:
        with self._lock:
            sess = self._sessions.pop(alias, None)
        if sess is None:
            raise KeyError(f"unknown alias {alias!r}")
        sess.close()

    def aliases(self) -> list[str]:
        return list(self._sessions.keys())

    def close_all(self) -> None:
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for sess in sessions:
            sess.close()
