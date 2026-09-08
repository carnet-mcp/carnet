"""How JSON-RPC messages reach an MCP server.

The seam exists for three reasons, in increasing order of importance:

  1. Tests. A subprocess is not the network, but it is a Docker image and a binary,
     and the suite must run without either. Every MCP test drives a fake.
  2. The remote server. GitHub also publishes a Streamable HTTP endpoint, and other
     vendors publish only one or the other.
  3. Delegated credentials. This is the real one. A **stdio** server takes its token
     as an environment variable at process launch, so per-user credentials mean one
     long-lived subprocess per user, each holding a plaintext secret in its
     environment for its whole life. An **HTTP** server takes the token per request
     in a header, and no long-lived process holds it. That difference is why the
     access layer waited for this file, and why the choice must not be welded into
     the client.

Two transports now, answering the same three methods:

    send(dict) -> dict | None     one message, and its reply if it has one
    set_protocol_version(str)     stamp later requests with the negotiated version
    close()

Deliberately message-level, not byte-level. Stdio frames with newlines and HTTP frames
with bodies, and a client that knew which would be a client that could only ever speak
one. Nothing above this file knows which it is holding.
"""

import json
import queue
import shutil
import subprocess
import threading

from ...config import REQUEST_TIMEOUT


class TransportError(RuntimeError):
    """The server could not be reached, or did not answer in time.

    `delivered` says whether the request reached the server before things went wrong,
    and it is the difference between two situations that look identical from here:

        delivered=False   the request never left. Nothing happened. Safe to retry.
        delivered=True    it was written to the wire and no reply came. The server
                          may have acted on it. For a read that is academic; for a
                          write it is the whole question, because a retry might
                          comment twice.

    A transport can always tell the two apart — failing to write to a pipe is not the
    same event as writing successfully and hearing nothing — so the distinction is
    free to carry and impossible to reconstruct later.

    Over HTTP there are more ways to be ambiguous than over a pipe, and getting one
    wrong does not fail loudly: it turns "this might have happened" into "this
    definitely did not", which is the one lie the audit log must never tell. See
    HttpTransport for the mapping, and note which way it errs.
    """

    def __init__(self, message: str, *, delivered: bool = False, status: int | None = None):
        super().__init__(message)
        self.delivered = delivered
        # The HTTP status when there was one, else None. Carried as a fact rather than
        # left as a substring of the message, because the door needs to ask "was this
        # an auth refusal?" (step 046) and parsing our own prose to answer it would
        # couple the door to this module's wording.
        self.status = status


class SessionExpired(TransportError):
    """The server no longer recognises our session and we must start a new one.

    Always `delivered=False`, and that is not a guess: the server told us it does not
    know this session, so it cannot have executed anything under it. That is what makes
    re-initializing and retrying once safe even for a write — see Session._request,
    where it looks alarming and isn't.
    """

    def __init__(self, message: str):
        super().__init__(message, delivered=False)


class StdioTransport:
    """A server run as a child process, speaking newline-delimited JSON-RPC.

    Two background threads, both necessary rather than decorative:

      stdout  read into a queue, so a request can wait with a deadline. Windows
              cannot select() on a pipe, so a blocking read on the main thread would
              be a hang with no timeout.
      stderr  drained and discarded but for a short tail. A server that logs more
              than the pipe buffer holds blocks forever on write if nobody reads —
              the classic subprocess deadlock, and it looks exactly like a hung tool.
    """

    STDERR_TAIL = 20

    def __init__(self, command, env: dict | None = None, timeout: int = REQUEST_TIMEOUT):
        self.command = list(command)
        self.timeout = timeout
        self._stderr_tail: list[str] = []

        try:
            self._proc = subprocess.Popen(
                [self._resolve(self.command[0]), *self.command[1:]],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                text=True,
                encoding="utf-8",
                bufsize=1,
            )
        except OSError as exc:
            raise TransportError(f"could not start {self.command[0]!r}: {exc}") from exc

        self._inbox: queue.Queue = queue.Queue()
        self._pump(self._proc.stdout, self._inbox.put)
        self._pump(self._proc.stderr, self._remember_stderr)

    @staticmethod
    def _resolve(program: str) -> str:
        """The command's absolute path, looked up **in this process**.

        ## The bug this exists for, and why it is not fixed the obvious way

        `StdioLaunch.env_for` builds the child's environment from scratch rather than from
        `os.environ` — *"a server should receive the secret it needs and nothing else we
        happen to hold"* — so the child gets `GITHUB_TOOLSETS` and no `PATH`. And
        `subprocess.Popen` with an explicit `env` does **not** search the parent's PATH:
        it falls back to `os.defpath`, which is `/bin:/usr/bin`. A manifest naming a bare
        `docker` therefore works on a machine whose toolchain is in `/usr/bin` and fails on
        one that keeps it anywhere else — which is every machine without an administrator
        password, where the whole toolchain ends up in `$HOME`.

        Two correct decisions meeting. The failure appears only at the first launch of a
        stdio connector, which is a thing no test does.

        **The obvious fix is to put `PATH` into the child's environment, and it is the
        wrong one.** It widens what the server may execute for the whole of its life, to
        solve a problem that exists for one instant — finding the program we already
        chose. A lookup is not a secret and an executable's location is not one either, so
        it happens **here, in the parent**, against the operator's own PATH, and the
        child's environment stays exactly as minimal as it was.

        The other candidate — absolute commands in the manifest — makes a vetted connector
        unportable between machines, which is wrong for a record meant to say what was
        approved rather than where it happens to be installed.

        An absolute path is returned unchanged if it is executable, so a manifest that
        does pin one still works.
        """
        found = shutil.which(program)
        if found is None:
            raise TransportError(
                f"could not start {program!r}: it is not on this process's PATH. A "
                "connector's manifest names the program and this process has to be able "
                "to find it — check the PATH of whatever launched the server or the "
                "worker rather than the one in your shell."
            )
        return found

    def _pump(self, stream, sink) -> None:
        def run():
            for line in stream:
                sink(line)

        threading.Thread(target=run, daemon=True).start()

    def _remember_stderr(self, line: str) -> None:
        self._stderr_tail.append(line.rstrip())
        del self._stderr_tail[: -self.STDERR_TAIL]

    def send(self, message: dict) -> dict | None:
        """Write one message. Returns the matching response, or None for a notification.

        Messages arriving that aren't the response we're waiting for — server-initiated
        notifications, progress updates — are discarded. We speak a deliberate subset
        of MCP and have nothing to say to them.
        """
        if self._proc.poll() is not None:
            raise TransportError(f"server exited ({self._proc.returncode}). {self._stderr()}")

        try:
            self._proc.stdin.write(json.dumps(message) + "\n")
            self._proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise TransportError(f"server closed its input: {exc}. {self._stderr()}") from exc

        if "id" not in message:
            return None

        return self._await(message["id"])

    def _await(self, message_id) -> dict:
        deadline = threading.Event()
        timer = threading.Timer(self.timeout, deadline.set)
        timer.start()
        try:
            while not deadline.is_set():
                try:
                    line = self._inbox.get(timeout=0.1)
                except queue.Empty:
                    if self._proc.poll() is not None:
                        # The request was on the wire before it died, so it may have
                        # acted on it. Ambiguous, not clean.
                        raise TransportError(
                            f"server exited while awaiting a reply. {self._stderr()}",
                            delivered=True,
                        ) from None
                    continue

                if not line.strip():
                    continue
                try:
                    parsed = json.loads(line)
                except json.JSONDecodeError:
                    continue  # servers do print stray output; it isn't ours to fix
                if parsed.get("id") == message_id:
                    return parsed
        finally:
            timer.cancel()

        raise TransportError(
            f"no reply within {self.timeout}s for request {message_id}. {self._stderr()}",
            delivered=True,
        )

    def _stderr(self) -> str:
        tail = " | ".join(self._stderr_tail[-5:])
        return f"Server said: {tail}" if tail else "Server said nothing."

    def set_protocol_version(self, version: str) -> None:
        """No-op. stdio negotiates in-band and has no headers to stamp.

        Present so the transport interface is explicit rather than duck-typed: every
        transport answers `send`, `set_protocol_version` and `close`, and a caller
        never has to ask which kind it is holding.
        """

    def close(self) -> None:
        if self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()


class HttpTransport:
    """A Streamable HTTP server, reached over the network.

    The reason this exists: the credential travels **per request**, in a header, and no
    long-lived process holds it. That is what makes per-user credentials possible at
    all — a stdio server would need one subprocess per user, each sitting on a plaintext
    secret for its whole life.

    Three things the spec requires that are easy to get wrong by assuming otherwise:

      - Every message is a POST, and `Accept` must list **both** `application/json` and
        `text/event-stream`. For a request the *server* chooses which to answer with,
        and the client must handle both. SSE is not optional.
      - A notification (no `id`) is answered with **202 and no body**. That maps exactly
        onto `send() -> None`, which is why the seam did not have to change shape.
      - A session that has expired comes back as **404**, and the client must start a
        new one rather than treating it as a failure.

    `post` is injectable so tests drive status codes, content types and connection
    failures without a socket — the same reason `transport.py` is a seam at all, one
    level down. It is the only place in this class that touches the network.
    """

    def __init__(
        self,
        url: str,
        headers: dict | None = None,
        timeout: int = REQUEST_TIMEOUT,
        post=None,
    ):
        self.url = url
        self.timeout = timeout
        self._headers = dict(headers or {})
        self._post = post or _requests_post()
        self._protocol_version: str | None = None
        self._session_id: str | None = None
        self._closed = False

    # --- the interface ----------------------------------------------------------

    def set_protocol_version(self, version: str) -> None:
        """Stamp every later request with the version negotiated at initialize.

        The spec wants the *negotiated* version, which is not known until the handshake
        has answered — so this is told to us rather than configured.
        """
        self._protocol_version = version

    def send(self, message: dict) -> dict | None:
        """POST one message. Returns the matching response, or None for a notification."""
        body = json.dumps(message)
        response = self._deliver(body, is_request="id" in message)

        try:
            return self._read(response, message)
        finally:
            response.close()

    def close(self) -> None:
        """Best-effort session teardown. Never raises — this runs on the way out."""
        self._closed = True
        if not self._session_id:
            return
        try:
            self._post(
                self.url,
                method="DELETE",
                headers=self._request_headers(),
                body=None,
                timeout=self.timeout,
            ).close()
        except Exception:  # noqa: BLE001 - teardown must not mask the real failure
            pass
        finally:
            self._session_id = None

    # --- sending ----------------------------------------------------------------

    def _request_headers(self) -> dict:
        headers = dict(self._headers)
        headers["Content-Type"] = "application/json"
        # Both, mandatory. The server picks which one it answers with.
        headers["Accept"] = "application/json, text/event-stream"
        if self._protocol_version:
            headers["MCP-Protocol-Version"] = self._protocol_version
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        return headers

    def _deliver(self, body: str, is_request: bool):
        """POST, and translate every way that can fail into a delivered/not decision."""
        try:
            response = self._post(
                self.url,
                method="POST",
                headers=self._request_headers(),
                body=body,
                timeout=self.timeout,
            )
        except Exception as exc:  # noqa: BLE001 - classified immediately below
            raise _classify(exc) from exc

        status = response.status_code

        # A session id is assigned at initialize and must ride on everything after.
        assigned = response.headers.get("Mcp-Session-Id")
        if assigned:
            self._session_id = assigned

        if status == 404 and self._session_id:
            response.close()
            self._session_id = None
            raise SessionExpired(
                "the server no longer recognises this session; a new one is needed"
            )

        if 400 <= status < 500:
            detail = _brief(response)
            response.close()
            # Rejected before dispatch, so the tool did not run. Safe to retry, and
            # saying otherwise would flood the audit log with ambiguous writes every
            # time a credential expired.
            raise TransportError(
                f"server refused the request ({status}). {detail}",
                delivered=False,
                status=status,
            )

        if status >= 500:
            detail = _brief(response)
            response.close()
            # It reached the server. Whether the server got far enough to act on it is
            # exactly what nobody can tell from here.
            raise TransportError(
                f"server failed to handle the request ({status}). {detail}",
                delivered=True,
                status=status,
            )

        if not is_request:
            # Notifications and responses get 202 with no body. Anything else is a
            # server we do not understand, and guessing is how a notification silently
            # becomes a dropped message.
            if status != 202:
                response.close()
                raise TransportError(
                    f"expected 202 for a notification, got {status}", delivered=True
                )

        return response

    # --- reading ----------------------------------------------------------------

    def _read(self, response, message: dict) -> dict | None:
        if "id" not in message:
            return None

        content_type = (response.headers.get("Content-Type") or "").split(";")[0].strip()

        if content_type == "application/json":
            return self._read_json(response, message["id"])

        if content_type == "text/event-stream":
            return self._read_sse(response, message["id"])

        raise TransportError(
            f"server answered a request with unsupported content type {content_type!r}",
            delivered=True,
        )

    def _read_sse(self, response, message_id) -> dict:
        """Read the stream until the reply to `message_id` arrives.

        The server MAY send its own requests and notifications before the response,
        and they are discarded — exactly what stdio already does with messages that
        are not the one being awaited. We speak a deliberate subset of MCP and have
        nothing to say to them.

        A stream that ends without the response is the sharpest case in this file.
        The spec says explicitly that disconnection **is not** cancellation: the server
        may still be working. So this is `delivered=True`, it becomes `outcome=unknown`
        for a write, and it must never be retried automatically.
        """
        try:
            for payload in _sse_messages(response):
                if not isinstance(payload, dict):
                    continue
                if payload.get("id") == message_id:
                    return payload
        except TransportError:
            raise
        except Exception as exc:  # noqa: BLE001 - the stream died; that is the finding
            raise TransportError(
                f"the response stream failed before answering: {exc}", delivered=True
            ) from exc

        raise TransportError(
            f"the response stream ended without answering request {message_id}. "
            "The server may still have acted on it — a disconnection is not a "
            "cancellation.",
            delivered=True,
        )

    def _read_json(self, response, message_id) -> dict:
        try:
            payload = response.json()
        except Exception as exc:  # noqa: BLE001 - any parse failure means the same thing
            raise TransportError(
                f"server sent a body that is not JSON: {exc}", delivered=True
            ) from exc

        if not isinstance(payload, dict):
            raise TransportError(
                "server answered a request with something other than one JSON object",
                delivered=True,
            )

        if payload.get("id") != message_id:
            raise TransportError(
                f"server answered request {message_id} with a reply for "
                f"{payload.get('id')!r}",
                delivered=True,
            )

        return payload


def _sse_messages(response):
    """Yield the JSON payload of each `data:` event on an SSE stream.

    A deliberately small reader, matching the deliberately small protocol subset above
    it. Server-Sent Events allows a good deal we neither send nor need: `event:` types
    (we only care that a message arrived, not what the server calls it), `id:` and
    `retry:` (resumability, which we do not implement), and comment lines.

    Multi-line `data:` is joined with newlines, per the SSE spec, because a JSON body
    containing a newline is split across several `data:` lines by conforming servers
    and rejoining it wrongly would corrupt the message.
    """
    data: list[str] = []

    for raw in response.iter_lines(decode_unicode=True):
        line = raw.decode("utf-8") if isinstance(raw, bytes) else (raw or "")

        if not line.strip():
            # A blank line dispatches the event.
            if data:
                try:
                    yield json.loads("\n".join(data))
                except json.JSONDecodeError:
                    pass  # servers do emit keep-alives and stray output
                data = []
            continue

        if line.startswith(":"):
            continue  # comment / keep-alive

        field, _, value = line.partition(":")
        if field == "data":
            data.append(value[1:] if value.startswith(" ") else value)

    # A final event with no trailing blank line. Conforming servers send one; not all
    # servers conform, and dropping the reply over a missing newline would be a
    # miserable way to lose a tool result.
    if data:
        try:
            yield json.loads("\n".join(data))
        except json.JSONDecodeError:
            pass


def _brief(response, limit: int = 200) -> str:
    """A short, safe tail of an error body. Servers put useful things there and also
    occasionally put a stack trace, so it is bounded."""
    try:
        text = (response.text or "").strip().replace("\n", " ")
    except Exception:  # noqa: BLE001 - a body we cannot read is not the interesting failure
        return "Server said nothing readable."
    return f"Server said: {text[:limit]}" if text else "Server said nothing."


def _classify(exc: Exception) -> TransportError:
    """Map a client-side failure onto delivered / not delivered.

    The bias, stated once: **when it is genuinely unclear, say delivered.** A false
    "delivered" costs a person a glance at a run that was fine. A false "not delivered"
    tells the audit log a write definitely did not happen when it may have, and that is
    the record nobody can reconstruct afterwards.

    But the common cases are worth getting exactly right rather than biasing, because
    if every outage produced ambiguous writes then `outcome="unknown"` would stop
    meaning anything — and it is valuable precisely because it is rare.
    """
    import requests

    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return TransportError(f"could not connect to the server: {exc}", delivered=False)

    if isinstance(exc, requests.exceptions.ReadTimeout):
        return TransportError(
            f"no reply from the server in time: {exc}", delivered=True
        )

    if isinstance(exc, requests.exceptions.ConnectionError):
        if _is_connect_failure(exc):
            return TransportError(
                f"could not reach the server: {exc}", delivered=False
            )
        # The connection broke, and we cannot tell whether that was before or after
        # the server acted. Ambiguous, so: ambiguous.
        return TransportError(f"connection to the server failed: {exc}", delivered=True)

    if isinstance(exc, requests.exceptions.RequestException):
        return TransportError(f"request failed: {exc}", delivered=True)

    raise exc


def _is_connect_failure(exc: BaseException) -> bool:
    """Did this fail while establishing the connection, before anything was sent?

    DNS failure and connection-refused are the overwhelmingly common cases — a typo'd
    URL, a server that is down — and they are unambiguously "nothing happened".
    urllib3 marks both with NewConnectionError, so we look for it in the cause chain
    rather than matching on message text.

    If urllib3 ever stops saying so, this returns False and the caller falls back to
    the safe direction. That is the right way for a heuristic to fail.
    """
    try:
        from urllib3.exceptions import NewConnectionError
    except ImportError:  # pragma: no cover - urllib3 ships with requests
        return False

    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if isinstance(exc, NewConnectionError):
            return True
        exc = exc.__cause__ or exc.__context__
    return False


def _requests_post():
    """The real network call, and the only place in this module that makes one.

    A `requests.Session` so connections are reused across calls to the same server —
    it is the same endpoint every time, and a new TCP + TLS handshake per JSON-RPC
    message would be most of the latency.

    **The dial is pinned (step 058, through `egress.dial` since 064).** The URL's host
    is resolved on this transport's first message, every DNS answer refused if it is an
    address nobody may consent to, and the socket goes to the checked address with the
    TLS name kept — so what is dialled is what was checked, and a record that moves
    after the check moves nothing. Resolved once and kept for the transport's life,
    deliberately: the session keeps the connection anyway, and re-resolving per
    JSON-RPC message would be a DNS query per message for an address the pin makes
    irrelevant. That is why `dial` takes an already-resolved `pin` at all — this is the
    one caller with a reason to hold one. Sitting inside this seam keeps every injected
    fake `post` hermetic.

    **One pin, not a map.** This was a dict keyed by URL, which held at most one entry:
    a transport has exactly one URL (`self.url`, set in `__init__`). The generality was
    a trap rather than dead weight — a second host would have re-mounted the shared
    session's adapter and silently replaced the first pin's `assert_hostname` — so the
    single `nonlocal` states the contract the seam actually has.

    Redirects are refused by `dial`, the same closure at the HTTP layer that
    `rest._request` took at birth: the allowlist was checked against this URL, and a
    3xx pointing anywhere else is a dial the check never saw.
    """
    import requests

    from . import egress

    session = requests.Session()
    pin = None

    def post(url, *, method, headers, body, timeout):
        nonlocal pin
        if pin is None:
            pin = egress.pinned(url)
        return egress.dial(
            session,
            method,
            url,
            pin=pin,
            headers=headers,
            data=body,
            timeout=(timeout, timeout),
            stream=True,
        )

    return post
