"""The HTTP transport, and mostly one question: did this maybe happen?

`HttpTransport` is the first place in the codebase that talks to the network, so it is
also the first place where "the request failed" stops being one thing. A pipe either
took the bytes or it didn't. HTTP can refuse to connect, accept and then time out,
answer 500 after doing half the work, or hand back a stream that dies mid-flight — and
those do not all mean the same thing to a write.

`TransportError.delivered` is what carries that distinction up to `outcome="unknown"`
and a human's attention, so the mapping is the thing worth testing hardest. Getting a
row wrong does not fail loudly: it silently turns "this might have happened" into "this
definitely did not".

Nothing here opens a socket. `HttpTransport` takes an injectable `post`, which is the
same "seam so tests start nothing" reasoning as transport.py itself, one level down.
"""

import json

import pytest
import requests
from urllib3.exceptions import NewConnectionError

from carnet.tools.mcp.transport import (
    HttpTransport,
    SessionExpired,
    TransportError,
)

URL = "https://mcp.example.com/mcp"

REQUEST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
NOTIFICATION = {"jsonrpc": "2.0", "method": "notifications/initialized"}


class FakeResponse:
    def __init__(self, status_code=200, body="", content_type="application/json", headers=None):
        self.status_code = status_code
        self.headers = {"Content-Type": content_type, **(headers or {})}
        self._body = body
        self.closed = False

    @property
    def text(self):
        return self._body

    def json(self):
        return json.loads(self._body)

    def iter_lines(self, decode_unicode=False):
        for line in self._body.split("\n"):
            yield line

    def close(self):
        self.closed = True


def reply(result=None, message_id=1, **overrides):
    payload = {"jsonrpc": "2.0", "id": message_id, "result": result or {}}
    payload.update(overrides)
    return FakeResponse(body=json.dumps(payload))


ACCEPTED = FakeResponse(status_code=202, body="", content_type="")


class FakePost:
    """Records what was sent; returns or raises whatever the test scripted."""

    def __init__(self, *scripted):
        self.scripted = list(scripted)
        self.calls = []

    def __call__(self, url, *, method, headers, body, timeout):
        self.calls.append(
            {
                "url": url,
                "method": method,
                "headers": headers,
                "body": json.loads(body) if body else None,
                "timeout": timeout,
            }
        )
        outcome = self.scripted.pop(0) if self.scripted else reply()
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def transport(*scripted, **kwargs):
    post = FakePost(*scripted)
    return HttpTransport(URL, post=post, **kwargs), post


# --- the shape of a request ------------------------------------------------------


def test_a_message_is_posted_to_the_endpoint():
    http, post = transport(reply({"tools": []}))

    http.send(REQUEST)

    assert post.calls[0]["method"] == "POST"
    assert post.calls[0]["url"] == URL
    assert post.calls[0]["body"] == REQUEST


def test_accept_lists_both_content_types():
    """Mandatory. The server chooses which one it answers with, so a client that
    accepted only JSON would break against a server that streams."""
    http, post = transport(reply())

    http.send(REQUEST)

    accept = post.calls[0]["headers"]["Accept"]
    assert "application/json" in accept
    assert "text/event-stream" in accept


def test_the_credential_headers_are_sent_on_every_request():
    """The whole point of this transport: the credential travels per request rather
    than sitting in a process's environment for its lifetime."""
    http, post = transport(
        reply(), reply(message_id=2), headers={"Authorization": "Bearer sekrit"}
    )

    http.send(REQUEST)
    http.send({**REQUEST, "id": 2})

    for call in post.calls:
        assert call["headers"]["Authorization"] == "Bearer sekrit"


def test_the_protocol_version_header_appears_once_negotiated():
    """The spec wants the *negotiated* version, which is not known until the handshake
    answers — so it is told to the transport rather than configured."""
    http, post = transport(reply(), reply(message_id=2))

    http.send(REQUEST)
    assert "MCP-Protocol-Version" not in post.calls[0]["headers"]

    http.set_protocol_version("2025-06-18")
    http.send({**REQUEST, "id": 2})
    assert post.calls[1]["headers"]["MCP-Protocol-Version"] == "2025-06-18"


# --- replies ---------------------------------------------------------------------


def test_a_json_reply_is_returned():
    http, _ = transport(reply({"tools": [{"name": "x"}]}))

    assert http.send(REQUEST)["result"] == {"tools": [{"name": "x"}]}


def test_a_notification_expects_202_and_returns_nothing():
    """202 with no body is what the spec says a notification gets, and `send()`
    returning None is what the seam already promised. They line up exactly."""
    http, _ = transport(ACCEPTED)

    assert http.send(NOTIFICATION) is None


def test_a_notification_answered_with_anything_else_is_refused():
    """Guessing is how a notification silently becomes a dropped message."""
    http, _ = transport(FakeResponse(status_code=200, body="{}"))

    with pytest.raises(TransportError, match="expected 202"):
        http.send(NOTIFICATION)


def test_a_reply_for_a_different_request_is_refused():
    http, _ = transport(reply(message_id=99))

    with pytest.raises(TransportError, match="reply for"):
        http.send(REQUEST)


def test_a_body_that_is_not_json_is_refused():
    http, _ = transport(FakeResponse(body="<html>gateway</html>"))

    with pytest.raises(TransportError, match="not JSON"):
        http.send(REQUEST)


def test_an_unsupported_content_type_is_refused():
    http, _ = transport(FakeResponse(body="{}", content_type="text/plain"))

    with pytest.raises(TransportError, match="unsupported content type"):
        http.send(REQUEST)


def test_the_response_is_always_closed():
    """A streamed response holds a connection until it is released."""
    response = reply()
    http, _ = transport(response)

    http.send(REQUEST)

    assert response.closed


# --- the mapping this file exists for --------------------------------------------


def connection_refused():
    """What `requests` raises for a refused connection or a DNS failure: a
    ConnectionError whose cause chain carries urllib3's NewConnectionError."""
    exc = requests.exceptions.ConnectionError("connection refused")
    exc.__cause__ = NewConnectionError(None, "connection refused")
    return exc


def test_a_refused_connection_is_not_delivered():
    """Nothing happened. Saying otherwise would make every outage produce ambiguous
    writes, and `unknown` is valuable precisely because it is rare."""
    http, _ = transport(connection_refused())

    with pytest.raises(TransportError) as caught:
        http.send(REQUEST)
    assert caught.value.delivered is False


def test_a_connect_timeout_is_not_delivered():
    http, _ = transport(requests.exceptions.ConnectTimeout("too slow to connect"))

    with pytest.raises(TransportError) as caught:
        http.send(REQUEST)
    assert caught.value.delivered is False


def test_a_read_timeout_is_delivered():
    """It is on the wire. The server may be acting on it right now."""
    http, _ = transport(requests.exceptions.ReadTimeout("no answer"))

    with pytest.raises(TransportError) as caught:
        http.send(REQUEST)
    assert caught.value.delivered is True


def test_a_broken_connection_of_unknown_cause_is_delivered():
    """The bias, stated: when it is genuinely unclear, say delivered. A false
    'delivered' costs a glance; a false 'not delivered' tells the audit log a write
    definitely did not happen when it may have."""
    http, _ = transport(requests.exceptions.ConnectionError("reset by peer"))

    with pytest.raises(TransportError) as caught:
        http.send(REQUEST)
    assert caught.value.delivered is True


def test_a_client_error_is_not_delivered():
    """4xx is a rejection before dispatch, so the tool did not run."""
    http, _ = transport(FakeResponse(status_code=401, body="bad token"))

    with pytest.raises(TransportError) as caught:
        http.send(REQUEST)
    assert caught.value.delivered is False
    assert "401" in str(caught.value)


def test_a_server_error_is_delivered():
    """It reached the server. Whether the server got far enough to act on it is
    exactly what nobody can tell from here."""
    http, _ = transport(FakeResponse(status_code=503, body="overloaded"))

    with pytest.raises(TransportError) as caught:
        http.send(REQUEST)
    assert caught.value.delivered is True


def test_an_error_body_is_reported_but_bounded():
    """Servers put useful things there, and occasionally a stack trace."""
    http, _ = transport(FakeResponse(status_code=400, body="x" * 5000))

    with pytest.raises(TransportError) as caught:
        http.send(REQUEST)
    assert len(str(caught.value)) < 500


# --- SSE, which the server chooses and the client does not get to refuse ---------


def sse(*events, status_code=200, headers=None):
    body = "".join(f"data: {json.dumps(e)}\n\n" for e in events)
    return FakeResponse(
        status_code=status_code,
        body=body,
        content_type="text/event-stream",
        headers=headers,
    )


def test_a_streamed_reply_is_read():
    http, _ = transport(sse({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}))

    assert http.send(REQUEST)["result"] == {"tools": []}


def test_a_streamed_reply_matches_the_json_one():
    """The server picks the encoding, so the two must be indistinguishable from
    above. If they differ, every caller has to care which one it got."""
    result = {"content": [{"type": "text", "text": "hi"}]}

    streamed, _ = transport(sse({"jsonrpc": "2.0", "id": 1, "result": result}))
    plain, _ = transport(reply(result))

    assert streamed.send(REQUEST) == plain.send(REQUEST)


def test_messages_before_the_reply_are_discarded():
    """The server MAY send its own requests and notifications first. We speak a
    deliberate subset and have nothing to say to them — the same rule stdio follows."""
    http, _ = transport(
        sse(
            {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"pct": 10}},
            {"jsonrpc": "2.0", "id": 99, "method": "sampling/createMessage"},
            {"jsonrpc": "2.0", "id": 1, "result": {"done": True}},
        )
    )

    assert http.send(REQUEST)["result"] == {"done": True}


def test_a_stream_that_ends_without_the_reply_is_delivered():
    """The sharpest case in the transport. The spec says a disconnection is NOT a
    cancellation — the server may still be working — so this is ambiguous, becomes
    outcome=unknown for a write, and must never be retried automatically."""
    http, _ = transport(sse({"jsonrpc": "2.0", "method": "notifications/progress"}))

    with pytest.raises(TransportError) as caught:
        http.send(REQUEST)

    assert caught.value.delivered is True
    assert "not a cancellation" in str(caught.value)


def test_an_empty_stream_is_delivered():
    http, _ = transport(FakeResponse(body="", content_type="text/event-stream"))

    with pytest.raises(TransportError) as caught:
        http.send(REQUEST)
    assert caught.value.delivered is True


def test_a_stream_that_breaks_mid_flight_is_delivered():
    class Exploding(FakeResponse):
        def iter_lines(self, decode_unicode=False):
            yield 'data: {"jsonrpc": "2.0", "method": "x"}'
            yield ""
            raise requests.exceptions.ChunkedEncodingError("connection reset")

    http, _ = transport(Exploding(content_type="text/event-stream"))

    with pytest.raises(TransportError) as caught:
        http.send(REQUEST)
    assert caught.value.delivered is True


def test_keep_alives_and_comments_are_ignored():
    body = (
        ": keep-alive\n"
        "\n"
        "event: message\n"
        'data: {"jsonrpc": "2.0", "id": 1, "result": {"ok": true}}\n'
        "\n"
    )
    http, _ = transport(FakeResponse(body=body, content_type="text/event-stream"))

    assert http.send(REQUEST)["result"] == {"ok": True}


def test_multi_line_data_is_rejoined():
    """Conforming servers split a payload containing newlines across several `data:`
    lines. Rejoining it wrongly corrupts the message."""
    body = 'data: {"jsonrpc": "2.0",\ndata:  "id": 1,\ndata:  "result": {"ok": true}}\n\n'
    http, _ = transport(FakeResponse(body=body, content_type="text/event-stream"))

    assert http.send(REQUEST)["result"] == {"ok": True}


def test_a_final_event_without_a_trailing_blank_line_is_still_read():
    """Not all servers conform, and dropping a tool result over a missing newline
    would be a miserable way to lose one."""
    body = 'data: {"jsonrpc": "2.0", "id": 1, "result": {"ok": true}}'
    http, _ = transport(FakeResponse(body=body, content_type="text/event-stream"))

    assert http.send(REQUEST)["result"] == {"ok": True}


def test_a_session_id_on_a_streamed_response_is_captured():
    http, post = transport(
        sse({"jsonrpc": "2.0", "id": 1, "result": {}}, headers={"Mcp-Session-Id": "s1"}),
        reply(message_id=2),
    )

    http.send(REQUEST)
    http.send({**REQUEST, "id": 2})

    assert post.calls[1]["headers"]["Mcp-Session-Id"] == "s1"


# --- sessions --------------------------------------------------------------------


def test_a_session_id_is_captured_and_resent():
    http, post = transport(
        FakeResponse(body=json.dumps({"jsonrpc": "2.0", "id": 1, "result": {}}),
                     headers={"Mcp-Session-Id": "abc123"}),
        reply(message_id=2),
    )

    http.send(REQUEST)
    http.send({**REQUEST, "id": 2})

    assert "Mcp-Session-Id" not in post.calls[0]["headers"]
    assert post.calls[1]["headers"]["Mcp-Session-Id"] == "abc123"


def test_a_404_with_a_session_raises_session_expired():
    http, _ = transport(
        FakeResponse(body=json.dumps({"jsonrpc": "2.0", "id": 1, "result": {}}),
                     headers={"Mcp-Session-Id": "abc123"}),
        FakeResponse(status_code=404, body="unknown session"),
    )
    http.send(REQUEST)

    with pytest.raises(SessionExpired) as caught:
        http.send({**REQUEST, "id": 2})

    # Not a guess: the server told us it does not know this session, so it cannot
    # have executed anything under it. That is what makes retrying safe.
    assert caught.value.delivered is False


def test_an_expired_session_is_forgotten():
    """So the next attempt initializes cleanly instead of presenting a dead id."""
    http, post = transport(
        FakeResponse(body=json.dumps({"jsonrpc": "2.0", "id": 1, "result": {}}),
                     headers={"Mcp-Session-Id": "abc123"}),
        FakeResponse(status_code=404, body="unknown session"),
        reply(message_id=3),
    )
    http.send(REQUEST)
    with pytest.raises(SessionExpired):
        http.send({**REQUEST, "id": 2})

    http.send({**REQUEST, "id": 3})

    assert "Mcp-Session-Id" not in post.calls[2]["headers"]


def test_a_404_without_a_session_is_an_ordinary_client_error():
    """A wrong URL, not an expired session."""
    http, _ = transport(FakeResponse(status_code=404, body="no such endpoint"))

    with pytest.raises(TransportError) as caught:
        http.send(REQUEST)
    assert not isinstance(caught.value, SessionExpired)
    assert caught.value.delivered is False


def test_close_deletes_the_session():
    http, post = transport(
        FakeResponse(body=json.dumps({"jsonrpc": "2.0", "id": 1, "result": {}}),
                     headers={"Mcp-Session-Id": "abc123"}),
        FakeResponse(status_code=200, body=""),
    )
    http.send(REQUEST)

    http.close()

    assert post.calls[1]["method"] == "DELETE"
    assert post.calls[1]["headers"]["Mcp-Session-Id"] == "abc123"


def test_close_never_raises():
    """It runs on the way out, where a failure would mask the real one."""
    http, _ = transport(
        FakeResponse(body=json.dumps({"jsonrpc": "2.0", "id": 1, "result": {}}),
                     headers={"Mcp-Session-Id": "abc123"}),
        requests.exceptions.ConnectionError("gone"),
    )
    http.send(REQUEST)

    http.close()


def test_closing_without_a_session_sends_nothing():
    http, post = transport()

    http.close()

    assert post.calls == []


# --- what Session does about an expired one --------------------------------------
#
# This is the one place a write gets retried, so it is the one place worth being sure
# about. A server that returns 404 has told us it does not recognise the session, so
# it cannot have executed anything under it — nothing ran, so nothing can run twice.


def initialized(message_id, session_id="s1"):
    return FakeResponse(
        body=json.dumps(
            {
                "jsonrpc": "2.0",
                "id": message_id,
                "result": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "serverInfo": {"name": "fake", "version": "1"},
                },
            }
        ),
        headers={"Mcp-Session-Id": session_id},
    )


EXPIRED = FakeResponse(status_code=404, body="unknown session")


def session_over(*scripted):
    from carnet.tools.mcp.client import Session

    http, post = transport(*scripted)
    return Session(http), post


def test_an_expired_session_is_re_initialized_and_the_call_retried():
    session, post = session_over(
        initialized(1),                       # initialize
        ACCEPTED,                             # notifications/initialized
        EXPIRED,                              # tools/list -> session gone
        initialized(3, session_id="s2"),      # re-initialize
        ACCEPTED,                             # notifications/initialized again
        reply({"tools": [{"name": "x"}]}, message_id=4),
    )
    session.initialize()

    assert session.list_tools() == [{"name": "x"}]

    methods = [c["body"]["method"] for c in post.calls]
    assert methods == [
        "initialize",
        "notifications/initialized",
        "tools/list",
        "initialize",
        "notifications/initialized",
        "tools/list",
    ]


def test_the_new_session_id_is_used_after_re_initializing():
    session, post = session_over(
        initialized(1),
        ACCEPTED,
        EXPIRED,
        initialized(3, session_id="s2"),
        ACCEPTED,
        reply({"tools": []}, message_id=4),
    )
    session.initialize()
    session.list_tools()

    assert post.calls[-1]["headers"]["Mcp-Session-Id"] == "s2"


def test_a_session_that_expires_again_is_not_retried_forever():
    """A server that expires every session immediately is broken, and looping on it
    would turn one bad server into an infinite one."""
    session, post = session_over(
        initialized(1),
        ACCEPTED,
        EXPIRED,
        initialized(3, session_id="s2"),
        ACCEPTED,
        EXPIRED,
    )
    session.initialize()

    with pytest.raises(SessionExpired):
        session.list_tools()

    assert [c["body"]["method"] for c in post.calls].count("tools/list") == 2


def test_the_negotiated_protocol_version_is_what_gets_stamped():
    """Not the version we asked for — the one the server agreed to."""
    negotiated = FakeResponse(
        body=json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"protocolVersion": "2025-03-26", "capabilities": {}},
            }
        )
    )
    session, post = session_over(negotiated, ACCEPTED, reply({"tools": []}, message_id=2))
    session.initialize()
    session.list_tools()

    assert post.calls[-1]["headers"]["MCP-Protocol-Version"] == "2025-03-26"
