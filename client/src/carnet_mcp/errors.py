"""What can go wrong between an agent and the door, in two kinds.

The split is the one a model can act on. A **refusal** is the door answering — a token
it does not accept, a tool this token is not granted, an argument it will not record —
and the sentence it answers with is something a model can read and adapt to. An
**unavailable** door did not answer: the connection failed, timed out, or came back as
a gateway error or a body that is not JSON. No sentence a model reads changes that.

A brokered denial — *this call is outside the agent's scope* — is deliberately neither.
The door returns it as a `tools/call` **result** with `isError: true`, because from the
caller's side a broker refusing and a tool failing are the same thing: the tool did not
do what was asked, and here is why. `_door.CallResult.is_error` carries it, and the
adapters relay it on the framework's tool-error channel rather than raising, so a model
sees *denied: 'OTHER' is outside this agent's 'read' scope. Allowed: ACME* and can say
so. An agent that crashes on a denial makes least privilege look like a bug.
"""


class DoorError(Exception):
    """Base of the two, so a caller who wants one `except` has one."""


class DoorRefused(DoorError):
    """The door answered and said no.

    `message` is the door's own sentence, relayed. `code` is the JSON-RPC error code when
    the refusal came inside the envelope (an ungranted tool name is `-32602`), and
    `status` is the HTTP status when it came as one (a bad token is `401`). One of the
    two is set; a refusal is never both.
    """

    def __init__(self, message: str, *, code: int | None = None, status: int | None = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status


class DoorUnavailable(DoorError):
    """The door did not answer: a connection failure, a timeout, a 5xx, or a body that
    is not the protocol. Not something a model can adapt to, so the adapters let it
    propagate and end the turn."""


class ProtocolVersionWarning(UserWarning):
    """The door negotiated a protocol revision this client does not know. Warned once at
    the handshake and then ignored: the door is self-hosted and often older or newer
    than the client, and refusing to start would make upgrading either a coordinated
    deployment. The five methods this client uses have not changed across the three
    revisions the door speaks."""
