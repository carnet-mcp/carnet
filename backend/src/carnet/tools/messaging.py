"""Chat messaging tools.

`webhook_url` is injected by the broker from its credential store. It is not in the
input_schema, so the model can neither see nor set it — and core/permissions.py
refuses the call outright if the model invents one.
"""

import json
from datetime import datetime, timezone

import requests

from ..config import OUTBOX_PATH, REQUEST_TIMEOUT, ensure_var_dir
from .base import Resource, Tool
from .mcp import egress


def post_message(channel: str, text: str, *, webhook_url: str | None = None) -> dict:
    """Post a message to a chat channel.

    Transport is chosen from the URL shape, so the same tool works for Slack and
    Discord unchanged. With no URL configured the message goes to a local outbox
    file, which makes the whole runtime exercisable with no external accounts.
    """
    if not webhook_url:
        ensure_var_dir()
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "channel": channel,
            "text": text,
        }
        with open(OUTBOX_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        return {
            "delivered": True,
            "channel": channel,
            "transport": "local-outbox",
            "note": "No webhook configured for this channel; written to var/outbox.jsonl.",
        }

    # Discord and Slack incoming webhooks differ only in the body key.
    is_discord = "discord.com/api/webhooks" in webhook_url
    payload = {"content": text} if is_discord else {"text": text}

    # Pinned like every other dial (step 064). This was the second call 058's closure
    # missed: a webhook URL is a credential the broker injects, so nothing above ever
    # sees the host, and it was reaching the network with no dial-time check at all —
    # and following redirects, which the connector dials had refused since birth.
    with requests.Session() as session:
        resp = egress.dial(session, "POST", webhook_url, json=payload, timeout=REQUEST_TIMEOUT)
        if resp.status_code >= 400:
            # Deliberately does not echo the URL — it's a secret.
            return {"error": f"Webhook delivery failed with HTTP {resp.status_code}."}

    return {
        "delivered": True,
        "channel": channel,
        "transport": "discord" if is_discord else "slack",
    }


TOOLS = [
    Tool(
        name="post_message",
        description=(
            "Post a message to a team chat channel. Use this to deliver a finished "
            "summary or report. You may only post to channels you are permitted to "
            "use; the call will be refused otherwise."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "channel": {
                    "type": "string",
                    "description": "Channel name including the leading '#', e.g. '#eng'.",
                },
                "text": {
                    "type": "string",
                    "description": "The message body. Markdown is supported.",
                },
            },
            "required": ["channel", "text"],
        },
        impl=post_message,
        # Message bodies are user content — hashed in the audit log, never stored raw.
        redact_args=frozenset({"text"}),
        # Posting is externally visible and irreversible: a write.
        effect="write",
        # `text` is payload, not a resource. `channel` is what gets scoped.
        resources=[Resource("chat.channel", "channel")],
    ),
]
