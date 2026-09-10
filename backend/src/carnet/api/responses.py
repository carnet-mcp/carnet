"""One response class, for the bodies this API does not write itself.

Starlette renders JSON with `ensure_ascii=False`, which is right for text this codebase
composes and wrong for text that merely passes through it. Two places pass text
through: a 422 echoes the caller's own offending `input`, and — found by step 108's
edge pass — the MCP door's `tools/call` result **is the connector's response body**.

A lone surrogate is the value that separates them. `\\ud800` is legal JSON syntax that
`json.loads` turns into a string UTF-8 cannot encode, so a caller's 422 and a vendor's
answer both died in `render` and became a **500** — in the door's case after the call
had already executed and been paid for.

This lives in its own module rather than in `errors.py` because `errors.py` imports the
door's endpoint (to widen its 401 challenge), so the door cannot import from it.
"""

import json

from fastapi.responses import JSONResponse


class AsciiJSONResponse(JSONResponse):
    """A `JSONResponse` that escapes non-ASCII on the way out. Step 087, step 108.

    Same status, same shape, same fields; only the escaping differs, and every JSON
    parser reads both. `allow_nan=False` for the same family of reason: a bare `NaN` is
    not JSON and no client's parser is obliged to accept it.
    """

    def render(self, content) -> bytes:
        return json.dumps(
            content, ensure_ascii=True, allow_nan=False, indent=None, separators=(",", ":")
        ).encode("utf-8")
