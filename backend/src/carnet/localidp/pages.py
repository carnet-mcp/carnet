"""The login and register screens, server-rendered.

The SPA deliberately grows no auth UI — these pages belong to the provider, the way
Okta's do. Everything is inline (one style block, no scripts, no external requests)
under the provider's own strict CSP, and the authorize request's parameters ride
through the form as hidden fields so a successful login can finish the flow it
interrupted.
"""

import html

# What an authorize request carries and a form must carry forward.
FLOW_FIELDS = (
    "client_id",
    "redirect_uri",
    "state",
    "code_challenge",
    "code_challenge_method",
    "scope",
)

_STYLE = """
  body { font-family: system-ui, sans-serif; background: #f4f5f7; color: #1a1d21;
         display: grid; place-items: center; min-height: 100vh; margin: 0; }
  main { background: #fff; border: 1px solid #d7dade; border-radius: 8px;
         padding: 2rem 2.5rem; width: 22rem; box-shadow: 0 1px 3px rgba(0,0,0,.06); }
  h1 { font-size: 1.1rem; margin: 0 0 .25rem; }
  p.what { color: #5a6069; font-size: .85rem; margin: 0 0 1.25rem; }
  label { display: block; font-size: .85rem; margin: .75rem 0 .25rem; }
  input { width: 100%; box-sizing: border-box; padding: .5rem .6rem; font: inherit;
          border: 1px solid #b9bec6; border-radius: 5px; }
  button { width: 100%; margin-top: 1.25rem; padding: .55rem; font: inherit;
           background: #1f6feb; color: #fff; border: 0; border-radius: 5px;
           cursor: pointer; }
  p.error { background: #fdeced; border: 1px solid #f5c2c7; color: #842029;
            border-radius: 5px; padding: .5rem .6rem; font-size: .85rem; }
  p.alt { font-size: .85rem; margin: 1rem 0 0; }
  p.first { background: #eef6ee; border: 1px solid #badbba; color: #1e4620;
            border-radius: 5px; padding: .5rem .6rem; font-size: .85rem; }
"""


def _hidden(params: dict) -> str:
    return "".join(
        f'<input type="hidden" name="{name}" value="{html.escape(params.get(name, ""), quote=True)}">'
        for name in FLOW_FIELDS
        if params.get(name)
    )


def _page(title: str, body: str) -> bytes:
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{html.escape(title)}</title><style>{_STYLE}</style></head>"
        f"<body><main>{body}</main></body></html>"
    ).encode()


def login_page(
    params: dict, error: str = "", registration_open: bool = True
) -> bytes:
    error_html = f'<p class="error">{html.escape(error)}</p>' if error else ""
    register = (
        '<p class="alt">No account yet? <a href="/idp/register'
        + _query(params)
        + '">Create one</a>.</p>'
        if registration_open
        else ""
    )
    return _page(
        "Sign in — Carnet",
        f"""
        <h1>Sign in</h1>
        <p class="what">The local identity provider for this deployment.</p>
        {error_html}
        <form method="post" action="/idp/login">
          {_hidden(params)}
          <label for="email">Email</label>
          <input id="email" name="email" type="email" autocomplete="username" required autofocus>
          <label for="password">Password</label>
          <input id="password" name="password" type="password" autocomplete="current-password" required>
          <button type="submit">Sign in</button>
        </form>
        {register}
        """,
    )


def register_page(
    params: dict,
    error: str = "",
    prefill_email: str = "",
    first_account: bool = False,
) -> bytes:
    error_html = f'<p class="error">{html.escape(error)}</p>' if error else ""
    first = (
        '<p class="first">This is the first account, so it becomes the '
        "administrator.</p>"
        if first_account
        else ""
    )
    return _page(
        "Create account — Carnet",
        f"""
        <h1>Create account</h1>
        <p class="what">The local identity provider for this deployment.</p>
        {first}
        {error_html}
        <form method="post" action="/idp/register">
          {_hidden(params)}
          <label for="email">Email</label>
          <input id="email" name="email" type="email" autocomplete="username" required
                 value="{html.escape(prefill_email, quote=True)}">
          <label for="name">Name</label>
          <input id="name" name="name" type="text" autocomplete="name">
          <label for="password">Password</label>
          <input id="password" name="password" type="password" autocomplete="new-password" required>
          <button type="submit">Create account</button>
        </form>
        <p class="alt">Already have one? <a href="/idp/login{_query(params)}">Sign in</a>.</p>
        """,
    )


def registration_closed_page() -> bytes:
    return _page(
        "Registration closed — Carnet",
        """
        <h1>Registration is closed</h1>
        <p class="what">An administrator closed self-registration on this deployment.
        Ask them to create your account, or to reopen registration.</p>
        """,
    )


def _query(params: dict) -> str:
    from urllib.parse import urlencode

    kept = {k: v for k, v in params.items() if k in FLOW_FIELDS and v}
    return "?" + urlencode(kept) if kept else ""
