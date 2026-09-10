import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

import Failure from "../../components/Failure";
import { Button, Card, Field, Notice, PageHead, Spinner } from "../../components/ui";
import { ApiError, api } from "../../lib/api";
import { useResource } from "../../lib/useResource";

/** The consent page — where an MCP client's OAuth flow meets the person. Step 083.
 *
 *  A client that was handed only the door's URL registers itself, then sends the
 *  browser here with the authorize request in the query string. This page sits behind
 *  the app's gate, so by the time it renders the person has signed in with the identity
 *  provider they already have (`signIn` returns to `pathname + search`, so the query
 *  survives the round trip). It then shows the one sentence that matters, and two
 *  buttons.
 *
 *  ## What it asks the server, and what it never decides itself
 *
 *  `GET /oauth/clients/{id}` for the name and the registered redirect list — a
 *  registration is not a public directory, so that read needs the session too. Then
 *  `POST /oauth/consent` with the request's parameters and the decision, and the server
 *  answers with **where the browser goes next** — always a registered redirect URI, or a
 *  400 that names why nothing is redirected. The page navigates to whatever it is told
 *  and decides nothing about URLs: a consent page that sent a browser to an address the
 *  query string chose would be an open redirect on our own origin. The buttons are
 *  disabled until the server-returned list contains the request's `redirect_uri`, which
 *  is the same comparison the server makes, so a bad request is refused before a click
 *  rather than after one.
 *
 *  ## The sentence
 *
 *  The token this mints is *personal* (033d): the client acts as the person, reaches
 *  what they reach, and follows their access as it changes. That is what *connect your
 *  own assistant* means, and the page says so rather than offering a picker over agents
 *  it could not honour — a personal token cannot be narrowed. Narrowing a client to less
 *  than its owner is the tokens page's job (a service token, granted per agent).
 *
 *  The name is rendered as text and never trusted as an identity: anybody may register a
 *  client called anything. The host the browser will be sent back to is the one fact
 *  the page can show that the registrant did not simply type. */
export default function AuthorizePage() {
  const [params] = useSearchParams();
  const clientId = params.get("client_id") ?? "";
  const redirectUri = params.get("redirect_uri") ?? "";
  const { data: client, error, loading } = useResource(
    () => api.oauthClient(clientId),
    [clientId],
  );
  const [tokenName, setTokenName] = useState("");
  const [busy, setBusy] = useState<"approve" | "deny" | null>(null);
  const [problem, setProblem] = useState<string | null>(null);

  const registered = client !== null && client.redirect_uris.includes(redirectUri);
  const host = hostOf(redirectUri);

  async function decide(approve: boolean) {
    setBusy(approve ? "approve" : "deny");
    setProblem(null);
    try {
      const answer = await api.oauthConsent({
        client_id: clientId,
        redirect_uri: redirectUri,
        approve,
        state: params.get("state"),
        response_type: params.get("response_type"),
        code_challenge: params.get("code_challenge"),
        code_challenge_method: params.get("code_challenge_method"),
        resource: params.get("resource"),
        scope: params.get("scope"),
        token_name: tokenName.trim() || null,
      });
      window.location.assign(answer.redirect_to);
    } catch (failure) {
      setBusy(null);
      setProblem(
        failure instanceof ApiError
          ? failure.detail
          : "the request could not be sent. Try again.",
      );
    }
  }

  return (
    <>
      <PageHead
        title="Connect a client"
        lede={
          <>
            An application is asking to use this workspace&rsquo;s MCP server as you.
            Approving gives it a token of its own. You can revoke it at any time from{" "}
            <Link to="/tokens">Access tokens</Link>.
          </>
        }
      />

      {loading && <Spinner label="Loading the request…" />}
      {error && <Failure error={error} />}

      {client && !registered && (
        <Notice tone="bad" title="This request cannot be approved">
          The redirect address is not one <strong>{client.client_name}</strong> registered.
          Close this tab and start again from the application.
        </Notice>
      )}

      {client && registered && (
        <Card title={client.client_name} hint={host ? `sends you back to ${host}` : undefined}>
          <p className="sentence">
            <strong>{client.client_name}</strong> will act <strong>as you</strong>. It can
            use the tools of every agent shared with you, with your access. It never sees
            your sign-in. It receives a personal token, listed on Access tokens and revoked
            when your account is disabled.
          </p>
          <p className="muted sentence">
            To give an application <em>less</em> than you have, generate a service token
            on Access tokens and grant it agents instead.
          </p>
          {client.client_uri && (
            <p className="muted tiny">
              The application says it is <span className="mono">{client.client_uri}</span>.
              This workspace has not verified that.
            </p>
          )}

          <Field
            label="Token name"
            hint="Shown on Access tokens. Leave blank to use the application's name."
          >
            <input
              value={tokenName}
              onChange={(event) => setTokenName(event.target.value)}
              placeholder={client.client_name}
              maxLength={200}
              disabled={busy !== null}
            />
          </Field>

          {problem && (
            <Notice tone="bad" title="Not approved">
              {problem}
            </Notice>
          )}

          <div className="row-action consent-actions">
            <Button kind="primary" busy={busy === "approve"} disabled={busy === "deny"} onClick={() => void decide(true)}>
              Approve
            </Button>
            <Button busy={busy === "deny"} disabled={busy === "approve"} onClick={() => void decide(false)}>
              Deny
            </Button>
          </div>
        </Card>
      )}
    </>
  );
}

/** The host a redirect URI names, for the sentence — or the scheme for a native
 *  app's private-use URI (`cursor://…`), which has no host anybody recognises. */
function hostOf(uri: string): string {
  try {
    const parsed = new URL(uri);
    if (parsed.protocol === "https:" || parsed.protocol === "http:") return parsed.host;
    return `the ${parsed.protocol.replace(/:$/, "")} application`;
  } catch {
    return "";
  }
}
