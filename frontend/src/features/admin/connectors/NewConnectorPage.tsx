import { useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";

import Failure from "../../../components/Failure";
import {
  Badge,
  BrandMark,
  Button,
  Card,
  Field,
  FieldGroup,
  Icon,
  Notice,
  PageHead,
  Spinner,
} from "../../../components/ui";
import { api } from "../../../lib/api";
import type { ConnectorDetail, DiscoveryResult, HostEntry, Recipe } from "../../../lib/types";
import { useResource } from "../../../lib/useResource";
import { AuthorTool, Discovery } from "../ConnectorDetailPage";

/** Adding a connector, as a sequence on its own pages — plan 107, decision 4.
 *
 * Setup used to be four cards on the list page and five on the connector's, gated by state
 * the reader had to infer: *Discover* answered a 401 until a credential existed, the OAuth
 * form opened blank, and the stage somebody was on was nowhere on the screen. The owner's
 * report was that the flow was invisible, and order alone does not make a stage visible —
 * a stepper says *you are on 4 of 6* and a stack of cards does not.
 *
 * One question per screen, in the order the backend needs them: a credential cannot be
 * sealed against a connector that does not exist, no server lists its tools to an
 * unauthenticated caller, and registration checks the address's host against the
 * allowlist. So: start (a preset, or not), the address and its host, the server, the
 * credentials — the shared one and the OAuth app, **pre-filled from the preset**, which
 * is the step the owner found blank — then the tools, then done.
 *
 * **A client over routes that already exist.** Nothing here is a new write: the host is
 * `POST /admin/hosts`, the registration `POST /admin/connectors` with the preset applied
 * on the server (110 D6), the OAuth app `PUT .../oauth`, discovery and approval the
 * connector page's own components, imported rather than reimplemented. Registration
 * happens once, at the end of the credentials step, because it is the first write that
 * needs everything the earlier steps asked; coming back afterwards lands on the tools
 * step through `?connector=`, which is what a reload does too.
 *
 * **A recipe is a default, never a dependency.** Every value it supplies is in an
 * editable field, and the server merges the preset under what the person changed — so a
 * stale preset costs one form's worth of wrong defaults, never a broken registration.
 */

type Kind = "http" | "rest";

interface Step {
  key: "start" | "address" | "server" | "credentials" | "tools" | "done";
  title: string;
}

const STEPS: Step[] = [
  { key: "start", title: "Start" },
  { key: "address", title: "Address" },
  { key: "server", title: "Server" },
  { key: "credentials", title: "Credentials" },
  { key: "tools", title: "Tools" },
  { key: "done", title: "Done" },
];

/** The host of a URL, as the allowlist spells one — lowercase, no port. The server's
 *  `host_of` is the authority; this only decides which row on the allowlist to point
 *  at, and a URL that does not parse points at none. */
export function hostOf(url: string): string {
  try {
    return new URL(url.trim()).hostname.toLowerCase();
  } catch {
    return "";
  }
}

export default function NewConnectorPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  // A reload after registering, or a link somebody sent: the connector exists, so the
  // steps before it are answered and the tools step is the first incomplete one.
  const resumed = params.get("connector") ?? "";

  const hosts = useResource(() => api.listHosts(), []);
  const recipes = useResource(() => api.listRecipes(), []);

  const [step, setStep] = useState(resumed ? 4 : 0);
  const [chosen, setChosen] = useState<Recipe | null>(null);
  const [url, setUrl] = useState("");
  const [id, setId] = useState("");
  const [kind, setKind] = useState<Kind>("http");
  const [description, setDescription] = useState("");
  const [created, setCreated] = useState<string>(resumed);

  const approved = (hosts.data ?? []).filter((row) => !row.warning);
  const host = hostOf(url);
  const hostApproved = approved.some((row) => row.host === host);

  /** A preset's values become the fields' state at the moment it is chosen — a
   *  remount's worth of initial state, applied once, so a value somebody then edits is
   *  not overwritten by an effect deciding what to do about it. */
  const choose = (recipe: Recipe | null) => {
    setChosen(recipe);
    const preset = recipe?.connector;
    setUrl(preset?.url ?? "");
    setId(preset?.connector_id ?? "");
    setKind(preset?.kind ?? "http");
    setDescription(preset?.description ?? "");
  };

  const blockers: Record<Step["key"], string> = {
    start: hosts.error ? "The allowlist could not be read." : "",
    address: !url.trim()
      ? "Enter the server's address."
      : !host
        ? "The address is not a URL."
        : !hostApproved
          ? `Approve ${host} to continue. Connectors can only connect to approved hosts.`
          : "",
    server: !id.trim() ? "Enter an ID." : "",
    credentials: "",
    tools: "",
    done: "",
  };
  const current = STEPS[step];
  const blocker = blockers[current.key];

  return (
    <>
      <Link className="back" to="/admin/connectors">
        ← Connectors
      </Link>
      <PageHead
        title="Add a connector"
        lede="An MCP server or a REST API that agents can use tools from. Six steps, in the order the setup needs them."
      />

      <ol className="steps">
        {STEPS.map((s, i) => (
          <li key={s.key} className={i === step ? "on" : i < step ? "done" : ""}>
            <button
              type="button"
              // Backwards only, and never back across the registration: once the row
              // exists the first four steps are facts, and the connector's own page
              // is where they change.
              disabled={i > step || (created !== "" && i < 4)}
              onClick={() => setStep(i)}
            >
              <span className="n">{i < step ? <Icon name="check" size={12} /> : i + 1}</span>
              {s.title}
            </button>
          </li>
        ))}
      </ol>

      {current.key === "start" && (
        <StepStart
          recipes={recipes}
          chosen={chosen}
          onChoose={choose}
          approved={approved}
          onAllowed={hosts.reload}
          canAllow={Boolean(hosts.data)}
        />
      )}
      {current.key === "address" && (
        <StepAddress
          url={url}
          onUrl={setUrl}
          kind={kind}
          host={host}
          hosts={hosts}
          approved={hostApproved}
          onApproved={hosts.reload}
        />
      )}
      {current.key === "server" && (
        <StepServer
          id={id}
          onId={setId}
          kind={kind}
          onKind={setKind}
          description={description}
          onDescription={setDescription}
        />
      )}
      {current.key === "credentials" && (
        <StepCredentials
          recipe={chosen}
          connectorId={id.trim()}
          url={url.trim()}
          kind={kind}
          description={description.trim()}
          onRegistered={(connectorId) => {
            setCreated(connectorId);
            // In the URL, so a reload lands here rather than at Start with a
            // registration already made.
            navigate(`/admin/connectors/new?connector=${encodeURIComponent(connectorId)}`, {
              replace: true,
            });
            setStep(4);
          }}
        />
      )}
      {current.key === "tools" && created && <StepTools connectorId={created} />}
      {current.key === "done" && created && <StepDone connectorId={created} />}

      {current.key !== "credentials" && current.key !== "done" && (
        <div className="spread wizard-nav">
          <Button
            disabled={step === 0 || (created !== "" && step <= 4)}
            onClick={() => setStep(step - 1)}
          >
            Back
          </Button>
          <Button kind="primary" disabled={blocker !== ""} onClick={() => setStep(step + 1)}>
            {current.key === "tools" ? "Done" : "Continue"}
          </Button>
          {blocker ? <span className="muted">{blocker}</span> : null}
        </div>
      )}
    </>
  );
}

/** Step 1 — a preset, or not. The chooser from the old list page, moved: it names the
 *  addresses a preset needs, so it is the thing that answers *which hosts do I approve*,
 *  and the next step is where that answer is acted on. */
function StepStart({
  recipes,
  chosen,
  onChoose,
  approved,
  onAllowed,
  canAllow,
}: {
  recipes: ReturnType<typeof useResource<Recipe[]>>;
  chosen: Recipe | null;
  onChoose: (recipe: Recipe | null) => void;
  approved: HostEntry[];
  onAllowed: () => void;
  canAllow: boolean;
}) {
  return (
    <Card title="Start">
      <p className="sentence">
        Start from a preset for an app this version knows, or from nothing. A preset fills
        in the steps that follow; every value stays editable.
      </p>
      <RecipeChooser
        resource={recipes}
        chosen={chosen}
        onChoose={onChoose}
        approved={approved}
        onAllowed={onAllowed}
        canAllow={canAllow}
      />
    </Card>
  );
}

/** Step 2 — the address, and the host it points at. **Approve host** inline when the
 *  host is not on the allowlist: the same request the allowlist card makes, offered where
 *  the question is asked. A host that can never be dialled is approved with a warning and
 *  does not count — the refusal would otherwise arrive at the first call. */
function StepAddress({
  url,
  onUrl,
  kind,
  host,
  hosts,
  approved,
  onApproved,
}: {
  url: string;
  onUrl: (url: string) => void;
  kind: Kind;
  host: string;
  hosts: ReturnType<typeof useResource<HostEntry[]>>;
  approved: boolean;
  onApproved: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");
  const [warning, setWarning] = useState("");

  const approve = () => {
    setBusy(true);
    setFailure("");
    setWarning("");
    api
      .approveHost(host, "")
      .then((outcome) => {
        setWarning(outcome.warning);
        onApproved();
      })
      .catch((cause: unknown) =>
        setFailure(cause instanceof Error ? cause.message : String(cause)),
      )
      .finally(() => setBusy(false));
  };

  return (
    <Card title="Address">
      <Field
        label="Address"
        hint={
          kind === "rest"
            ? "The base URL each tool's path is joined to."
            : "The Streamable HTTP endpoint."
        }
      >
        <input
          value={url}
          placeholder={kind === "rest" ? "https://api.acme.com/v1" : "https://mcp.acme.com/mcp"}
          onChange={(e) => onUrl(e.target.value)}
        />
      </Field>

      {hosts.error ? <Failure error={hosts.error} /> : null}
      {hosts.loading && <Spinner label="Loading approved hosts…" />}

      {host && hosts.data && (
        <div className="spread">
          <span>
            <code>{host}</code>{" "}
            {approved ? (
              <Badge tone="good">approved</Badge>
            ) : (
              <Badge tone="warn">not approved</Badge>
            )}
          </span>
          {!approved && (
            <Button busy={busy} onClick={approve}>
              Approve host
            </Button>
          )}
        </div>
      )}
      {host && hosts.data && !approved && (
        <p className="muted">
          Connectors can only connect to approved hosts. Approving one is a deliberate act,
          recorded under your name.
        </p>
      )}

      {failure && (
        <Notice tone="warn">
          <p className="sentence">{failure}</p>
        </Notice>
      )}
      {warning && (
        <Notice tone="warn" title="Approved, and not reachable">
          <p className="sentence">{warning}</p>
        </Notice>
      )}
    </Card>
  );
}

/** Step 3 — what it is. The kind is chosen here and never edited: it decides how tools
 *  get onto this connector at all, and there is no update path. */
function StepServer({
  id,
  onId,
  kind,
  onKind,
  description,
  onDescription,
}: {
  id: string;
  onId: (id: string) => void;
  kind: Kind;
  onKind: (kind: Kind) => void;
  description: string;
  onDescription: (d: string) => void;
}) {
  const rest = kind === "rest";
  return (
    <Card title="Server">
      <Field label="ID" hint="Lowercase letters, digits and hyphens. Prefixes every tool name.">
        <input value={id} placeholder="jira" onChange={(e) => onId(e.target.value)} />
      </Field>

      <div className="choices stacked" role="radiogroup" aria-label="What kind of server it is">
        <label className={`choice big${rest ? "" : " on"}`}>
          <input type="radio" name="connector-kind" checked={!rest} onChange={() => onKind("http")} />
          <span>
            <strong>MCP server</strong>
            <span className="muted"> — Tools are discovered from the server. Streamable HTTP.</span>
          </span>
        </label>
        <label className={`choice big${rest ? " on" : ""}`}>
          <input type="radio" name="connector-kind" checked={rest} onChange={() => onKind("rest")} />
          <span>
            <strong>REST API</strong>
            <span className="muted">
              {" "}
              — You write each tool&rsquo;s schema and request mapping. Used for model providers.
            </span>
          </span>
        </label>
      </div>

      <Field label="Description" hint="Optional. Shown when choosing tools.">
        <input value={description} onChange={(e) => onDescription(e.target.value)} />
      </Field>
    </Card>
  );
}

/** Step 4 — the credentials, and the write. Two panels: the shared credential (an
 *  environment variable or a vault reference, with the REST scheme folded under it) and
 *  the OAuth app, **pre-filled from the preset** — endpoints, scopes and parameters, never
 *  the client id or secret, which a checked-in file cannot carry. Either or both.
 *
 *  **Register** is here because this is the first step with everything the row needs.
 *  It registers, then configures the OAuth app when a client id was entered; a refused
 *  OAuth app leaves the registration standing and says so, since that is what happened. */
function StepCredentials({
  recipe,
  connectorId,
  url,
  kind,
  description,
  onRegistered,
}: {
  recipe: Recipe | null;
  connectorId: string;
  url: string;
  kind: Kind;
  description: string;
  onRegistered: (connectorId: string) => void;
}) {
  const preset = recipe?.connector;
  const [held, setHeld] = useState<"env" | "vault">("env");
  const [credentialEnv, setCredentialEnv] = useState(preset?.credential_env ?? "");
  const [credentialRef, setCredentialRef] = useState("");
  // `null` on the wire means *the launch's own default*, which is what a blank box means
  // here — so a preset that does not override the header arrives as a blank box rather
  // than as the literal word "Authorization".
  const [credentialHeader, setCredentialHeader] = useState(preset?.credential_header ?? "");
  // Starts at the real default and is ALWAYS sent for a REST connector (061): what the
  // field shows is what precedes the credential. A preset's `""` (an x-api-key vendor)
  // survives; its `null` takes the default.
  const [credentialPrefix, setCredentialPrefix] = useState(preset?.credential_prefix ?? "Bearer ");
  const [headers, setHeaders] = useState<{ name: string; value: string }[]>(
    Object.entries(preset?.headers ?? {}).map(([name, value]) => ({ name, value })),
  );
  const [asserts, setAsserts] = useState(false);

  const app = recipe?.oauth ?? null;
  const [authorize, setAuthorize] = useState(app?.authorize_endpoint ?? "");
  const [token, setToken] = useState(app?.token_endpoint ?? "");
  const [revoke, setRevoke] = useState(app?.revoke_endpoint ?? "");
  const [scopes, setScopes] = useState((app?.scopes ?? []).join(" "));
  const [clientId, setClientId] = useState("");
  const [secret, setSecret] = useState("");

  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");
  const [oauthFailure, setOauthFailure] = useState("");
  // Set when the row was registered and the OAuth app was refused: the step stays, with
  // the refusal and the way on, and Register is not offered twice for one row.
  const [registeredAnyway, setRegisteredAnyway] = useState("");

  const rest = kind === "rest";
  const wantsOauth = clientId.trim() !== "";

  const register = () => {
    setBusy(true);
    setFailure("");
    setOauthFailure("");
    api
      .registerConnector({
        connector_id: connectorId,
        url,
        kind,
        // Exactly one of the two is ever sent, and the other is sent EMPTY rather than
        // omitted — so switching the choice cannot leave the previous answer behind.
        credential_env: held === "env" ? credentialEnv.trim() : "",
        credential_ref: held === "vault" ? credentialRef.trim() : "",
        description,
        allow_asserted_identity: asserts,
        // The preset is applied on the server (110 D6): every field left empty takes
        // its value, under one merge rule the CLI shares.
        ...(recipe ? { from_recipe: recipe.id } : {}),
        ...(rest && credentialHeader.trim() ? { credential_header: credentialHeader.trim() } : {}),
        ...(rest ? { credential_prefix: credentialPrefix } : {}),
        ...(rest && headers.some((h) => h.name.trim())
          ? {
              headers: Object.fromEntries(
                headers.filter((h) => h.name.trim()).map((h) => [h.name.trim(), h.value]),
              ),
            }
          : {}),
      })
      .then(() => {
        if (!wantsOauth) return;
        return api
          .configureOAuth(connectorId, {
            authorize_endpoint: authorize.trim(),
            token_endpoint: token.trim(),
            revoke_endpoint: revoke.trim(),
            client_id: clientId.trim(),
            client_secret: secret,
            scopes: scopes.split(/\s+/).filter(Boolean),
            scope_notes: Object.fromEntries(
              Object.entries(app?.scope_notes ?? {}).filter(([scope]) =>
                scopes.split(/\s+/).includes(scope),
              ),
            ),
            authorize_params: app?.authorize_params ?? {},
          })
          .then(() => "ok" as const)
          .catch((cause: unknown) => {
            // The row stands; the flow does not. Said as it is, on this step, with the
            // way on — and the connector's own page is where the OAuth app is set up next.
            setOauthFailure(cause instanceof Error ? cause.message : String(cause));
            setRegisteredAnyway(connectorId);
            return "refused" as const;
          });
      })
      .then((outcome) => {
        setSecret("");
        if (outcome !== "refused") onRegistered(connectorId);
      })
      .catch((cause: unknown) =>
        setFailure(cause instanceof Error ? cause.message : String(cause)),
      )
      .finally(() => setBusy(false));
  };

  return (
    <>
      <Card title="Shared credential" hint="optional">
        <p className="sentence">
          The credential every call uses unless the caller has connected their own account.
        </p>
        <div className="choices stacked" role="radiogroup" aria-label="Where the shared key is kept">
          <label className={`choice big${held === "env" ? " on" : ""}`}>
            <input type="radio" name="credential-held" checked={held === "env"} onChange={() => setHeld("env")} />
            <span>
              <strong>Environment variable</strong>
              <span className="muted"> — Read from this deployment&rsquo;s environment. The default.</span>
            </span>
          </label>
          <label className={`choice big${held === "vault" ? " on" : ""}`}>
            <input type="radio" name="credential-held" checked={held === "vault"} onChange={() => setHeld("vault")} />
            <span>
              <strong>Vault reference</strong>
              <span className="muted">
                {" "}
                — A 1Password reference, read on every call and never stored here. Calls
                are slower and fail while the vault is unavailable.
              </span>
            </span>
          </label>
        </div>

        {held === "env" ? (
          <Field label="Credential variable" hint="Optional. The environment variable holding the shared credential.">
            <input value={credentialEnv} placeholder="JIRA_TOKEN" onChange={(e) => setCredentialEnv(e.target.value)} />
          </Field>
        ) : (
          <Field label="Vault reference" hint="The credential's location in your 1Password vault. Item IDs resolve faster than names.">
            <input
              value={credentialRef}
              placeholder="op://Engineering/Jira/credential"
              onChange={(e) => setCredentialRef(e.target.value)}
            />
          </Field>
        )}

        {rest && (
          <details className="more">
            <summary>How the credential is sent</summary>
            <div className="more-body">
              <Field label="Credential header" hint="The header the API reads the credential from. Blank means Authorization.">
                <input value={credentialHeader} placeholder="x-api-key" onChange={(e) => setCredentialHeader(e.target.value)} />
              </Field>
              <Field label="Credential prefix" hint="Sent before the credential, trailing space included. Clear it to send the bare token.">
                <input value={credentialPrefix} onChange={(e) => setCredentialPrefix(e.target.value)} />
              </Field>
              <FieldGroup label="Other headers" hint="Sent on every request, for example an API version. Not secret.">
                {headers.map((header, index) => (
                  <div className="spread" key={index}>
                    <input
                      value={header.name}
                      placeholder="anthropic-version"
                      onChange={(e) => setHeaders(headers.map((h, i) => (i === index ? { ...h, name: e.target.value } : h)))}
                    />
                    <input
                      value={header.value}
                      placeholder="2023-06-01"
                      onChange={(e) => setHeaders(headers.map((h, i) => (i === index ? { ...h, value: e.target.value } : h)))}
                    />
                    <Button kind="quiet" onClick={() => setHeaders(headers.filter((_, i) => i !== index))}>
                      Remove
                    </Button>
                  </div>
                ))}
                <Button onClick={() => setHeaders([...headers, { name: "", value: "" }])}>Add a header</Button>
              </FieldGroup>
            </div>
          </details>
        )}
      </Card>

      <Card title="OAuth app" hint="optional">
        <p className="sentence">
          Lets users connect their own accounts. Without it, every call uses the shared
          credential. Leave the client ID empty to set it up later on the connector&rsquo;s page.
        </p>
        {app && (
          <Notice tone="info" title={`From the ${recipe?.name} preset`}>
            <p className="sentence">
              Endpoints and scopes are from the {recipe?.name} preset
              {recipe?.verified_on ? `, verified on ${recipe.verified_on}` : ", not yet verified"}.
              Enter the client ID and secret from your OAuth app.
            </p>
          </Notice>
        )}
        <Field label="Client ID" hint="Public. Appears in the authorize URL.">
          <input value={clientId} placeholder="client-id" onChange={(e) => setClientId(e.target.value)} />
        </Field>
        <Field label="Client secret" hint="Stored once. You can't view it again.">
          <input type="password" value={secret} onChange={(e) => setSecret(e.target.value)} />
        </Field>
        <Field label="Authorize endpoint">
          <input value={authorize} placeholder="https://auth.acme.com/authorize" onChange={(e) => setAuthorize(e.target.value)} />
        </Field>
        <Field label="Token endpoint">
          <input value={token} placeholder="https://auth.acme.com/token" onChange={(e) => setToken(e.target.value)} />
        </Field>
        <Field label="Revoke endpoint" hint="Optional.">
          <input value={revoke} onChange={(e) => setRevoke(e.target.value)} />
        </Field>
        <Field label="Scopes" hint="Space-separated.">
          <input value={scopes} onChange={(e) => setScopes(e.target.value)} />
        </Field>
      </Card>

      <Card title="Register">
        <label className="choice big">
          <input type="checkbox" checked={asserts} onChange={(e) => setAsserts(e.target.checked)} />
          <span>
            <strong>Accept asserted identity</strong>
            <span className="muted">
              {" "}
              — A calling service may name who it acts on behalf of without verification.
              Such calls are logged as <code>asserted</code>, not <code>verified</code>. You
              can change this later on the connector&apos;s page.
            </span>
          </span>
        </label>

        {failure && (
          <Notice tone="warn">
            <p className="sentence">{failure}</p>
          </Notice>
        )}
        {oauthFailure && (
          <Notice tone="warn" title="Registered, and the OAuth app was not set up">
            <p className="sentence">{oauthFailure}</p>
            <p className="sentence">
              The connector is registered. Set up the OAuth app on its page, or continue to
              the tools.
            </p>
            <Button onClick={() => onRegistered(registeredAnyway)}>Continue to tools</Button>
          </Notice>
        )}

        {!registeredAnyway && (
          <>
            <Button kind="primary" busy={busy} disabled={!connectorId || !url} onClick={register}>
              Register
            </Button>
            <p className="muted">Next: approve the tools you want to make available.</p>
          </>
        )}
      </Card>
    </>
  );
}

/** Step 5 — the tools, through the connector page's own components, so approving here
 *  and approving there are one implementation. The credential sentence above Discover is
 *  the whole reason this step sits after the credentials one. */
function StepTools({ connectorId }: { connectorId: string }) {
  const connector = useResource(() => api.getConnector(connectorId), [connectorId]);
  const [seen, setSeen] = useState<DiscoveryResult | null>(null);

  if (connector.loading) return <Spinner label="Loading…" />;
  if (connector.error) return <Failure error={connector.error} />;
  const detail: ConnectorDetail | null = connector.data;
  if (!detail) return null;

  return detail.transport === "rest" ? (
    <AuthorTool connectorId={connectorId} vetted={detail.tools} onVetted={connector.reload} />
  ) : (
    <Discovery
      connectorId={connectorId}
      vetted={detail.tools}
      oauth={detail.oauth !== null}
      seen={seen}
      onSeen={setSeen}
      openTool={null}
      onVetted={connector.reload}
    />
  );
}

/** Step 6 — done. The connector's page, opened for the first time, and the next thing
 *  that makes these tools usable: an agent that grants them. */
function StepDone({ connectorId }: { connectorId: string }) {
  const connector = useResource(() => api.getConnector(connectorId), [connectorId]);
  const approved = connector.data?.vetted ?? 0;

  return (
    <Card title="Done">
      <p className="sentence">
        <strong>{connectorId}</strong> is registered
        {connector.data
          ? approved === 0
            ? " with no tools approved yet. Approve them on its page."
            : ` with ${approved} tool${approved === 1 ? "" : "s"} approved.`
          : "."}
      </p>
      <div className="spread">
        <Button kind="primary" to={`/admin/connectors/${connectorId}`}>
          Open the connector
        </Button>
        <Button to="/agents/new">Next: share these tools through an agent</Button>
      </div>
    </Card>
  );
}

/** Stage 1b: the apps this build ships a preset for. Step 068, redrawn by 091.
 *
 * **A recipe fills the form below and decides nothing.** It switches nothing on, allows no
 * address, and carries no client id or secret — every one of those is a property of the
 * checked-in files rather than of this component, so none of them can be undone by an edit
 * here. What it does is set the initial state of a form, which is why choosing one is a
 * remount rather than a mutation.
 *
 * **091: the addresses it needs can be allowed from here.** They used to be listed here and
 * allowed from a form in a different card, which is the question and the answer on opposite
 * ends of a page. `Allow` posts exactly the request that form posts — same endpoint, same
 * deliberate act by somebody who may make it, offered where the question is asked.
 */
function RecipeChooser({
  resource,
  chosen,
  onChoose,
  approved,
  onAllowed,
  canAllow,
}: {
  resource: ReturnType<typeof useResource<Recipe[]>>;
  chosen: Recipe | null;
  onChoose: (recipe: Recipe | null) => void;
  approved: HostEntry[];
  onAllowed: () => void;
  /** False when the allowlist could not be read — the 403 case. An `Allow` button that
   *  refuses the person who pressed it reads as a bug where its absence reads as a rule,
   *  which is `your_role`'s lesson applied to the second control that learned it. */
  canAllow: boolean;
}) {
  const [allowing, setAllowing] = useState("");
  const [failure, setFailure] = useState("");

  if (resource.loading) return <Spinner label="Loading presets…" />;
  // A failed catalogue is not a failed page: everything below still works, and the whole
  // feature is a convenience over a form somebody can fill in by hand. Saying so beats
  // rendering `Failure` and implying registration is broken.
  if (resource.error)
    return (
      <p className="sentence muted">
        Presets could not be loaded ({String(resource.error)}). You can still register a
        connector below.
      </p>
    );
  const recipes = resource.data ?? [];
  if (recipes.length === 0) return null;

  const approvedHosts = new Set(approved.map((row) => row.host));

  const allow = (host: string, why: string) => {
    setAllowing(host);
    setFailure("");
    api
      .approveHost(host, why)
      .then(onAllowed)
      .catch((cause: unknown) =>
        setFailure(cause instanceof Error ? cause.message : String(cause)),
      )
      .finally(() => setAllowing(""));
  };

  return (
    <>
      <FieldGroup label="Start from a preset" hint="A preset fills in the form below.">
        <div className="pick-grid">
          {recipes.map((recipe) => (
            <label
              key={recipe.id}
              className={`pick-card${chosen?.id === recipe.id ? " on" : ""}`}
            >
              <input
                type="radio"
                name="recipe"
                checked={chosen?.id === recipe.id}
                onChange={() => onChoose(recipe)}
              />
              <BrandMark hints={[recipe.id, recipe.connector.connector_id]} size={36} />
              <span className="pick-name">{recipe.name}</span>
            </label>
          ))}
          <label className={`pick-card${chosen === null ? " on" : ""}`}>
            <input
              type="radio"
              name="recipe"
              checked={chosen === null}
              onChange={() => onChoose(null)}
            />
            <BrandMark hints={[]} plain size={36} />
            <span className="pick-name">Something else</span>
          </label>
        </div>
      </FieldGroup>

      {chosen && (
        <div className="recipe-detail">
          {/* Staleness is computed by the server and rendered as a fact, never hidden. We
              are not in the call path of a consent flow once the URL is handed over, so a
              vendor moving an endpoint is something we learn from a customer — there is no
              freshness to check, only a claim to stop making. */}
          <p className="sentence">
            <strong>{chosen.name}</strong>{" "}
            {chosen.staleness === "verified" ? (
              <Badge tone="good">checked {chosen.verified_on}</Badge>
            ) : chosen.staleness === "stale" ? (
              <Badge tone="warn">last checked {chosen.verified_on}</Badge>
            ) : (
              <Badge tone="warn">not checked</Badge>
            )}
          </p>
          <p className="sentence muted">{chosen.description}</p>

          {chosen.staleness !== "verified" && (
            <Notice tone="warn" title="Check these values against the vendor">
              <p className="sentence">
                {chosen.staleness === "unverified"
                  ? "These endpoints and scopes have not been verified."
                  : `These values were last checked on ${chosen.verified_on}.`}{" "}
                Vendors change OAuth endpoints and scopes. You can edit every field below
                before you register.
              </p>
            </Notice>
          )}

          {/* The addresses, with the button that allows one beside the reason it is
              needed. Allowing is still a separate deliberate act — it is the same act,
              in the place the question is asked. */}
          <p className="sentence">
            <strong>Hosts this preset needs.</strong> Connectors can only connect to
            approved hosts.
          </p>
          <ul className="needs">
            {chosen.hosts.map((host) => (
              <li key={host.host} className="needs-host">
                <span className="needs-name">
                  {/* The address and its state on one line, then the reason under it.
                      A `Badge` is `display: inline-flex` and stretches to whatever box it
                      is a flex item of — in a column that is the full width of the row. */}
                  <span className="needs-top">
                    <code>{host.host}</code>
                    {approvedHosts.has(host.host) ? (
                      <Badge tone="good">approved</Badge>
                    ) : (
                      <Badge tone="warn">not approved</Badge>
                    )}
                  </span>
                  <span className="row-sub">{host.why}</span>
                </span>
                {!approvedHosts.has(host.host) && canAllow && (
                  <Button
                    busy={allowing === host.host}
                    onClick={() => allow(host.host, host.why)}
                  >
                    Allow
                  </Button>
                )}
              </li>
            ))}
          </ul>
          {failure && (
            <Notice tone="warn">
              <p className="sentence">{failure}</p>
            </Notice>
          )}

          {/* The two things a preset deliberately did not do, said out loud. Silence here
              is how somebody concludes a preset with four proposed tools approved four. */}
          {(chosen.tools.length > 0 || chosen.oauth) && (
            <p className="sentence muted">
              {chosen.tools.length > 0
                ? `The preset suggests ${chosen.tools.length} tool${chosen.tools.length === 1 ? "" : "s"}. Approve each one on the connector's page after registering. `
                : ""}
              {chosen.oauth
                ? "The OAuth app is set up on the connector's page. The client ID and secret come from the vendor's console."
                : ""}
            </p>
          )}
        </div>
      )}
    </>
  );
}

