import { Fragment, useState } from "react";

import Failure from "../../components/Failure";
import {
  BrandMark,
  Button,
  Card,
  Empty,
  Badge,
  Field,
  FieldGroup,
  Notice,
  PageHead,
  Spinner,
  Tag,
  type Tone,
} from "../../components/ui";
import { api } from "../../lib/api";
import type { ConnectorSummary, HostEntry, Recipe } from "../../lib/types";
import { useResource } from "../../lib/useResource";

/** Connector onboarding, in the order migration 021 forces — read as a screen, not as a
 * proof. Step 091.
 *
 * ```
 * allow an address   →   add a connector   →   open it   →   switch on what it may do
 * ```
 *
 * **The ordering is real and it is no longer the first thing on the page.** A credential
 * cannot be sealed against a connector that does not exist, and no MCP server lists its
 * tools to an unauthenticated caller — so *connect, look, then decide whether to register*
 * is not expressible, and the row genuinely has to come first. Registration then checks the
 * URL's host against the allowlist, so the address genuinely has to come before that. All
 * of that is still enforced. What 091 changed is that the enforcement is a disabled stage
 * with one sentence rather than a card of reasoning above everything else: the page now
 * opens with **what is connected**, offers **adding one** second, and keeps the allowlist —
 * plumbing, and the answer to a question nobody asks first — at the bottom.
 *
 * **The sentence explaining a refusal is still the server's.** This screen does not get to
 * invent an explanation for a rule it does not own.
 *
 * The two later stages — looking at a server, and switching on its tools one at a time —
 * are on the connector's own page, because they are about one server and because a URL
 * naming it is a thing an administrator sends to a colleague.
 *
 * ## Where the words went
 *
 * Every paragraph of *why* on this page was true and is now in these comments. Three
 * sentences are load-bearing in the other direction — somebody got the opposite impression
 * once — and all three stayed, shortened: registering switches nothing on, revoking an
 * address strands connectors rather than deleting them, and an asserted identity is
 * believed without verification.
 */
export default function ConnectorsPage() {
  const hosts = useResource(() => api.listHosts(), []);
  const connectors = useResource(() => api.listConnectors(), []);
  const recipes = useResource(() => api.listRecipes(), []);
  // The recipe whose values the form below is pre-filled from, or null for a blank form.
  const [chosen, setChosen] = useState<Recipe | null>(null);

  const approved = (hosts.data ?? []).filter((row) => !row.warning);
  const live = connectors.data ?? [];

  return (
    <>
      <PageHead
        title="Connectors"
        lede="Connect the apps your team already uses. Add one here, then choose exactly what it is allowed to do."
      />

      {/* **What is connected, first and as cards.** The page used to reach this last, as a
          stack of full-width rows whose only visual difference was the length of their
          sentence. A person who comes here to look at what is connected now gets that
          answer above the fold. */}
      <Card
        title="Your connectors"
        hint={live.length > 0 ? `${live.length} connected` : undefined}
      >
        {connectors.loading && <Spinner label="Loading…" />}
        {connectors.error ? <Failure error={connectors.error} /> : null}

        {connectors.data && live.length === 0 && (
          <Empty title="Nothing connected yet" icon="connectors">
            <p className="sentence">
              Add your first connector below — your assistants can only use the tools
              that ship with the platform until you do.
            </p>
          </Empty>
        )}

        {live.length > 0 && (
          <div className="conn-grid">
            {live.map((connector) => (
              <ConnectorCard key={connector.connector_id} connector={connector} />
            ))}
          </div>
        )}
      </Card>

      <Card title="Add a connector">
        {/* **Above the gate, deliberately.** A recipe names the addresses it needs, so it
            is the thing that answers "which addresses do I allow" — and gating it behind
            having already allowed one would hide the answer behind the question. The
            *form* stays gated, because registration genuinely cannot succeed yet. */}
        <RecipeChooser
          resource={recipes}
          chosen={chosen}
          onChoose={setChosen}
          approved={approved}
          onAllowed={hosts.reload}
          canAllow={Boolean(hosts.data)}
        />

        {/* Stage 2, disabled with the reason rather than hidden. Hiding it would make the
            page look complete while the thing somebody came to do is invisible.

            **Three states, not two.** The allowlist failing to load is not the same as
            being empty, and saying "add one below" to somebody the server just refused
            would send them to a form that is not there and would not work if it were.
            `Failure` on the allowlist card has already said the true thing. */}
        {/* **Nothing at all until the allowlist has answered.** `approved` is derived
            from `hosts.data ?? []`, so it is empty while the request is in flight and
            the gate below is true of *loading* as well as of *empty* — which flashed
            "nothing can be added yet" at somebody whose workspace has twelve addresses
            allowed. Found by an e2e that matched this paragraph's own words before the
            card it points at had rendered. */}
        {hosts.loading || hosts.error ? null : approved.length === 0 ? (
          <p className="sentence">
            Nothing can be added yet. A connector&rsquo;s address has to be on this
            workspace&rsquo;s allowed list first — add it under{" "}
            <strong>Allowed addresses</strong> at the bottom of this page, or pick an app
            above and allow what it asks for.
          </p>
        ) : (
          <NewConnector
            // Remounted when the choice changes, so a recipe's values become the form's
            // initial state rather than being copied in by an effect that then has to
            // decide what to do about fields somebody already typed in.
            key={chosen?.id ?? "blank"}
            recipe={chosen}
            hosts={approved}
            onCreated={connectors.reload}
          />
        )}
      </Card>

      {/* Plumbing, and last. It is a control with exactly one consumer and that consumer
          is above it — a separate screen would be a screen somebody visits once, gets
          wrong, and does not connect to the registration that then fails. */}
      <Hosts resource={hosts} />
    </>
  );
}

/** Stage 1: the egress allowlist, under a name somebody outside this repository can read.
 *
 * The refusals are the interesting part and both are the server's own words. A pasted URL
 * is a 400 saying what to strip — which is why the host goes in the request body rather
 * than a path segment, since a `/` in a path is a bare 404 with nothing to say. A host
 * that can never be dialled is approved anyway and carries a **warning**: the row is real,
 * the control is not in force, and being told plain *yes* about that is the exact failure
 * the egress module is written against.
 */
function Hosts({ resource }: { resource: ReturnType<typeof useResource<HostEntry[]>> }) {
  const [host, setHost] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");
  const [warning, setWarning] = useState("");
  const [stranded, setStranded] = useState<string[]>([]);
  // The host whose Revoke is one click from happening (061): revoking was the app's
  // one destructive control that acted on first click, and it is the one that can
  // strand every connector on the host — which deserves the two-step everything
  // else already has. One at a time, because confirming two revocations at once is
  // not a state a person is in.
  const [confirming, setConfirming] = useState("");

  const approve = () => {
    setBusy(true);
    setFailure("");
    setWarning("");
    setStranded([]);
    api
      .approveHost(host.trim(), note.trim())
      .then((outcome) => {
        setWarning(outcome.warning);
        setHost("");
        setNote("");
        resource.reload();
      })
      .catch((cause: unknown) =>
        setFailure(cause instanceof Error ? cause.message : String(cause)),
      )
      .finally(() => setBusy(false));
  };

  const revoke = (which: string) => {
    setFailure("");
    setWarning("");
    setConfirming("");
    api
      .revokeHost(which)
      .then((outcome) => {
        // `stranded` is why revoke answers with a body. Those connectors keep their
        // registration and their whole vetting record and simply stop connecting, which
        // is the opposite of what somebody assumes happened.
        setStranded(outcome.stranded);
        resource.reload();
      })
      .catch((cause: unknown) =>
        setFailure(cause instanceof Error ? cause.message : String(cause)),
      );
  };

  return (
    <Card title="Allowed addresses" hint="the servers this workspace may connect to">
      {resource.loading && <Spinner label="Loading…" />}
      {resource.error ? <Failure error={resource.error} /> : null}

      {resource.data && resource.data.length === 0 && (
        <p className="sentence">
          Nothing is allowed yet, so this workspace cannot connect anywhere. That is the
          safe default, not a fault.
        </p>
      )}

      {resource.data && resource.data.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Address</th>
              <th>Allowed by</th>
              <th>Note</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {resource.data.map((row) => (
              <Fragment key={row.host}>
                <tr>
                  <td className="mono">
                    {row.host}
                    {/* Marked in the list and not only at the moment of approval: this row
                        looks exactly like a working one otherwise, and whoever reads the
                        allowlist next was not the person who approved it. */}
                    {row.warning && <Tag write>never dialled</Tag>}
                  </td>
                  <td className="mono">{row.allowed_by}</td>
                  <td className="row-sub">{row.warning || row.note}</td>
                  <td>
                    <Button kind="quiet" onClick={() => setConfirming(row.host)}>
                      Revoke
                    </Button>
                  </td>
                </tr>
                {confirming === row.host && (
                  <tr>
                    <td colSpan={4}>
                      {/* The house two-step (061). The sentence carries the part nobody
                          assumes: connectors on this host keep their registration and
                          their whole vetting record and simply STOP CONNECTING at their
                          next dial — the stranding the post-revoke notice below reports
                          after the fact, said here before it. */}
                      <Notice tone="warn" title={`Revoke ${row.host}?`}>
                        <p className="sentence">
                          Every connector on this host stops connecting at its next
                          dial — registrations and vetting records stay, so approving
                          the host again restores them, but until then their tools
                          vanish from every caller&rsquo;s list. Approvals by other
                          administrators go with it: the allowlist is the
                          workspace&rsquo;s, not yours.
                        </p>
                        <div className="spread">
                          <Button onClick={() => setConfirming("")}>Keep it</Button>
                          <Button kind="primary" onClick={() => revoke(row.host)}>
                            Revoke it
                          </Button>
                        </div>
                      </Notice>
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      )}

      {/* **Only when the allowlist actually loaded**, which is `your_role`'s lesson
          arriving in a screen written by somebody who had just written that lesson down.
          A non-administrator who deep-links here gets the server's 403 *and*, until this
          condition existed, a complete host-approval form underneath it — a control that
          refuses the person who pressed it, which reads as a bug rather than as a rule.
          Found by pointing a browser at `/admin/connectors` as the second person, which
          is the only way it could have been found. */}
      {resource.data && (
        <div className="inline-form">
          <FieldGroup label="Allow an address" hint="Just the hostname — no https://, no port, no path.">
            <div className="spread">
              <input
                value={host}
                placeholder="mcp.acme.com"
                onChange={(e) => setHost(e.target.value)}
              />
              <input
                value={note}
                placeholder="why (optional)"
                onChange={(e) => setNote(e.target.value)}
              />
              <Button busy={busy} disabled={!host.trim()} onClick={approve}>
                Approve
              </Button>
            </div>
          </FieldGroup>
        </div>
      )}

      {failure && (
        <Notice tone="warn">
          {/* The server's sentence. For a pasted URL it names what is wrong and what to
              pass instead, which is the whole reason this field is a body and not a path. */}
          <p className="sentence">{failure}</p>
        </Notice>
      )}
      {warning && (
        <Notice tone="warn" title="Saved, but it will not be dialled">
          <p className="sentence">{warning}</p>
        </Notice>
      )}
      {stranded.length > 0 && (
        <Notice tone="warn" title="Connectors still point at that address">
          <p className="sentence">
            {stranded.join(", ")} — they keep their registration and everything switched
            on, and will refuse to connect until the address is allowed again. Nothing was
            deleted.
          </p>
        </Notice>
      )}
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

  if (resource.loading) return <Spinner label="Loading apps…" />;
  // A failed catalogue is not a failed page: everything below still works, and the whole
  // feature is a convenience over a form somebody can fill in by hand. Saying so beats
  // rendering `Failure` and implying registration is broken.
  if (resource.error)
    return (
      <p className="sentence muted">
        The presets could not be loaded ({String(resource.error)}). Filling the form in by
        hand below still works.
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
      <FieldGroup label="Which app?" hint="Presets for the services people ask for most. They fill the form in — nothing more.">
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
            <Notice tone="warn" title="Check these against the vendor">
              <p className="sentence">
                {chosen.staleness === "unverified"
                  ? "Nobody here has signed in to this vendor to confirm these details."
                  : `These details were last checked on ${chosen.verified_on}.`}{" "}
                Vendors move endpoints and rename permissions without telling anybody.
                Every field below is yours to change before you add it.
              </p>
            </Notice>
          )}

          {/* The addresses, with the button that allows one beside the reason it is
              needed. Allowing is still a separate deliberate act — it is the same act,
              in the place the question is asked. */}
          <p className="sentence">
            <strong>It needs these addresses allowed.</strong> That is your call, not
            its: a preset cannot widen where this workspace may connect.
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
              is how somebody concludes a preset with four proposed tools switched four on. */}
          {(chosen.tools.length > 0 || chosen.oauth) && (
            <p className="sentence muted">
              {chosen.tools.length > 0
                ? `It suggests ${chosen.tools.length} tool${chosen.tools.length === 1 ? "" : "s"} and has switched none of them on — you choose those on the connector's own page once it is added. `
                : ""}
              {chosen.oauth
                ? "Its sign-in details are set up separately, and the client id and secret are yours: you create them in the vendor's own console."
                : ""}
            </p>
          )}
        </div>
      )}
    </>
  );
}

/** Stage 2: the row, which switches nothing on and says so.
 *
 * There is no field for a command, and that is `tools.STDIO_REFUSED` expressed as a form:
 * a registered connector speaks HTTP because HTTP is the only transport that can carry a
 * per-user credential. A stdio server takes its credential from the environment when it
 * starts and holds it for the process's life, so every user of every agent would share one
 * service account.
 *
 * **091 folded four controls behind `<details>` and no more than four.** The REST credential
 * scheme, the extra headers and the description matter to the person registering an API
 * vendor and to nobody else. The asserted-identity box stayed visible: it is the one control
 * on this page whose failure mode is being ticked unread, and a tidying pass that hid it
 * would be the wrong half of the form getting shorter.
 */
function NewConnector({
  recipe,
  hosts,
  onCreated,
}: {
  /** The recipe this form's initial state came from, or null. Its values are DEFAULTS —
   *  every field below is editable, and that is what makes a wrong recipe cost one form
   *  rather than a broken registration. Carried through to the request as provenance
   *  only; nothing in the database points back at it. */
  recipe: Recipe | null;
  hosts: HostEntry[];
  onCreated: () => void;
}) {
  // **A recipe's values are this form's initial state and nothing more.** Not an effect
  // that copies them in later, which would have to decide what to do about fields
  // somebody has already typed into; the component is remounted on a new choice instead.
  // Every one of these stays editable, which is the property that makes a stale recipe
  // cost one form's worth of wrong defaults rather than a broken registration.
  const preset = recipe?.connector;
  const [id, setId] = useState(preset?.connector_id ?? "");
  const [url, setUrl] = useState(preset?.url ?? "");
  const [kind, setKind] = useState<"http" | "rest">(preset?.kind ?? "http");
  const [credentialEnv, setCredentialEnv] = useState(preset?.credential_env ?? "");
  // 070. Two fields on the wire and **one choice** here, because the server refuses
  // both being set and a form that can express a refusal is a form that will. A recipe
  // never presets this: a checked-in file knows a vendor's endpoints and cannot know
  // where in your vault your token is.
  const [held, setHeld] = useState<"env" | "vault">("env");
  const [credentialRef, setCredentialRef] = useState("");
  // `null` on the wire means *the launch's own default*, which is what a blank box means
  // here — so a recipe that does not override the header arrives as a blank box rather
  // than as the literal word "Authorization".
  const [credentialHeader, setCredentialHeader] = useState(
    preset?.credential_header ?? "",
  );
  // Starts at the real default and is ALWAYS sent for a REST connector (061): what
  // the field shows is what precedes the credential, with no hidden untouched state.
  // It used to start at "" and be omitted when empty, and the hint taught a
  // keystroke trick (type a space, delete it) that landed back on "" — so the
  // documented way to select the bare token was a no-op and every x-api-key
  // connector 401ed with a remedy that did not remedy (plan 049's audit).
  //
  // A recipe's `credential_prefix` is `""` for an `x-api-key` vendor and `null` for one
  // that wants the default — and 061's whole finding was that those two must not
  // collapse. `?? "Bearer "` keeps them apart: null takes the default, `""` survives.
  const [credentialPrefix, setCredentialPrefix] = useState(
    preset?.credential_prefix ?? "Bearer ",
  );
  const [headers, setHeaders] = useState<{ name: string; value: string }[]>(
    Object.entries(preset?.headers ?? {}).map(([name, value]) => ({ name, value })),
  );
  const [description, setDescription] = useState(preset?.description ?? "");
  const [asserts, setAsserts] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");

  const rest = kind === "rest";

  const register = () => {
    setBusy(true);
    setFailure("");
    api
      .registerConnector({
        connector_id: id.trim(),
        url: url.trim(),
        kind,
        // Exactly one of the two is ever sent, and the other is sent EMPTY rather than
        // omitted — so switching the choice and registering cannot leave the previous
        // answer behind on a field the request no longer mentions.
        credential_env: held === "env" ? credentialEnv.trim() : "",
        credential_ref: held === "vault" ? credentialRef.trim() : "",
        description: description.trim(),
        allow_asserted_identity: asserts,
        // Provenance only. The server checks it names a recipe this build ships and
        // drops it otherwise; nothing in the database points back at one.
        ...(recipe ? { from_recipe: recipe.id } : {}),
        // **REST only.** The header keeps omit-when-empty — empty genuinely means the
        // default header name, with no second meaning to collide with. The prefix is
        // the opposite case and is always sent (061): its field starts at the real
        // default, so what it shows is what is sent, and a cleared field honestly
        // means "" — the bare token an x-api-key vendor wants.
        ...(rest && credentialHeader.trim()
          ? { credential_header: credentialHeader.trim() }
          : {}),
        ...(rest ? { credential_prefix: credentialPrefix } : {}),
        ...(rest && headers.some((h) => h.name.trim())
          ? {
              headers: Object.fromEntries(
                headers
                  .filter((h) => h.name.trim())
                  .map((h) => [h.name.trim(), h.value]),
              ),
            }
          : {}),
      })
      .then(() => {
        setId("");
        setUrl("");
        setCredentialEnv("");
        setCredentialHeader("");
        setCredentialPrefix("");
        setHeaders([]);
        setDescription("");
        setAsserts(false);
        // `kind` deliberately survives: registering three REST connectors in a row is
        // the ordinary shape, and resetting it would silently make the fourth an MCP
        // server whose authored tools are then refused.
        onCreated();
      })
      .catch((cause: unknown) =>
        setFailure(cause instanceof Error ? cause.message : String(cause)),
      )
      .finally(() => setBusy(false));
  };

  return (
    <div className="inline-form">
      <Field label="Name it" hint="Lowercase letters, digits and hyphens. It goes in front of every tool name.">
        <input value={id} placeholder="jira" onChange={(e) => setId(e.target.value)} />
      </Field>

      {/* **Chosen here and never edited**, on the token kind radio's precedent — the
          two have different security properties and there is no update path, so the
          consequence belongs at the point of choice rather than at the first surprise.
          What it decides is how tools get onto this connector at all. */}
      <div className="choices stacked" role="radiogroup" aria-label="What kind of server it is">
        <label className={`choice big${rest ? "" : " on"}`}>
          <input
            type="radio"
            name="connector-kind"
            checked={!rest}
            onChange={() => setKind("http")}
          />
          <span>
            <strong>An MCP server</strong>
            <span className="muted"> It lists its own tools, so you pick from a list.</span>
          </span>
        </label>
        <label className={`choice big${rest ? " on" : ""}`}>
          <input
            type="radio"
            name="connector-kind"
            checked={rest}
            onChange={() => setKind("rest")}
          />
          <span>
            <strong>A REST API</strong>
            <span className="muted">
              {" "}
              It lists nothing, so you describe each tool yourself. This is the shape an AI
              model provider takes.
            </span>
          </span>
        </label>
      </div>

      <Field
        label="Address"
        hint={
          rest
            ? `The base URL each tool's path is added to. Must be on: ${hosts
                .map((h) => h.host)
                .join(", ")}`
            : `Where the server answers. Must be on: ${hosts.map((h) => h.host).join(", ")}`
        }
      >
        <input
          value={url}
          placeholder={rest ? "https://api.acme.com/v1" : "https://mcp.acme.com/mcp"}
          onChange={(e) => setUrl(e.target.value)}
        />
      </Field>

      {/* Where the shared credential lives. One choice rather than two boxes, because
          the server refuses both being set — and a form that can express a refusal is a
          form somebody will fill in that way. A per-person credential is neither: it
          comes from a consent flow.

          `stacked` and `big`, because each option carries a sentence — the shape the
          model picker uses, and the shape `.choice.big.on` is the only one styled for:
          a plain `.choice` renders the selected state as nothing at all. */}
      <div
        className="choices stacked"
        role="radiogroup"
        aria-label="Where the shared key is kept"
      >
        <label className={`choice big${held === "env" ? " on" : ""}`}>
          <input
            type="radio"
            name="credential-held"
            checked={held === "env"}
            onChange={() => setHeld("env")}
          />
          <span>
            <strong>In this deployment</strong>
            <span className="muted">
              {" "}
              An environment variable this platform reads. The default, and it costs
              nothing per call.
            </span>
          </span>
        </label>
        <label className={`choice big${held === "vault" ? " on" : ""}`}>
          <input
            type="radio"
            name="credential-held"
            checked={held === "vault"}
            onChange={() => setHeld("vault")}
          />
          <span>
            <strong>In your own vault &mdash; we never hold it</strong>
            <span className="muted">
              {" "}
              A 1Password reference, read at call time and never stored here. Costs one
              to three requests to your vault on every call, so a call to this connector
              is slower and stops working while your vault is down.
            </span>
          </span>
        </label>
      </div>

      {held === "env" ? (
        <Field
          label="Key variable"
          hint="Optional. The environment variable holding the key everyone shares. A per-person sign-in is set up later instead."
        >
          <input
            value={credentialEnv}
            placeholder="JIRA_TOKEN"
            onChange={(e) => setCredentialEnv(e.target.value)}
          />
        </Field>
      ) : (
        <Field
          label="Vault reference"
          hint="Where in your 1Password vault the key is — a location, never the value. Item ids resolve in one request and names in three, so use ids for a connector that is called often."
        >
          <input
            value={credentialRef}
            placeholder="op://Engineering/Jira/credential"
            onChange={(e) => setCredentialRef(e.target.value)}
          />
        </Field>
      )}

      {/* **Folded, not removed.** Four controls that matter to the person registering an
          API vendor and to nobody else. REST-only for the two credential fields, because
          only REST has a reason: an MCP server presents its credential as
          `Authorization: Bearer` by protocol convention, so offering these there would be
          offering a way to break it. */}
      <details className="more">
        <summary>More options</summary>
        <div className="more-body">
          {rest && (
            <>
              <Field
                label="Credential header"
                hint="Blank means Authorization. The header this API reads its key from."
              >
                <input
                  value={credentialHeader}
                  placeholder="x-api-key"
                  onChange={(e) => setCredentialHeader(e.target.value)}
                />
              </Field>
              <Field
                label="Credential prefix"
                hint="Sent exactly as shown before the key, trailing space included. Clear it to send the bare token, which is what an x-api-key vendor wants."
              >
                <input
                  value={credentialPrefix}
                  onChange={(e) => setCredentialPrefix(e.target.value)}
                />
              </Field>
              <FieldGroup
                label="Other headers"
                hint="Sent on every request — an API version, typically. Not secret: anything typed here is stored in the connector's manifest."
              >
                {headers.map((header, index) => (
                  <div className="spread" key={index}>
                    <input
                      value={header.name}
                      placeholder="anthropic-version"
                      onChange={(e) =>
                        setHeaders(
                          headers.map((h, i) =>
                            i === index ? { ...h, name: e.target.value } : h,
                          ),
                        )
                      }
                    />
                    <input
                      value={header.value}
                      placeholder="2023-06-01"
                      onChange={(e) =>
                        setHeaders(
                          headers.map((h, i) =>
                            i === index ? { ...h, value: e.target.value } : h,
                          ),
                        )
                      }
                    />
                    <Button
                      kind="quiet"
                      onClick={() => setHeaders(headers.filter((_, i) => i !== index))}
                    >
                      Remove
                    </Button>
                  </div>
                ))}
                <Button onClick={() => setHeaders([...headers, { name: "", value: "" }])}>
                  Add a header
                </Button>
              </FieldGroup>
            </>
          )}

          <Field label="Description" hint="Optional. Shown to whoever is choosing tools.">
            <input
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </Field>
        </div>
      </details>

      {/* **A security control, so not a preference-shaped checkbox.** The claim is the
          label and the consequence is beside it — the device the wizard's ceilings step
          used before 081 deleted it, for the same reason: 033's posture is *verified or
          nothing*, and the failure mode of this field is somebody ticking it without
          reading it. It is the one control 091 refused to fold away.

          Settable at registration because a connector born trusting a caller should say so
          from its first administrative record. **Changed afterwards on the connector's own
          page**, and the last sentence says so: registration writes one record for the whole
          registration, while `PUT .../asserted-identity` writes a record naming the actor
          and the new value — which is what a security control changing state is owed. This
          form must not become a second toggle. */}
      <label className="choice big">
        <input
          type="checkbox"
          checked={asserts}
          onChange={(e) => setAsserts(e.target.checked)}
        />
        <span>
          <strong>A calling app may say who it is acting for.</strong>
          <span className="muted">
            {" "}
            An email address, believed without verification — exactly as honest as the app
            making the call, and every such call is logged as <code>asserted</code>, kept
            apart from <code>verified</code>. Leave it clear and only a verified
            acting-for is accepted. You can change this later on the connector&apos;s own
            page, which is where the change gets its own record.
          </span>
        </span>
      </label>

      {failure && (
        <Notice tone="warn">
          <p className="sentence">{failure}</p>
        </Notice>
      )}

      <Button
        kind="primary"
        busy={busy}
        disabled={!id.trim() || !url.trim()}
        onClick={register}
      >
        Register
      </Button>
      <p className="muted">
        Adding it does not switch anything on. Nothing the server offers can be used until
        you switch a tool on, one at a time, on its page.
      </p>
    </div>
  );
}

/** One connector, as a card.
 *
 * **A card rather than a row, and a mark rather than nothing** — 091. Nine full-width rows
 * distinguished only by the length of their sentence is a list nobody scans; nine tiles
 * with a logo, a name and a status word is one somebody reads across in two seconds. The
 * facts on it are the same four the row carried.
 */
function ConnectorCard({ connector }: { connector: ConnectorSummary }) {
  const state = status(connector);
  return (
    <div className="conn-card">
      <div className="conn-head">
        <BrandMark hints={[connector.connector_id, connector.host]} />
        <div className="conn-title">
          <strong>{connector.connector_id}</strong>
          <span className="row-sub mono">{connector.host}</span>
        </div>
        <Badge tone={state.tone}>{state.word}</Badge>
      </div>

      {connector.description && <p className="muted">{connector.description}</p>}
      <p className="sentence">{describe(connector)}</p>

      {(connector.writes > 0 || connector.allow_asserted_identity) && (
        <div className="conn-tags">
          {connector.writes > 0 && (
            <Tag write>
              {connector.writes} can change things
            </Tag>
          )}
          {/* Marked, and marked only where it is true. This page's other two tags mark
              exceptions — an address that will not be dialled, a connector with writes —
              and false here is the posture, the schema's default and every connector's
              state until somebody decides otherwise. A tag on all of them saying *verified
              only* would bury the one card a security review came to find. */}
          {connector.allow_asserted_identity && <Tag write>asserted identity</Tag>}
        </div>
      )}
      {asserted(connector) && <p className="sentence muted">{asserted(connector)}</p>}

      <div className="conn-foot">
        <Button to={`/admin/connectors/${connector.connector_id}`}>Open</Button>
      </div>
    </div>
  );
}

/** The word on the card, and its colour. Step 091.
 *
 *  **A second function beside `describe()`, on the same branches.** It is not folded in
 *  because a badge and a sentence are read at different speeds by different people: the
 *  badge is what somebody scanning nine cards sees, and the sentence is what the one who
 *  stops reads. They must agree, so they are computed from the same three conditions in
 *  the same order — and keeping them adjacent is what makes a later edit to one obviously
 *  an edit to both. */
export function status(connector: ConnectorSummary): { tone: Tone; word: string } {
  if (!connector.host_allowed) return { tone: "warn", word: "Paused" };
  if (connector.vetted === 0) return { tone: "waiting", word: "Needs setup" };
  return { tone: "good", word: "Ready" };
}

/** One sentence per connector, saying which of the three things is still missing.
 *
 * One function so the states cannot be worded several ways, and each branch says what is
 * true **and** what it means — a tool count on its own does not tell an administrator
 * whether anybody can use this, and the answer differs by state.
 *
 * **091 rewrote every branch and changed none of them.** *Vetted* is "switched on",
 * *the allowlist* is "the allowed list", and the oauth split — the whole of 7a and 7b — is
 * "everyone shares one login" against "people sign in with their own account". The
 * vocabulary a customer meets here is the vocabulary of their own working day; the
 * vocabulary of the schema is in the schema.
 */
export function describe(connector: ConnectorSummary): string {
  if (!connector.host_allowed) {
    return `Paused: ${connector.host} is no longer on the allowed list, so this cannot connect. Nothing was deleted — allow the address again and everything switched on comes back.`;
  }
  if (connector.vetted === 0) {
    return "Nothing is switched on yet, so it cannot do anything. Open it to choose what it can do.";
  }
  const tools = `${connector.vetted} tool${connector.vetted === 1 ? "" : "s"} switched on`;
  if (!connector.oauth) {
    return `${tools}. Everyone shares one login — there is no way yet for people to connect their own account.`;
  }
  return `${tools}, and people can connect their own accounts.`;
}

/** Whether the MCP door believes a caller's claim about who it acts for — 033c, and a
 *  **second function beside `describe()` rather than a branch inside it.**
 *
 *  `describe()` answers one question with a three-branch state machine: *is this reachable,
 *  and whose account does a call use*. This is orthogonal to all three: it is independently
 *  true or false in every branch, so folding it in would turn three branches into six and
 *  make one sentence answer two questions.
 *
 *  And they are the two questions that get confused. `VettedTool.identity` is *whose account
 *  a tool acts as*; this is *whether the door believes a caller's claim about who they are*.
 *  One sentence carrying both is how those merge in somebody's head. 035f made the same call
 *  putting `lapse()` beside `ConnectionsPage`'s `describe()`.
 *
 *  Empty on the resting posture, deliberately — see the tag's comment. */
export function asserted(connector: ConnectorSummary): string {
  if (!connector.allow_asserted_identity) return "";
  return "A calling app may say who it is acting for here — an email address, believed without verification. Those calls are logged as asserted, never as verified.";
}
