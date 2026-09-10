import { Fragment, useState } from "react";
import { Link, useParams } from "react-router-dom";

import Failure from "../../components/Failure";
import {
  Button,
  Card,
  Field,
  FieldGroup,
  Notice,
  PageHead,
  Spinner,
  Tag,
} from "../../components/ui";
import { api } from "../../lib/api";
import { bytes } from "../../lib/format";
import type {
  ConnectorDetail,
  DiscoveredTool,
  DiscoveryResult,
  ResourceSpec,
  ScopeNote,
  VettedTool,
} from "../../lib/types";
import { useResource } from "../../lib/useResource";

/** One connector, and **this page is the vetting screen** — the thing 12 deferred and 12b
 * unblocked.
 *
 * ## The screen's job is smaller than it looks, and that is finding 2
 *
 * `tools.vet_tool` already carries the whole correctness burden: six checks, all
 * server-side, all below the CLI. The connector exists, the server advertises this tool,
 * the annotation validates **against the advertised schema**, the local name is legal,
 * nothing already vetted has drifted, then the stamped write. So this form cannot approve
 * a tool nobody offers or scope one to an argument that does not exist, and it does not
 * try to check either — it collects five fields and renders refusals.
 *
 * What it does owe is **the argument names**. That is `--discover`'s reason for existing
 * and it is the only part of vetting a person cannot guess: what *this* server calls the
 * argument carrying the identifier, and whether it is optional. A form with a free text
 * box there would be a form whose commonest outcome is a refusal at submit, so the
 * discovered names are offered as a list and the resource rows pick from it.
 *
 * ## Looking is a separate click, and deliberately
 *
 * Everything above the fold renders from the stored manifest and contacts nothing —
 * migration 018's argument, which applies here at least as much as to the catalogue: a
 * page about what somebody approved must not be down whenever a customer's server is.
 * **Discover** is the button that opens a socket, and it is a `POST` for the same reason:
 * a GET that dials a third party would be dialled by anything that prefetches links.
 *
 * ## Drift blocks, and is rendered as blocking
 *
 * A `refuse` finding means `vet_tool` will approve nothing further on this connector until
 * somebody deals with it. A `report` finding is a tool the server has started advertising
 * that nobody approved — which is never adopted, because a server that could add
 * capabilities by shipping a release is the entire thing an allowlist denies. Rendering
 * the two the same way would make the blocking one look optional, so they are separate
 * and the blocking one hides the forms.
 */
export default function ConnectorDetailPage() {
  const { connectorId = "" } = useParams();
  const connector = useResource(() => api.getConnector(connectorId), [connectorId]);
  const [seen, setSeen] = useState<DiscoveryResult | null>(null);

  return (
    <>
      <PageHead
        title={`Connector · ${connectorId}`}
        lede={
          <>
            <Link to="/admin/connectors">← Connectors</Link>
          </>
        }
      />

      {connector.loading && <Spinner label="Loading…" />}
      {connector.error ? <Failure error={connector.error} /> : null}

      {connector.data && (
        <>
          <Registration connector={connector.data} />
          <AssertedIdentity connector={connector.data} onChange={connector.reload} />
          <Vetted connector={connector.data} />
          {/* **The branch, and REST gets no Discover button** — step 047. There is
              nothing to dial: `Discovery`'s whole subject is what the server advertises
              right now and what has drifted since, and an API that advertises nothing
              has neither. A greyed-out Discover would imply the fact exists and is
              merely unavailable. */}
          {connector.data.transport === "rest" ? (
            <AuthorTool
              connectorId={connectorId}
              vetted={connector.data.tools}
              onVetted={() => {
                connector.reload();
              }}
            />
          ) : (
            <Discovery
              connectorId={connectorId}
              vetted={connector.data.tools}
              seen={seen}
              onSeen={setSeen}
              onVetted={() => {
                connector.reload();
              }}
            />
          )}
          <ConsentFlow connector={connector.data} onChange={connector.reload} />
        </>
      )}
    </>
  );
}

function Registration({ connector }: { connector: ConnectorDetail }) {
  return (
    <Card title="Registration">
      <dl className="pairs">
        <dt>URL</dt>
        <dd className="mono">{connector.url}</dd>
        <dt>Transport</dt>
        <dd className="mono">{connector.transport}</dd>
        <dt>Shared credential</dt>
        {/* 070. Three states, and the third is the one worth a sentence: a reference is
            not just "a different variable name", it is the platform not holding the
            secret — and it is the reason a call to this connector can fail because
            somebody else's vault is down. Naming the vault reference here is safe for
            the reason it is safe in the manifest: it is a location, never a value. */}
        {connector.credential_ref ? (
          <dd>
            <span className="mono">{connector.credential_ref}</span>
            <span className="muted">
              {" "}
              (read from your vault on every call; tools are unavailable while the vault
              is unreachable)
            </span>
          </dd>
        ) : (
          <dd className="mono">{connector.credential_env || "none"}</dd>
        )}
      </dl>
      {!connector.host_allowed && (
        <Notice tone="warn" title={`${connector.host} is not approved`}>
          <p className="sentence">
            This connector cannot connect until the host is approved again. Its
            registration and approved tools are kept.
          </p>
        </Notice>
      )}
    </Card>
  );
}

/** 033c: whether an *asserted* acting-for through the MCP door is believed for this
 *  server's tools. Rendered as the security control it is — the state in a sentence,
 *  the consequence beside it, and one deliberate action to change it — rather than a
 *  preference-shaped checkbox that would make disabling a control look like taste. */
function AssertedIdentity({
  connector,
  onChange,
}: {
  connector: ConnectorDetail;
  onChange: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");

  const flip = () => {
    setBusy(true);
    setFailure("");
    api
      .setAssertedIdentity(connector.connector_id, !connector.allow_asserted_identity)
      .then(() => onChange())
      .catch((error: Error) => setFailure(error.message))
      .finally(() => setBusy(false));
  };

  return (
    <Card title="On behalf of">
      {connector.allow_asserted_identity ? (
        <p className="sentence">
          A calling service may <strong>assert</strong> who it acts on behalf of, without
          verification. Such calls are logged as <code>asserted</code>, not{" "}
          <code>verified</code>.
        </p>
      ) : (
        <p className="sentence">
          Only a <strong>verified</strong> on-behalf-of claim is accepted: the
          person&apos;s own IdP token, forwarded per call. Asserted claims are denied for
          this connector&apos;s tools.
        </p>
      )}
      {failure && (
        <Notice tone="warn" title="Not changed">
          <p className="sentence">{failure}</p>
        </Notice>
      )}
      <Button onClick={flip} disabled={busy}>
        {connector.allow_asserted_identity
          ? "Stop accepting asserted identity"
          : "Accept asserted identity"}
      </Button>
    </Card>
  );
}

function Vetted({ connector }: { connector: ConnectorDetail }) {
  if (connector.tools.length === 0) {
    return (
      <Card title="Approved tools">
        <p className="sentence">
          No tools approved.{" "}
          {connector.transport === "rest"
            ? "Author each tool below."
            : "Discover the server's tools below, then approve the ones you want."}
        </p>
      </Card>
    );
  }

  return (
    <Card title={`Approved tools (${connector.tools.length})`}>
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Server name</th>
            <th>Effect</th>
            <th>Acts as</th>
            <th>Resources</th>
            <th>Approved by</th>
          </tr>
        </thead>
        <tbody>
          {connector.tools.map((tool) => (
            <Fragment key={tool.remote_name}>
              <tr>
                <td className="mono">{tool.name}</td>
                <td className="mono">{tool.remote_name}</td>
                <td>
                  {/* Marked, because read and write are the one property of a tool that
                      decides whether a mistake is recoverable. */}
                  <Tag write={tool.effect === "write"}>{tool.effect}</Tag>
                </td>
                <td>
                  {/* Whose account it runs on — the approval's third judgment (033a). */}
                  {tool.identity === "user" ? "the caller" : "the service"}
                </td>
                <td className="mono">
                  {tool.resources.map((r) => r.type).join(", ") || "none"}
                </td>
                <td className="row-sub">{provenance(tool)}</td>
              </tr>
              {/* **A sub-row, not a seventh and eighth column** — `provenance` above is the
                  precedent for answering an extra question inside the row rather than by
                  growing the table.

                  The note is *prose*, and somebody here wrote it at approval time. It
                  **does** already reach the person it was written for — `ToolSummary`
                  carries it and the grant picker renders it — and until 035g it reached
                  nobody on the screen where approvals themselves are listed. So the
                  administrator who wrote it, and the one auditing what was approved, were
                  the two people who could not see it.

                  The ceiling is a number and a different problem: it is interesting only
                  when it is not the platform's default, which is nearly every row, so a
                  column would have been empty cells with one value in it.

                  Nothing at all when there is neither. A line saying *no note* on every row
                  would bury the rows that have one. */}
              {(tool.note.trim() || tool.max_response_bytes !== null) && (
                <tr>
                  <td colSpan={6}>
                    {/* Trimmed before it decides anything, because a note of three spaces
                        is not a note — the form trims what it sends and `--note "   "`
                        does not, and a blank paragraph reads as a rendering fault. */}
                    {tool.note.trim() && <p className="row-sub">{tool.note}</p>}
                    {tool.max_response_bytes !== null && (
                      <p className="row-sub">
                        Responses over {bytes(tool.max_response_bytes)} are denied, not
                        truncated.
                      </p>
                    )}
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

/** Who approved a tool, and **against which version of the server**.
 *
 * Migration 023's field, and it is not decoration: a tool approved against `jira-mcp 2.3.0`
 * and running against `4.0.0` is the question `--discover`'s drift check answers, and this
 * is where somebody reads the first half of it. Empty for anything vetted without
 * contacting a server, and empty is what that says rather than a guess.
 */
export function provenance(tool: VettedTool): string {
  const who = tool.vetted_by || "nobody recorded";
  if (!tool.server_name && !tool.server_version) {
    return `${who} (no server version recorded)`;
  }
  return `${who}, against ${tool.server_name} ${tool.server_version}`.trim();
}

function Discovery({
  connectorId,
  vetted,
  seen,
  onSeen,
  onVetted,
}: {
  connectorId: string;
  /** What is already approved, so *Approve again* can start from the last review rather
   *  than from an empty form — see `ToolForm`. Keyed by the **remote** name, which is what
   *  a discovered tool is called and what the write is keyed by. */
  vetted: VettedTool[];
  seen: DiscoveryResult | null;
  onSeen: (result: DiscoveryResult) => void;
  onVetted: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");

  const look = () => {
    setBusy(true);
    setFailure("");
    api
      .discover(connectorId)
      .then(onSeen)
      // A 502 is the customer's own server not answering — neither our outage nor their
      // mistake — and the transport's sentence names the host. Rendered rather than
      // paraphrased, because "could not connect" loses which of the two it was.
      .catch((cause: unknown) =>
        setFailure(cause instanceof Error ? cause.message : String(cause)),
      )
      .finally(() => setBusy(false));
  };

  const blocking = (seen?.findings ?? []).filter((f) => f.severity === "refuse");
  const reports = (seen?.findings ?? []).filter((f) => f.severity === "report");

  return (
    <Card title="Available tools" hint={seen ? seen.server : undefined}>
      <p className="sentence">
        Discovery connects to the server and lists the tools it offers. It uses your
        connected account if you have one.
      </p>
      <Button kind="primary" busy={busy} onClick={look}>
        {seen ? "Discover again" : "Discover"}
      </Button>

      {failure && (
        <Notice tone="bad" title="The server did not answer">
          <p className="sentence">{failure}</p>
        </Notice>
      )}

      {blocking.length > 0 && (
        <Notice tone="bad" title="Approved tools have changed on the server">
          {blocking.map((finding) => (
            <p className="sentence" key={finding.message}>
              {finding.message}
            </p>
          ))}
          <p className="sentence">
            No further tools can be approved on this connector until this is resolved.
          </p>
        </Notice>
      )}

      {reports.length > 0 && (
        <Notice tone="info" title="New since approval">
          {reports.map((finding) => (
            <p className="sentence" key={finding.message}>
              {finding.message}
            </p>
          ))}
          <p className="muted">New tools are not approved automatically.</p>
        </Notice>
      )}

      {seen &&
        blocking.length === 0 &&
        seen.tools.map((tool) => (
          <ToolForm
            key={tool.name}
            connectorId={connectorId}
            tool={tool}
            approved={vetted.find((v) => v.remote_name === tool.name) ?? null}
            onVetted={onVetted}
          />
        ))}
    </Card>
  );
}

/** One advertised tool, and the form that approves it.
 *
 * **One `PUT` per tool, which is append semantics made visible.** A form that submitted
 * the whole list would be `save_connector`'s wholesale replace wearing a UI, and an
 * administrator who has approved nine tools and gets the tenth wrong must not lose nine.
 * So each tool has its own button, each is a separate write, and a refusal on this one
 * costs nothing anywhere else.
 */
function ToolForm({
  connectorId,
  tool,
  approved,
  onVetted,
}: {
  connectorId: string;
  tool: DiscoveredTool;
  /** The row this tool already has, or null. See `start` — **a re-vet replaces the whole
   *  row**, so an empty form on *Approve again* is a form that silently un-scopes a write. */
  approved: VettedTool | null;
  onVetted: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [effect, setEffect] = useState<"read" | "write">("read");
  const [identity, setIdentity] = useState<"service" | "user">("service");
  const [resources, setResources] = useState<ResourceSpec[]>([]);
  const [note, setNote] = useState("");
  const [localName, setLocalName] = useState("");
  const [ceiling, setCeiling] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");
  const [done, setDone] = useState("");

  /** Open the form on the **last review**, when there was one.
   *
   *  `vet_tool` upserts the whole row — *"a new review overwrites the old rather than being
   *  edited underneath its name"* — so an empty *Approve again* form is `ConsentFlow`'s
   *  wholesale-replace trap at the other write on this page, and worse: the defaults are
   *  `read`, `service` and no resources, so pressing Approve again on a scoped write and
   *  changing nothing **downgrades it to an unscoped read and erases the note**. Found by
   *  035g's edge pass asking what a re-vet that omits a field does to the row.
   *
   *  Starting from the last review is also what *approve again* means to a person: the
   *  judgment is being made a second time, not from nothing. It still writes a fresh
   *  record with a fresh stamp, because that is what a second review is. */
  const start = () => {
    setEffect((approved?.effect as "read" | "write") ?? "read");
    setIdentity((approved?.identity as "service" | "user") ?? "service");
    // **The types come back and the argument names deliberately do not.** `ResourceType`
    // is `{type}` alone, and its own comment says why: *"a client that was handed the
    // argument names would be invited to build a scope out of them, which is the coupling
    // the type exists to prevent."* So a re-vet can restore what this tool touches and not
    // which argument names it — the row is seeded with the type and an empty picker, and
    // `submit` refuses rather than dropping it.
    setResources((approved?.resources ?? []).map((r) => ({ type: r.type, args: [] })));
    setNote(approved?.note ?? "");
    setLocalName(approved && approved.name !== tool.local_name ? approved.name : "");
    setCeiling(
      approved?.max_response_bytes == null ? "" : String(approved.max_response_bytes),
    );
    setFailure("");
    setDone("");
    setOpen(true);
  };

  const submit = () => {
    // **Refused here rather than by the server, and this is the one place on this page
    // that pre-empts a refusal.** Everything else — a tool the server does not advertise,
    // an argument not in the schema, an unscopeable write — is a 400 carrying a sentence
    // written for the person filling in this form, and rendering those verbatim is the
    // rule. This one is a **422**, because the bound is `Field(gt=0)` on the request
    // model, and a 422's `detail` is a list of field errors rather than a sentence:
    // `readProblem` collapses every one of them to "the request was not in a shape the
    // server accepts", which is true, names no field, and is identical whatever somebody
    // got wrong. So the form says what a zero would do, and the schema bound is the floor
    // under every caller that is not this form.
    const size = ceiling.trim() === "" ? null : Number(ceiling);
    if (size !== null && Number.isFinite(size) && size <= 0) {
      setFailure(
        "A limit of zero or less denies every response. Leave it blank for the default, " +
          "or enter a size.",
      );
      return;
    }
    // Anything that is not a whole number this browser can hold exactly: a fraction, a
    // number so large that JavaScript has already rounded it before it reaches here, or
    // nothing numeric at all. **Refused rather than sent**, because the server's own
    // refusals for these are `le` and the integer type — 422s, and therefore the one
    // generic sentence — and because sending a silently rounded number would store a
    // ceiling somebody did not type.
    if (size !== null && (!Number.isSafeInteger(size) || size > Number.MAX_SAFE_INTEGER)) {
      setFailure(
        "A limit must be a whole number of bytes. Leave it blank for the default.",
      );
      return;
    }

    // A row with a type and no argument used to be **dropped silently** by the filter
    // below, which is a scope somebody named and did not get. Reachable on a create — type
    // the type, forget the picker — and reachable on every re-vet, because the argument
    // names are the half the wire does not return. Refused, with the sentence.
    if (resources.some((r) => r.type.trim() && r.args.length === 0)) {
      setFailure(
        "Every resource needs the argument that names it. Pick one, or remove the row.",
      );
      return;
    }

    setBusy(true);
    setFailure("");
    setDone("");
    api
      .vetTool(connectorId, tool.name, {
        effect,
        identity,
        resources: resources.filter((r) => r.type.trim() && r.args.length > 0),
        note: note.trim(),
        local_name: localName.trim() || null,
        // Blank is `null`, and null is the **correct** value rather than an omission being
        // tolerated: it means *this deployment's `MAX_RESPONSE_BYTES`*. The inverse of
        // `max_tokens: null`, where null is the hazard.
        max_response_bytes: size,
      })
      .then((outcome) => {
        setDone(`Approved as ${outcome.local_name}, against ${outcome.server}.`);
        onVetted();
      })
      // Every one of these is written for the person filling in this form: the tool is
      // not advertised (and here is what is), this argument is not in the schema, a write
      // with nothing to scope it to, a name that shadows a built-in. Verbatim.
      .catch((cause: unknown) =>
        setFailure(cause instanceof Error ? cause.message : String(cause)),
      )
      .finally(() => setBusy(false));
  };

  return (
    <div className="row">
      <div className="row-main">
        <div className="spread">
          <strong className="mono">{tool.name}</strong>
          {tool.vetted && <Tag>approved</Tag>}
        </div>
        {tool.description && <p className="muted">{tool.description}</p>}

        {/* **The reason this whole screen exists.** Argument names and requiredness, which
            are the one thing a person cannot guess and which `resources` needs exactly. */}
        <p className="mono row-sub">
          {tool.arguments.length === 0
            ? "(takes no arguments)"
            : tool.arguments
                .map((a) => `${a.name} (${a.type}, ${a.required ? "required" : "optional"})`)
                .join("  ")}
        </p>

        {open && (
          <div className="inline-form">
            <Field
              label="Effect"
              hint="Read: does not change data. Write: creates, updates or deletes data."
            >
              <select
                value={effect}
                onChange={(e) => setEffect(e.target.value as "read" | "write")}
              >
                <option value="read">read</option>
                <option value="write">write</option>
              </select>
            </Field>

            <Field
              label="Acts as"
              hint="Service: uses the shared credential. Caller: uses the caller's connected account. Denied if they have none."
            >
              <select
                value={identity}
                onChange={(e) => setIdentity(e.target.value as "service" | "user")}
              >
                <option value="service">the service</option>
                <option value="user">the caller</option>
              </select>
            </Field>

            <ResourceRows
              args={tool.arguments.map((a) => a.name)}
              resources={resources}
              onChange={setResources}
            />

            {approved && approved.resources.length > 0 && (
              <p className="muted">
                This tool is restricted to{" "}
                {approved.resources.map((r) => r.type).join(", ")}. Pick the argument for
                each again. The API does not return it.
              </p>
            )}

            {effect === "write" && resources.length === 0 && (
              <p className="muted">A write tool with no resource cannot be approved.</p>
            )}

            <Field label="Name" hint={`Optional. Defaults to ${tool.local_name}.`}>
              <input
                value={localName}
                placeholder={tool.local_name}
                onChange={(e) => setLocalName(e.target.value)}
              />
            </Field>

            <Field label="Note" hint="Optional. Shown to people choosing this tool.">
              <input value={note} onChange={(e) => setNote(e.target.value)} />
            </Field>

            {/* **Blank is meaningful and is the right answer for nearly every tool.** It
                means the platform's own ceiling, which is a fact about this deployment and
                is on no response, so this hint cannot truthfully name the number — 035e's
                argument about `TokenSpend.ceiling`, arriving at a different field.

                A number here is for a tool whose output is genuinely large. Zero is the
                hazard `submit` refuses. */}
            <Field
              label="Response limit"
              hint="Optional, in bytes. Blank means the deployment default. Larger responses are denied, not truncated."
            >
              <input
                type="number"
                min="1"
                value={ceiling}
                onChange={(e) => setCeiling(e.target.value)}
              />
            </Field>

            {failure && (
              <Notice tone="warn">
                <p className="sentence">{failure}</p>
              </Notice>
            )}
            {done && (
              <Notice tone="info">
                <p className="sentence">{done}</p>
              </Notice>
            )}

            <Button kind="primary" busy={busy} onClick={submit}>
              {tool.vetted ? "Approve again" : "Approve"}
            </Button>
          </div>
        )}
      </div>
      <div className="row-action">
        <Button onClick={() => (open ? setOpen(false) : start())}>
          {open ? "Cancel" : tool.vetted ? "Edit approval" : "Approve…"}
        </Button>
      </div>
    </div>
  );
}

/** Resource rows: a type, and which of **this tool's own arguments** carries it.
 *
 * The argument is a `select` over the discovered names rather than a text box, which is
 * the whole payoff of discovery being on this page: the commonest way to get vetting wrong
 * is to name an argument the server does not have, and a list of the ones it does have
 * makes that unspellable rather than merely refused.
 *
 * The type is free text on purpose. It is the *vocabulary* — `jira.project`,
 * `github.repo` — and it is a decision about how this organisation names things across
 * connectors, not something one server can offer a list for. Two connectors both touching
 * repositories should agree on `github.repo`, and only a person knows that.
 *
 * More than one argument means a **composed** identifier and needs a template, because
 * gluing two values together without a stated shape is a guess. GitHub splits a repo
 * across `owner` and `repo`, which is why the case exists at all.
 */
/** The top-level argument names of an authored schema, and why one could not be read.
 *
 * **This is the function that makes the REST form worth having.** `check_binding` requires
 * every schema property to be mapped somewhere and every `{placeholder}` in the path to
 * name one — refusals a person can only meet *after* typing the whole thing. Reading the
 * names out of the schema as it is typed is how the form offers the same pickers discovery
 * buys the MCP form, reconstructed from the only thing here that can supply them.
 *
 * Top-level `properties` only, deliberately. A schema using `$ref` or `allOf` returns no
 * names and the person maps by hand; `check_binding` is the enforcement either way, so the
 * failure mode is a form that helps less, never a binding that is wrong.
 */
function schemaArguments(text: string): { names: string[]; error: string } {
  if (!text.trim()) return { names: [], error: "" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (cause) {
    return { names: [], error: cause instanceof Error ? cause.message : String(cause) };
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { names: [], error: "A schema is a JSON object." };
  }
  const properties = (parsed as { properties?: unknown }).properties;
  if (!properties || typeof properties !== "object") {
    return {
      names: [],
      error:
        "No top-level properties, so the arguments cannot be listed. Map them by hand.",
    };
  }
  return { names: Object.keys(properties as Record<string, unknown>), error: "" };
}

/** Which arguments the path template consumes. `/repos/{owner}/{repo}` → owner, repo. */
function pathArguments(path: string): string[] {
  return [...path.matchAll(/\{([A-Za-z0-9_]+)\}/g)].map((m) => m[1]);
}

/** Authoring a tool on a connector that describes nothing — step 047.
 *
 * The REST twin of `Discovery`, and the differences are the plan's decision 3 made
 * visible: no button that opens a socket, no drift findings, no advertised list to work
 * through. What replaces them is one form, because the vetter is the source of everything
 * a server would otherwise have said.
 *
 * **One `PUT` per tool, exactly as the MCP side.** Append semantics are the same rule and
 * the same reason: an administrator who has authored nine tools and gets the tenth wrong
 * must not lose nine.
 *
 * **Re-authoring cannot prefill the binding**, and the form says so rather than showing an
 * empty one. `VettedTool` does not return `binding`, so a form that looked pre-filled
 * would silently replace a working request mapping with a blank — `ToolForm.start`'s trap
 * at a new address, where the missing half is bigger.
 */
function AuthorTool({
  connectorId,
  vetted,
  onVetted,
}: {
  connectorId: string;
  vetted: VettedTool[];
  onVetted: () => void;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [method, setMethod] = useState<"GET" | "POST" | "PUT" | "PATCH" | "DELETE">("GET");
  const [path, setPath] = useState("");
  const [schemaText, setSchemaText] = useState("");
  const [mapping, setMapping] = useState<Record<string, "query" | "body">>({});
  const [effect, setEffect] = useState<"read" | "write">("read");
  const [identity, setIdentity] = useState<"service" | "user">("service");
  const [resources, setResources] = useState<ResourceSpec[]>([]);
  const [redact, setRedact] = useState<string[]>([]);
  const [usageMap, setUsageMap] = useState("");
  const [localName, setLocalName] = useState("");
  const [ceiling, setCeiling] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");
  const [done, setDone] = useState("");

  const { names, error: schemaError } = schemaArguments(schemaText);
  const inPath = pathArguments(path);
  const already = vetted.find((v) => v.remote_name === name.trim()) ?? null;

  const submit = () => {
    setFailure("");
    setDone("");

    let schema: Record<string, unknown>;
    try {
      schema = JSON.parse(schemaText) as Record<string, unknown>;
    } catch {
      setFailure("The input schema is not valid JSON.");
      return;
    }

    // **Pre-empted here because the server's version of this arrives too late to be
    // cheap.** `check_binding` refuses an unmapped property with a good sentence — after
    // a round trip, and after somebody has filled in every other field. The form knows
    // the same fact the moment the schema is typed.
    const unmapped = names.filter((n) => !inPath.includes(n) && !mapping[n]);
    if (unmapped.length > 0) {
      setFailure(
        `Every argument must be mapped: ${unmapped.join(", ")} ${
          unmapped.length === 1 ? "is" : "are"
        } in the schema but not in the path, query or body.`,
      );
      return;
    }

    const missing = inPath.filter((n) => names.length > 0 && !names.includes(n));
    if (missing.length > 0) {
      setFailure(
        `The path names ${missing.join(", ")}, which the schema does not define.`,
      );
      return;
    }

    if (resources.some((r) => r.type.trim() && r.args.length === 0)) {
      setFailure(
        "Every resource needs the argument that names it. Pick one, or remove the row.",
      );
      return;
    }

    let usage: Record<string, string> | null = null;
    if (usageMap.trim()) {
      try {
        usage = JSON.parse(usageMap) as Record<string, string>;
      } catch {
        setFailure("The usage map is not valid JSON.");
        return;
      }
    }

    const size = ceiling.trim() === "" ? null : Number(ceiling);
    if (size !== null && (!Number.isSafeInteger(size) || size <= 0)) {
      setFailure(
        "A limit must be a whole number of bytes above zero. Leave it blank for the default.",
      );
      return;
    }

    setBusy(true);
    api
      .vetTool(connectorId, name.trim(), {
        effect,
        identity,
        resources: resources.filter((r) => r.type.trim() && r.args.length > 0),
        note: note.trim(),
        local_name: localName.trim() || null,
        max_response_bytes: size,
        description: description.trim(),
        redact_args: redact.filter((r) => names.includes(r)),
        binding: {
          method,
          path: path.trim(),
          query: names.filter((n) => mapping[n] === "query"),
          body: names.filter((n) => mapping[n] === "body"),
          input_schema: schema,
          usage_map: usage,
        },
      })
      .then((outcome) => {
        setDone(`Approved as ${outcome.local_name}.`);
        onVetted();
      })
      // The server's sentences are written for the person at this form — an argument
      // not in the schema, an unscopeable write, a name that shadows a built-in.
      // Rendered verbatim, which is this page's rule everywhere.
      .catch((cause: unknown) =>
        setFailure(cause instanceof Error ? cause.message : String(cause)),
      )
      .finally(() => setBusy(false));
  };

  return (
    <Card title="Author a tool">
      <p className="sentence">
        A REST API does not describe its tools. Enter the schema, description and request
        mapping for each tool. Resources, effect and identity mean the same as for an MCP
        server.
      </p>

      <div className="inline-form">
        <Field label="Tool name" hint="Prefixed with the connector ID in the name a model sees.">
          <input
            value={name}
            placeholder="chat"
            onChange={(e) => setName(e.target.value)}
          />
        </Field>

        {already && (
          <Notice tone="warn" title={`${already.remote_name} is already approved`}>
            <p className="sentence">
              Submitting replaces the whole tool. The request mapping cannot be read
              back, so enter the method, path and schema again.
            </p>
          </Notice>
        )}

        <Field
          label="Description"
          hint="What the tool does. The model reads this when choosing tools."
        >
          <input
            value={description}
            placeholder="Think with a model."
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>

        <Field label="Method" hint="The HTTP method this tool's request uses.">
          <select
            value={method}
            onChange={(e) => setMethod(e.target.value as typeof method)}
          >
            {(["GET", "POST", "PUT", "PATCH", "DELETE"] as const).map((verb) => (
              <option key={verb} value={verb}>
                {verb}
              </option>
            ))}
          </select>
        </Field>

        <Field
          label="Path"
          hint="Joined to the connector's base URL. A {name} segment is filled from the argument of that name."
        >
          <input
            value={path}
            placeholder="/repos/{owner}/{repo}/issues"
            onChange={(e) => setPath(e.target.value)}
          />
        </Field>

        <Field label="Input schema" hint="JSON Schema for the tool's arguments.">
          <textarea
            className="mono"
            rows={8}
            value={schemaText}
            placeholder={
              '{"type":"object","properties":{"owner":{"type":"string"}},' +
              '"required":["owner"]}'
            }
            onChange={(e) => setSchemaText(e.target.value)}
          />
        </Field>

        {schemaError && (
          <Notice tone="warn" title="The schema could not be read">
            <p className="sentence">{schemaError}</p>
          </Notice>
        )}

        {names.length > 0 && (
          <FieldGroup
            label="Argument mapping"
            hint="Every argument must be mapped. Arguments named in the path are filled from there."
          >
            {names.map((argument) => {
              const consumed = inPath.includes(argument);
              return (
                <div className="spread" key={argument}>
                  <span className="mono">{argument}</span>
                  {consumed ? (
                    <span className="muted">in the path</span>
                  ) : (
                    <select
                      value={mapping[argument] ?? ""}
                      onChange={(e) =>
                        setMapping({
                          ...mapping,
                          [argument]: e.target.value as "query" | "body",
                        })
                      }
                    >
                      <option value="">Select…</option>
                      <option value="query">query parameter</option>
                      <option value="body">JSON body</option>
                    </select>
                  )}
                </div>
              );
            })}
          </FieldGroup>
        )}

        <Field
          label="Effect"
          hint="Read: does not change data. Write: creates, updates or deletes data."
        >
          <select
            value={effect}
            onChange={(e) => setEffect(e.target.value as "read" | "write")}
          >
            <option value="read">read</option>
            <option value="write">write</option>
          </select>
        </Field>

        <Field
          label="Acts as"
          hint="Service: uses the shared credential. Caller: uses the caller's connected account. Denied if they have none."
        >
          <select
            value={identity}
            onChange={(e) => setIdentity(e.target.value as "service" | "user")}
          >
            <option value="service">the service</option>
            <option value="user">the caller</option>
          </select>
        </Field>

        <ResourceRows args={names} resources={resources} onChange={setResources} />

        {names.length > 0 && (
          <FieldGroup
            label="Redacted arguments"
            hint="Arguments whose value is not kept in the audit log, for example a prompt."
          >
            {names.map((argument) => (
              <label className="choice" key={argument}>
                <input
                  type="checkbox"
                  checked={redact.includes(argument)}
                  onChange={(e) =>
                    setRedact(
                      e.target.checked
                        ? [...redact, argument]
                        : redact.filter((r) => r !== argument),
                    )
                  }
                />
                <span className="mono">{argument}</span>
              </label>
            ))}
          </FieldGroup>
        )}

        <Field
          label="Token usage paths"
          hint="Optional, for a model API. Dotted paths into the response body, so calls can be priced and metered."
        >
          <textarea
            className="mono"
            rows={3}
            value={usageMap}
            placeholder={
              '{"model":"model","input_tokens":"usage.input_tokens",' +
              '"output_tokens":"usage.output_tokens"}'
            }
            onChange={(e) => setUsageMap(e.target.value)}
          />
        </Field>

        <Field
          label="Response limit (bytes)"
          hint="Blank means the deployment default. Larger responses are denied."
        >
          <input
            value={ceiling}
            inputMode="numeric"
            placeholder="default"
            onChange={(e) => {
              if (/^\d*$/.test(e.target.value)) setCeiling(e.target.value);
            }}
          />
        </Field>

        <Field
          label="Name"
          hint="Optional. Needed only when the connector ID and tool name together exceed 64 characters."
        >
          <input
            value={localName}
            onChange={(e) => setLocalName(e.target.value)}
          />
        </Field>

        <Field label="Note" hint="Optional. Shown to people choosing this tool.">
          <input value={note} onChange={(e) => setNote(e.target.value)} />
        </Field>

        {failure && (
          <Notice tone="bad" title="Not approved">
            <p className="sentence">{failure}</p>
          </Notice>
        )}
        {done && (
          <Notice tone="info" title="Approved">
            <p className="sentence">{done}</p>
          </Notice>
        )}

        <Button
          kind="primary"
          busy={busy}
          disabled={!name.trim() || !path.trim() || !schemaText.trim()}
          onClick={submit}
        >
          {already ? "Approve again" : "Approve"}
        </Button>
      </div>
    </Card>
  );
}

function ResourceRows({
  args,
  resources,
  onChange,
}: {
  args: string[];
  resources: ResourceSpec[];
  onChange: (next: ResourceSpec[]) => void;
}) {
  const update = (index: number, patch: Partial<ResourceSpec>) =>
    onChange(resources.map((r, i) => (i === index ? { ...r, ...patch } : r)));

  return (
    <FieldGroup
      label="Resources"
      hint="The argument that names the resource this tool acts on, for example repo. Agents restrict access per resource. Without one, the tool is unrestricted."
    >
      {resources.map((resource, index) => (
        <div className="spread" key={index}>
          <input
            value={resource.type}
            placeholder="jira.project"
            onChange={(e) => update(index, { type: e.target.value })}
          />
          <select
            value={resource.args[0] ?? ""}
            onChange={(e) => update(index, { args: [e.target.value] })}
          >
            <option value="">Select argument…</option>
            {args.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
          <Button
            kind="quiet"
            onClick={() => onChange(resources.filter((_, i) => i !== index))}
          >
            Remove
          </Button>
        </div>
      ))}
      <Button
        kind="quiet"
        disabled={args.length === 0}
        onClick={() => onChange([...resources, { type: "", args: [] }])}
      >
        Add a resource
      </Button>
      {args.length === 0 && (
        <p className="muted">
          This tool takes no arguments, so it cannot be restricted by resource.
        </p>
      )}
    </FieldGroup>
  );
}

/** One provider-specific authorize parameter, as a row of the form holds it.
 *
 *  Not `Record<string, string>` in component state: two rows may briefly share a name while
 *  somebody is typing, and a map would silently eat one of them. The map is built at submit,
 *  which is also where blank names are dropped. */
interface Param {
  name: string;
  value: string;
}

/** Provider-specific parameters on the sign-in link — `audience`, `prompt`, whatever a
 *  vendor mandates. Migration 025's field, and **key/value rows rather than a JSON
 *  textarea**, for three reasons in order of weight.
 *
 *  **1. A row of inputs cannot produce a 422 and a textarea can.** `dict[str, str]` is true
 *  by construction when every value is an `<input>`'s value, so no keystroke makes the body
 *  fail validation and every refusal on this path is the server's own 400 sentence. A
 *  textarea hands somebody `{"audience": 1}` — valid JSON, invalid `dict[str, str]` — and a
 *  422's `detail` is a list of field errors, which `readProblem` collapses to the one
 *  generic sentence *"the request was not in a shape the server accepts"*. True, and it
 *  names neither the parameter nor what is wrong with it, in the box that otherwise carries
 *  a paragraph explaining a security design. This is how the form stops being able to
 *  produce that at all.
 *
 *  **2. Parity with the CLI's spelling.** `--authorize-param NAME=VALUE`, repeatable. Rows
 *  *are* that spelling; a JSON document would be a third rendering of one dict, and the only
 *  one nobody could paste from `--help`.
 *
 *  **3. The page already has this control** — `ResourceRows` below is the same shape, and
 *  two structured inputs on one screen should read alike.
 *
 *  **The seven reserved names are not checked here.** `RESERVED_AUTHORIZE_PARAMS` and its
 *  per-name sentences are the server's, and a copy in the browser is a copy of a security
 *  rule that can drift from the original. The sentences are the point: *"the callback
 *  carries no token, so a fixed or guessable value makes every consent flow in this tenant
 *  forgeable"* is why the platform refuses, and no client-side `if` reproduces it. Type it,
 *  send it, render the 400.
 */
function AuthorizeParams({
  params,
  onChange,
}: {
  params: Param[];
  onChange: (next: Param[]) => void;
}) {
  const update = (index: number, patch: Partial<Param>) =>
    onChange(params.map((p, i) => (i === index ? { ...p, ...patch } : p)));

  return (
    <FieldGroup
      label="Extra parameters"
      hint="Optional. Parameters some providers require on the authorize URL, for example audience=api.atlassian.com and prompt=consent for Atlassian. Parameters the OAuth flow sets itself are rejected."
    >
      {params.map((param, index) => (
        <div className="spread" key={index}>
          <input
            value={param.name}
            placeholder="audience"
            onChange={(e) => update(index, { name: e.target.value })}
          />
          <input
            value={param.value}
            placeholder="api.atlassian.com"
            onChange={(e) => update(index, { value: e.target.value })}
          />
          <Button
            kind="quiet"
            onClick={() => onChange(params.filter((_, i) => i !== index))}
          >
            Remove
          </Button>
        </div>
      ))}
      <Button kind="quiet" onClick={() => onChange([...params, { name: "", value: "" }])}>
        Add a parameter
      </Button>
    </FieldGroup>
  );
}

/** What a configured flow puts on the sign-in link besides what the flow builds itself.
 *
 *  `name=value` per parameter, and **one line each rather than the CLI's single space-joined
 *  string**. The CLI prints `also sends audience=api.atlassian.com prompt=consent`, which is
 *  unambiguous only while no value contains a space — and a value is free text that reaches
 *  a URL, so one that does is storable and was confirmed to round-trip. `prompt=consent
 *  please` in a joined line is indistinguishable from two parameters. The screen has the
 *  vertical space the CLI does not, so it uses it; found by 035g's comprehensive pass
 *  asking what an adversarial value does to the rendering, which is the same family as
 *  035f's comma-in-a-scope.
 *
 *  Empty renders as the word it is: *none* is a complete answer and a true one, and it is
 *  a different fact from a connector with no OAuth app at all. */
export function sends(params: Record<string, string>): string[] {
  const pairs = Object.entries(params).map(([name, value]) => `${name}=${value}`);
  return pairs.length > 0 ? pairs : ["none"];
}

/** The consent flow: `--set-oauth`'s fields, and the two things it answers with.
 *
 * **The secret is `type="password"`, sent once, and never comes back** — not even masked.
 * A masked echo implies the value is retrievable and nothing in this system can retrieve
 * it for a person, so the saved state says *stored*. That is the same distinction the
 * storage layer draws by putting `client_secret` after `OAUTH_APP_PUBLIC_FIELDS`.
 *
 * The `redirect_uri` renders on success because the person who has to register it at the
 * provider is standing exactly here, and it is the one real onboarding ask in the flow.
 */
function ConsentFlow({
  connector,
  onChange,
}: {
  connector: ConnectorDetail;
  onChange: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [authorize, setAuthorize] = useState("");
  const [token, setToken] = useState("");
  const [revoke, setRevoke] = useState("");
  const [clientId, setClientId] = useState("");
  const [secret, setSecret] = useState("");
  const [scopes, setScopes] = useState("");
  const [params, setParams] = useState<Param[]>([]);
  /** Migration 051's prose, carried through a re-save **without an editor**. The `PUT` is
   *  a wholesale replace and this form has no field for a scope's description, so until
   *  this was held in state every rotation of a client secret from this screen erased what
   *  non-administrators were reading at consent. Narrowed to the scopes still requested at
   *  save, as `--set-oauth` narrows a preset's notes: dropping a scope drops its sentence,
   *  and a sentence for a scope nobody asks for is a 400 the server is right to give.
   *  Authoring a note is `--scope-notes`'s job; this only refuses to lose one. */
  const [notes, setNotes] = useState<Record<string, ScopeNote>>({});
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");
  const [saved, setSaved] = useState<{ redirect_uri: string; warnings: string[] } | null>(
    null,
  );

  /** Open the form with what is already configured in it. **The `PUT` is a wholesale
   *  replace** — `authorize_params = EXCLUDED.authorize_params`, deliberately, because that
   *  is how a rotated client secret is installed — so a blank form is a data-loss control:
   *  every box left alone is a stored field cleared.
   *
   *  Until 035g this form opened empty, which meant pressing *Replace it*, filling in the
   *  four required fields and saving silently dropped the connector's scopes. 035g would
   *  have added a fifth losable field, and the one most likely to exist and least likely to
   *  be remembered — the person who set `audience` was following a vendor's onboarding page
   *  a year ago.
   *
   *  The secret is the one thing that cannot be seeded, and that is not an oversight to
   *  work around: nothing in this system can read it back, which is the whole meaning of
   *  the word *stored* above. The form says so rather than letting somebody find out at the
   *  submit button. */
  const openForm = () => {
    const app = connector.oauth;
    setAuthorize(app?.authorize_endpoint ?? "");
    setToken(app?.token_endpoint ?? "");
    setRevoke(app?.revoke_endpoint ?? "");
    setClientId(app?.client_id ?? "");
    setScopes((app?.scopes ?? []).join(" "));
    setParams(
      Object.entries(app?.authorize_params ?? {}).map(([name, value]) => ({ name, value })),
    );
    setNotes(app?.scope_notes ?? {});
    setSecret("");
    setOpen(true);
  };

  const save = () => {
    setBusy(true);
    setFailure("");
    setSaved(null);
    const requested = scopes.split(/\s+/).filter(Boolean);
    api
      .configureOAuth(connector.connector_id, {
        authorize_endpoint: authorize.trim(),
        token_endpoint: token.trim(),
        revoke_endpoint: revoke.trim(),
        client_id: clientId.trim(),
        client_secret: secret,
        scopes: requested,
        scope_notes: Object.fromEntries(
          Object.entries(notes).filter(([scope]) => requested.includes(scope)),
        ),
        // A row with no name is not a parameter yet — dropped, exactly as `resources` drops
        // its half-filled rows. A named one with an empty value **is** sent: the server
        // accepts it, and refusing it here would be this screen inventing a rule the
        // platform does not have.
        authorize_params: Object.fromEntries(
          params.filter((p) => p.name.trim()).map((p) => [p.name.trim(), p.value]),
        ),
      })
      .then((outcome) => {
        // Cleared the instant it is accepted. It is in a form field on somebody's screen
        // and it does not need to stay there.
        setSecret("");
        setParams([]);
        setOpen(false);
        setSaved({ redirect_uri: outcome.redirect_uri, warnings: outcome.warnings });
        onChange();
      })
      .catch((cause: unknown) =>
        setFailure(cause instanceof Error ? cause.message : String(cause)),
      )
      .finally(() => setBusy(false));
  };

  const remove = () => {
    api
      .removeOAuth(connector.connector_id)
      .then(() => {
        setSaved(null);
        onChange();
      })
      .catch((cause: unknown) =>
        setFailure(cause instanceof Error ? cause.message : String(cause)),
      );
  };

  return (
    <Card title="OAuth app" hint={connector.oauth ? "configured" : "not configured"}>
      {/* **stdio, not "anything but http"** — step 047, and the bug it fixes was
          invisible until a REST connector could be made in a browser. `Connector
          .carries_per_user_credentials` has been true for REST since 045a (its finding
          5: a REST tool presents the acting person's credential in a header exactly the
          way an HTTP MCP server does), and `oauth.configure` refuses stdio and only
          stdio. Testing `!== "http"` here told every REST connector it could never have
          a consent flow, and hid the form that would have configured one — a screen
          refusing what the server permits, which is 021's disagreement in the direction
          that silently removes a capability. */}
      {connector.transport === "stdio" && (
        <p className="sentence">
          This connector uses stdio, which holds one credential per process. An OAuth app
          is not available for it.
        </p>
      )}

      {connector.transport !== "stdio" && !connector.oauth && !open && (
        <>
          <p className="sentence">
            Lets users connect their own accounts. Without it, every call uses the shared
            credential.
          </p>
          <Button kind="primary" onClick={openForm}>
            Set up OAuth app
          </Button>
        </>
      )}

      {connector.oauth && (
        <>
          <dl className="pairs">
            <dt>Client ID</dt>
            <dd className="mono">{connector.oauth.client_id}</dd>
            <dt>Client secret</dt>
            {/* Not `••••••`, which would imply it can be read back. It cannot, by
                anybody, including us. */}
            <dd>stored</dd>
            <dt>Authorize</dt>
            <dd className="mono">{connector.oauth.authorize_endpoint}</dd>
            <dt>Token</dt>
            <dd className="mono">{connector.oauth.token_endpoint}</dd>
            <dt>Revoke</dt>
            <dd className="mono">{connector.oauth.revoke_endpoint || "none"}</dd>
            <dt>Scopes</dt>
            <dd className="mono">
              {connector.oauth.scopes.join(" ") || "none requested"}
            </dd>
            {/* **The half nothing rendered.** `--set-oauth --authorize-param` has existed
                since migration 025 and prints `also sends audience=…` when it succeeds; this
                screen showed nothing, so an administrator could not see that their Atlassian
                connector sends an audience — let alone which one. Same word as the CLI, so
                the two surfaces read alike. */}
            <dt>Extra parameters</dt>
            <dd className="mono">
              {sends(connector.oauth.authorize_params).map((line) => (
                <div key={line}>{line}</div>
              ))}
            </dd>
            <dt>Configured by</dt>
            <dd className="mono">{connector.oauth.configured_by}</dd>
          </dl>
          <div className="spread">
            <Button onClick={() => (open ? setOpen(false) : openForm())}>
              {open ? "Cancel" : "Replace"}
            </Button>
            <Button kind="quiet" onClick={remove}>
              Remove
            </Button>
          </div>
          <p className="muted">
            Removing it keeps existing connections working until their access tokens
            expire. After that they cannot be renewed or reconnected.
          </p>
        </>
      )}

      {open && connector.transport !== "stdio" && (
        <div className="inline-form">
          {connector.oauth && (
            <p className="sentence">
              This replaces the whole OAuth app. Enter the client secret again. The stored
              one cannot be read back.
            </p>
          )}
          <Field label="Authorize endpoint">
            <input
              value={authorize}
              placeholder="https://auth.acme.com/authorize"
              onChange={(e) => setAuthorize(e.target.value)}
            />
          </Field>
          <Field label="Token endpoint" hint="Its host must be an approved host. The client secret is posted to it.">
            <input
              value={token}
              placeholder="https://auth.acme.com/token"
              onChange={(e) => setToken(e.target.value)}
            />
          </Field>
          <Field label="Revoke endpoint" hint="Optional. Without it, disconnecting deletes the credential here but not at the provider.">
            <input
              value={revoke}
              onChange={(e) => setRevoke(e.target.value)}
            />
          </Field>
          <Field label="Client ID" hint="Public. Appears in the authorize URL.">
            <input value={clientId} onChange={(e) => setClientId(e.target.value)} />
          </Field>
          <Field label="Client secret" hint="Stored once. You can't view it again.">
            <input
              type="password"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
            />
          </Field>
          <Field
            label="Scopes"
            hint="Space separated. Include the provider's offline-access scope so connections can be renewed."
          >
            <input
              value={scopes}
              placeholder="read:jira-work offline_access"
              onChange={(e) => setScopes(e.target.value)}
            />
          </Field>
          {Object.keys(notes).length > 0 && (
            <p className="muted">
              {Object.keys(notes).length === 1
                ? "One scope carries"
                : `${Object.keys(notes).length} scopes carry`}{" "}
              a description shown at consent. Descriptions stay with the scopes you keep.
              To change the wording, use <code>--set-oauth --scope-notes</code>.
            </p>
          )}

          <AuthorizeParams params={params} onChange={setParams} />

          {failure && (
            <Notice tone="warn">
              <p className="sentence">{failure}</p>
            </Notice>
          )}

          <Button
            kind="primary"
            busy={busy}
            disabled={!authorize.trim() || !token.trim() || !clientId.trim() || !secret}
            onClick={save}
          >
            Save OAuth app
          </Button>
        </div>
      )}

      {saved && (
        <Notice tone="info" title="Register this redirect URI at the provider">
          <p className="sentence mono">{saved.redirect_uri}</p>
          <p className="muted">
            Use exactly this value. It is the same for every connector on this deployment.
            Users can now connect their accounts from Connections.
          </p>
          {saved.warnings.map((warning) => (
            <p className="sentence" key={warning}>
              {warning}
            </p>
          ))}
        </Notice>
      )}
    </Card>
  );
}
