import { useState } from "react";

import Failure from "../../components/Failure";
import { Button, Empty, Notice, PageHead, Spinner, Tag } from "../../components/ui";
import { api } from "../../lib/api";
import { useAdmin } from "../../lib/me";
import type { PersonEntry } from "../../lib/types";
import { useResource } from "../../lib/useResource";

/** People — step 110, decision 4.
 *
 * Who is in the tenant, their status, and whether they have ever signed in; and the one
 * act an operations team needs most and until now could not reach without a terminal:
 * cutting somebody off. `--disable-user` *reduces* authority — sign-in refused from now,
 * every token they own refused at its next call, nothing they made deleted — and a
 * compromised admin session that disables people is a nuisance an administrator with a
 * shell can undo. That is why this button is here and the one that appoints an
 * administrator is not (see `RolesPage`).
 *
 * **No create.** People arrive by signing in, which is 016's rule and stays. A row that
 * has never signed in is one the directory pushed (071), and the page says so rather
 * than showing a dash.
 *
 * **Disabling is a sentence and a second button, in place** — `GroupsPage`'s precedent:
 * a confirm dialog asking *are you sure* asks a question the person cannot answer; one
 * naming what stops and what stays is a question they can. The server refuses the
 * caller's own row, and that refusal is rendered verbatim because it says the way back.
 */
export default function PeoplePage() {
  const { data, error, loading, reload } = useResource(() => api.listPeople(), []);
  const { me } = useAdmin();

  return (
    <>
      <PageHead
        title="People"
        lede="Everyone who has signed in here, or whom your directory has sent. Cutting somebody off stops their sign-in and every token they hold; nothing they made is deleted."
      />

      {loading && <Spinner label="Loading people…" />}
      {error ? <Failure error={error} /> : null}

      {data && data.length === 0 && (
        <Empty title="Nobody yet">
          <p className="sentence">People appear here at their first sign-in.</p>
        </Empty>
      )}

      {data && data.length > 0 && (
        <div className="rows">
          {data.map((person) => (
            <PersonRow
              key={person.id}
              person={person}
              you={me?.principal === `user:${person.id}`}
              onChange={reload}
            />
          ))}
        </div>
      )}
    </>
  );
}

function PersonRow({
  person,
  you,
  onChange,
}: {
  person: PersonEntry;
  you: boolean;
  onChange: () => void;
}) {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");
  const [note, setNote] = useState("");

  const set = (active: boolean) => {
    setBusy(true);
    setFailure("");
    setNote("");
    (active ? api.enablePerson(person.id) : api.disablePerson(person.id))
      .then((outcome) => {
        setConfirming(false);
        // The seam writes no record for a restatement, and this says nothing it did
        // not do: a screen that was stale says so rather than claiming the act.
        if (!outcome.changed) {
          setNote(`${outcome.email || outcome.id} was already ${outcome.status}.`);
        }
        onChange();
      })
      .catch((cause: unknown) => {
        setConfirming(false);
        setFailure(cause instanceof Error ? cause.message : String(cause));
      })
      .finally(() => setBusy(false));
  };

  const disabled = person.status === "disabled";

  return (
    <div className="row">
      <div className="row-main">
        <div className="spread">
          <strong>{person.email || person.display_name || person.id}</strong>
          {you && <Tag>you</Tag>}
          {disabled && <Tag write>cut off</Tag>}
          {!person.signed_in && <Tag>never signed in</Tag>}
        </div>
        <p className="row-sub">
          {person.display_name && person.email ? `${person.display_name}. ` : ""}
          {person.signed_in
            ? `Last signed in ${person.last_seen_at}.`
            : person.external_id
              ? "Sent by your directory; has not signed in yet."
              : "Has not signed in yet."}{" "}
          Through <span className="mono">{person.issuer}</span>.
        </p>
        <p className="row-sub mono">{person.id}</p>

        {confirming && (
          <Notice tone="warn" title={`Cut ${person.email || person.id} off?`}>
            <p className="sentence">
              Their sign-in stops now, and every access token they hold stops at its next
              call. Their agents, shares, group memberships and connections stay exactly as
              they are; nothing is deleted, and letting them back in is one click.
            </p>
            <div className="spread">
              <Button kind="primary" busy={busy} onClick={() => set(false)}>
                Cut off
              </Button>
              <Button onClick={() => setConfirming(false)}>Cancel</Button>
            </div>
          </Notice>
        )}
        {failure && (
          <Notice tone="bad">
            <p className="sentence">{failure}</p>
          </Notice>
        )}
        {note && (
          <Notice tone="info">
            <p className="sentence">{note}</p>
          </Notice>
        )}
      </div>
      {!confirming && (
        <div className="row-action">
          {disabled ? (
            <Button busy={busy} onClick={() => set(true)}>
              Let back in
            </Button>
          ) : (
            <Button
              kind="quiet"
              onClick={() => {
                setFailure("");
                setNote("");
                setConfirming(true);
              }}
            >
              Cut off…
            </Button>
          )}
        </div>
      )}
    </div>
  );
}
