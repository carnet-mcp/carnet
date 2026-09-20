import { useState } from "react";

import Failure from "../../components/Failure";
import { Button, Field } from "../../components/ui";
import { api } from "../../lib/api";
import type { MintedToken } from "../../lib/types";

/** The generate form — the tokens page's, and since plan 107 D9 the connect card's too.
 *
 *  One form, two places, because the five-screen loop 107 counted (generate on the tokens
 *  page, go back to the agent, share it with the token, copy the id, paste) was the same
 *  form on the wrong page. On an agent's page it can take `grantAgent`: a service token is
 *  granted that agent in the same request, so the client it is for can use it at once.
 *  A personal token needs no grant and takes none — it uses its owner's access.
 *
 *  `canGrant` is whether the viewer may share the agent (an editor or its owner). The
 *  share seam decides that on the server; here it decides whether the service option is
 *  offered with a grant or with the sentence saying why not. */
export default function MintForm({
  grantAgent,
  canGrant = false,
  onMinted,
  onCancel,
}: {
  grantAgent?: string;
  canGrant?: boolean;
  onMinted: (minted: MintedToken) => void;
  onCancel: () => void;
}) {
  const [name, setName] = useState("");
  const [personal, setPersonal] = useState(true);
  const [expiresDays, setExpiresDays] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<unknown>(null);

  const grants = Boolean(grantAgent) && !personal && canGrant;

  async function mint() {
    setBusy(true);
    setFailure(null);
    try {
      const made = await api.mintToken({
        name: name.trim(),
        acts_as_owner: personal,
        // Omitted when blank — "no expiry" is spelled by omission, the server's rule.
        ...(expiresDays.trim() === "" ? {} : { expires_days: Number(expiresDays) }),
        ...(grants ? { grant: { agent: grantAgent as string } } : {}),
      });
      onMinted(made);
    } catch (cause: unknown) {
      setFailure(cause);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="inline-form">
      <Field label="Name" hint="Shown in the list. One active token per name.">
        <input
          value={name}
          placeholder="my-client"
          onChange={(event) => setName(event.target.value)}
        />
      </Field>

      <div className="choices stacked">
        <label className={`choice big${personal ? " on" : ""}`}>
          <input type="radio" name="token-kind" checked={personal} onChange={() => setPersonal(true)} />
          <span>
            <strong>Personal</strong>
            <span className="muted">
              {" "}
              — Uses your access. Can use every agent shared with you. Revoked when your
              account is disabled.
            </span>
          </span>
        </label>
        <label className={`choice big${personal ? "" : " on"}`}>
          <input type="radio" name="token-kind" checked={!personal} onChange={() => setPersonal(false)} />
          <span>
            <strong>Service</strong>
            <span className="muted">
              {" "}
              — Has its own access. Can use only the agents granted to it. For CI and
              shared machines.
            </span>
          </span>
        </label>
      </div>

      {grantAgent && !personal && (
        <p className="muted">
          {canGrant
            ? `This agent is granted to the token as it is generated, so the client can use it at once.`
            : `Granting this agent needs edit access to it. The token is generated with no agents; an editor can grant it from the agent's Share dialog.`}
        </p>
      )}

      <Field label="Expires after (days)" hint="Blank means never.">
        <input
          value={expiresDays}
          inputMode="numeric"
          placeholder="never"
          onChange={(event) => {
            if (/^\d*$/.test(event.target.value)) setExpiresDays(event.target.value);
          }}
        />
      </Field>

      {failure ? <Failure error={failure} /> : null}

      <div className="spread">
        <Button onClick={onCancel} disabled={busy}>
          Cancel
        </Button>
        <Button kind="primary" busy={busy} disabled={name.trim() === ""} onClick={mint}>
          {busy ? "Generating" : "Generate token"}
        </Button>
      </div>
    </div>
  );
}
