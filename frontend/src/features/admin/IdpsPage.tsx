import { useState } from "react";

import Failure from "../../components/Failure";
import {
  Button,
  Card,
  Empty,
  Field,
  FieldGroup,
  Notice,
  PageHead,
  Spinner,
  Tag,
} from "../../components/ui";
import { api } from "../../lib/api";
import type { IdpEntry, IdpRequest } from "../../lib/types";
import { useResource } from "../../lib/useResource";

/** Identity providers — step 110, decisions 2 and 5.
 *
 * The first thing in an administrator's hour, and until this page the only one with no
 * browser path at all: `--add-idp` and `--list-idps` were the whole of it, so the hour
 * began in `docker compose exec` whatever else had a screen. This is a form over the nine
 * flags and a list, and two things about it are not cosmetic.
 *
 * ## The form pre-empts nothing
 *
 * Every rule about what a valid provider *is* — the three required fields, the
 * discriminator pair, the JWKS address, the wildcard domain only the local provider may
 * claim, an issuer that would make a token ambiguous between two tenants — lives in one
 * place on the server, and both doors (this one and the CLI) reach it. A copy here would
 * be a second opinion about what a valid issuer is, and the two would disagree on the day
 * somebody fixed one. So the refusals are rendered verbatim, which is this app's rule
 * everywhere and here is the whole design.
 *
 * ## Discovery is offered, never required
 *
 * Given an issuer, *Look it up* asks the server to fetch the provider's discovery document
 * and fills the JWKS URL from it — the same document the browser's own sign-in reads to
 * find its endpoints. The server dials it with the operator's consent presumed, as it
 * does for the key set, because an identity provider is the deployment's own and lives on
 * a private network in every estate 109 was written for. A provider that serves no
 * discovery is typed in by hand, as it always was, and the 502 says so.
 *
 * ## Removing the provider you signed in through is refused, and the screen says why
 *
 * The server refuses it with a sentence: removing it locks the tenant out with the person
 * who pressed the button inside it. There is no `--delete-idp` either, so the refusal is
 * not a shell command away, and the page says that rather than leaving it to be found.
 */
export default function IdpsPage() {
  const { data, error, loading, reload } = useResource(() => api.listIdps(), []);

  return (
    <>
      <PageHead
        title="Identity providers"
        lede="Who may vouch for a person signing in here. Register the provider your company uses; it must be the same provider the browser sign-in is configured with."
      />

      <NewProvider onRegistered={reload} />

      {loading && <Spinner label="Loading identity providers…" />}
      {error ? <Failure error={error} /> : null}

      {data && data.length === 0 && (
        <Empty title="No identity provider registered">
          <p className="sentence">
            Nobody can sign in until one is. Register the provider above.
          </p>
        </Empty>
      )}

      {data && data.length > 0 && (
        <div className="rows">
          {data.map((provider) => (
            <ProviderRow
              key={`${provider.issuer} ${provider.discriminator_value ?? ""}`}
              provider={provider}
              onChange={reload}
            />
          ))}
        </div>
      )}
    </>
  );
}

/** `"acme.com, acme.co.uk"` → the list, empties dropped. The wildcard is sent as typed:
 *  refusing it here would refuse the one issuer for which it is legal, and the server
 *  knows which that is. */
function domains(text: string): string[] {
  return text
    .split(",")
    .map((d) => d.trim())
    .filter((d) => d.length > 0);
}

function NewProvider({ onRegistered }: { onRegistered: () => void }) {
  const [issuer, setIssuer] = useState("");
  const [jwks, setJwks] = useState("");
  const [audience, setAudience] = useState("");
  const [claim, setClaim] = useState("");
  const [value, setValue] = useState("");
  const [subjectClaim, setSubjectClaim] = useState("sub");
  const [emailClaim, setEmailClaim] = useState("email");
  const [groupsClaim, setGroupsClaim] = useState("");
  const [domainText, setDomainText] = useState("");
  const [claims, setClaims] = useState<string[]>([]);
  const [looking, setLooking] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");
  const [done, setDone] = useState("");

  const lookUp = () => {
    setLooking(true);
    setFailure("");
    setDone("");
    api
      .discoverIdp(issuer.trim())
      .then((found) => {
        // The issuer as the document spells it — the server has already refused one
        // that differs from what was typed, so this is the same string or the form
        // would not be here.
        setIssuer(found.issuer);
        setJwks(found.jwks_uri);
        setClaims(found.claims_supported);
        setDone(
          found.claims_supported.length > 0
            ? "Found the key set. The claims this provider says it emits are listed under Claims."
            : "Found the key set. The provider does not say which claims it emits.",
        );
      })
      .catch((cause: unknown) =>
        setFailure(cause instanceof Error ? cause.message : String(cause)),
      )
      .finally(() => setLooking(false));
  };

  const register = () => {
    setBusy(true);
    setFailure("");
    setDone("");
    const body: IdpRequest = {
      issuer: issuer.trim(),
      jwks_uri: jwks.trim(),
      audience: audience.trim(),
      // Together or not at all is the server's rule; a half-typed pair is sent as
      // typed so the refusal is its sentence rather than this form's guess.
      discriminator_claim: claim.trim() || null,
      discriminator_value: value.trim() || null,
      subject_claim: subjectClaim.trim() || "sub",
      email_claim: emailClaim.trim() || "email",
      groups_claim: groupsClaim.trim() || null,
      allowed_domains: domains(domainText),
    };
    api
      .registerIdp(body)
      .then((outcome) => {
        setDone(
          outcome.replaced
            ? `Replaced ${outcome.provider.issuer}. Every claim mapping is now what this form said, including the ones left at their defaults.`
            : `Registered ${outcome.provider.issuer}. People with an address it vouches for can sign in.`,
        );
        setIssuer("");
        setJwks("");
        setAudience("");
        setClaim("");
        setValue("");
        setSubjectClaim("sub");
        setEmailClaim("email");
        setGroupsClaim("");
        setDomainText("");
        setClaims([]);
        onRegistered();
      })
      .catch((cause: unknown) =>
        setFailure(cause instanceof Error ? cause.message : String(cause)),
      )
      .finally(() => setBusy(false));
  };

  const claimHint = (what: string) =>
    claims.length > 0
      ? `${what} The provider says it emits: ${claims.join(", ")}.`
      : what;

  return (
    <Card title="Register a provider">
      <p className="sentence">
        Any OpenID Connect provider. The issuer and audience must be exactly what its
        tokens carry, and the issuer must be the one the browser sign-in is configured
        with, or nobody can sign in through it.
      </p>

      <Field
        label="Issuer"
        hint="The provider's iss claim, exactly as it emits it. Look it up to fill the key set from its discovery document."
      >
        <div className="spread">
          <input
            value={issuer}
            placeholder="https://acme.okta.com"
            onChange={(e) => setIssuer(e.target.value)}
          />
          <Button busy={looking} disabled={!issuer.trim()} onClick={lookUp}>
            Look it up
          </Button>
        </div>
      </Field>

      <Field
        label="Key set URL"
        hint="Where the provider publishes its signing keys (jwks_uri). Filled by Look it up, or from the provider's documentation."
      >
        <input
          value={jwks}
          placeholder="https://acme.okta.com/oauth2/v1/keys"
          onChange={(e) => setJwks(e.target.value)}
        />
      </Field>

      <Field
        label="Audience"
        hint="What a token's aud must be: this deployment's client id at the provider."
      >
        <input
          value={audience}
          placeholder="api://default"
          onChange={(e) => setAudience(e.target.value)}
        />
      </Field>

      <Field
        label="Email domains"
        hint="The domains this provider may vouch for, comma-separated. A person with an address outside them cannot sign in."
      >
        <input
          value={domainText}
          placeholder="acme.com, acme.co.uk"
          onChange={(e) => setDomainText(e.target.value)}
        />
      </Field>

      {/* The three claim mappings, with their defaults visible rather than implied:
          registering again resets every one of them to what this form says, which is
          `--add-idp`'s own warning and the reason `replaced` comes back. */}
      <FieldGroup
        label="Claims"
        hint={claimHint(
          "Which claims carry the identity, the email and the groups. The defaults are what a conformant token uses; Entra puts the email in preferred_username, Okta access tokens put the stable id in uid.",
        )}
      >
        <div className="spread">
          <input
            value={subjectClaim}
            aria-label="Subject claim"
            placeholder="sub"
            onChange={(e) => setSubjectClaim(e.target.value)}
          />
          <input
            value={emailClaim}
            aria-label="Email claim"
            placeholder="email"
            onChange={(e) => setEmailClaim(e.target.value)}
          />
          <input
            value={groupsClaim}
            aria-label="Groups claim"
            placeholder="groups (optional)"
            onChange={(e) => setGroupsClaim(e.target.value)}
          />
        </div>
      </FieldGroup>

      <FieldGroup
        label="Routes on"
        hint="Only for a provider shared by many companies, such as Google Workspace: the claim and value that identify yours (hd = acme.com). Leave both empty for a provider that is yours alone."
      >
        <div className="spread">
          <input
            value={claim}
            aria-label="Discriminator claim"
            placeholder="hd"
            onChange={(e) => setClaim(e.target.value)}
          />
          <input
            value={value}
            aria-label="Discriminator value"
            placeholder="acme.com"
            onChange={(e) => setValue(e.target.value)}
          />
        </div>
      </FieldGroup>

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

      <Button
        kind="primary"
        busy={busy}
        disabled={!issuer.trim() || !jwks.trim() || !audience.trim()}
        onClick={register}
      >
        Register
      </Button>
      {(!issuer.trim() || !jwks.trim() || !audience.trim()) && (
        <p className="muted">Enter the issuer, the key set URL and the audience.</p>
      )}
    </Card>
  );
}

function ProviderRow({ provider, onChange }: { provider: IdpEntry; onChange: () => void }) {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");

  const remove = () => {
    setBusy(true);
    setFailure("");
    api
      .removeIdp(provider.issuer, provider.discriminator_value)
      .then(() => {
        setConfirming(false);
        onChange();
      })
      // The one refusal here is the server saying this is the provider you signed in
      // through. Verbatim, because the sentence says what to do instead — and the
      // confirmation closes, so the sentence stands alone rather than above a button
      // that would only produce it again.
      .catch((cause: unknown) => {
        setConfirming(false);
        setFailure(cause instanceof Error ? cause.message : String(cause));
      })
      .finally(() => setBusy(false));
  };

  const routes = provider.discriminator_claim
    ? `${provider.discriminator_claim} = ${provider.discriminator_value}`
    : "the whole issuer";

  return (
    <div className="row">
      <div className="row-main">
        <div className="spread">
          <strong className="mono">{provider.issuer}</strong>
          {!provider.enabled && <Tag>disabled</Tag>}
        </div>
        <p className="row-sub">
          Routes on {routes}. Vouches for{" "}
          {provider.allowed_domains.length > 0
            ? provider.allowed_domains.join(", ")
            : "no domains, so nobody can sign in through it"}
          . Audience <span className="mono">{provider.audience}</span>.
        </p>
        <p className="row-sub mono">
          identity: {provider.subject_claim}  email: {provider.email_claim}  groups:{" "}
          {provider.groups_claim ?? "(the directory decides nothing)"}
        </p>
        <p className="row-sub mono">keys: {provider.jwks_uri}</p>

        {confirming && (
          <Notice tone="warn" title="Remove this provider?">
            <p className="sentence">
              Everyone who signs in through it is locked out at their next sign-in, and
              every token they own stops working at its next call. Nothing they made is
              deleted.
              The provider you are signed in through cannot be removed from here.
            </p>
            <div className="spread">
              <Button kind="primary" busy={busy} onClick={remove}>
                Remove
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
      </div>
      {!confirming && (
        <div className="row-action">
          <Button
            kind="quiet"
            onClick={() => {
              setFailure("");
              setConfirming(true);
            }}
          >
            Remove…
          </Button>
        </div>
      )}
    </div>
  );
}
