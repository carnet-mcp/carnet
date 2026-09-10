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
import type { GroupDetail, GroupSummary } from "../../lib/types";
import { useResource } from "../../lib/useResource";

/** Group management, which has been routes-without-a-screen since 12b — deliberately.
 *
 * 9a wanted this and could not have it: `access/groups.py`'s docstring said for three
 * steps that a route here before a tenant-admin role existed would be the mistake it
 * guarded against. 12b built the role and the six routes and stopped, arguing that a route
 * with no screen was defensible *this once* because its consumer was the same engineer who
 * runs `--add-group`. This is the other consumer arriving, and with them the reason the
 * argument had an expiry date.
 *
 * ## What a group is, said on the screen rather than assumed
 *
 * A group is a name for a set of people, so that a share can be written against the set.
 * Everything on this page is therefore one step removed from access: nothing here grants
 * anybody anything, and adding somebody to a group gives them **whatever that group has
 * already been shared onto**, on every agent, at once. That sentence is on the page,
 * because it is the one thing an administrator can get wrong here and the mistake is
 * silent.
 *
 * ## Deleting warns, and the warning names the consequence rather than asking twice
 *
 * `--delete-group` prints the counts because deleting a group takes its grants with it —
 * on every agent, immediately, and **nobody is told**. A confirm dialog saying *are you
 * sure* asks a question the person cannot answer; one naming what goes is a question they
 * can. So the button becomes a sentence and a second button, in place, rather than a
 * modal: the thing being deleted stays visible while the decision is made.
 */
export default function GroupsPage() {
  const { data, error, loading, reload } = useResource(() => api.listGroups(), []);
  const [open, setOpen] = useState<string>("");

  return (
    <>
      <PageHead
        title="Groups"
        lede="A group is a set of users. Share an agent with a group to share it with everyone in the group."
      />

      <NewGroup onCreated={reload} />

      {loading && <Spinner label="Loading groups…" />}
      {error ? <Failure error={error} /> : null}

      {data && data.length === 0 && (
        <Empty title="No groups yet">
          <p className="sentence">Create one above, then share an agent with it.</p>
        </Empty>
      )}

      {data && data.length > 0 && (
        <div className="rows">
          {data.map((group) => (
            <GroupRow
              key={group.group_id}
              group={group}
              open={open === group.group_id}
              onToggle={() =>
                setOpen(open === group.group_id ? "" : group.group_id)
              }
              onChange={reload}
            />
          ))}
        </div>
      )}
    </>
  );
}

function NewGroup({ onCreated }: { onCreated: () => void }) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [externalId, setExternalId] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");

  const create = () => {
    setBusy(true);
    setFailure("");
    api
      .createGroup(name.trim(), description.trim(), externalId)
      .then(() => {
        setName("");
        setDescription("");
        setExternalId("");
        onCreated();
      })
      // The server's own sentence — a duplicate name is a **400** naming the group, and
      // it says why two groups with one name is a command whose meaning depends on
      // insertion order. Paraphrasing it would lose that.
      .catch((cause: unknown) =>
        setFailure(cause instanceof Error ? cause.message : String(cause)),
      )
      .finally(() => setBusy(false));
  };

  return (
    <Card title="New group">
      <Field label="Name" hint="Shown when sharing.">
        <input value={name} onChange={(e) => setName(e.target.value)} />
      </Field>
      <Field label="Description" hint="Optional.">
        <input
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />
      </Field>
      {/* Step 033e. Optional here and changeable later — a group that already exists can
          be linked without being re-created, which matters because deleting one takes
          its grants with it. */}
      <Field
        label="Directory group"
        hint="Optional. The group's id in your directory: an object id in Entra, a name in Okta."
      >
        <input
          value={externalId}
          placeholder="8f2c1ae0-…"
          onChange={(e) => setExternalId(e.target.value)}
        />
      </Field>
      {externalId.trim() && (
        <p className="muted">
          Members come from your directory at each person&rsquo;s next sign-in. You cannot
          add or remove people here.
        </p>
      )}
      {failure && (
        <Notice tone="warn">
          <p className="sentence">{failure}</p>
        </Notice>
      )}
      <Button kind="primary" busy={busy} disabled={!name.trim()} onClick={create}>
        Create group
      </Button>
      {/* Disabled with the reason beside it rather than silently: a button that does
          nothing when pressed reads as broken, and one that says why reads as a rule. */}
      {!name.trim() && <p className="muted">Enter a name.</p>}
    </Card>
  );
}

function GroupRow({
  group,
  open,
  onToggle,
  onChange,
}: {
  group: GroupSummary;
  open: boolean;
  onToggle: () => void;
  onChange: () => void;
}) {
  return (
    <div className="row">
      <div className="row-main">
        <div className="spread">
          <strong>{group.name}</strong>
          <span className="mono muted">{group.group_id}</span>
        </div>
        {/* Step 035h, and **both** kinds are labelled rather than one marked.
            `ConnectorsPage` marks its exception and leaves the norm silent, which is right
            there because the norm is safe and the exception is the hazard. Here neither is
            a hazard and which one is the norm is a property of the deployment: a lone "from
            your directory" tag is noise in an SSO-everywhere tenant and a surprise in a
            hand-managed one, and a reader cannot tell which they are in. Two labels say the
            same thing in both. Neither carries `write`, which is the statement that neither
            is a warning.

            The boolean comes off `GroupSummary` — no second request, and no member count.
            Fetching each group to render this list would rebuild the company directory out
            of ten requests, which is the disclosure that shape refuses. */}
        <div className="tags">
          {group.directory ? (
            <Tag>from your directory</Tag>
          ) : (
            <Tag>managed here</Tag>
          )}
        </div>
        <p className="muted">
          {group.directory
            ? "Membership comes from your directory at each person's next sign-in."
            : "An administrator adds and removes members here."}
        </p>
        {group.description && <p className="muted">{group.description}</p>}
        {open && <GroupMembers groupId={group.group_id} onDeleted={onChange} />}
      </div>
      <div className="row-action">
        <Button onClick={onToggle}>{open ? "Close" : "Members"}</Button>
      </div>
    </div>
  );
}

/** The membership of one group, loaded only when it is opened.
 *
 * **Per group rather than for the whole list**, because `GET /groups/{id}` is the
 * administrator-only route and `GET /groups` deliberately carries no member count — a
 * count is the first step of the directory that shape refuses to become. Fetching every
 * group's membership to render a list would rebuild the directory client-side out of ten
 * requests, which is the same disclosure by another route.
 */
function GroupMembers({
  groupId,
  onDeleted,
}: {
  groupId: string;
  onDeleted: () => void;
}) {
  const { data, error, loading, reload } = useResource(
    () => api.getGroup(groupId),
    [groupId],
  );

  return (
    <div className="nested">
      {loading && <Spinner label="Loading members…" />}
      {error ? <Failure error={error} /> : null}
      {data && (
        <>
          <DirectoryLink group={data} onChange={reload} />
          <MemberList group={data} onChange={reload} />
          {/* Keyed on the link state: `kind` is `useState`-initialised from it, and a
              reload does not unmount this component — so after linking, the select
              still said `user` and offered an Add the server refuses. */}
          <AddMember key={data.external_id ?? "unlinked"} group={data} onAdded={reload} />
          <DeleteGroup group={data} onDeleted={onDeleted} />
        </>
      )}
    </div>
  );
}

/** Handing a group's membership to the workspace's directory, and taking it back.
 *
 * Step 033e. The control is a **takeover**, so the sentence before it says what happens
 * to the people who are in the group now rather than asking whether they are sure — the
 * same reasoning `DeleteGroup` below states as a consequence and `--group-link` prints as
 * a count. Unlinking needs no warning of its own: it removes nobody and hands the
 * membership back.
 */
function DirectoryLink({
  group,
  onChange,
}: {
  group: GroupDetail;
  onChange: () => void;
}) {
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");

  const save = (externalId: string | null) => {
    setBusy(true);
    setFailure("");
    api
      .linkGroup(group.group_id, externalId)
      .then(() => {
        setValue("");
        onChange();
      })
      // The server's own sentence — a directory id another group already holds says why
      // one directory group is one group here, which a paraphrase would lose.
      .catch((cause: unknown) =>
        setFailure(cause instanceof Error ? cause.message : String(cause)),
      )
      .finally(() => setBusy(false));
  };

  const people = group.members.filter((member) => member.kind === "user").length;

  if (group.external_id) {
    return (
      <div className="inline-form">
        <p className="sentence">
          Membership follows the directory group{" "}
          <span className="mono">{group.external_id}</span>. It is set at each
          person&rsquo;s next sign-in.
        </p>
        {failure && (
          <Notice tone="warn">
            <p className="sentence">{failure}</p>
          </Notice>
        )}
        <Button kind="quiet" busy={busy} onClick={() => save(null)}>
          Stop following the directory
        </Button>
        <p className="muted">Nobody is removed. You can edit the membership here again.</p>
      </div>
    );
  }

  return (
    <div className="inline-form">
      <FieldGroup
        label="Follow a directory group"
        hint="The group's id in your directory: an object id in Entra, a name in Okta."
      >
        <div className="spread">
          <input
            value={value}
            placeholder="Directory group id"
            onChange={(e) => setValue(e.target.value)}
          />
          <Button busy={busy} disabled={!value.trim()} onClick={() => save(value.trim())}>
            Link
          </Button>
        </div>
      </FieldGroup>
      {failure && (
        <Notice tone="warn">
          <p className="sentence">{failure}</p>
        </Notice>
      )}
      {value.trim() && (
        <p className="muted">
          Membership comes from your directory at each person&rsquo;s next sign-in.{" "}
          {people > 0 && (
            <>
              {people} {people === 1 ? "person is" : "people are"} in it now. Anyone the
              directory does not name is removed at their next sign-in.
            </>
          )}
        </p>
      )}
    </div>
  );
}

function MemberList({
  group,
  onChange,
}: {
  group: GroupDetail;
  onChange: () => void;
}) {
  const [busy, setBusy] = useState("");
  const [note, setNote] = useState("");

  const remove = (kind: string, id: string) => {
    setBusy(`${kind}:${id}`);
    setNote("");
    api
      .removeMember(group.group_id, kind, id)
      .then((outcome) => {
        // `changed: false` is reported rather than swallowed. "Removed" and "was not in
        // it" are different facts, and an administrator who cannot tell them apart cannot
        // tell a working control from a stale screen.
        if (!outcome.changed) setNote(`${kind}:${id} was not in this group.`);
        onChange();
      })
      .catch((cause: unknown) =>
        setNote(cause instanceof Error ? cause.message : String(cause)),
      )
      .finally(() => setBusy(""));
  };

  if (group.members.length === 0) {
    return (
      <p className="sentence muted">
        No members yet.
        {group.external_id
          ? " People appear here after their next sign-in if your directory names them."
          : ""}
      </p>
    );
  }

  return (
    <>
      <table>
        <thead>
          <tr>
            <th>Who</th>
            <th>Added by</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {group.members.map((member) => (
            <tr key={`${member.kind}:${member.id}`}>
              <td className="mono">
                {member.kind}:{member.id}
              </td>
              <td className="mono">{member.added_by || "—"}</td>
              <td>
                {/* A person in a directory-backed group is the directory's, and a
                    Remove that the next sign-in undoes reads as a broken control —
                    which is what the server refuses. `system` members are still ours. */}
                {group.external_id && member.kind === "user" ? (
                  <span className="muted">from your directory</span>
                ) : (
                  <Button
                    kind="quiet"
                    busy={busy === `${member.kind}:${member.id}`}
                    onClick={() => remove(member.kind, member.id)}
                  >
                    Remove
                  </Button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {note && (
        <Notice tone="warn">
          <p className="sentence">{note}</p>
        </Notice>
      )}
      <p className="muted">
        Removing a member ends their access through this group on every agent,
        immediately.
      </p>
      {group.external_id &&
        group.members.some((member) => member.kind === "user") && (
          <p className="muted">
            Members who have not signed in since being added to the directory group are
            listed after their next sign-in.
          </p>
        )}
    </>
  );
}

/** Adding a member, by principal id.
 *
 * **By id and not by email**, and that is a limit rather than a preference. `--group-add`
 * resolves an address by looking somebody up in `users`, which only answers for a person
 * who has logged in at least once — and there is no route that resolves an address to a
 * principal, because one would be an enumeration oracle over the company directory for
 * anybody authenticated in the tenant. So this screen takes what the audit log and the
 * share sheet both show, and the CLI keeps the wider form.
 *
 * A group may not be a member of a group. Refused by `check_principal_kind`, which has
 * permitted exactly `user` and `system` since 009 — so nesting is refused by a rule older
 * than these routes rather than by cycle detection, and arrives here as a 400.
 */
function AddMember({
  group,
  onAdded,
}: {
  group: GroupDetail;
  onAdded: () => void;
}) {
  const groupId = group.group_id;
  const [kind, setKind] = useState(group.external_id ? "system" : "user");
  const [id, setId] = useState("");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState("");

  const add = () => {
    setBusy(true);
    setNote("");
    api
      .addMember(groupId, kind, id.trim())
      .then((outcome) => {
        if (!outcome.changed) setNote(`${kind}:${id.trim()} was already in this group.`);
        setId("");
        onAdded();
      })
      .catch((cause: unknown) =>
        setNote(cause instanceof Error ? cause.message : String(cause)),
      )
      .finally(() => setBusy(false));
  };

  return (
    <div className="inline-form">
      <FieldGroup label="Add a member" hint="The user ID, as shown in the audit log.">
        <div className="spread">
          <select value={kind} onChange={(e) => setKind(e.target.value)}>
            {/* A person cannot be hand-added to a directory-backed group: the next
                sign-in would undo it. The option is absent rather than disabled,
                because the server refuses it and an offer it refuses is the control
                that reads as broken. A scheduler is still ours to add — the directory
                never writes those rows, so the two sources cannot fight. */}
            {!group.external_id && <option value="user">user</option>}
            <option value="system">system</option>
          </select>
          <input
            value={id}
            placeholder="u_9311cad7b95c4592"
            onChange={(e) => setId(e.target.value)}
          />
          <Button busy={busy} disabled={!id.trim()} onClick={add}>
            Add
          </Button>
        </div>
      </FieldGroup>
      {group.external_id && (
        <p className="muted">
          Members of this group come from your directory. Add people to{" "}
          <span className="mono">{group.external_id}</span> there, or unlink the group
          above to manage it here.
        </p>
      )}
      {note && (
        <Notice tone="warn">
          <p className="sentence">{note}</p>
        </Notice>
      )}
    </div>
  );
}

function DeleteGroup({
  group,
  onDeleted,
}: {
  group: GroupDetail;
  onDeleted: () => void;
}) {
  const [asked, setAsked] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");

  if (!asked) {
    return (
      <Button kind="quiet" onClick={() => setAsked(true)}>
        Delete group
      </Button>
    );
  }

  return (
    <Notice tone="warn" title={`Delete ${group.name}?`}>
      {/* The consequence, not "are you sure". A person cannot answer the second question
          and can answer this one — which is `--delete-group`'s reasoning, where the
          counts are printed for the same reason. */}
      <p className="sentence">
        All {group.members.length} {group.members.length === 1 ? "member" : "members"}{" "}
        lose access to every agent shared with this group, immediately. Access they hold
        directly is unaffected. This cannot be undone.
      </p>
      {failure && <p className="sentence">{failure}</p>}
      <div className="spread">
        <Button
          kind="danger"
          busy={busy}
          onClick={() => {
            setBusy(true);
            setFailure("");
            api
              .deleteGroup(group.group_id)
              .then(onDeleted)
              .catch((cause: unknown) => {
                setFailure(cause instanceof Error ? cause.message : String(cause));
                setBusy(false);
              });
          }}
        >
          Delete
        </Button>
        <Button kind="quiet" onClick={() => setAsked(false)}>
          Cancel
        </Button>
      </div>
    </Notice>
  );
}
