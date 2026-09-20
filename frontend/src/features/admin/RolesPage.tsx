import Failure from "../../components/Failure";
import { Card, Empty, PageHead, Spinner } from "../../components/ui";
import { api } from "../../lib/api";
import { useResource } from "../../lib/useResource";

/** Administrators — step 110, decision 3. **A read screen, and the reason is on it.**
 *
 * Plan 12b refused `PUT /roles/...` with an argument that has not weakened: admins
 * appointing admins over HTTP is the one thing a stolen admin session cannot be cured of.
 * Every other authority a stolen session holds is revocable by an administrator who still
 * has a shell; the authority to appoint administrators is the one that reproduces. So
 * this page says who holds a platform role, since when, and appointed by whom — and for
 * a change it prints the command, and says in a sentence why, rather than leaving an
 * operations team without a shell to discover the gap.
 *
 * What would change this answer is named in plan 110 so it is not re-argued from
 * scratch: a *step-up* — re-authenticating at the identity provider immediately before
 * the grant, so the act needs the person and not merely their session. That is a step of
 * its own with a trigger of its own, and not a rider on a screen.
 *
 * **This page does not list the administrators**, and says so as `--list-roles` does:
 * every `system` principal — the shell — administers and holds no row here. That is the
 * bootstrap and the way back from an empty table.
 */
export default function RolesPage() {
  const { data, error, loading } = useResource(() => api.listRoles(), []);

  return (
    <>
      <PageHead
        title="Administrators"
        lede="Who may administer this workspace: approve hosts, register connectors, cut people off, and read every log."
      />

      {loading && <Spinner label="Loading administrators…" />}
      {error ? <Failure error={error} /> : null}

      {data && data.length === 0 && (
        <Empty title="No platform role granted">
          <p className="sentence">
            Only the shell administers this workspace today. The first person to sign in
            while the deployment names them as its first administrator is granted the
            role; anybody else is appointed from the shell, below.
          </p>
        </Empty>
      )}

      {data && data.length > 0 && (
        <Card title={`Platform roles (${data.length})`}>
          <table>
            <thead>
              <tr>
                <th>Who</th>
                <th>Role</th>
                <th>Appointed by</th>
                <th>Since</th>
              </tr>
            </thead>
            <tbody>
              {data.map((row) => (
                <tr key={`${row.principal} ${row.role}`}>
                  <td>
                    {row.email || row.display_name || row.principal}
                    {row.email && (
                      <span className="row-sub mono"> {row.principal}</span>
                    )}
                  </td>
                  <td>{row.role}</td>
                  {/* The appointer stays a principal string: `system:bootstrap` is the
                      deployment's own first-administrator rule and `system:cli` is a
                      shell, and neither has an address to show. */}
                  <td className="mono">{row.granted_by || "unrecorded"}</td>
                  <td className="row-sub">{row.granted_at || "unrecorded"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      <Card title="Appointing or removing an administrator">
        <p className="sentence">
          This is done from the shell, on purpose, and not from this screen. A stolen
          administrator session can undo anything else it does here, but an administrator
          it appoints keeps the authority after the session is gone — so appointing one
          needs the shell, which a stolen session does not have.
        </p>
        <pre className="mono">
          docker compose exec api carnet --grant-role admin someone@example.com
          {"\n"}
          docker compose exec api carnet --revoke-role admin someone@example.com
        </pre>
        <p className="row-sub">
          The address must belong to somebody who has already signed in; a role is not an
          invitation. The shell itself always administers and appears in no row above.
        </p>
      </Card>
    </>
  );
}
