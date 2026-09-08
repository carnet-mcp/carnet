-- Append-only, enforced by the database rather than by convention.
--
-- A JSONL file was append-only because of what it is. A table is mutable by default,
-- and an audit log somebody can UPDATE is a weaker artifact than the one it replaced —
-- the whole value of the record is that it says what happened, not what someone would
-- prefer had happened.
--
-- A trigger rather than REVOKE UPDATE, DELETE, because a revoke depends on the
-- deployment having a separate application role and does nothing when the app connects
-- as the owner. This holds regardless of who is connected, including the owner, and
-- it is testable.
--
-- Retention deletion, when it exists, has to drop this trigger explicitly. That is the
-- intended friction: erasing audit records should be a deliberate, visible operation
-- and never something a stray DELETE can do.

CREATE FUNCTION audit_is_append_only() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit is append-only: % is not permitted', TG_OP
        USING HINT = 'Records are the enforcement history. Drop the trigger '
                     'deliberately if you are implementing retention.';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_no_update
    BEFORE UPDATE ON audit
    FOR EACH ROW EXECUTE FUNCTION audit_is_append_only();

CREATE TRIGGER audit_no_delete
    BEFORE DELETE ON audit
    FOR EACH ROW EXECUTE FUNCTION audit_is_append_only();

-- Note the consequence, which is deliberate: `audit.tenant_id` references tenants(id)
-- WITHOUT ON DELETE CASCADE, so deleting a tenant that has audit records fails. You
-- cannot remove a customer and silently erase the record of what their agents did.
