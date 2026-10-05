"""S0 exit demonstration, part 2: RLS isolation (CR-003-001-01, CIC-003-001 §5, CIC-014-001 §3).

Checks the live catalog and data of every ucos_* schema through the service and relay roles:
tenant tables have tenant_id as the first PK column, RLS enabled + forced with a tenant policy;
service roles are neither superuser nor BYPASSRLS; a session of tenant B sees zero rows of tenant A on
every tenant table and cannot write rows for tenant A; non-tenant bookkeeping tables are not readable
by the service role.
"""
import psycopg
import pytest
import requests

from conftest import tenant_id, unique_tenant, wait_for

TENANT_TABLES_SQL = """
SELECT c.oid::regclass::text, c.relrowsecurity, c.relforcerowsecurity,
       (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid) AS policies,
       (SELECT a.attname FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0]
         WHERE i.indrelid = c.oid AND i.indisprimary) AS first_pk_col
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname LIKE 'ucos\\_%' AND n.nspname <> 'ucos_meta' AND c.relkind IN ('r', 'p')
   AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped)
 ORDER BY 1
"""


def tenant_tables(conn):
    return conn.execute(TENANT_TABLES_SQL).fetchall()


def set_tenant(conn, slug):
    conn.execute("SELECT set_config('ucos.tenant_id', %s, false)", (tenant_id(slug),))


def test_service_roles_cannot_bypass_rls(app_db):
    roles = app_db.execute("""SELECT rolname, rolsuper, rolbypassrls FROM pg_roles
                               WHERE rolname LIKE 'ucos\\_%\\_app' OR rolname LIKE 'ucos\\_%\\_relay'""").fetchall()
    assert len(roles) >= 2
    for name, su, bypass in roles:
        assert not su and not bypass, name


def test_every_tenant_table_has_forced_rls(app_db):
    rows = tenant_tables(app_db)
    assert rows, "no tenant tables found in ucos_* schemas"
    for name, rls, forced, policies, first_pk in rows:
        assert rls and forced, f"{name}: RLS must be enabled and forced"
        assert policies >= 1, f"{name}: no RLS policy"
        if first_pk is not None:
            assert first_pk == "tenant_id", f"{name}: tenant_id must be the first PK column"


def test_tenant_b_sees_zero_rows_of_tenant_a_on_every_table(base_url, app_db):
    a, b = unique_tenant("rls-a"), unique_tenant("rls-b")
    r = requests.post(f"{base_url}/v1/echo/messages", json={"text": "tenant A data"},
                      headers={"UCOS-Tenant": a, "Idempotency-Key": "k-rls-a-0001"}, timeout=5)
    assert r.status_code == 201
    mid = r.json()["id"]
    assert wait_for(lambda: requests.get(f"{base_url}/v1/echo/messages/{mid}", headers={"UCOS-Tenant": a},
                                         timeout=5).json()["status"] == "echoed")
    tables = [t[0] for t in tenant_tables(app_db)]
    readable = {}
    for t in tables:
        try:
            with app_db.transaction():
                set_tenant(app_db, a)
                readable[t] = app_db.execute(f"SELECT count(*) FROM {t} WHERE tenant_id = %s",
                                             (tenant_id(a),)).fetchone()[0]
        except psycopg.errors.InsufficientPrivilege:
            readable[t] = None  # not granted to the service role at all: isolation holds trivially
    assert readable.get("ucos_echo.messages", 0) >= 1 and readable.get("ucos_echo.event_store", 0) >= 2
    for t in tables:
        if readable[t] is None:
            continue
        with app_db.transaction():
            set_tenant(app_db, b)
            leaked = app_db.execute(f"SELECT count(*) FROM {t} WHERE tenant_id = %s", (tenant_id(a),)).fetchone()[0]
            foreign = app_db.execute(f"SELECT count(*) FROM {t} WHERE tenant_id <> %s", (tenant_id(b),)).fetchone()[0]
        assert leaked == 0 and foreign == 0, f"{t}: tenant B session sees tenant A rows"


def test_tenant_b_cannot_write_tenant_a_rows(app_db):
    a, b = unique_tenant("rls-a"), unique_tenant("rls-b")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with app_db.transaction():
            set_tenant(app_db, b)
            app_db.execute("""INSERT INTO ucos_echo.messages (tenant_id, id, text, status, revision, accepted_at)
                              VALUES (%s, '01J9Z3K8Q4N6XG2W7T5R0VYB1C', 'x', 'accepted', 1, now())""", (tenant_id(a),))


def test_no_tenant_setting_fails_closed(app_db):
    try:
        with app_db.transaction():
            n = app_db.execute("SELECT count(*) FROM ucos_echo.messages").fetchone()[0]
        assert n == 0
    except (psycopg.errors.UndefinedObject, psycopg.errors.InvalidTextRepresentation):
        pass  # unset or empty ucos.tenant_id raises: fails closed


def test_bookkeeping_tables_not_readable_by_service_role(app_db):
    """Per schema, every service role with USAGE may only INSERT into the outbox; every relay role may only read and
    mark the outbox and has no privilege on tenant tables. Checked on grants by OID (no schema privileges needed)."""
    q = lambda sql, *a: app_db.execute(sql, a or None).fetchall()  # noqa: E731
    roles = [r[0] for r in q("SELECT rolname FROM pg_roles WHERE rolname LIKE 'ucos\\_%\\_app' OR rolname LIKE 'ucos\\_%\\_relay'")]
    checked = 0
    for nsp_oid, schema in q("SELECT oid, nspname FROM pg_namespace WHERE nspname LIKE 'ucos\\_%' AND nspname <> 'ucos_meta'"):
        outbox = q("SELECT c.oid FROM pg_class c WHERE c.relnamespace = %s AND c.relname = 'outbox'", nsp_oid)[0][0]
        tenant_oids = [r[0] for r in q("""SELECT c.oid FROM pg_class c WHERE c.relnamespace = %s AND c.relkind IN ('r','p')
            AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'tenant_id')""", nsp_oid)]
        for role in roles:
            if not q("SELECT has_schema_privilege(%s, %s, 'USAGE')", role, nsp_oid)[0][0]:
                continue
            can = lambda oid, priv: q("SELECT has_table_privilege(%s, %s, %s)", role, oid, priv)[0][0]  # noqa: E731
            if role.endswith("_app"):
                assert not can(outbox, "SELECT") and can(outbox, "INSERT"), f"{schema}.outbox grants for {role}"
            else:
                assert can(outbox, "SELECT") and can(outbox, "UPDATE"), f"{schema}.outbox grants for {role}"
                for oid in tenant_oids:
                    for priv in ("SELECT", "INSERT", "UPDATE", "DELETE"):
                        assert not can(oid, priv), f"relay role {role} has {priv} on a tenant table in {schema}"
            checked += 1
    assert checked >= 4
