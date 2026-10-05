"""Standard tables per context schema (CIC-003-001 §4) against contracts/persistence/standard-tables.yaml."""
import yaml

from conftest import CONTRACTS

CONTRACT = yaml.safe_load((CONTRACTS / "persistence/standard-tables.yaml").read_text())


def schemas(conn):
    return [r[0] for r in conn.execute(
        "SELECT nspname FROM pg_namespace WHERE nspname LIKE 'ucos\\_%' AND nspname <> 'ucos_meta' ORDER BY 1")]


def test_every_context_schema_has_standard_tables(app_db):
    """Reads pg_catalog by name/OID only, so it needs no privileges on the schemas it inspects."""
    found = schemas(app_db)
    assert found, "no ucos_* context schemas"
    for schema in found:
        for table, spec in CONTRACT["standardTables"].items():
            rel = app_db.execute(
                """SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = %s AND c.relname = %s""", (schema, table)).fetchone()
            assert rel, f"{schema}.{table} missing"
            cols = dict(app_db.execute(
                """SELECT attname, format_type(atttypid, NULL) FROM pg_attribute
                    WHERE attrelid = %s AND attnum > 0 AND NOT attisdropped""", (rel[0],)).fetchall())
            for col, typ in spec["columns"].items():
                assert col in cols, f"{schema}.{table}.{col} missing"
                assert cols[col] == typ, f"{schema}.{table}.{col} is {cols[col]}, contract says {typ}"
            if spec.get("partitioned") == "range":
                strat = app_db.execute("SELECT partstrat FROM pg_partitioned_table WHERE partrelid = %s", (rel[0],)).fetchone()
                assert strat and strat[0] == "r", f"{schema}.{table} must be range-partitioned"
