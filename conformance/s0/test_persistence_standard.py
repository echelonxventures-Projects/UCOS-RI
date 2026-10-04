"""Standard tables per context schema (CIC-003-001 §4) against contracts/persistence/standard-tables.yaml."""
import yaml

from conftest import CONTRACTS

CONTRACT = yaml.safe_load((CONTRACTS / "persistence/standard-tables.yaml").read_text())


def schemas(conn):
    return [r[0] for r in conn.execute(
        "SELECT nspname FROM pg_namespace WHERE nspname LIKE 'ucos\\_%' AND nspname <> 'ucos_meta' ORDER BY 1")]


def test_every_context_schema_has_standard_tables(app_db):
    found = schemas(app_db)
    assert found, "no ucos_* context schemas"
    for schema in found:
        for table, spec in CONTRACT["standardTables"].items():
            cols = dict(app_db.execute(
                """SELECT column_name, data_type FROM information_schema.columns
                    WHERE table_schema = %s AND table_name = %s""", (schema, table)).fetchall())
            if not cols:  # information_schema hides tables without privileges; fall back to pg_catalog
                cols = dict(app_db.execute(
                    """SELECT a.attname, format_type(a.atttypid, NULL) FROM pg_attribute a
                        WHERE a.attrelid = to_regclass(%s) AND a.attnum > 0 AND NOT a.attisdropped""",
                    (f"{schema}.{table}",)).fetchall())
            assert cols, f"{schema}.{table} missing"
            for col, typ in spec["columns"].items():
                assert col in cols, f"{schema}.{table}.{col} missing"
                assert cols[col] == typ, f"{schema}.{table}.{col} is {cols[col]}, contract says {typ}"
            if spec.get("partitioned") == "range":
                strat = app_db.execute(
                    "SELECT partstrat FROM pg_partitioned_table WHERE partrelid = to_regclass(%s)",
                    (f"{schema}.{table}",)).fetchone()
                assert strat and strat[0] == "r", f"{schema}.{table} must be range-partitioned"
