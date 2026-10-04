#!/usr/bin/env python3
"""Language-neutral migrator: applies <module>/migrations/NNNN_*.sql in order, each in one transaction,
recording (module, version, sha256) in ucos_meta.schema_migrations. An applied file whose checksum changed
fails the run (expand/contract: never edit an applied migration — CIC-030-001 §4.6).

  UCOS_MIGRATE_DB_URL=postgresql://ucos_owner:…@db/ucos  migrate.py domains/echo [more modules…]
"""
import hashlib
import os
import pathlib
import sys

import psycopg

ROOT = pathlib.Path(__file__).resolve().parent.parent


def main(modules):
    with psycopg.connect(os.environ["UCOS_MIGRATE_DB_URL"], autocommit=True) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS ucos_meta.schema_migrations (
            module text NOT NULL, version text NOT NULL, checksum text NOT NULL,
            applied_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (module, version))""")
        for mod in modules:
            name = pathlib.Path(mod).name
            for f in sorted((ROOT / mod / "migrations").glob("*.sql")):
                version, sql = f.stem, f.read_text()
                checksum = hashlib.sha256(sql.encode()).hexdigest()
                row = conn.execute("SELECT checksum FROM ucos_meta.schema_migrations WHERE module=%s AND version=%s",
                                   (name, version)).fetchone()
                if row:
                    if row[0] != checksum:
                        print(f"migrate: {name}/{version} was modified after being applied")
                        return 1
                    continue
                with conn.transaction():
                    conn.execute(sql)
                    conn.execute("INSERT INTO ucos_meta.schema_migrations (module, version, checksum) VALUES (%s,%s,%s)",
                                 (name, version, checksum))
                print(f"migrate: applied {name}/{version}")
    print("migrate: up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
