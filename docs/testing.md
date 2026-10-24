# Testing

Run `uv run pytest -W error`; tests that need Postgres skip unless
`HAKAPIK_TEST_DB` is set. The `conn` fixture drops and recreates every table, so it
refuses (fails the test) any database whose name does not end in `_test`:
never point it at the live `hakapik` database. Create the test database once
with `docker exec hakapik-postgres-1 psql -U hakapik -d hakapik -c 'CREATE DATABASE hakapik_test'`
and run, for example,
`HAKAPIK_TEST_DB=postgresql://hakapik:hakapik@172.20.0.2:5432/hakapik_test uv run pytest -v -W error`
(172.20.0.2 is the compose container's IP; use `127.0.0.1` where the port
forward works).

The browser tests need the Chromium install
(`uv run playwright install chromium --no-shell`) and are skipped without it.
