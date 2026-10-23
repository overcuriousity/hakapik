"""Shared pytest fixtures."""

import os

import psycopg
import pytest
import pytest_asyncio

from hakapik.db import connect, migrate


def _test_db_url() -> str:
    """Return HAKAPIK_TEST_DB, skipping if unset and failing if unsafe.

    The ``conn`` fixture drops every table, so it refuses any database
    whose name does not end in ``_test`` (it must never touch a live DB).
    """
    url = os.getenv("HAKAPIK_TEST_DB")
    if not url:
        pytest.skip("needs postgres (set HAKAPIK_TEST_DB)")
    dbname = psycopg.conninfo.conninfo_to_dict(url).get("dbname") or ""
    if not dbname.endswith("_test"):
        pytest.fail(
            f"HAKAPIK_TEST_DB names database {dbname!r}; the test fixtures drop "
            "all tables, so the database name must end in '_test'"
        )
    return url


@pytest_asyncio.fixture
async def conn():
    url = _test_db_url()
    c = await connect(url)
    try:
        # Dropped, not truncated: every test gets the current schema, even on
        # a test database created by an older version of hakapik.
        await c.execute(
            "DROP TABLE IF EXISTS log_cursor, raw_batch, candidate, ingest_stat, "
            "fetch_job, node, blob, attempt, dns_answer, artifact, manifest CASCADE"
        )
        await migrate(c)
        yield c
    finally:
        await c.close()
