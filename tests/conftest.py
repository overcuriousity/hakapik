"""Shared pytest fixtures (grown in later tasks)."""

import os

import psycopg
import pytest_asyncio
import pytest

from hakapik.db import connect, migrate


@pytest_asyncio.fixture
async def conn():
    url = os.getenv("HAKAPIK_TEST_DB")
    if not url:
        pytest.skip("needs postgres (set HAKAPIK_TEST_DB)")
    c = await connect(url)
    try:
        await migrate(c)
        await c.execute("TRUNCATE log_cursor, raw_batch, candidate, ingest_stat")
        await c.commit()
        yield c
    finally:
        await c.close()
