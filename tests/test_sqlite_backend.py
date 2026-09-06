"""
SqliteDatabase, a real SQL engine behind the same `Database` protocol.

These tests cover what `MockDatabase` deliberately cannot: parameter binding,
malformed SQL, and non-SELECT statements. The attested flow is exercised on top
of it, so the end-to-end demo path runs against genuine SQL rather than canned
rows.
"""

import pytest

from sentinel.attestation import (
    MockSilicon, bind_response, new_nonce, sha384, verify, verifier_from_public_key,
)
from sentinel.database import Credentials, QueryError, SqliteDatabase
from sentinel.enclave import Enclave
from sentinel.kbs import KeyBroker, ReleasePolicy
from sentinel.mcp import MCPServer, ToolError
from sentinel.mcp.tools import PostgresQueryTool

APPROVED = sha384(b"sentinel-miner-image-v0.1")
RESOURCE = "customer-db"
DSN = "postgres://app:secret@customer-db:5432/prod"

SEED = """
CREATE TABLE findings (contract TEXT, class TEXT, severity TEXT);
INSERT INTO findings VALUES ('0xABC', 'reentrancy', 'high');
INSERT INTO findings VALUES ('0xABC', 'int_overflow', 'medium');
INSERT INTO findings VALUES ('0xDEF', 'none', 'none');
"""


@pytest.fixture
def db():
    d = SqliteDatabase(Credentials(dsn=DSN, resource=RESOURCE), seed_sql=SEED)
    yield d
    d.close()


def test_real_sql_is_executed(db):
    r = db.query("SELECT class, severity FROM findings WHERE contract = ?", ("0xABC",))
    assert r.columns == ["class", "severity"]
    assert r.rows == [["reentrancy", "high"], ["int_overflow", "medium"]]


def test_parameters_are_bound_not_interpolated(db):
    """The classic injection string must be treated as a value, not as SQL."""
    r = db.query("SELECT * FROM findings WHERE contract = ?", ("0xABC'; DROP TABLE findings; --",))
    assert r.rows == []
    assert db.query("SELECT COUNT(*) FROM findings").rows == [[3]]  # table survived


def test_malformed_sql_raises(db):
    """A mock would happily return rows here; a real engine will not."""
    with pytest.raises(QueryError, match="query failed"):
        db.query("SELEKT * FROM findings")


def test_unknown_column_raises(db):
    with pytest.raises(QueryError, match="query failed"):
        db.query("SELECT nonexistent FROM findings")


def test_aggregates_and_ordering_work(db):
    r = db.query("SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity ORDER BY severity")
    assert r.columns == ["severity", "n"]
    assert r.rows == [["high", 1], ["medium", 1], ["none", 1]]


def test_non_select_returns_empty_result():
    d = SqliteDatabase(Credentials(dsn=DSN, resource=RESOURCE), seed_sql=SEED)
    r = d.query("DELETE FROM findings WHERE contract = ?", ("0xDEF",))
    assert r.columns == [] and r.rows == []
    assert d.query("SELECT COUNT(*) FROM findings").rows == [[2]]
    d.close()


def test_query_after_close_raises(db):
    db.close()
    with pytest.raises(QueryError, match="closed database"):
        db.query("SELECT 1")


def test_tool_write_guard_applies_to_sqlite_too(db):
    server = MCPServer()
    server.register(PostgresQueryTool(db))
    with pytest.raises(ToolError, match="read-only"):
        server.call_tool("postgres.query", {"sql": "DROP TABLE findings"})
    assert db.query("SELECT COUNT(*) FROM findings").rows == [[3]]  # untouched


def test_attested_flow_over_real_sql():
    """The full milestone-2 path, with genuine SQL underneath."""
    broker = KeyBroker(policy=ReleasePolicy(approved_measurement=APPROVED))
    broker.store_secret(RESOURCE, DSN)
    enclave = Enclave(MockSilicon(), launch_measurement=APPROVED)
    broker.trust_chip(enclave.chip_id, enclave.public_key_hex)

    credentials = enclave.unlock(broker, RESOURCE)
    db = SqliteDatabase(credentials, seed_sql=SEED)
    try:
        server = MCPServer()
        server.register(PostgresQueryTool(db))

        request_id, nonce = "req-sql", new_nonce()
        attested = enclave.run_attested(
            request_id, nonce,
            lambda: server.call_tool(
                "postgres.query",
                {"sql": "SELECT class FROM findings WHERE severity = ?", "params": ["high"]},
            ),
        )
        assert attested.result["rows"] == [["reentrancy"]]
        assert verify(
            attested.attestation,
            verifier_from_public_key(enclave.public_key_hex),
            approved_measurement=APPROVED,
            expected_nonce=nonce,
            expected_report_data=bind_response(request_id, attested.response_hash),
        )
    finally:
        db.close()


def test_the_database_is_usable_from_the_threads_that_actually_serve():
    """A miner answers each request on a new thread, so the DB must survive that.

    SQLite binds a connection to its creating thread by default, which made
    every validator challenge fail while the miner looked perfectly healthy:
    it started, it served, its attestations verified, and only the answer was
    an error. Cheap to assert, expensive to rediscover in production.
    """
    import threading

    db = SqliteDatabase(
        Credentials(dsn="sqlite:///", resource="customer-db"),
        seed_sql="CREATE TABLE t (id INTEGER); INSERT INTO t VALUES (1),(2),(3);",
    )
    results: list[object] = []

    def run() -> None:
        try:
            results.append(db.query("SELECT id FROM t ORDER BY id").rows)
        except Exception as exc:  # noqa: BLE001 - the failure is the point
            results.append(exc)

    threads = [threading.Thread(target=run) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results == [[[1], [2], [3]]] * 8, results
