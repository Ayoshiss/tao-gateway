"""
Database access for in-enclave tools.

The enclave never holds a connection string at rest, it receives one from the
Key Broker Service only after proving what code it is running (see `kbs.py`).
This module is what it does with that credential once released.

`Database` is the seam. `MockDatabase` backs tests, CI and the demo with a fixed
in-memory dataset; `PostgresDatabase` is the real client. Both satisfy the same
protocol, so the tool layer above them cannot tell the difference.

MOCK, NOT AN INTEGRATION TEST. `MockDatabase` proves the *flow*, credential
release, query execution, result binding, not that a real server returns the
right rows. Point `PostgresDatabase` at a live instance for that.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol, Sequence


@dataclass(frozen=True)
class Credentials:
    """A released secret. Never logged, never persisted outside the enclave."""

    dsn: str
    resource: str

    def __repr__(self) -> str:  # keep secrets out of tracebacks and logs
        return f"Credentials(resource={self.resource!r}, dsn=<redacted>)"


@dataclass
class QueryResult:
    columns: list[str] = field(default_factory=list)
    rows: list[list[Any]] = field(default_factory=list)

    @property
    def row_count(self) -> int:
        return len(self.rows)

    def to_dict(self) -> dict[str, Any]:
        return {"columns": self.columns, "rows": self.rows, "row_count": self.row_count}


def canonical(payload: Any) -> bytes:
    """Stable byte encoding, so the same result always hashes the same.

    Key order and separators are pinned: a hash bound into an attestation must
    not change because a dict happened to iterate differently.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()


class QueryError(Exception):
    pass


class Database(Protocol):
    """The seam between the tool layer and whatever actually stores the data."""

    def query(self, sql: str, params: Sequence[Any] = ()) -> QueryResult: ...
    def close(self) -> None: ...


# --- Mock backend (tests / CI / demo) ----------------------------------------

class MockDatabase:
    """In-memory stand-in for a customer's Postgres.

    Holds one table's worth of canned rows and answers any SQL with them, which
    is enough to exercise credential release, execution and result binding
    end to end. It does not parse SQL and is not a substitute for integration
    testing against a real server.
    """

    def __init__(
        self,
        credentials: Credentials,
        columns: Sequence[str] | None = None,
        rows: Sequence[Sequence[Any]] | None = None,
    ) -> None:
        self.credentials = credentials
        self.closed = False
        self.queries: list[tuple[str, tuple[Any, ...]]] = []  # audit trail for tests
        self._columns = list(columns or ["id", "email", "plan"])
        self._rows = [list(r) for r in (rows or [
            [1, "ada@example.com", "enterprise"],
            [2, "grace@example.com", "pro"],
            [3, "alan@example.com", "free"],
        ])]

    def query(self, sql: str, params: Sequence[Any] = ()) -> QueryResult:
        if self.closed:
            raise QueryError("query on a closed database")
        if not sql or not sql.strip():
            raise QueryError("empty SQL")
        self.queries.append((sql, tuple(params)))
        return QueryResult(columns=list(self._columns), rows=[list(r) for r in self._rows])

    def close(self) -> None:
        self.closed = True


# --- SQLite backend (dev / CI with real SQL) ----------------------------------

class SqliteDatabase:
    """A real SQL engine with no server to run.

    Sits between `MockDatabase` and `PostgresDatabase`: unlike the mock it
    actually parses SQL, binds parameters and enforces types, so a malformed
    query fails here rather than surviving until production. Unlike Postgres it
    needs no service, so CI keeps running in milliseconds.

    Dialect differences remain: SQLite is not Postgres. Use
    `PostgresDatabase` (see `tests/test_postgres_integration.py`) for anything
    that depends on real dialect behaviour.
    """

    def __init__(
        self,
        credentials: Credentials,
        path: str = ":memory:",
        seed_sql: str | None = None,
    ) -> None:
        import sqlite3
        import threading

        self.credentials = credentials
        self.closed = False
        try:
            # The miner serves on a threading HTTP server, so queries arrive on
            # whichever thread took the request, never the one that opened the
            # connection. SQLite's default refuses that outright, which makes
            # every challenge fail; the lock below is what makes lifting the
            # check safe rather than merely quiet.
            self._conn = sqlite3.connect(path, check_same_thread=False)
        except Exception as exc:
            raise QueryError(f"could not open {credentials.resource}: {exc}") from exc
        self._lock = threading.Lock()
        self._conn.row_factory = sqlite3.Row
        if seed_sql:
            try:
                self._conn.executescript(seed_sql)
            except Exception as exc:
                raise QueryError(f"seed failed: {exc}") from exc

    def query(self, sql: str, params: Sequence[Any] = ()) -> QueryResult:
        if self.closed:
            raise QueryError("query on a closed database")
        try:
            # Held across the fetch, not just the execute: the cursor draws from
            # the connection as it is read, so releasing early would let a
            # concurrent query interleave and scramble both result sets.
            with self._lock:
                cur = self._conn.execute(sql, tuple(params))
                if cur.description is None:  # non-SELECT
                    return QueryResult(columns=[], rows=[])
                columns = [d[0] for d in cur.description]
                rows = [list(r) for r in cur.fetchall()]
        except QueryError:
            raise
        except Exception as exc:
            raise QueryError(f"query failed: {exc}") from exc
        return QueryResult(columns=columns, rows=rows)

    def close(self) -> None:
        if not self.closed:
            with self._lock:
                self._conn.close()
            self.closed = True


# --- Real backend -------------------------------------------------------------

class PostgresDatabase:
    """Real Postgres client, constructed from KBS-released credentials.

    `psycopg` is imported lazily so that tests, CI and the demo never require a
    database driver to be installed.
    """

    def __init__(self, credentials: Credentials, connect_timeout: int = 10) -> None:
        try:
            import psycopg  # noqa: F401
        except ModuleNotFoundError as exc:  # pragma: no cover - env dependent
            raise QueryError(
                "PostgresDatabase needs the 'psycopg' package "
                "(pip install 'psycopg[binary]')"
            ) from exc

        import psycopg

        self.credentials = credentials
        self.closed = False
        try:
            self._conn = psycopg.connect(credentials.dsn, connect_timeout=connect_timeout)
        except Exception as exc:
            raise QueryError(f"could not connect to {credentials.resource}: {exc}") from exc

    def query(self, sql: str, params: Sequence[Any] = ()) -> QueryResult:
        if self.closed:
            raise QueryError("query on a closed database")
        try:
            with self._conn.cursor() as cur:
                cur.execute(sql, tuple(params) or None)
                if cur.description is None:  # non-SELECT
                    return QueryResult(columns=[], rows=[])
                columns = [d[0] for d in cur.description]
                rows = [list(r) for r in cur.fetchall()]
                return QueryResult(columns=columns, rows=rows)
        except Exception as exc:
            raise QueryError(f"query failed: {exc}") from exc

    def close(self) -> None:
        if not self.closed:
            self._conn.close()
            self.closed = True
