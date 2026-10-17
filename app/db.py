from collections.abc import Iterator

from fastapi import Request
from sqlalchemy import Engine, event
from sqlmodel import Session, create_engine


def make_engine(db_url: str) -> Engine:
    engine = create_engine(db_url, connect_args={"check_same_thread": False})

    if engine.dialect.name == "sqlite":

        @event.listens_for(engine, "connect")
        def _on_connect(dbapi_conn, _record):
            # Take over transaction control from pysqlite so we can issue BEGIN IMMEDIATE.
            dbapi_conn.isolation_level = None
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA busy_timeout=5000")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.close()

        @event.listens_for(engine, "begin")
        def _on_begin(conn):
            if conn.get_execution_options().get("sqlite_immediate"):
                conn.exec_driver_sql("BEGIN IMMEDIATE")
            else:
                conn.exec_driver_sql("BEGIN")

    return engine


def request_engine(engine: Engine) -> Engine:
    """Engine for API requests: every transaction takes the write lock up front.

    Most requests write (even GETs, which lazily close timed-out sessions). A deferred
    transaction that reads and then writes can fail with SQLITE_BUSY in WAL mode without
    honoring busy_timeout; BEGIN IMMEDIATE waits for the lock instead. Requests are short,
    so serializing them is fine on a single instance.
    """
    return engine.execution_options(sqlite_immediate=True)


def get_db(request: Request) -> Iterator[Session]:
    with Session(request.app.state.request_engine) as session:
        yield session
