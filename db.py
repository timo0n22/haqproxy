"""
Слой хранения для hackproxy.

Один SQLite-файл на весь инструмент. Схема сделана так, чтобы под одной
таблицей `entries` жили и трафик из проксирования (source='proxy'),
и запросы из Repeater (source='repeater'), и позже — из Intruder
(source='intruder'), не размазывая логику по трём разным хранилищам.

Сырые запрос/ответ храним ЦЕЛИКОМ как байты (через latin-1 туда-обратно,
это lossless: каждый байт 0-255 однозначно маппится на один codepoint),
чтобы ничего не терять — включая бинарные тела и странный порядок/регистр
заголовков. Индексируемые колонки (host, method, status и т.д.) — это
просто извлечённые для быстрой фильтрации метаданные, источник правды —
raw_request/raw_response.
"""

import sqlite3
import time
from pathlib import Path
from contextlib import contextmanager

DB_PATH = Path(__file__).parent / "hackproxy.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,              -- 'proxy' | 'repeater' | 'intruder'
    parent_id INTEGER,                 -- если repeater/intruder создан "из" записи истории
    timestamp REAL NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    scheme TEXT NOT NULL,               -- 'http' | 'https'
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    resp_status INTEGER,
    duration_ms INTEGER,
    raw_request TEXT NOT NULL,          -- сырые байты запроса (latin-1 текст)
    raw_response TEXT,                  -- сырые байты ответа (latin-1 текст), NULL если не было ответа/ошибка
    error TEXT,                         -- текст ошибки, если запрос не удался (для repeater/intruder)
    note TEXT,                          -- свободная заметка пользователя (для будущих находок)
    tag TEXT                            -- короткий тег/лейбл, например "IDOR?" — для быстрой сортировки
);

CREATE INDEX IF NOT EXISTS idx_entries_host ON entries(host);
CREATE INDEX IF NOT EXISTS idx_entries_source ON entries(source);
CREATE INDEX IF NOT EXISTS idx_entries_timestamp ON entries(timestamp);

CREATE TABLE IF NOT EXISTS scope (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern TEXT NOT NULL UNIQUE,       -- например "*.example.com" или "example.com"
    enabled INTEGER NOT NULL DEFAULT 1
);
"""


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")  # чтобы recorder.py (mitmproxy) и app.py (Flask) не блокировали друг друга
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)


def insert_entry(
    source, host, port, scheme, method, path,
    raw_request, raw_response=None, resp_status=None,
    duration_ms=None, error=None, parent_id=None,
):
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO entries
               (source, parent_id, timestamp, host, port, scheme, method, path,
                resp_status, duration_ms, raw_request, raw_response, error)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (source, parent_id, time.time(), host, port, scheme, method, path,
             resp_status, duration_ms, raw_request, raw_response, error),
        )
        return cur.lastrowid


def query_entries(host=None, method=None, status=None, q=None, source=None,
                   scope_only=False, limit=200):
    clauses = []
    params = []

    if host:
        clauses.append("host LIKE ?")
        params.append(f"%{host}%")
    if method:
        clauses.append("method = ?")
        params.append(method.upper())
    if status:
        clauses.append("resp_status = ?")
        params.append(int(status))
    if source:
        clauses.append("source = ?")
        params.append(source)
    if q:
        clauses.append("(raw_request LIKE ? OR raw_response LIKE ? OR path LIKE ?)")
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])
    if scope_only:
        patterns = [r["pattern"] for r in list_scope() if r["enabled"]]
        if patterns:
            scope_clauses = []
            for p in patterns:
                p_sql = p.replace("*", "%")
                scope_clauses.append("host LIKE ?")
                params.append(p_sql)
            clauses.append("(" + " OR ".join(scope_clauses) + ")")
        else:
            # если scope пуст, а фильтр запрошен — не показываем ничего,
            # чтобы не создавать ложное ощущение "всё в scope"
            clauses.append("1=0")

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"""SELECT id, source, parent_id, timestamp, host, port, scheme, method,
                     path, resp_status, duration_ms, error, note, tag
              FROM entries {where}
              ORDER BY id DESC LIMIT ?"""
    params.append(limit)

    with get_conn() as conn:
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]


def get_entry(entry_id):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM entries WHERE id = ?", (entry_id,)).fetchone()
        return dict(row) if row else None


def update_entry_meta(entry_id, note=None, tag=None):
    with get_conn() as conn:
        conn.execute("UPDATE entries SET note = COALESCE(?, note), tag = COALESCE(?, tag) WHERE id = ?",
                     (note, tag, entry_id))


def list_scope():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM scope ORDER BY id").fetchall()
        return [dict(r) for r in rows]


def add_scope(pattern):
    with get_conn() as conn:
        conn.execute("INSERT OR IGNORE INTO scope (pattern, enabled) VALUES (?, 1)", (pattern,))


def remove_scope(scope_id):
    with get_conn() as conn:
        conn.execute("DELETE FROM scope WHERE id = ?", (scope_id,))


def set_scope_enabled(scope_id, enabled):
    with get_conn() as conn:
        conn.execute("UPDATE scope SET enabled = ? WHERE id = ?", (1 if enabled else 0, scope_id))
