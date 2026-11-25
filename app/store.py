"""SQLite 持久层。

设计要点：
- candidates 与 roas 均为 WITHOUT ROWID 表，所有查询路径只走索引，无全表扫描；
- 增、撤均为按键点查/点写，复杂度只与本批条数有关，与表内既有数据量无关；
- 每次连接开启 WAL；读路径用 deferred BEGIN 拿快照，写路径用 BEGIN IMMEDIATE 串行化；
- 索引键探测计数集中在本模块，见 counter.py 的口径说明。
"""
from __future__ import annotations

import contextlib
import ipaddress
import sqlite3
from collections.abc import Iterator, Sequence
from typing import Any

from .config import db_path
from .counter import Counter

# ---------------------------------------------------------------------------
# 表结构
# ---------------------------------------------------------------------------
# candidates：聚簇主键 (prefix, prefix_len, seq)；
# 二级索引 (prefix, prefix_len, preference, seq) 与选路 ORDER BY 对齐，
# 消除排序临时 B 树。单条 INSERT/DELETE 共维护 2 个索引。
SCHEMA_CANDIDATES = """
CREATE TABLE IF NOT EXISTS candidates (
    prefix     TEXT    NOT NULL,
    prefix_len INTEGER NOT NULL CHECK (prefix_len BETWEEN 0 AND 32),
    seq        INTEGER NOT NULL CHECK (seq BETWEEN 0 AND 4294967295),
    asn        INTEGER NOT NULL CHECK (asn BETWEEN 0 AND 4294967295),
    next_hop   TEXT    NOT NULL,
    preference INTEGER NOT NULL CHECK (preference BETWEEN 0 AND 4294967295),
    PRIMARY KEY (prefix, prefix_len, seq)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_candidates_route
    ON candidates (prefix, prefix_len, preference, seq);
"""

# roas：聚簇主键 (prefix, prefix_len, id) 让「某前缀的全部覆盖授权」成为一次
# 覆盖索引区间扫描（asn/max_len 就在叶子页，无需回表）；UNIQUE(id) 保证编号唯一，
# 单条 INSERT/DELETE 共维护 2 个索引。
SCHEMA_ROAS = """
CREATE TABLE IF NOT EXISTS roas (
    id         INTEGER NOT NULL,
    prefix     TEXT    NOT NULL,
    prefix_len INTEGER NOT NULL CHECK (prefix_len BETWEEN 0 AND 32),
    asn        INTEGER NOT NULL CHECK (asn BETWEEN 0 AND 4294967295),
    max_len    INTEGER NOT NULL CHECK (max_len BETWEEN prefix_len AND 32),
    UNIQUE (id),
    PRIMARY KEY (prefix, prefix_len, id)
) WITHOUT ROWID;
"""

# ---------------------------------------------------------------------------
# SQL（模块级常量，便于用 EXPLAIN QUERY PLAN 核对索引使用情况）
# ---------------------------------------------------------------------------
SQL_CAND_EXISTS = (
    "SELECT 1 FROM candidates WHERE prefix = ? AND prefix_len = ? AND seq = ? LIMIT 1"
)
SQL_CAND_COUNT_PREFIX = (
    "SELECT count(*) FROM candidates WHERE prefix = ? AND prefix_len = ?"
)
SQL_CAND_INSERT = (
    "INSERT INTO candidates (prefix, prefix_len, seq, asn, next_hop, preference) "
    "VALUES (?, ?, ?, ?, ?, ?)"
)
SQL_CAND_DELETE = "DELETE FROM candidates WHERE prefix = ? AND prefix_len = ? AND seq = ?"
SQL_CAND_LPM = (
    "SELECT seq, asn, next_hop, preference "
    "FROM candidates WHERE prefix = ? AND prefix_len = ? "
    "ORDER BY preference ASC, seq ASC"
)
SQL_CAND_LIST_FILTERED = (
    "SELECT prefix, prefix_len, seq, asn, next_hop, preference "
    "FROM candidates WHERE prefix = ? AND prefix_len = ?"
)
SQL_CAND_LIST_ALL = (
    "SELECT prefix, prefix_len, seq, asn, next_hop, preference FROM candidates"
)

SQL_ROA_ID_EXISTS = "SELECT 1 FROM roas WHERE id = ? LIMIT 1"
SQL_ROA_INSERT = (
    "INSERT INTO roas (id, prefix, prefix_len, asn, max_len) VALUES (?, ?, ?, ?, ?)"
)
SQL_ROA_DELETE = "DELETE FROM roas WHERE id = ?"
# 覆盖授权扫描：沿候选前缀的祖先链逐键点查（见 covering_roas），
# 聚簇主键 (prefix, prefix_len, id) 上每个键都是一次覆盖索引探测。
SQL_ROA_COVER = (
    "SELECT id, prefix, prefix_len, asn, max_len FROM roas "
    "WHERE prefix = ? AND prefix_len = ?"
)
SQL_ROA_LIST_FILTERED = (
    "SELECT id, prefix, prefix_len, asn, max_len FROM roas "
    "WHERE prefix = ? AND prefix_len = ?"
)
SQL_ROA_LIST_ALL = "SELECT id, prefix, prefix_len, asn, max_len FROM roas"


def init_db() -> None:
    """建库建表（幂等）。"""
    with connect() as conn:
        conn.executescript(SCHEMA_CANDIDATES)
        conn.executescript(SCHEMA_ROAS)
        conn.commit()


def reset_db() -> None:
    """演练重置：清空两张表并重建。属于 DDL，不计入索引键读写。"""
    with connect() as conn:
        conn.execute("DROP TABLE IF EXISTS candidates")
        conn.execute("DROP TABLE IF EXISTS roas")
        conn.executescript(SCHEMA_CANDIDATES)
        conn.executescript(SCHEMA_ROAS)
        conn.commit()


@contextlib.contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(db_path())
    try:
        conn.row_factory = sqlite3.Row
        # WAL 允许写事务进行时其它连接继续读快照。
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        yield conn
    finally:
        conn.close()


@contextlib.contextmanager
def snapshot() -> Iterator[sqlite3.Connection]:
    """读快照：deferred BEGIN 后的第一条 SELECT 固化同一已提交状态。"""
    with connect() as conn:
        conn.isolation_level = None
        conn.execute("BEGIN")
        try:
            yield conn
        finally:
            conn.rollback()


@contextlib.contextmanager
def transaction() -> Iterator[sqlite3.Connection]:
    """写事务：BEGIN IMMEDIATE 立即拿写锁，整批成功才 COMMIT，失败全部回滚。"""
    with connect() as conn:
        conn.isolation_level = None
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise


# ---------------------------------------------------------------------------
# candidates 操作
# ---------------------------------------------------------------------------
def candidate_exists(
    conn: sqlite3.Connection,
    counter: Counter,
    prefix: str,
    prefix_len: int,
    seq: int,
) -> bool:
    counter.read()  # 1 次主键点查，未命中也计
    row = conn.execute(SQL_CAND_EXISTS, (prefix, prefix_len, seq)).fetchone()
    return row is not None


def count_candidates_for_prefix(
    conn: sqlite3.Connection, counter: Counter, prefix: str, prefix_len: int
) -> int:
    counter.read()  # 1 次主键前缀区间统计
    return int(
        conn.execute(SQL_CAND_COUNT_PREFIX, (prefix, prefix_len)).fetchone()[0]
    )


def insert_candidate(
    conn: sqlite3.Connection,
    counter: Counter,
    prefix: str,
    prefix_len: int,
    seq: int,
    asn: int,
    next_hop: str,
    preference: int,
) -> None:
    # 唯一性由主键兜底；这里显式点查 1 次以便给出 409 语义（未命中也计入读）。
    if candidate_exists(conn, counter, prefix, prefix_len, seq):
        return
    conn.execute(
        SQL_CAND_INSERT, (prefix, prefix_len, seq, asn, next_hop, preference)
    )
    counter.write(2)  # 聚簇主键 + idx_candidates_route：2 次键写


def delete_candidate(
    conn: sqlite3.Connection,
    counter: Counter,
    prefix: str,
    prefix_len: int,
    seq: int,
) -> bool:
    counter.read()  # 1 次主键点查
    cur = conn.execute(SQL_CAND_DELETE, (prefix, prefix_len, seq))
    existed = cur.rowcount > 0
    if existed:
        counter.write(2)  # 同步维护 2 个索引
    return existed


def candidates_for_prefix(
    conn: sqlite3.Connection, counter: Counter, prefix: str, prefix_len: int
) -> list[sqlite3.Row]:
    """LPM 中对某个长度的候选前缀做 1 次主键探测（可能未命中，未命中也计）。"""
    counter.read()
    return list(conn.execute(SQL_CAND_LPM, (prefix, prefix_len)).fetchall())


def list_candidates(
    conn: sqlite3.Connection,
    counter: Counter,
    prefix: str | None,
    prefix_len: int | None = None,
) -> list[sqlite3.Row]:
    if prefix is None:
        rows = list(conn.execute(SQL_CAND_LIST_ALL).fetchall())
        # 全量列表：实际触达的索引键即返回行数
        counter.read(len(rows))
        return rows
    counter.read()  # 1 次主键前缀区间
    return list(
        conn.execute(SQL_CAND_LIST_FILTERED, (prefix, prefix_len)).fetchall()
    )


# ---------------------------------------------------------------------------
# roas 操作
# ---------------------------------------------------------------------------
def roa_id_exists(conn: sqlite3.Connection, counter: Counter, roa_id: int) -> bool:
    counter.read()  # 1 次 UNIQUE(id) 点查，未命中也计
    row = conn.execute(SQL_ROA_ID_EXISTS, (roa_id,)).fetchone()
    return row is not None


def insert_roa(
    conn: sqlite3.Connection,
    counter: Counter,
    roa_id: int,
    prefix: str,
    prefix_len: int,
    asn: int,
    max_len: int,
) -> None:
    """单条授权插入：1 次 id 点查 + 2 个索引键写；编号已存在则抛错由调用方回滚。"""
    if roa_id_exists(conn, counter, roa_id):
        from .errors import ConflictError

        raise ConflictError(f"授权编号 {roa_id} 已存在")
    conn.execute(SQL_ROA_INSERT, (roa_id, prefix, prefix_len, asn, max_len))
    counter.write(2)  # 聚簇主键 + UNIQUE(id)：2 次键写


def delete_roa(conn: sqlite3.Connection, counter: Counter, roa_id: int) -> bool:
    counter.read()  # 1 次 UNIQUE(id) 点查
    cur = conn.execute(SQL_ROA_DELETE, (roa_id,))
    existed = cur.rowcount > 0
    if existed:
        counter.write(2)  # 同步维护 2 个索引
    return existed


def covering_roas(
    conn: sqlite3.Connection,
    counter: Counter,
    candidate_network: str,
    candidate_len: int,
) -> list[sqlite3.Row]:
    """返回覆盖候选前缀的全部授权，按 prefix_len 降序。

    覆盖授权的前缀必然是候选前缀的祖先（含自身），共 L+1 个可能的
    (网络地址, 长度) 键。沿祖先链逐键做聚簇索引探测：
    - 每个键 1 次索引读，库里不存在该键（未命中）也计入，共 L+1 次；
    - 同一键上可挂多条授权（重叠授权），一次探测全部取回；
    - 因为按长度从大到小探测，结果天然按 prefix_len 降序。
    """
    addr = ipaddress.IPv4Address(candidate_network)
    rows: list[sqlite3.Row] = []
    for length in range(candidate_len, -1, -1):
        ancestor_net = ipaddress.IPv4Network((addr, length), strict=False)
        ancestor = str(ancestor_net.network_address)
        counter.read()  # 1 次主键点查，未命中也计
        rows.extend(
            conn.execute(SQL_ROA_COVER, (ancestor, length)).fetchall()
        )
    return rows


def list_roas(
    conn: sqlite3.Connection,
    counter: Counter,
    prefix: str | None,
    prefix_len: int | None = None,
) -> list[sqlite3.Row]:
    if prefix is None:
        rows = list(conn.execute(SQL_ROA_LIST_ALL).fetchall())
        counter.read(len(rows))
        return rows
    counter.read()  # 1 次聚簇索引前缀区间
    return list(
        conn.execute(SQL_ROA_LIST_FILTERED, (prefix, prefix_len)).fetchall()
    )


def explain(conn: sqlite3.Connection, sql: str, params: Sequence[Any] = ()) -> list[str]:
    """供测试核对执行计划（期望全部出现 USING 索引、无 SCAN）。"""
    return [
        str(row[3]) if len(row) >= 4 else str(tuple(row))
        for row in conn.execute("EXPLAIN QUERY PLAN " + sql, params).fetchall()
    ]
