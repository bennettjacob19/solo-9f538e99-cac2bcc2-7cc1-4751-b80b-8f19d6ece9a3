"""持久层测试：执行计划全索引化、计数口径、WAL 快照隔离与事务原子性。"""
from __future__ import annotations

import sqlite3

import pytest

from app import rpki, store
from app.counter import Counter
from app.store import (
    SQL_CAND_COUNT_PREFIX,
    SQL_CAND_DELETE,
    SQL_CAND_EXISTS,
    SQL_CAND_LPM,
    SQL_ROA_COVER,
    SQL_ROA_DELETE,
    SQL_ROA_ID_EXISTS,
)


@pytest.fixture()
def conn():
    store.reset_db()
    with store.connect() as c:
        yield c


def test_all_hot_sql_uses_indexes_no_scan(conn):
    plans = {
        "cand_exists": store.explain(conn, SQL_CAND_EXISTS, ("10.0.0.0", 8, 1)),
        "cand_count": store.explain(conn, SQL_CAND_COUNT_PREFIX, ("10.0.0.0", 8)),
        "cand_lpm": store.explain(conn, SQL_CAND_LPM, ("10.0.0.0", 8)),
        "roa_id": store.explain(conn, SQL_ROA_ID_EXISTS, (1,)),
        "roa_cover": store.explain(conn, SQL_ROA_COVER, ("10.0.0.0", 8)),
        "cand_del": store.explain(conn, SQL_CAND_DELETE, ("10.0.0.0", 8, 1)),
        "roa_del": store.explain(conn, SQL_ROA_DELETE, (1,)),
    }
    for name, lines in plans.items():
        joined = " | ".join(lines)
        assert "SCAN" not in joined, f"{name} 出现全表扫描: {joined}"
        assert "SEARCH" in joined or "USING" in joined, f"{name} 未使用索引: {joined}"


def test_miss_still_counts(conn):
    counter = Counter()
    assert store.candidate_exists(conn, counter, "9.9.9.0", 24, 1) is False
    assert counter.index_reads == 1
    assert counter.index_writes == 0

    assert store.delete_candidate(conn, counter, "9.9.9.0", 24, 1) is False
    assert counter.index_reads == 2  # 又一次未命中点查
    assert counter.index_writes == 0

    assert store.roa_id_exists(conn, counter, 42) is False
    assert store.delete_roa(conn, counter, 42) is False
    assert counter.index_reads == 4
    assert counter.index_writes == 0


def test_insert_and_delete_counts(conn):
    counter = Counter()
    store.insert_candidate(conn, counter, "10.0.0.0", 8, 1, 64500, "1.1.1.1", 10)
    # 候选：1 次存在性读 + 主键与选路索引各 1 次写
    assert (counter.index_reads, counter.index_writes) == (1, 2)
    assert store.delete_candidate(conn, counter, "10.0.0.0", 8, 1) is True
    assert (counter.index_reads, counter.index_writes) == (2, 4)

    counter = Counter()
    store.insert_roa(conn, counter, 7, "10.0.0.0", 8, 64500, 16)
    assert (counter.index_reads, counter.index_writes) == (1, 2)
    assert store.delete_roa(conn, counter, 7) is True
    assert (counter.index_reads, counter.index_writes) == (2, 4)


def test_roa_covering_scan_returns_only_covering(conn):
    counter = Counter()
    store.insert_roa(conn, counter, 1, "10.0.0.0", 8, 64500, 16)
    store.insert_roa(conn, counter, 2, "10.0.0.0", 16, 64501, 24)
    store.insert_roa(conn, counter, 3, "10.128.0.0", 9, 64502, 24)  # 不覆盖 10.0 系
    conn.commit()
    counter = Counter()
    rows = store.covering_roas(conn, counter, "10.0.0.0", 16)
    assert [r["id"] for r in rows] == [2, 1]  # 沿祖先链：长度降序
    assert counter.index_reads == 17  # L+1 = 17 个祖先键，未命中也计
    # 更短候选只看到 /8 祖先
    counter = Counter()
    rows = store.covering_roas(conn, counter, "10.0.0.0", 12)
    assert [r["id"] for r in rows] == [1]
    assert counter.index_reads == 13


def test_roa_covering_finds_coarser_ancestor_with_different_network(conn):
    """候选网络地址与授权网络地址不同（如 198.20.4.0/24 vs 198.20.0.0/16）也必须命中。"""
    counter = Counter()
    store.insert_roa(conn, counter, 200, "198.20.0.0", 16, 64899, 24)
    conn.commit()
    counter = Counter()
    rows = store.covering_roas(conn, counter, "198.20.4.0", 24)
    assert [r["id"] for r in rows] == [200]
    assert counter.index_reads == 25  # 24..0 共 25 个祖先键


def test_write_cost_independent_of_table_size(conn):
    """授权增撤只与本批条数相关，不随存量增长。"""
    for i in range(1, 51):
        c = Counter()
        store.insert_roa(conn, c, i, "172.16.0.0", 12, 64600 + i, 24)
        assert (c.index_reads, c.index_writes) == (1, 2)
        conn.commit()
    c = Counter()
    store.insert_roa(conn, c, 999, "172.17.0.0", 16, 64999, 20)
    assert (c.index_reads, c.index_writes) == (1, 2)
    c = Counter()
    store.delete_roa(conn, c, 999)
    assert (c.index_reads, c.index_writes) == (1, 2)


def test_transaction_rollback_on_error():
    store.reset_db()
    counter = Counter()
    with pytest.raises(RuntimeError):
        with store.transaction() as conn:
            store.insert_roa(conn, counter, 1, "10.0.0.0", 8, 1, 16)
            store.insert_roa(conn, counter, 2, "10.0.0.0", 8, 2, 16)
            raise RuntimeError("boom")
    with store.snapshot() as conn:
        assert conn.execute("SELECT count(*) FROM roas").fetchone()[0] == 0


def test_snapshot_isolation_during_concurrent_write():
    """读连接拿到快照后，写连接提交新授权，读连接仍看到旧状态。"""
    store.reset_db()
    with store.transaction() as conn:
        c = Counter()
        store.insert_candidate(conn, c, "192.0.2.0", 24, 1, 64700, "10.0.0.1", 10)
        store.insert_roa(conn, c, 1, "192.0.2.0", 24, 64777, 24)

    reader_cm = store.connect()
    reader = reader_cm.__enter__()
    reader.isolation_level = None
    reader.execute("BEGIN")  # deferred 事务：快照由第一条读语句固化
    # 必须在写者提交前执行一次读，把快照固定在旧状态
    assert reader.execute("SELECT count(*) FROM roas").fetchone()[0] == 1
    try:
        with store.transaction() as writer:
            store.delete_roa(writer, Counter(), 1)

        # 旧快照仍能读到授权
        row = reader.execute("SELECT count(*) FROM roas").fetchone()
        assert row[0] == 1
        counter = Counter()
        rows = store.covering_roas(reader, counter, "192.0.2.0", 24)
        assert len(rows) == 1
    finally:
        reader.rollback()
        reader.close()

    # 新快照看到已撤回的状态
    with store.snapshot() as conn:
        assert conn.execute("SELECT count(*) FROM roas").fetchone()[0] == 0


def test_lpm_helpers():
    pfx = list(rpki.lpm_prefixes("192.168.1.9"))
    assert len(pfx) == 33
    assert pfx[0] == ("192.168.1.9", 32)
    assert pfx[-1] == ("0.0.0.0", 0)
    assert ("192.168.1.0", 24) in pfx
    with pytest.raises(rpki.ValidationError):
        rpki.parse_v4_network("bad")
    with pytest.raises(rpki.ValidationError):
        rpki.parse_v4_address("10.0.0.256")
