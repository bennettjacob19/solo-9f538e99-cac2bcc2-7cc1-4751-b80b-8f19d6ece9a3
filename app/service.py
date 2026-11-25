"""业务服务层：事务边界、批量原子性、选路与计数汇总。"""
from __future__ import annotations

import sqlite3

from . import rpki, store
from .counter import MAX_LOOKUP_PROBES, Counter
from .errors import ConflictError
from .rpki import ValidationError
from .schemas import CandidateIn, RoaIn

MAX_CANDIDATES_PER_PREFIX = 4


def add_candidate(item: CandidateIn) -> dict:
    counter = Counter()
    network, prefix_len = rpki.parse_v4_network(item.prefix)
    with store.transaction() as conn:
        if store.candidate_exists(conn, counter, network, prefix_len, item.seq):
            raise ConflictError(f"候选 {item.prefix} 编号 {item.seq} 已存在")
        current = store.count_candidates_for_prefix(conn, counter, network, prefix_len)
        if current >= MAX_CANDIDATES_PER_PREFIX:
            raise ConflictError(
                f"前缀 {item.prefix} 已有 {current} 条候选，每前缀最多 "
                f"{MAX_CANDIDATES_PER_PREFIX} 条"
            )
        store.insert_candidate(
            conn,
            counter,
            network,
            prefix_len,
            item.seq,
            item.asn,
            item.next_hop,
            item.preference,
        )
    return {
        "status": "committed",
        "affected": 1,
        "detail": f"候选已录入（前缀长度 {prefix_len}）",
        **counter.as_dict(),
    }


def delete_candidate(prefix: str, seq: int) -> dict:
    network, prefix_len = rpki.parse_v4_network(prefix)
    counter = Counter()
    with store.transaction() as conn:
        existed = store.delete_candidate(conn, counter, network, prefix_len, seq)
        if not existed:
            # 未删到任何行：事务回滚，已发生的探测计数仍如实返回
            raise ConflictError(f"候选 {network}/{prefix_len} 编号 {seq} 不存在")
    return {
        "status": "committed",
        "affected": 1,
        "detail": "候选已删除",
        **counter.as_dict(),
    }


def add_roas_batch(items: list[RoaIn]) -> dict:
    counter = Counter()
    # 批内重复与 max_len 合法性先做无 IO 预检；与存量编号的冲突在插入时
    # 以每条恰好 1 次 id 点查发现，任一条失败即整体回滚、不产生部分写入。
    seen_ids: set[int] = set()
    normalized: list[tuple[int, str, int, int, int]] = []
    for item in items:
        if item.id in seen_ids:
            raise ConflictError(f"本批内编号 {item.id} 重复")
        seen_ids.add(item.id)
        network, prefix_len = rpki.parse_v4_network(item.prefix)
        if item.max_len < prefix_len:
            raise ValidationError(
                f"授权 {item.id} 的 max_len={item.max_len} 小于前缀长度 {prefix_len}"
            )
        normalized.append((item.id, network, prefix_len, item.asn, item.max_len))

    with store.transaction() as conn:
        for roa_id, network, prefix_len, asn, max_len in normalized:
            store.insert_roa(conn, counter, roa_id, network, prefix_len, asn, max_len)
    return {
        "status": "committed",
        "affected": len(normalized),
        "detail": f"整批 {len(normalized)} 条授权已切换生效",
        **counter.as_dict(),
    }


def revoke_roas(ids: list[int]) -> dict:
    counter = Counter()
    with store.transaction() as conn:
        seen: set[int] = set()
        removed = 0
        for roa_id in ids:
            if roa_id in seen:
                raise ConflictError(f"撤销列表中编号 {roa_id} 重复")
            seen.add(roa_id)
            if store.delete_roa(conn, counter, roa_id):
                removed += 1
            else:
                # 编号不存在即整批失败、全部照旧
                raise ConflictError(f"授权编号 {roa_id} 不存在，整批撤销已回滚")
    return {
        "status": "committed",
        "affected": removed,
        "detail": f"整批 {removed} 条授权已撤销",
        **counter.as_dict(),
    }


def lookup(destination: str) -> dict:
    """查路：同一快照内完成最长前缀选择与 RPKI 校验。"""
    ip = rpki.parse_v4_address(destination)
    counter = Counter()
    evaluated: list[dict] = []
    result: dict | None = None

    with store.snapshot() as conn:
        # 1) 自 /32 向 /0 做最长前缀匹配，每个长度 1 次主键探测，共最多 33 次
        for network, length in rpki.lpm_prefixes(ip):
            rows = store.candidates_for_prefix(conn, counter, network, length)
            if not rows:
                continue

            # 2) 只对实际命中的候选前缀取一次覆盖授权（L+1 次索引键探测口径）
            roa_rows = store.covering_roas(conn, counter, network, length)
            roas = [dict(r) for r in roa_rows]

            eligible: list[sqlite3.Row] = []
            for row in rows:
                candidate = {
                    "prefix": network,
                    "prefix_len": length,
                    "asn": row["asn"],
                }
                ok, status = rpki.candidate_is_eligible(candidate, roas)
                evaluated.append(
                    {
                        "prefix": network,
                        "prefix_len": length,
                        "seq": row["seq"],
                        "asn": row["asn"],
                        "preference": row["preference"],
                        "roa_status": status,
                        "eligible": ok,
                    }
                )
                if ok:
                    eligible.append(row)

            # 3) 该长度有可用候选即定局：SQL 已按 preference、seq 升序返回
            if eligible:
                winner = eligible[0]
                winner_status = next(
                    e["roa_status"]
                    for e in evaluated
                    if e["prefix"] == network and e["seq"] == winner["seq"]
                )
                result = {
                    "next_hop": winner["next_hop"],
                    "matched_prefix": f"{network}/{length}",
                    "winning_seq": winner["seq"],
                    "winning_asn": winner["asn"],
                    "roa_status": winner_status,
                }
                break

        # 硬约束自检：单次查路探测超过预算直接失败，而不是静默放行
        if counter.index_reads > MAX_LOOKUP_PROBES:
            raise RuntimeError(
                f"查路索引探测 {counter.index_reads} 次，超过上限 {MAX_LOOKUP_PROBES}"
            )

    return {
        "destination": ip,
        "routed": result is not None,
        "next_hop": result["next_hop"] if result else None,
        "matched_prefix": result["matched_prefix"] if result else None,
        "winning_seq": result["winning_seq"] if result else None,
        "winning_asn": result["winning_asn"] if result else None,
        "roa_status": result["roa_status"] if result else None,
        "index_reads": counter.index_reads,
        "index_writes": counter.index_writes,
        "evaluated_prefixes": evaluated,
    }


def list_candidates(prefix: str | None) -> dict:
    network = prefix_len = None
    if prefix is not None:
        network, prefix_len = rpki.parse_v4_network(prefix)
    counter = Counter()
    with store.snapshot() as conn:
        rows = store.list_candidates(conn, counter, network, prefix_len)
    return {
        "count": len(rows),
        "items": [
            {
                "prefix": f"{r['prefix']}/{r['prefix_len']}",
                "seq": r["seq"],
                "asn": r["asn"],
                "next_hop": r["next_hop"],
                "preference": r["preference"],
            }
            for r in rows
        ],
        **counter.as_dict(),
    }


def list_roas(prefix: str | None) -> dict:
    network = prefix_len = None
    if prefix is not None:
        network, prefix_len = rpki.parse_v4_network(prefix)
    counter = Counter()
    with store.snapshot() as conn:
        rows = store.list_roas(conn, counter, network, prefix_len)
    return {
        "count": len(rows),
        "items": [
            {
                "id": r["id"],
                "prefix": f"{r['prefix']}/{r['prefix_len']}",
                "prefix_len": r["prefix_len"],
                "asn": r["asn"],
                "max_len": r["max_len"],
            }
            for r in rows
        ],
        **counter.as_dict(),
    }
