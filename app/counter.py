"""索引键读写计数器。

计数口径（README「计数口径」一节有同样的说明）：
- index_reads：一条带参数、走索引的点查/区间查 SQL 计 1 次，命中与未命中都计；
- index_writes：一条维护索引的 INSERT/DELETE，按该表索引数量计入：
  * candidates 有 1 个聚簇主键 + 1 个选路复合索引，INSERT/DELETE 各计 2；
  * roas 有 1 个聚簇主键 + 1 个 UNIQUE(id) 索引，INSERT/DELETE 各计 2。

所有计数在持久层函数内完成，业务层不感知，方便审计与测试。
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Counter:
    index_reads: int = 0
    index_writes: int = 0

    def read(self, n: int = 1) -> None:
        self.index_reads += n

    def write(self, n: int = 1) -> None:
        self.index_writes += n

    def as_dict(self) -> dict[str, int]:
        return {"index_reads": self.index_reads, "index_writes": self.index_writes}


# 单次查路允许的索引键探测上限（需求硬约束）。
MAX_LOOKUP_PROBES = 2500
