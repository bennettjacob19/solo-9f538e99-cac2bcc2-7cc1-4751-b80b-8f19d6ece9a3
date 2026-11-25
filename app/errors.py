"""业务层与持久层共享的异常类型。"""
from __future__ import annotations


class ConflictError(Exception):
    """唯一编号冲突、每前缀候选超限、撤销目标不存在等可预期冲突（HTTP 409）。"""
