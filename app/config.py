"""运行期配置。"""
from __future__ import annotations

import os
from pathlib import Path

DEFAULT_DB_PATH = str(Path(__file__).resolve().parent.parent / "data" / "drill.db")


def db_path() -> str:
    """每次调用读取环境变量，便于测试切换临时库。"""
    return os.environ.get("RPKI_DRILL_DB", DEFAULT_DB_PATH)
