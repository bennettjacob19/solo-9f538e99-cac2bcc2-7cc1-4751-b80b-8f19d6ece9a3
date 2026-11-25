"""FastAPI 入口：RPKI 撤回本地演练。"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse

from . import service, store
from .errors import ConflictError
from .rpki import ValidationError
from .schemas import (
    CandidateIn,
    ListOut,
    LookupOut,
    RoaBatchIn,
    RoaRevokeIn,
    WriteOut,
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    store.init_db()
    yield


app = FastAPI(
    title="RPKI 授权撤回本地演练",
    description=(
        "录入 IPv4 路由候选与模拟 RPKI 授权（ROA），"
        "在授权增撤期间基于同一已提交状态查路，并返回实际索引键读写次数。"
    ),
    version="1.0.0",
    lifespan=lifespan,
)


@app.exception_handler(ConflictError)
def _conflict_handler(_request, exc: ConflictError):
    return JSONResponse(status_code=409, content={"detail": str(exc)})


@app.exception_handler(ValidationError)
def _validation_handler(_request, exc: ValidationError):
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.get("/health", tags=["运维"])
def health() -> dict:
    return {"status": "ok"}


@app.post("/candidates", response_model=WriteOut, status_code=201, tags=["路由候选"])
def add_candidate(item: CandidateIn):
    """录入一条候选；同一前缀最多 4 条，(prefix, seq) 唯一。"""
    return service.add_candidate(item)


@app.delete("/candidates", response_model=WriteOut, tags=["路由候选"])
def delete_candidate(
    prefix: str = Query(..., description="候选前缀，如 10.1.0.0/16"),
    seq: int = Query(..., ge=0, le=4_294_967_295, description="候选编号"),
):
    return service.delete_candidate(prefix, seq)


@app.get("/candidates", response_model=ListOut, tags=["路由候选"])
def list_candidates(prefix: str | None = Query(None, description="可选，按前缀过滤")):
    return service.list_candidates(prefix)


@app.post("/roas", response_model=WriteOut, tags=["模拟授权 ROA"])
def add_roas(batch: RoaBatchIn):
    """同批添加授权：整批成功才切换，任一条冲突则全部回滚。"""
    return service.add_roas_batch(batch.roas)


@app.post("/roas/revoke", response_model=WriteOut, tags=["模拟授权 ROA"])
def revoke_roas(batch: RoaRevokeIn):
    """按编号撤销（可批量）：任一编号不存在即整批回滚、状态照旧。"""
    return service.revoke_roas(batch.ids)


@app.get("/roas", response_model=ListOut, tags=["模拟授权 ROA"])
def list_roas(prefix: str | None = Query(None, description="可选，按授权前缀过滤")):
    return service.list_roas(prefix)


@app.get("/lookup/{destination}", response_model=LookupOut, tags=["查路"])
def lookup(destination: str):
    """最长前缀 → 最小优先值 → 最小编号；返回下一跳或无路由。"""
    return service.lookup(destination)


@app.post("/admin/reset", response_model=WriteOut, tags=["运维"])
def admin_reset():
    """清空候选与授权，恢复空库（演练重置）。"""
    store.reset_db()
    return {
        "status": "committed",
        "affected": 0,
        "detail": "候选与授权已清空（DDL 不计索引键读写）",
        "index_reads": 0,
        "index_writes": 0,
    }
