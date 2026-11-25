"""请求/响应模型（/docs 中展示中文说明）。"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

from .rpki import parse_v4_address, parse_v4_network

_UINT32 = Field(ge=0, le=4_294_967_295)


class CandidateIn(BaseModel):
    prefix: str = Field(description="IPv4 前缀，如 10.1.0.0/16；自动规范化主机位并保留长度")
    seq: int = Field(..., description="前缀内编号（uint32），与 prefix 共同唯一")
    asn: int = Field(..., description="来源 ASN（0-4294967295）", ge=0, le=4_294_967_295)
    next_hop: str = Field(description="下一跳 IPv4 地址")
    preference: int = Field(..., description="优先值，同前缀取最小者", ge=0, le=4_294_967_295)

    @field_validator("prefix")
    @classmethod
    def _prefix(cls, v: str) -> str:
        network, length = parse_v4_network(v)
        return f"{network}/{length}"

    @field_validator("next_hop")
    @classmethod
    def _next_hop(cls, v: str) -> str:
        return parse_v4_address(v)


class RoaIn(BaseModel):
    id: int = Field(..., description="授权编号（uint32），全局唯一", ge=0, le=4_294_967_295)
    prefix: str = Field(description="授权 IPv4 前缀，如 203.0.113.0/24")
    asn: int = Field(..., description="授权来源 ASN", ge=0, le=4_294_967_295)
    max_len: int = Field(
        ..., description="最大前缀长度，须不小于授权前缀长度且不超过 32", ge=0, le=32
    )

    @field_validator("prefix")
    @classmethod
    def _prefix(cls, v: str) -> str:
        network, length = parse_v4_network(v)
        return f"{network}/{length}"


class RoaBatchIn(BaseModel):
    roas: list[RoaIn] = Field(..., min_length=1, description="同批添加的授权列表")


class RoaRevokeIn(BaseModel):
    ids: list[int] = Field(..., min_length=1, description="按编号撤销，支持批量")


class WriteOut(BaseModel):
    status: Literal["committed", "rolled_back"]
    affected: int
    index_reads: int
    index_writes: int
    detail: str = ""


class LookupOut(BaseModel):
    destination: str
    next_hop: str | None
    routed: bool
    matched_prefix: str | None
    winning_seq: int | None
    winning_asn: int | None
    roa_status: Literal["valid", "no_roa"] | None
    index_reads: int
    index_writes: int
    evaluated_prefixes: list[dict]


class CandidateOut(BaseModel):
    prefix: str
    seq: int
    asn: int
    next_hop: str
    preference: int


class RoaOut(BaseModel):
    id: int
    prefix: str
    prefix_len: int
    asn: int
    max_len: int


class ListOut(BaseModel):
    count: int
    index_reads: int
    index_writes: int
    items: list[dict]
