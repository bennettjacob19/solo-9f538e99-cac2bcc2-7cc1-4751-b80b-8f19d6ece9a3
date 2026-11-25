"""IPv4 前缀工具与 RPKI 覆盖授权判定。"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterator
from typing import Any

MAX_PREFIX_LEN = 32


class ValidationError(ValueError):
    """输入校验失败，路由层翻译成 422 之外的业务 400。"""


def parse_v4_network(value: str) -> tuple[str, int]:
    """解析 IPv4 前缀并强制规范化（主机位清零），返回 (规范化前缀, 长度)。"""
    try:
        net = ipaddress.IPv4Network(value, strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as exc:
        raise ValidationError(f"非法 IPv4 前缀: {value!r}") from exc
    return str(net.network_address), net.prefixlen


def parse_v4_address(value: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value))
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise ValidationError(f"非法 IPv4 地址: {value!r}") from exc


def lpm_prefixes(ip: str) -> Iterator[tuple[str, int]]:
    """目的 IP 的 /32 → /0 全部可能前缀（网络地址形式），共 33 个。"""
    addr = ipaddress.IPv4Address(ip)
    for length in range(MAX_PREFIX_LEN, -1, -1):
        net = ipaddress.IPv4Network((addr, length), strict=False)
        yield str(net.network_address), length


def is_covered(candidate_network: str, candidate_len: int, roa: Any) -> bool:
    """授权前缀是否覆盖候选前缀（含主机位包含关系与长度下界）。"""
    if candidate_len < roa["prefix_len"]:
        return False
    roa_net = ipaddress.IPv4Network((roa["prefix"], roa["prefix_len"]))
    cand_net = ipaddress.IPv4Network((candidate_network, candidate_len), strict=False)
    return cand_net.subnet_of(roa_net)


def candidate_is_eligible(candidate: Any, roas: list[Any]) -> tuple[bool, str]:
    """RPKI 判定。

    - 无任何覆盖授权：照常参与（状态 no_roa）；
    - 存在覆盖授权：必须有一条 ASN 相同且候选前缀长度不超过该授权 max_len（valid）；
    - 其余情况 invalid，不参与选路。
    ASN 0（AS0）按普通来源 ASN 处理，仅 ASN=0 的候选能与之匹配。
    """
    covering = [
        roa
        for roa in roas
        if is_covered(candidate["prefix"], candidate["prefix_len"], roa)
    ]
    if not covering:
        return True, "no_roa"
    for roa in covering:
        if roa["asn"] == candidate["asn"] and candidate["prefix_len"] <= roa["max_len"]:
            return True, "valid"
    return False, "invalid"
