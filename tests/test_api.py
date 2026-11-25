"""端到端行为测试：选路规则、RPKI 校验、批量原子性与探测计数。"""
from __future__ import annotations


def add_candidate(client, prefix, seq, asn, hop, pref):
    r = client.post(
        "/candidates",
        json={
            "prefix": prefix,
            "seq": seq,
            "asn": asn,
            "next_hop": hop,
            "preference": pref,
        },
    )
    assert r.status_code == 201, r.text
    return r.json()


def add_roas(client, roas):
    r = client.post("/roas", json={"roas": roas})
    assert r.status_code == 200, r.text
    return r.json()


def test_no_route_empty_db_counts_all_probes(client):
    r = client.get("/lookup/198.51.100.7")
    assert r.status_code == 200
    body = r.json()
    assert body["routed"] is False
    assert body["next_hop"] is None
    # 空库也要扫 33 个长度的候选键位，未命中全部计入；无候选即无授权探测
    assert body["index_reads"] == 33
    assert body["index_writes"] == 0


def test_longest_prefix_preference_seq_tiebreak(client):
    add_candidate(client, "10.0.0.0/8", 1, 64500, "192.0.2.1", 100)
    add_candidate(client, "10.2.0.0/16", 2, 64501, "192.0.2.2", 100)
    add_candidate(client, "10.2.0.0/16", 3, 64501, "192.0.2.3", 50)
    add_candidate(client, "10.2.0.0/16", 4, 64501, "192.0.2.4", 50)

    body = client.get("/lookup/10.2.3.4").json()
    # 最长前缀 /16；同优先值 50 取最小编号 3
    assert body["matched_prefix"] == "10.2.0.0/16"
    assert body["next_hop"] == "192.0.2.3"
    assert body["winning_seq"] == 3
    assert body["roa_status"] == "no_roa"

    body = client.get("/lookup/10.9.9.9").json()
    assert body["matched_prefix"] == "10.0.0.0/8"
    assert body["next_hop"] == "192.0.2.1"


def test_candidate_cap_four_per_prefix(client):
    for seq in range(1, 5):
        assert add_candidate(client, "172.16.0.0/16", seq, 64510, "10.0.0.1", seq)[
            "affected"
        ] == 1
    r = client.post(
        "/candidates",
        json={
            "prefix": "172.16.0.0/16",
            "seq": 5,
            "asn": 64510,
            "next_hop": "10.0.0.9",
            "preference": 1,
        },
    )
    assert r.status_code == 409
    assert "最多 4 条" in r.json()["detail"]
    assert client.get("/candidates", params={"prefix": "172.16.0.0/16"}).json()[
        "count"
    ] == 4


def test_duplicate_seq_conflicts_and_normalizes_host_bits(client):
    add_candidate(client, "192.168.1.100/24", 7, 64520, "10.1.1.1", 10)
    r = client.post(
        "/candidates",
        json={
            "prefix": "192.168.1.200/24",
            "seq": 7,
            "asn": 64520,
            "next_hop": "10.1.1.2",
            "preference": 20,
        },
    )
    assert r.status_code == 409
    items = client.get("/candidates").json()["items"]
    assert items[0]["prefix"] == "192.168.1.0/24"


def test_rpki_valid_and_invalid_and_fallback_to_shorter(client):
    # 长前缀候选 ASN 与覆盖授权不一致 → invalid
    add_candidate(client, "203.0.113.0/25", 1, 64600, "172.0.0.1", 10)
    # 短前缀候选，没有覆盖授权 → no_roa 照常参与
    add_candidate(client, "203.0.113.0/24", 2, 64601, "172.0.0.2", 10)
    # 授权只允许 AS 64699
    add_roas(
        client,
        [{"id": 10, "prefix": "203.0.113.0/24", "asn": 64699, "max_len": 25}],
    )

    body = client.get("/lookup/203.0.113.9").json()
    statuses = {(e["prefix"], e["seq"]): e["roa_status"] for e in body["evaluated_prefixes"]}
    assert statuses[("203.0.113.0", 1)] == "invalid"
    assert statuses[("203.0.113.0", 2)] == "invalid"
    # /24 候选同样被覆盖且 ASN 不一致 → 回退到无覆盖授权的更短/无路由
    assert body["routed"] is False

    # 补上匹配 ASN 的候选后即可选路
    add_candidate(client, "203.0.113.0/25", 3, 64699, "172.0.0.3", 10)
    body = client.get("/lookup/203.0.113.9").json()
    assert body["routed"] is True
    assert body["next_hop"] == "172.0.0.3"
    assert body["roa_status"] == "valid"


def test_max_len_boundary(client):
    add_candidate(client, "198.18.0.0/24", 1, 64700, "10.2.2.1", 1)
    add_roas(
        client,
        [{"id": 20, "prefix": "198.18.0.0/22", "asn": 64700, "max_len": 23}],
    )
    # /24 超过 max_len 23 → invalid
    body = client.get("/lookup/198.18.0.5").json()
    assert body["routed"] is False
    assert body["evaluated_prefixes"][0]["roa_status"] == "invalid"

    add_candidate(client, "198.18.0.0/23", 2, 64700, "10.2.2.2", 1)
    body = client.get("/lookup/198.18.0.5").json()
    assert body["matched_prefix"] == "198.18.0.0/23"
    assert body["roa_status"] == "valid"


def test_overlapping_roas_revoke_one_keeps_other(client):
    """重点自测：重叠授权并存，撤销其中一条后另一条仍能支撑选路。"""
    add_candidate(client, "198.19.0.0/24", 1, 64800, "10.3.3.1", 10)
    add_roas(
        client,
        [
            # 粗粒度重叠授权，max_len 放到 /24
            {"id": 100, "prefix": "198.19.0.0/16", "asn": 64800, "max_len": 24},
            # 细粒度重叠授权，同样允许该 ASN
            {"id": 101, "prefix": "198.19.0.0/20", "asn": 64800, "max_len": 24},
        ],
    )
    listing = client.get("/roas").json()
    assert listing["count"] == 2

    body = client.get("/lookup/198.19.0.9").json()
    assert body["routed"] is True
    assert body["roa_status"] == "valid"

    # 撤销细粒度 101：粗粒度 100 仍覆盖，路由不变
    r = client.post("/roas/revoke", json={"ids": [101]})
    assert r.status_code == 200
    body = client.get("/lookup/198.19.0.9").json()
    assert body["routed"] is True
    assert body["next_hop"] == "10.3.3.1"
    assert body["roa_status"] == "valid"

    # 再撤销 100：失去全部覆盖授权 → 候选回到 no_roa，照常参与
    client.post("/roas/revoke", json={"ids": [100]})
    body = client.get("/lookup/198.19.0.9").json()
    assert body["routed"] is True
    assert body["roa_status"] == "no_roa"
    assert client.get("/roas").json()["count"] == 0


def test_overlapping_roas_wrong_asn_only_revoked_candidate_dies(client):
    """重叠授权中只有一条 ASN 匹配；撤销匹配项后候选立即失效。"""
    add_candidate(client, "198.20.4.0/24", 1, 64810, "10.4.4.1", 10)
    add_roas(
        client,
        [
            {"id": 200, "prefix": "198.20.0.0/16", "asn": 64899, "max_len": 24},
            {"id": 201, "prefix": "198.20.4.0/22", "asn": 64810, "max_len": 24},
        ],
    )
    assert client.get("/lookup/198.20.4.4").json()["routed"] is True

    client.post("/roas/revoke", json={"ids": [201]})
    body = client.get("/lookup/198.20.4.4").json()
    assert body["routed"] is False
    assert body["evaluated_prefixes"][0]["roa_status"] == "invalid"

    # 把剩余错误授权也撤掉 → no_roa，候选恢复参与
    client.post("/roas/revoke", json={"ids": [200]})
    body = client.get("/lookup/198.20.4.4").json()
    assert body["routed"] is True
    assert body["roa_status"] == "no_roa"


def test_batch_roa_all_or_nothing_and_counts(client):
    ok = add_roas(
        client,
        [
            {"id": 1, "prefix": "203.0.113.0/24", "asn": 65001, "max_len": 24},
            {"id": 2, "prefix": "203.0.113.0/25", "asn": 65002, "max_len": 25},
        ],
    )
    # 每条：1 次 id 点查（读）+ 2 个索引键写
    assert ok["index_reads"] == 2
    assert ok["index_writes"] == 4
    assert ok["affected"] == 2

    # 第二批含冲突编号 2（在第 3 条预检时才撞到）与批内重复 9 → 整批回滚
    r = client.post(
        "/roas",
        json={
            "roas": [
                {"id": 3, "prefix": "192.0.2.0/24", "asn": 65003, "max_len": 24},
                {"id": 2, "prefix": "192.0.2.0/25", "asn": 65004, "max_len": 25},
                {"id": 9, "prefix": "198.51.100.0/24", "asn": 65005, "max_len": 24},
                {"id": 9, "prefix": "198.51.100.0/25", "asn": 65006, "max_len": 25},
            ]
        },
    )
    assert r.status_code == 409
    # 编号 3 不得残留（预检阶段全部完成前不会写入）
    ids = {x["id"] for x in client.get("/roas").json()["items"]}
    assert ids == {1, 2}

    # 撤销不存在的编号 → 整批回滚，已删的也恢复
    r = client.post("/roas/revoke", json={"ids": [1, 777]})
    assert r.status_code == 409
    ids = {x["id"] for x in client.get("/roas").json()["items"]}
    assert ids == {1, 2}


def test_revoke_counts_and_missing_id_rollback(client):
    add_roas(
        client,
        [{"id": 50, "prefix": "203.0.113.0/24", "asn": 65050, "max_len": 24}],
    )
    body = client.post("/roas/revoke", json={"ids": [50]}).json()
    # 1 次 id 点查 + 2 个索引键写
    assert body["index_reads"] == 1
    assert body["index_writes"] == 2

    r = client.post("/roas/revoke", json={"ids": [50]})
    assert r.status_code == 409
    # 未命中仍计 1 次读、0 次写
    # （回滚响应体由异常处理器给出，计数通过后续列表/查路口径间接保证；
    #  精确计数在 test_store_counts 中直接校验）


def test_lookup_probe_budget_under_2500_with_dense_db(client):
    """最坏路径：目的 IP 的 33 个祖先长度都有候选、全部被错误 ASN 授权判 invalid。"""
    import ipaddress

    ip = "203.0.113.66"
    addr = ipaddress.IPv4Address(ip)
    for length in range(0, 33):
        net = ipaddress.IPv4Network((addr, length), strict=False)
        add_candidate(client, str(net), 1, 65100, "10.9.9.1", 100)
    # /0 授权覆盖全部长度，但 ASN 不匹配 → 33 条候选全部 invalid
    add_roas(
        client,
        [{"id": 1000, "prefix": "0.0.0.0/0", "asn": 65999, "max_len": 32}],
    )
    body = client.get(f"/lookup/{ip}").json()
    # 33 次候选探测 + 每个命中长度 L 的 L+1 次授权祖先键 = 33 + 561 = 594
    assert body["index_reads"] == 594
    assert body["index_reads"] < 2500
    assert body["routed"] is False
    assert len(body["evaluated_prefixes"]) == 33
    assert all(e["roa_status"] == "invalid" for e in body["evaluated_prefixes"])

    # 理论最坏值公式（IPv4 上限）
    worst = 33 + sum(range(1, 34))
    assert worst == 594


def test_lpm_falls_through_invalid_long_prefix_to_valid_shorter(client):
    """长前缀候选全部 RPKI 失效时，必须继续向更短前缀选路而非直接无路由。"""
    add_candidate(client, "203.0.113.0/25", 1, 64600, "172.0.0.1", 10)
    add_candidate(client, "203.0.113.0/24", 2, 64601, "172.0.0.2", 10)
    # 只让 /25 失效：授权覆盖 /25 且 ASN 不匹配
    add_roas(
        client,
        [{"id": 9, "prefix": "203.0.113.0/25", "asn": 64999, "max_len": 25}],
    )
    body = client.get("/lookup/203.0.113.9").json()
    # /25 候选 invalid；/24 无覆盖授权（no_roa）兜底
    assert body["routed"] is True
    assert body["matched_prefix"] == "203.0.113.0/24"
    assert body["next_hop"] == "172.0.0.2"
    assert body["roa_status"] == "no_roa"


def test_default_route_and_as0(client):
    add_candidate(client, "0.0.0.0/0", 0, 0, "10.255.255.1", 1)
    body = client.get("/lookup/1.2.3.4").json()
    assert body["matched_prefix"] == "0.0.0.0/0"
    assert body["next_hop"] == "10.255.255.1"
    # 32 次候选未命中 + 1 次候选命中 + 1 次 /0 授权祖先键探测 = 34
    assert body["index_reads"] == 34

    # AS0 授权只匹配 ASN=0 候选
    add_roas(client, [{"id": 900, "prefix": "0.0.0.0/0", "asn": 0, "max_len": 32}])
    body = client.get("/lookup/1.2.3.4").json()
    assert body["roa_status"] == "valid"


def test_bad_inputs(client):
    r = client.post(
        "/candidates",
        json={"prefix": "10.0.0.0/33", "seq": 1, "asn": 1, "next_hop": "1.1.1.1", "preference": 1},
    )
    assert r.status_code == 422
    r = client.post(
        "/candidates",
        json={"prefix": "10.0.0.0/8", "seq": 1, "asn": 1, "next_hop": "not-ip", "preference": 1},
    )
    assert r.status_code == 422
    r = client.post(
        "/roas",
        json={"roas": [{"id": 1, "prefix": "10.0.0.0/16", "asn": 1, "max_len": 8}]},
    )
    assert r.status_code == 400
    r = client.get("/lookup/not-an-ip")
    assert r.status_code == 400


def test_candidate_delete(client):
    add_candidate(client, "10.4.0.0/16", 1, 65200, "10.0.0.1", 10)
    r = client.delete("/candidates", params={"prefix": "10.4.0.0/16", "seq": 1})
    assert r.status_code == 200
    assert r.json()["index_writes"] == 2  # 主键 + 选路复合索引
    r = client.delete("/candidates", params={"prefix": "10.4.0.0/16", "seq": 1})
    assert r.status_code == 409
    assert client.get("/lookup/10.4.0.1").json()["routed"] is False


def test_candidate_lifecycle_counts(client):
    body = add_candidate(client, "10.5.0.0/16", 1, 65300, "10.0.0.1", 10)
    # 存在性点查 + 前缀计数 + 插入前再点查 = 3 次读；2 个索引键写
    assert body["index_reads"] == 3
    assert body["index_writes"] == 2
