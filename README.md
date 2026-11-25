# RPKI 授权撤回本地演练

网关值班员在 RPKI 授权（ROA）撤回后，需要确认流量实际走哪个下一跳。本项目用
FastAPI + SQLite 做本地演练：维护 IPv4 路由候选与模拟授权，支持授权批量增撤期间
持续查路，并对每次增、撤、查返回**实际索引键读写次数**。

## 一、启动方式

### docker compose（推荐）

```bash
docker compose up --build
# 文档与演练台：http://localhost:8000/docs
# 健康检查：     http://localhost:8000/health
```

SQLite 数据文件落在命名卷 `rpki_data`（容器内 `/data/drill.db`），容器重建不丢数据。

### 本地直接运行

```bash
python3 -m pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
# 数据库路径可用环境变量 RPKI_DRILL_DB 覆盖，默认 ./data/drill.db
```

### 跑测试

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest -q
```

## 二、数据模型与接口

| 表 | 关键字段 | 索引 |
| --- | --- | --- |
| `candidates` | prefix、prefix_len、seq、asn、next_hop、preference | 聚簇主键 `(prefix, prefix_len, seq)`；选路复合索引 `(prefix, prefix_len, preference, seq)` |
| `roas` | id、prefix、prefix_len、asn、max_len | 聚簇主键 `(prefix, prefix_len, id)`；`UNIQUE(id)` |

两张表均为 `WITHOUT ROWID`，所有热点 SQL 经 `EXPLAIN QUERY PLAN` 核对为
`SEARCH ... USING 索引`，无全表 `SCAN`。

接口（均在 `/docs` 可直接录入）：

- `POST /candidates`：录入候选。同一前缀最多 4 条，`(prefix, seq)` 唯一；
  前缀自动规范化（主机位清零）并保留长度，同网络地址的不同长度前缀（如
  `10.2.0.0/16` 与 `10.2.0.0/22`）互不撞键。
- `DELETE /candidates?prefix=&seq=`：删除单条候选。
- `GET /candidates?prefix=`：列出候选（可选前缀过滤）。
- `POST /roas`：**同批**添加授权，整批成功才切换；任一编号冲突 / 批内重复 /
  `max_len` 非法即整体回滚。
- `POST /roas/revoke`：按编号批量撤销；任一编号不存在即整批回滚、状态照旧。
- `GET /roas?prefix=`：列出授权。
- `GET /lookup/{destination}`：查路，返回下一跳或无路由。
- `POST /admin/reset`：清空两表（演练重置，DDL 不计索引键读写）。

## 三、选路与 RPKI 规则

1. **最长前缀匹配**：对目的 IP 从 `/32` 到 `/0` 逐长度探测候选。
2. **RPKI 校验**（仅对命中的候选前缀做）：
   - 无任何覆盖授权 → 候选照常参与，状态 `no_roa`；
   - 有覆盖授权 → 必须存在一条授权满足 `授权 ASN == 候选 ASN` 且
     `候选前缀长度 <= 授权 max_len`，候选才 `valid`；否则 `invalid`，不参与。
   - 覆盖授权沿候选前缀的祖先链逐键探测（粗粒度授权的网络地址与候选不同也能命中，
     例如候选 `198.20.4.0/24` 能被 `198.20.0.0/16` 覆盖）。
   - 某长度候选全部失效时，继续向更短前缀选路，而不是直接返回无路由。
3. **同前缀裁决**：最小 `preference`，再平手取最小 `seq`（由复合索引保证顺序，无临时排序）。

## 四、并发与一致性

- 写路径 `BEGIN IMMEDIATE`：整批要么 `COMMIT` 要么 `ROLLBACK`，不出现部分生效。
- 读路径 `BEGIN` 快照：查路全程读同一已提交状态；SQLite WAL 下写事务进行时读不阻塞。
  注意 SQLite 的 deferred 事务快照由**第一条读语句**固化（非 `BEGIN` 本身），
  应用代码在进入快照后立即读，故每次查路视图一致。
- 已用 200 路并发查路 + 40 批并发增撤压测：查路始终 200、无 5xx，授权视图只在
  `valid` / `no_roa` 间原子切换。

## 五、索引键计数口径（未命中也计入）

- **index_reads**：一条走索引的点查 SQL 计 1 次，命中与未命中都计。
  - 查路候选：每个长度 1 次主键探测（最多 33 次，未命中也计）。
  - 覆盖授权：对长度为 L 的候选，沿 L+1 个祖先键各探测 1 次（L+1 次，未命中也计）。
- **index_writes**：按一条 INSERT/DELETE 实际维护的索引数计；两张表各 2 个索引，
  故单条增/删均为 2 次键写（删不到行则为 0）。

### 探测预算（硬约束 ≤ 2500）

最坏情况：目的 IP 的 33 个祖先长度全部存在候选、且全部 RPKI 失效：

```
33（候选探测） + Σ(L+1), L=0..32（授权祖先键） = 33 + 561 = 594 次
```

实测 594 次，远低于 2500 上限；代码在每次查路后自检，超预算直接报错而非静默放行。

## 六、实测记录

- 单元/接口测试 `python3 -m pytest -q`：**25 passed**。
- 重点自测「重叠授权的撤销」（`tests/test_api.py` 中两个同名主题用例）：
  - 粗 `/16` 与细 `/20` 两条重叠授权并存 → 候选 `valid`；
  - 撤销细粒度授权后，粗粒度授权仍覆盖，下一跳不变、仍 `valid`；
  - 再撤销粗粒度授权 → 无覆盖授权，候选回到 `no_roa` 照常参与；
  - 另一组：重叠授权中仅一条 ASN 匹配，撤销匹配项后候选立即 `invalid`，
    撤销剩余错误授权后恢复 `no_roa`。
- 真实 uvicorn 端到端冒烟：批量回滚不留残、撤销计数 `reads=1 writes=2`、
  无路由空库查路 `reads=33`、最坏探测 594。
- `EXPLAIN QUERY PLAN`：7 条热点 SQL 全部 `SEARCH ... USING`，无 `SCAN`。

## 七、已知缺项与取舍

1. **未做认证/鉴权、限流**：定位为本地演练服务，默认只暴露在演练环境。
2. **计数是应用层口径**：统计的是「按索引键发起的探测/维护次数」，未深入 SQLite
   B-Tree 页级 IO；未命中键也按一次探测计入，属保守可审计口径。
3. **仅 IPv4**：模型与 0–32 长度校验均按 IPv4 实现，未支持 IPv6。
4. **ROA 不支持过期时间/信任锚层级**：只模拟「编号 + 前缀 + ASN + max_len」四元组。
5. **每前缀 4 条上限在录入时计数实现**：计数本身是一次索引区间统计（计入读），
   未用触发器维护物化计数。
6. **docker compose 未在本环境实跑**：当前环境无 Docker 守护进程，仅完成
   `Dockerfile`/`compose` 编写与 YAML 结构校验；镜像内依赖版本与本机实测一致。
