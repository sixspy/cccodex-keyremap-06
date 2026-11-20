# 实体键桥

> 遵守 `ops/底座生成前必读_效率与技术栈.md`。FastAPI + Vue 3 + SQLite，交付须 docker compose 一键起；库用 SQLite，不挂外置 Postgres。  
> **禁止同构换皮**：本仓主链路、表结构、接口与页面均独立，不得与其它仓共用同一套 `/api/items` 壳。

## 骨架一句话

实体键映射生效后入站先重映再进正式区，冲突进队列，映射版本与正式区对账

## 基本信息

| 项 | 值 |
|----|-----|
| 产品名（首页） | 实体键桥 |
| 目录 | `07-keyremap` |
| 领域建议 | 数仓与数据湖 |
| 接口 | http://127.0.0.1:10916 |
| 库 | `data/app.db` |
| 账号 | admin / 123456 |

## 为何能出多题

一对多/多对一、生效窗、旧键只读、重映重放

## 避开

别做成 Feed 冲突归并；正式区不是 staging 换皮

## 互斥切口候选

- 冲突拒收整批 vs 进冲突区后重放
- 废弃旧键只读保留 vs 重写正式键
- 生效窗原子切换 vs 双窗按事件时裁

## 旧键墓碑：物化处置与正确性口径（已落地）

落库形态二选一，本仓选定**第一形态：独立不可变墓碑表 `oldkey_tombstone`**（`old_key` 唯一 + `tombstone_at` + `map_version` + `new_key_at_tombstone` + `policy`），不采用 mappings 行 `tombstone_snapshot` 列。库级触发器 `trg_tombstone_no_update/no_delete` 禁止改碑、抹碑，版级追溯不会断裂；不是只改废弃徽章样式。

正确性口径全局唯一，存 `sys_config.tombstone_policy` 并快照进每座墓碑的 `policy` 列，立碑后禁止分叉：

- **甲 `readonly_retention`（默认，只读保留）**：立碑后再映该旧键直接 410 拒进（留痕 `tombstone_violations`），正式区一行不增一键不改，只向只追加表 `formal_history` 写碑刻快照史迹；墓碑与史迹同事务，失败同回滚。
- **乙 `inplace_rewrite`（就地改写）**：立碑时按新映射改写 `formal_entities.entity_key`，同事务向只追加表 `key_change_audit` 写改键审计世代（generation 从 1 连续、回指墓碑 id）；正式与审计同事务，失败皆回滚。

硬约束（库级强制，非应用自觉）：

- 禁止墓碑后无审计就地改键——`trg_formal_key_guard_update` 只认同事务 `arm_audit()` 挂出的连接私有门闩（`rewrite_gate` + `last_insert_rowid()`），裸 SQL UPDATE 一律 ABORT。
- 只读架构下废弃旧键重映不得成功进正式区（410 + 拒进留痕）。
- 两路不得混用：只读口径下 `key_change_audit` 必须为空；写事务一律 `BEGIN IMMEDIATE`，同旧键并发立碑后到者 409，全库只留一座碑，无双写。

建库时可用环境变量 `KEYREMAP_POLICY=readonly_retention|inplace_rewrite` 定口径（无墓碑前还可经 `PUT /api/policy` 切换，立碑后锁定）。

新增接口（均需登录，立碑/切口径仅管理员）：

| 方法 | 路径 | 说明 |
|----|----|----|
| POST | `/api/tombstone` | 废弃旧键立碑，按全局口径走甲或乙 |
| GET | `/api/tombstones` | 墓碑表只读列表 |
| GET | `/api/policy` / PUT | 查/切全局正确性口径（立碑后切返回 409） |
| GET | `/api/formal-history` | 甲路径只追加只读史迹 |
| GET | `/api/key-change-audits` | 乙路径改键审计世代 |
| GET | `/api/violations` | 墓碑后再映拒进留痕 |
| GET | `/api/tombstone-verification` | 核证只读卡：映射册、墓碑表、正式区、审计、互证五区对账 |

## 本地夹具（SQLite）

`tests/test_tombstone.py` 覆盖题目全部夹具，`pytest -q` 全绿：

- 只读架构：废弃后再映 410 被拒、正式不变；墓碑/史迹不可变（触发器实测）；裸改键被守卫 ABORT；注入故障后墓碑与史迹同事务回滚。
- 就地改写架构：正式键按新映射变化、审计世代链可查；注入故障后正式与审计皆回滚；裸 UPDATE 仍被守卫拦截。
- 并发：同旧键双线程立碑只成一座（后到只留争用）；立碑与再映并发，碑后无正式行偷渡。
- 口径：立碑后切口径/按另一口径重开库均被拒，墓碑 policy 快照与全局一致，两路不混用。

## 启动（一键）

`powershell
cd projects/07-keyremap
docker compose up -d --build
`

浏览器：http://127.0.0.1:10916/  
健康检查：GET http://127.0.0.1:10916/api/health

本机开发（可选）：

`powershell
python -m pip install -r requirements.txt
python -m uvicorn app:app --app-dir backend --host 127.0.0.1 --port 10604
python -m pytest -q
`
