
import sqlite3
import threading

import pytest
from fastapi.testclient import TestClient

import app as appmod
from app import app as fastapi_app
from app import (
    POLICY_READONLY, POLICY_REWRITE, connect, entomb_old_key,
    init_db, remap_ingress, verification_report,
)


@pytest.fixture
def db_factory(tmp_path, monkeypatch):
    """每个口径建独立 SQLite 文件，返回 (client, auth_headers, db_path) 工厂。"""
    def make(policy):
        path = tmp_path / f"{policy}.db"
        monkeypatch.setattr(appmod, "DB_PATH", path)
        init_db(policy=policy)
        c = TestClient(fastapi_app, raise_server_exceptions=False)
        token = c.post("/api/login", json={"username": "admin", "password": "123456"}).json()["token"]
        h = {"Authorization": "Bearer " + token}
        return c, h, path
    return make


def raw_conn(path):
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=8000")
    return conn


# ---------- 夹具一：只读架构下废弃后再映被拒、正式不变 ----------

class TestReadonlyRetention:
    def test_tombstone_materialized_and_remap_rejected(self, db_factory):
        c, h, _ = db_factory(POLICY_READONLY)
        # 先重映一条，制造正式区既有行
        ok = c.post("/api/remap", headers=h, json={"old_key": "OLD-B1"}).json()
        assert ok["entity_key"] == "NEW-200"
        before = c.get("/api/formal", headers=h).json()["items"]

        r = c.post("/api/tombstone", headers=h, json={"old_key": "OLD-B1", "note": "旧键退役"})
        assert r.status_code == 200, r.text
        t = r.json()
        assert t["policy"] == POLICY_READONLY
        assert t["formal_unchanged"] >= 1 and t["history_appended"] >= 1

        # 墓碑物化四要素齐备
        rows = c.get("/api/tombstones", headers=h).json()["items"]
        assert len(rows) == 1
        for col in ("old_key", "tombstone_at", "map_version", "policy"):
            assert rows[0][col]
        assert rows[0]["old_key"] == "OLD-B1"

        # 废弃后再映：硬拒，不得重映成功进正式区
        again = c.post("/api/remap", headers=h, json={"old_key": "OLD-B1"})
        assert again.status_code == 410
        assert "拒绝再映" in again.json()["detail"]

        # 正式区不变（无新增、键未改）
        after = c.get("/api/formal", headers=h).json()["items"]
        assert after == before
        assert all(x["entity_key"] == "NEW-200" for x in after if x["mapped_from"] == "OLD-B1")

        # 拒进留痕可核证
        violations = c.get("/api/violations", headers=h).json()["items"]
        assert any(v["old_key"] == "OLD-B1" for v in violations)

    def test_tombstone_and_history_are_immutable(self, db_factory):
        c, h, path = db_factory(POLICY_READONLY)
        c.post("/api/tombstone", headers=h, json={"old_key": "OLD-A1"})
        conn = raw_conn(path)
        with pytest.raises(sqlite3.Error, match="不可变"):
            conn.execute("UPDATE oldkey_tombstone SET note='x' WHERE old_key='OLD-A1'")
        with pytest.raises(sqlite3.Error, match="不可变"):
            conn.execute("DELETE FROM oldkey_tombstone WHERE old_key='OLD-A1'")
        with pytest.raises(sqlite3.Error, match="只追加"):
            conn.execute("DELETE FROM formal_history")
        conn.close()

    def test_guard_blocks_unaudited_inplace_key_update(self, db_factory):
        c, h, path = db_factory(POLICY_READONLY)
        c.post("/api/tombstone", headers=h, json={"old_key": "OLD-A1"})
        conn = raw_conn(path)
        # 硬约束：墓碑后无审计就地改键，库级触发器直接 ABORT
        with pytest.raises(sqlite3.Error, match="禁止墓碑后无审计就地改键"):
            conn.execute("UPDATE formal_entities SET entity_key='NEW-HACK' WHERE mapped_from='OLD-A1'")
        conn.rollback()
        row = conn.execute("SELECT entity_key FROM formal_entities WHERE mapped_from='OLD-A1'").fetchone()
        assert row["entity_key"] == "NEW-100"
        conn.close()

    def test_failed_entomb_rolls_back_tombstone_and_history(self, db_factory):
        c, h, path = db_factory(POLICY_READONLY)
        appmod.FAULT_HOOKS["entomb_after_history"] = True
        try:
            r = c.post("/api/tombstone", headers=h, json={"old_key": "OLD-A1"})
            assert r.status_code == 500
        finally:
            appmod.FAULT_HOOKS.clear()
        conn = raw_conn(path)
        # 墓碑与史迹同事务回滚：不留半座碑、不留半段史迹，正式区原样
        assert conn.execute("SELECT COUNT(*) c FROM oldkey_tombstone").fetchone()["c"] == 0
        assert conn.execute("SELECT COUNT(*) c FROM formal_history").fetchone()["c"] == 0
        row = conn.execute("SELECT entity_key FROM formal_entities WHERE mapped_from='OLD-A1'").fetchone()
        assert row["entity_key"] == "NEW-100"
        conn.close()
        # 回滚后旧键仍可正常重映
        assert c.post("/api/remap", headers=h, json={"old_key": "OLD-A1"}).status_code == 200


# ---------- 夹具二：就地改写架构正式键变且审计可查 ----------

class TestInplaceRewrite:
    def test_formal_key_rewritten_with_audit_generations(self, db_factory):
        c, h, _ = db_factory(POLICY_REWRITE)
        # 制造两条待改写正式行（先映到旧目标，再由新映射改写）
        c.post("/api/remap", headers=h, json={"old_key": "OLD-B1"})
        c.post("/api/remap", headers=h, json={"old_key": "OLD-B1"})
        with connect() as conn:
            # 模拟“新映射”：把 B1 的目标键改成 NEW-201 后再立碑
            conn.execute("UPDATE mappings SET new_key='NEW-201' WHERE old_key='OLD-B1' AND version='m-2026.11'")
            conn.commit()

        r = c.post("/api/tombstone", headers=h, json={"old_key": "OLD-B1"})
        assert r.status_code == 200, r.text
        t = r.json()
        assert t["policy"] == POLICY_REWRITE
        assert t["formal_rewritten"] == 2 and t["audit_generations"] == 2

        formal = c.get("/api/formal", headers=h).json()["items"]
        assert all(x["entity_key"] == "NEW-201" for x in formal if x["mapped_from"] == "OLD-B1")

        audits = c.get("/api/key-change-audits", headers=h).json()["items"]
        gens = sorted(a["generation"] for a in audits)
        assert gens == [1, 2]
        for a in audits:
            assert a["from_entity_key"] == "NEW-200"
            assert a["to_entity_key"] == "NEW-201"
            assert a["old_key_ref"] == "OLD-B1"
            assert a["tombstone_id"] == t["tombstone_id"]

        # 审计世代只追加，抹不掉
        conn = connect()
        with pytest.raises(sqlite3.Error, match="只追加"):
            conn.execute("DELETE FROM key_change_audit")
        conn.close()

    def test_failed_rewrite_rolls_back_formal_and_audit(self, db_factory):
        c, h, path = db_factory(POLICY_REWRITE)
        c.post("/api/remap", headers=h, json={"old_key": "OLD-B1"})
        with connect() as conn:
            conn.execute("UPDATE mappings SET new_key='NEW-201' WHERE old_key='OLD-B1'")
            conn.commit()
        appmod.FAULT_HOOKS["entomb_after_update"] = True
        try:
            r = c.post("/api/tombstone", headers=h, json={"old_key": "OLD-B1"})
            assert r.status_code == 500
        finally:
            appmod.FAULT_HOOKS.clear()
        conn = raw_conn(path)
        # 正式与审计皆回滚
        assert conn.execute("SELECT COUNT(*) c FROM key_change_audit").fetchone()["c"] == 0
        assert conn.execute("SELECT COUNT(*) c FROM oldkey_tombstone").fetchone()["c"] == 0
        row = conn.execute("SELECT entity_key FROM formal_entities WHERE mapped_from='OLD-B1'").fetchone()
        assert row["entity_key"] == "NEW-200"
        conn.close()

    def test_rewrite_policy_allows_remap_but_audit_still_required(self, db_factory):
        c, h, path = db_factory(POLICY_REWRITE)
        c.post("/api/tombstone", headers=h, json={"old_key": "OLD-B1"})
        # 乙路径不拒再映（与甲路径口径分叉、互不混用）
        r = c.post("/api/remap", headers=h, json={"old_key": "OLD-B1"})
        assert r.status_code == 200 and r.json()["tombstoned"] is True

        # 即便乙路径，裸 UPDATE 正式键仍被守卫拒绝：必须挂审计
        conn = raw_conn(path)
        with pytest.raises(sqlite3.Error, match="禁止墓碑后无审计就地改键"):
            conn.execute("UPDATE formal_entities SET entity_key='NEW-HACK' WHERE mapped_from='OLD-B1'")
        conn.rollback()
        conn.close()


# ---------- 夹具三：并发后到只留争用 ----------

class TestConcurrency:
    def test_double_entomb_same_old_key_leaves_single_tombstone(self, db_factory):
        db_factory(POLICY_READONLY)
        errors, successes = [], []

        def worker():
            try:
                with connect() as conn:
                    entomb_old_key(conn, "OLD-B1")
                successes.append(1)
            except Exception as e:  # noqa: BLE001 - 需按错误类型分类断言
                errors.append(str(e))
        t1, t2 = threading.Thread(target=worker), threading.Thread(target=worker)
        t1.start(); t2.start(); t1.join(); t2.join()

        assert len(successes) == 1 and len(errors) == 1
        assert "已存在墓碑" in errors[0]
        with connect() as conn:
            n = conn.execute("SELECT COUNT(*) c FROM oldkey_tombstone WHERE old_key='OLD-B1'").fetchone()["c"]
        assert n == 1  # 禁止双写，后到只留争用

    def test_entomb_vs_remap_never_leaks_post_tombstone_formal_row(self, db_factory):
        db_factory(POLICY_READONLY)
        barrier = threading.Barrier(2)
        outcomes = {"entomb": None, "remap": None}

        def entomb_worker():
            barrier.wait()
            try:
                with connect() as conn:
                    entomb_old_key(conn, "OLD-A1")
                outcomes["entomb"] = "ok"
            except Exception as e:  # noqa: BLE001
                outcomes["entomb"] = f"err:{e}"

        def remap_worker():
            barrier.wait()
            try:
                with connect() as conn:
                    remap_ingress(conn, "OLD-A1")
                outcomes["remap"] = "ok"
            except Exception as e:  # noqa: BLE001
                outcomes["remap"] = f"err:{type(e).__name__}"
        t1, t2 = threading.Thread(target=entomb_worker), threading.Thread(target=remap_worker)
        t1.start(); t2.start(); t1.join(); t2.join()

        with connect() as conn:
            tomb = conn.execute("SELECT * FROM oldkey_tombstone WHERE old_key='OLD-A1'").fetchone()
            assert tomb is not None  # 立碑最终成功
            late = conn.execute(
                "SELECT COUNT(*) c FROM formal_entities WHERE mapped_from='OLD-A1' AND created_at>?",
                (tomb["tombstone_at"],)).fetchone()["c"]
        # 核心不变式：墓碑之后不得有新正式行偷渡（拒进或锁争用，二选一，绝不静默写入）
        assert late == 0
        assert outcomes["entomb"] == "ok"
        assert outcomes["remap"] in ("ok", "err:DomainError", "err:OperationalError")


# ---------- 口径全局唯一、禁止分叉/混用 ----------

class TestPolicyCoherence:
    def test_policy_switchable_before_any_tombstone_but_locked_after(self, db_factory):
        c, h, _ = db_factory(POLICY_READONLY)
        assert c.get("/api/policy", headers=h).json()["locked"] is False
        r = c.put("/api/policy", headers=h, json={"policy": POLICY_REWRITE})
        assert r.status_code == 200 and r.json()["policy"] == POLICY_REWRITE

        c.post("/api/tombstone", headers=h, json={"old_key": "OLD-A1"})
        locked = c.put("/api/policy", headers=h, json={"policy": POLICY_READONLY})
        assert locked.status_code == 409 and "禁止分叉" in locked.json()["detail"]

    def test_every_tombstone_snapshots_global_policy(self, db_factory):
        c, h, _ = db_factory(POLICY_REWRITE)
        c.post("/api/tombstone", headers=h, json={"old_key": "OLD-A1"})
        c.post("/api/tombstone", headers=h, json={"old_key": "OLD-B1"})
        for t in c.get("/api/tombstones", headers=h).json()["items"]:
            assert t["policy"] == POLICY_REWRITE
        # 只读口径专属的改键审计在乙路径之外必须为空（两边不得混用）
        c2, h2, _ = db_factory(POLICY_READONLY)
        c2.post("/api/tombstone", headers=h2, json={"old_key": "OLD-A1"})
        assert c2.get("/api/key-change-audits", headers=h2).json()["items"] == []

    def test_reinit_with_other_policy_after_tombstones_refused(self, tmp_path, monkeypatch):
        monkeypatch.setattr(appmod, "DB_PATH", tmp_path / "p.db")
        init_db(policy=POLICY_READONLY)
        with connect() as conn:
            entomb_old_key(conn, "OLD-A1")
        with pytest.raises(RuntimeError, match="不得分叉"):
            init_db(policy=POLICY_REWRITE)

    def test_unknown_and_double_entomb_rejected(self, db_factory):
        c, h, _ = db_factory(POLICY_READONLY)
        r = c.post("/api/tombstone", headers=h, json={"old_key": "OLD-NOPE"})
        assert r.status_code == 404
        c.post("/api/tombstone", headers=h, json={"old_key": "OLD-A1"})
        again = c.post("/api/tombstone", headers=h, json={"old_key": "OLD-A1"})
        assert again.status_code == 409 and "不可重立" in again.json()["detail"]

    def test_viewer_cannot_entomb_or_switch_policy(self, db_factory):
        c, _h, _ = db_factory(POLICY_READONLY)
        tok = c.post("/api/login", json={"username": "viewer", "password": "view123"}).json()["token"]
        h = {"Authorization": "Bearer " + tok}
        assert c.post("/api/tombstone", headers=h, json={"old_key": "OLD-A1"}).status_code == 403
        assert c.put("/api/policy", headers=h, json={"policy": POLICY_REWRITE}).status_code == 403
        # 只读核证接口对普通登录用户开放
        assert c.get("/api/tombstones", headers=h).status_code == 200
        assert c.get("/api/tombstone-verification", headers=h).status_code == 200


# ---------- 核证只读接口：五区协同互证 ----------

class TestVerificationCard:
    def test_readonly_report_all_green(self, db_factory):
        c, h, _ = db_factory(POLICY_READONLY)
        c.post("/api/remap", headers=h, json={"old_key": "OLD-A1"})
        c.post("/api/tombstone", headers=h, json={"old_key": "OLD-A1"})
        c.post("/api/remap", headers=h, json={"old_key": "OLD-A1"})  # 被拒留痕
        rep = c.get("/api/tombstone-verification", headers=h).json()
        assert rep["ok"] is True
        assert rep["policy"] == POLICY_READONLY
        names = {x["check"] for x in rep["checks"]}
        assert {"全局口径唯一且墓碑未分叉", "不可变/改键守卫触发器在位"} <= names
        assert rep["counts"]["tombstones"] == 1
        assert rep["counts"]["audits"] == 0  # 甲路径下审计必空
        assert rep["counts"]["violations"] == 1

    def test_rewrite_report_all_green(self, db_factory):
        c, h, _ = db_factory(POLICY_REWRITE)
        c.post("/api/remap", headers=h, json={"old_key": "OLD-B1"})
        with connect() as conn:
            conn.execute("UPDATE mappings SET new_key='NEW-201' WHERE old_key='OLD-B1'")
            conn.commit()
        c.post("/api/tombstone", headers=h, json={"old_key": "OLD-B1"})
        rep = c.get("/api/tombstone-verification", headers=h).json()
        assert rep["ok"] is True
        assert rep["counts"]["audits"] == 1
        with connect() as conn:
            assert verification_report(conn)["ok"] is True

    def test_health_exposes_policy_and_tombstone_count(self, db_factory):
        c, h, _ = db_factory(POLICY_READONLY)
        body = c.get("/api/health").json()
        assert body["policy"] == POLICY_READONLY and body["tombstones"] == 0
        c.post("/api/tombstone", headers=h, json={"old_key": "OLD-A1"})
        body = c.get("/api/health").json()
        assert body["tombstones"] == 1
