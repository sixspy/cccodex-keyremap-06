
import hashlib, os, secrets, sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
DB_PATH = DATA / "app.db"
FRONTEND = ROOT / "frontend"
SESSIONS: dict[str, str] = {}

# 全局只贯彻一种正确性口径：甲=只读保留，乙=就地改写。建库时定下，立碑后禁止分叉。
POLICY_READONLY = "readonly_retention"
POLICY_REWRITE = "inplace_rewrite"
POLICIES = (POLICY_READONLY, POLICY_REWRITE)
POLICY_LABELS = {
    POLICY_READONLY: "甲路径·废弃旧键只读保留",
    POLICY_REWRITE: "乙路径·审计改键就地改写",
}
DEFAULT_POLICY = POLICY_READONLY

# 故障注入点：仅测试使用，在事务提交前抛错以验证同事务回滚。
FAULT_HOOKS: dict[str, bool] = {}


class DomainError(Exception):
    """业务失败，携带 HTTP 状态码与中文口径说明。"""

    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def now_ts() -> str:
    return datetime.now().isoformat(timespec="seconds")


class BridgeConn(sqlite3.Connection):
    """携带每连接改键门闩令牌的连接（C 基类无 __dict__，必须子类化）。"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.rewrite_token: int | None = None


def connect():
    DATA.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10, factory=BridgeConn)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=8000")
    return conn


def arm_audit(conn):
    """同事务内挂枪：允许改键，但必须与 key_change_audit 写入同生共死。

    先制造一个本连接私有的 last_insert_rowid() 凭据写入门闩；该值按连接私有，
    其它连接的裸 UPDATE 无法知道期望值，守卫触发器据此拦截无审计改键。
    """
    cur = conn.execute(
        "INSERT INTO sys_config(k,v) VALUES ('_gate_seed_'||hex(randomblob(8)),'1')")
    conn.execute("DELETE FROM sys_config WHERE k LIKE '_gate_seed_%'")
    conn.rewrite_token = cur.lastrowid
    conn.execute("UPDATE rewrite_gate SET token=? WHERE id=1", (conn.rewrite_token,))


def disarm_audit(conn):
    conn.execute("UPDATE rewrite_gate SET token=NULL WHERE id=1 AND token=?",
                 (conn.rewrite_token,))
    conn.rewrite_token = None


@contextmanager
def write_tx(conn):
    """BEGIN IMMEDIATE 串行化写事务；失败整体回滚，并保证守卫退枪。"""
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        disarm_audit(conn)


def sha(p: str) -> str:
    return hashlib.sha256(p.encode("utf-8")).hexdigest()


def ensure_users(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY, password_sha TEXT NOT NULL, role TEXT NOT NULL)""")
    if conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] == 0:
        conn.execute("INSERT INTO users VALUES (?,?,?)", ("admin", sha("123456"), "管理员"))
        conn.execute("INSERT INTO users VALUES (?,?,?)", ("viewer", sha("view123"), "只读"))


SCHEMA = """
CREATE TABLE IF NOT EXISTS map_versions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  version TEXT UNIQUE NOT NULL,
  status TEXT NOT NULL,
  effective_from TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS mappings(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  version TEXT NOT NULL,
  old_key TEXT NOT NULL,
  new_key TEXT NOT NULL,
  kind TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS formal_entities(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  entity_key TEXT NOT NULL,
  mapped_from TEXT NOT NULL,
  version TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS conflicts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  old_key TEXT NOT NULL,
  reason TEXT NOT NULL,
  status TEXT NOT NULL
);
-- 落库形态（二选一之第一形态）：独立不可变旧键墓碑表，而非 mappings 行快照列。
CREATE TABLE IF NOT EXISTS sys_config(
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS oldkey_tombstone(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  old_key TEXT NOT NULL UNIQUE,
  tombstone_at TEXT NOT NULL,
  map_version TEXT NOT NULL,
  new_key_at_tombstone TEXT NOT NULL,
  policy TEXT NOT NULL CHECK(policy IN ('readonly_retention','inplace_rewrite')),
  note TEXT
);
-- 甲路径史迹：正式区只追加、不可改的只读世代留痕。
CREATE TABLE IF NOT EXISTS formal_history(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  formal_id INTEGER NOT NULL,
  entity_key TEXT NOT NULL,
  mapped_from TEXT NOT NULL,
  version TEXT NOT NULL,
  event TEXT NOT NULL,
  at TEXT NOT NULL
);
-- 乙路径改键审计世代：每次就地改正式键必须同事务落一行。
CREATE TABLE IF NOT EXISTS key_change_audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  generation INTEGER NOT NULL,
  formal_id INTEGER NOT NULL,
  old_key_ref TEXT NOT NULL,
  from_entity_key TEXT NOT NULL,
  to_entity_key TEXT NOT NULL,
  map_version TEXT NOT NULL,
  tombstone_id INTEGER NOT NULL REFERENCES oldkey_tombstone(id),
  changed_at TEXT NOT NULL
);
-- 只读口径下墓碑后再映的拒进留痕（核证卡取证用）。
CREATE TABLE IF NOT EXISTS tombstone_violations(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  old_key TEXT NOT NULL,
  policy TEXT NOT NULL,
  detail TEXT NOT NULL,
  at TEXT NOT NULL
);
-- 改键门闩：单行。仅 entomb_old_key 乙路径在同事务内挂本连接令牌；
-- 行本身受触发器保护，绕过服务函数直接 UPDATE 门闩会被 ABORT。
CREATE TABLE IF NOT EXISTS rewrite_gate(
  id INTEGER PRIMARY KEY CHECK(id=1),
  token INTEGER
);
INSERT OR IGNORE INTO rewrite_gate(id,token) VALUES (1,NULL);
CREATE TRIGGER IF NOT EXISTS trg_gate_no_delete
BEFORE DELETE ON rewrite_gate
BEGIN
  SELECT RAISE(ABORT, '改键门闩单行不可删');
END;
-- 墓碑物化后不可变：禁止改写、禁止抹掉（版级追溯不得断裂）。
CREATE TRIGGER IF NOT EXISTS trg_tombstone_no_update
BEFORE UPDATE ON oldkey_tombstone
BEGIN
  SELECT RAISE(ABORT, '墓碑表不可变：禁止 UPDATE 旧键墓碑');
END;
CREATE TRIGGER IF NOT EXISTS trg_tombstone_no_delete
BEFORE DELETE ON oldkey_tombstone
BEGIN
  SELECT RAISE(ABORT, '墓碑表不可变：禁止 DELETE 抹除墓碑');
END;
-- 史迹只追加。
CREATE TRIGGER IF NOT EXISTS trg_history_no_update
BEFORE UPDATE ON formal_history
BEGIN
  SELECT RAISE(ABORT, '正式史迹只追加：禁止 UPDATE');
END;
CREATE TRIGGER IF NOT EXISTS trg_history_no_delete
BEFORE DELETE ON formal_history
BEGIN
  SELECT RAISE(ABORT, '正式史迹只追加：禁止 DELETE');
END;
-- 改键审计世代只追加。
CREATE TRIGGER IF NOT EXISTS trg_audit_no_update
BEFORE UPDATE ON key_change_audit
BEGIN
  SELECT RAISE(ABORT, '改键审计只追加：禁止 UPDATE');
END;
CREATE TRIGGER IF NOT EXISTS trg_audit_no_delete
BEFORE DELETE ON key_change_audit
BEGIN
  SELECT RAISE(ABORT, '改键审计只追加：禁止 DELETE');
END;
-- 硬约束：禁止墓碑后无审计就地改键。
-- 仅当当前连接在同一事务内 arm_audit() 挂出本连接凭据（即承诺同事务写审计世代）时放行。
-- last_insert_rowid() 按连接私有：别的连接或裸 SQL 无法知道门闩期望值。
CREATE TRIGGER IF NOT EXISTS trg_formal_key_guard_update
BEFORE UPDATE OF entity_key ON formal_entities
FOR EACH ROW
WHEN NEW.entity_key IS NOT OLD.entity_key
BEGIN
  SELECT CASE
    WHEN (SELECT token FROM rewrite_gate WHERE id=1) IS NULL
      OR (SELECT token FROM rewrite_gate WHERE id=1) <> last_insert_rowid()
    THEN RAISE(ABORT, '禁止墓碑后无审计就地改键：须同事务写 key_change_audit 世代')
  END;
END;
"""


def get_policy(conn) -> str:
    row = conn.execute("SELECT v FROM sys_config WHERE k='tombstone_policy'").fetchone()
    return row["v"] if row else DEFAULT_POLICY


def init_db(policy: str | None = None):
    if policy is not None and policy not in POLICIES:
        raise RuntimeError(f"未知正确性口径: {policy}")
    with connect() as conn:
        ensure_users(conn)
        conn.executescript(SCHEMA)
        existing = conn.execute("SELECT v FROM sys_config WHERE k='tombstone_policy'").fetchone()
        if existing is None:
            conn.execute("INSERT INTO sys_config(k,v) VALUES ('tombstone_policy', ?)",
                         (policy or DEFAULT_POLICY,))
        elif policy is not None and existing["v"] != policy:
            n = conn.execute("SELECT COUNT(*) c FROM oldkey_tombstone").fetchone()["c"]
            if n:
                raise RuntimeError(
                    f"已有 {n} 座墓碑按 {existing['v']} 口径物化，正确性口径不得分叉")
            conn.execute("UPDATE sys_config SET v=? WHERE k='tombstone_policy'", (policy,))
        if conn.execute("SELECT COUNT(*) c FROM map_versions").fetchone()["c"] == 0:
            conn.execute("INSERT INTO map_versions(version,status,effective_from) VALUES (?,?,?)",
                         ("m-2026.11", "生效", "2026-11-01"))
            conn.executemany(
                "INSERT INTO mappings(version,old_key,new_key,kind) VALUES (?,?,?,?)", [
                    ("m-2026.11", "OLD-A1", "NEW-100", "一对一"),
                    ("m-2026.11", "OLD-B1", "NEW-200", "多对一"),
                    ("m-2026.11", "OLD-B2", "NEW-200", "多对一"),
                ])
            conn.execute(
                "INSERT INTO formal_entities(entity_key,mapped_from,version,created_at) VALUES (?,?,?,?)",
                ("NEW-100", "OLD-A1", "m-2026.11", "2026-11-10T09:00:00"))
            conn.execute("INSERT INTO conflicts(old_key,reason,status) VALUES (?,?,?)",
                         ("OLD-C9", "无映射", "挂起"))


def active_version(conn):
    return conn.execute(
        "SELECT version FROM map_versions WHERE status='生效' ORDER BY id DESC LIMIT 1"
    ).fetchone()


def entomb_old_key(conn, old_key: str, note: str | None = None) -> dict:
    """废弃旧键物化处置。按全局口径走甲或乙，全程同一写事务，失败整体回滚。"""
    at = now_ts()
    with write_tx(conn):
        policy = get_policy(conn)
        ver = active_version(conn)
        if not ver:
            raise DomainError(404, "无生效映射版本，无法立碑")
        m = conn.execute(
            "SELECT * FROM mappings WHERE version=? AND old_key=?",
            (ver["version"], old_key)).fetchone()
        if not m:
            raise DomainError(404, f"旧键 {old_key} 不在生效映射册，不可立碑")
        if conn.execute("SELECT 1 FROM oldkey_tombstone WHERE old_key=?", (old_key,)).fetchone():
            raise DomainError(409, f"旧键 {old_key} 已存在墓碑，墓碑不可变、不可重立")

        cur = conn.execute(
            """INSERT INTO oldkey_tombstone
               (old_key,tombstone_at,map_version,new_key_at_tombstone,policy,note)
               VALUES (?,?,?,?,?,?)""",
            (old_key, at, ver["version"], m["new_key"], policy, note))
        tomb_id = cur.lastrowid
        formal_rows = conn.execute(
            "SELECT id,entity_key,mapped_from,version FROM formal_entities WHERE mapped_from=? ORDER BY id",
            (old_key,)).fetchall()

        if policy == POLICY_READONLY:
            # 甲路径：正式行保持原新键，只追加只读史迹；墓碑与史迹同事务。
            for r in formal_rows:
                conn.execute(
                    """INSERT INTO formal_history(formal_id,entity_key,mapped_from,version,event,at)
                       VALUES (?,?,?,?,'tombstone_snapshot',?)""",
                    (r["id"], r["entity_key"], r["mapped_from"], r["version"], at))
            if FAULT_HOOKS.get("entomb_after_history"):
                raise RuntimeError("injected fault: readonly entomb before commit")
            return {
                "tombstone_id": tomb_id, "old_key": old_key, "policy": policy,
                "map_version": ver["version"], "tombstone_at": at,
                "formal_unchanged": len(formal_rows),
                "history_appended": len(formal_rows),
            }

        # 乙路径：按新映射就地改写正式实体键，同事务写改键审计世代。
        # 两阶段：先完成全部正式键 UPDATE（此期间本连接 last_insert_rowid 保持门闩凭据），
        # 再统一写审计世代——审计 INSERT 会推进 rowid，故不得与改键 UPDATE 交错。
        arm_audit(conn)
        try:
            targets: list[tuple[int, str]] = []
            for r in formal_rows:
                if r["entity_key"] != m["new_key"]:
                    conn.execute(
                        "UPDATE formal_entities SET entity_key=? WHERE id=?",
                        (m["new_key"], r["id"]))
                targets.append((r["id"], r["entity_key"]))
            for generation, (formal_id, from_key) in enumerate(targets, start=1):
                conn.execute(
                    """INSERT INTO key_change_audit
                       (generation,formal_id,old_key_ref,from_entity_key,to_entity_key,
                        map_version,tombstone_id,changed_at)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    (generation, formal_id, old_key, from_key, m["new_key"],
                     ver["version"], tomb_id, at))
            if FAULT_HOOKS.get("entomb_after_update"):
                raise RuntimeError("injected fault: rewrite entomb before commit")
        finally:
            disarm_audit(conn)
        return {
            "tombstone_id": tomb_id, "old_key": old_key, "policy": policy,
            "map_version": ver["version"], "tombstone_at": at,
            "formal_rewritten": len(formal_rows),
            "audit_generations": len(formal_rows),
        }


def remap_ingress(conn, old_key: str) -> dict:
    """入站重映。只读口径下墓碑旧键拒进且正式不变；改写口径下仍可再映为新行。"""
    policy = get_policy(conn)
    at = now_ts()
    try:
        # IMMEDIATE 与立碑事务互斥，闭合“并发后到”与 TOCTOU 窗口。
        conn.execute("BEGIN IMMEDIATE")
        ver = active_version(conn)
        if not ver:
            conn.commit()
            raise DomainError(404, "无生效映射版本")
        m = conn.execute(
            "SELECT * FROM mappings WHERE version=? AND old_key=?",
            (ver["version"], old_key)).fetchone()
        if not m:
            conn.execute(
                "INSERT INTO conflicts(old_key,reason,status) VALUES (?,?,?)",
                (old_key, "无映射", "挂起"))
            conn.commit()
            raise DomainError(409, "无映射，已进冲突队列")

        tomb = conn.execute(
            "SELECT id FROM oldkey_tombstone WHERE old_key=?", (old_key,)).fetchone()
        if tomb and policy == POLICY_READONLY:
            # 甲路径硬约束：只读架构下废弃旧键不得重映成功进正式区。
            conn.execute(
                "INSERT INTO tombstone_violations(old_key,policy,detail,at) VALUES (?,?,?,?)",
                (old_key, policy, f"墓碑后再映被拒（墓碑 #{tomb['id']}），正式区不变", at))
            conn.commit()
            raise DomainError(410, f"旧键 {old_key} 已废弃立碑（只读保留），拒绝再映，正式区不变")

        cur = conn.execute(
            "INSERT INTO formal_entities(entity_key,mapped_from,version,created_at) VALUES (?,?,?,?)",
            (m["new_key"], old_key, ver["version"], at))
        formal_id = cur.lastrowid
        conn.execute(
            """INSERT INTO formal_history(formal_id,entity_key,mapped_from,version,event,at)
               VALUES (?,?,?,?,'ingress_remap',?)""",
            (formal_id, m["new_key"], old_key, ver["version"], at))
        conn.commit()
        return {
            "entity_key": m["new_key"], "version": ver["version"],
            "formal_id": formal_id, "tombstoned": bool(tomb),
        }
    except DomainError:
        raise
    except Exception:
        conn.rollback()
        raise


def set_global_policy(conn, new_policy: str) -> dict:
    if new_policy not in POLICIES:
        raise DomainError(400, f"未知口径，须为 {POLICIES} 之一")
    with write_tx(conn):
        current = get_policy(conn)
        n = conn.execute("SELECT COUNT(*) c FROM oldkey_tombstone").fetchone()["c"]
        if n and current != new_policy:
            raise DomainError(
                409, f"已有 {n} 座墓碑按 {current} 口径物化，全局正确性口径禁止分叉")
        conn.execute(
            "INSERT INTO sys_config(k,v) VALUES ('tombstone_policy',?) "
            "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (new_policy,))
        return {"policy": new_policy, "label": POLICY_LABELS[new_policy], "tombstones": n}


def verification_report(conn) -> dict:
    """墓碑策略核证只读接口：映射册、墓碑表、正式区、改键审计、互证卡协同对账。"""
    policy = get_policy(conn)
    checks: list[dict] = []

    def add(name: str, ok: bool, detail: str):
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    tombs = conn.execute("SELECT * FROM oldkey_tombstone ORDER BY id").fetchall()
    tomb_policies = {t["policy"] for t in tombs}
    add("全局口径唯一且墓碑未分叉",
        len(tomb_policies) <= 1 and all(p == policy for p in tomb_policies),
        f"当前口径={policy}；墓碑口径集合={sorted(tomb_policies) or '空'}")

    triggers = {r["name"] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='trigger'").fetchall()}
    add("不可变/改键守卫触发器在位",
        {"trg_tombstone_no_update", "trg_tombstone_no_delete",
         "trg_formal_key_guard_update"} <= triggers,
        "墓碑禁改禁删、正式键无审计禁改均由库级触发器强制")

    for t in tombs:
        m = conn.execute(
            "SELECT * FROM mappings WHERE version=? AND old_key=?",
            (t["map_version"], t["old_key"])).fetchone()
        add(f"墓碑 #{t['id']} {t['old_key']} ↔ 映射册互证",
            m is not None and m["new_key"] == t["new_key_at_tombstone"]
            and t["policy"] == policy,
            f"碑载新键={t['old_key']}→{t['new_key_at_tombstone']}@{t['map_version']}，"
            f"册载={'缺失' if not m else m['new_key']}")

        formal_rows = conn.execute(
            "SELECT id,entity_key FROM formal_entities WHERE mapped_from=? ORDER BY id",
            (t["old_key"],)).fetchall()

        if policy == POLICY_READONLY:
            # 甲：正式行键必须仍是碑载原新键；每一行都有同碑快照史迹可对。
            unchanged = all(r["entity_key"] == t["new_key_at_tombstone"] for r in formal_rows)
            snaps = conn.execute(
                """SELECT h.formal_id, h.entity_key FROM formal_history h
                   WHERE h.mapped_from=? AND h.event='tombstone_snapshot'""",
                (t["old_key"],)).fetchall()
            snap_map = {s["formal_id"]: s["entity_key"] for s in snaps}
            traced = all(snap_map.get(r["id"]) == r["entity_key"] for r in formal_rows)
            add(f"墓碑 #{t['id']} 正式区只读未改写且史迹可追溯",
                unchanged and traced and len(snaps) >= len(formal_rows),
                f"正式行 {len(formal_rows)} 条，碑刻快照史迹 {len(snaps)} 条")
        else:
            # 乙：正式行键必须已是当前映射新键；每行均有同碑审计世代，世代连续。
            m_now = conn.execute(
                "SELECT new_key FROM mappings WHERE version=? AND old_key=?",
                (t["map_version"], t["old_key"])).fetchone()
            target = m_now["new_key"] if m_now else t["new_key_at_tombstone"]
            rewritten = all(r["entity_key"] == target for r in formal_rows)
            audits = conn.execute(
                "SELECT * FROM key_change_audit WHERE tombstone_id=? ORDER BY generation",
                (t["id"],)).fetchall()
            gens = [a["generation"] for a in audits]
            chain_ok = (
                len(audits) == len(formal_rows)
                and gens == list(range(1, len(audits) + 1))
                and all(a["to_entity_key"] == target for a in audits)
                and all(conn.execute(
                    "SELECT 1 FROM formal_entities WHERE id=?",
                    (a["formal_id"],)).fetchone() for a in audits)
            )
            add(f"墓碑 #{t['id']} 正式键已就地改写且审计世代链完整",
                rewritten and chain_ok,
                f"正式行 {len(formal_rows)} 条，审计世代 {gens or '空'}，目标键 {target}")

    if policy == POLICY_READONLY:
        n_audit = conn.execute("SELECT COUNT(*) c FROM key_change_audit").fetchone()["c"]
        add("只读口径下改键审计必须为空（两路不得混用）", n_audit == 0,
            f"key_change_audit 行数={n_audit}")
    else:
        # 乙路径下每条审计都必须能回指一座真实墓碑。
        orphans = conn.execute(
            """SELECT COUNT(*) c FROM key_change_audit a
               LEFT JOIN oldkey_tombstone t ON t.id=a.tombstone_id WHERE t.id IS NULL"""
        ).fetchone()["c"]
        add("改写口径下审计世代全部回指墓碑", orphans == 0, f"孤儿审计行数={orphans}")

    counts = {
        "tombstones": len(tombs),
        "formal": conn.execute("SELECT COUNT(*) c FROM formal_entities").fetchone()["c"],
        "history": conn.execute("SELECT COUNT(*) c FROM formal_history").fetchone()["c"],
        "audits": conn.execute("SELECT COUNT(*) c FROM key_change_audit").fetchone()["c"],
        "violations": conn.execute("SELECT COUNT(*) c FROM tombstone_violations").fetchone()["c"],
    }
    return {
        "policy": policy, "policy_label": POLICY_LABELS[policy],
        "ok": all(c["ok"] for c in checks), "checks": checks, "counts": counts,
    }


# ---------------- HTTP 层 ----------------

PRODUCT = "实体键桥"
SKELETON = "实体键映射生效后入站先重映再进正式区，冲突进队列，映射版本与正式区对账"

app = FastAPI(title=PRODUCT)
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"])


@app.exception_handler(DomainError)
async def _domain_handler(_: Request, exc: DomainError):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.on_event("startup")
def _startup():
    init_db(policy=os.environ.get("KEYREMAP_POLICY"))


class LoginIn(BaseModel):
    username: str
    password: str


class RemapIn(BaseModel):
    old_key: str


class TombstoneIn(BaseModel):
    old_key: str
    note: str | None = None


class PolicyIn(BaseModel):
    policy: str


def require_user(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "未登录")
    u = SESSIONS.get(authorization.removeprefix("Bearer ").strip())
    if not u:
        raise HTTPException(401, "登录已失效")
    return u


def require_admin(authorization: str | None) -> str:
    u = require_user(authorization)
    with connect() as c:
        row = c.execute("SELECT role FROM users WHERE username=?", (u,)).fetchone()
    if not row or row["role"] != "管理员":
        raise HTTPException(403, "仅管理员可立碑或切换正确性口径")
    return u


@app.get("/api/health")
def health():
    with connect() as c:
        n = c.execute("SELECT COUNT(*) c FROM mappings").fetchone()["c"]
        t = c.execute("SELECT COUNT(*) c FROM oldkey_tombstone").fetchone()["c"]
        p = get_policy(c)
    return {"ok": True, "product": PRODUCT, "skeleton": SKELETON,
            "mappings": n, "tombstones": t, "policy": p,
            "policy_label": POLICY_LABELS[p], "db": str(DB_PATH)}


@app.post("/api/login")
def login(body: LoginIn):
    with connect() as c:
        row = c.execute(
            "SELECT username,role FROM users WHERE username=? AND password_sha=?",
            (body.username, sha(body.password))).fetchone()
    if not row:
        raise HTTPException(401, "账号或密码错误")
    tok = secrets.token_hex(16)
    SESSIONS[tok] = row["username"]
    return {"token": tok, "username": row["username"], "role": row["role"]}


@app.get("/api/map-versions")
def versions(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        return {"items": [dict(r) for r in c.execute(
            "SELECT * FROM map_versions ORDER BY id").fetchall()]}


@app.get("/api/mappings")
def mappings(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        return {"items": [dict(r) for r in c.execute(
            "SELECT * FROM mappings ORDER BY id").fetchall()]}


@app.post("/api/remap")
def remap(body: RemapIn, authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        return remap_ingress(c, body.old_key)


@app.get("/api/formal")
def formal(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        return {"items": [dict(r) for r in c.execute(
            "SELECT * FROM formal_entities ORDER BY id DESC").fetchall()]}


@app.get("/api/conflicts")
def conflicts(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        return {"items": [dict(r) for r in c.execute(
            "SELECT * FROM conflicts ORDER BY id DESC").fetchall()]}


@app.get("/api/policy")
def policy_api(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        p = get_policy(c)
        n = c.execute("SELECT COUNT(*) c FROM oldkey_tombstone").fetchone()["c"]
    return {"policy": p, "label": POLICY_LABELS[p],
            "options": [{"policy": k, "label": v} for k, v in POLICY_LABELS.items()],
            "tombstones": n, "locked": n > 0}


@app.put("/api/policy")
def policy_put(body: PolicyIn, authorization: str | None = Header(default=None)):
    require_admin(authorization)
    with connect() as c:
        return set_global_policy(c, body.policy)


@app.post("/api/tombstone")
def tombstone_put(body: TombstoneIn, authorization: str | None = Header(default=None)):
    require_admin(authorization)
    with connect() as c:
        return entomb_old_key(c, body.old_key, body.note)


@app.get("/api/tombstones")
def tombstones_api(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        return {"items": [dict(r) for r in c.execute(
            "SELECT * FROM oldkey_tombstone ORDER BY id DESC").fetchall()]}


@app.get("/api/formal-history")
def formal_history_api(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        return {"items": [dict(r) for r in c.execute(
            "SELECT * FROM formal_history ORDER BY id DESC").fetchall()]}


@app.get("/api/key-change-audits")
def audits_api(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        return {"items": [dict(r) for r in c.execute(
            "SELECT * FROM key_change_audit ORDER BY id DESC").fetchall()]}


@app.get("/api/violations")
def violations_api(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        return {"items": [dict(r) for r in c.execute(
            "SELECT * FROM tombstone_violations ORDER BY id DESC").fetchall()]}


@app.get("/api/tombstone-verification")
def verification_api(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        return verification_report(c)


@app.get("/")
def index():
    return FileResponse(FRONTEND / "index.html")


app.mount("/static", StaticFiles(directory=str(FRONTEND)), name="static")
