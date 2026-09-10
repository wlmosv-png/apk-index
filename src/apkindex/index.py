"""apk-index SQLite index layer.

Physical layout is normalised for size/speed, but every logical table named in
the design doc exists -- ``xrefs`` is a VIEW over ``refs`` + ``xref_edges`` so
callers can query it exactly as documented::

    xrefs(caller_method_id, callee_descriptor, kind)

All writes go to CACHE_DIR only.  Index files are named ``<sessionId>.db`` and
are reused idempotently by source sha256.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
from dataclasses import dataclass

from .config import ApkIndexError, ErrorCode, settings, iso

# v4：<clinit> 的 is_constructor 判据修正（旧库里静态初始化器被存成 constructor=1，
# DSL 会生成 constructors{} 去 hook 一个不存在的位置）。旧会话按 INDEX_STALE 重建。
# v6：annotation_item 按现行布局读（visibility 提到最前）；v5 及更早的 args_json 是错位垃圾
SCHEMA_VERSION = 6

KIND_TO_CODE = {
    "invoke-virtual": 1, "invoke-super": 2, "invoke-direct": 3,
    "invoke-static": 4, "invoke-interface": 5, "invoke-dynamic": 6,
    "invoke-polymorphic": 7, "invoke-custom": 8, "const-class": 9,
    "iput": 10, "iget": 11, "sput": 12, "sget": 13, "check-cast": 14,
    "instance-of": 15, "new-instance": 16, "new-array": 17,
}
CODE_TO_KIND = {v: k for k, v in KIND_TO_CODE.items()}

SCHEMA = f"""
PRAGMA user_version = {SCHEMA_VERSION};

CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY, value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dex (
  idx INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  origin TEXT NOT NULL,
  size INTEGER NOT NULL,
  version TEXT,
  source TEXT NOT NULL DEFAULT 'app',      -- app | library | system
  counts_json TEXT
);

CREATE TABLE IF NOT EXISTS classes (
  id INTEGER PRIMARY KEY,
  session_id TEXT NOT NULL,
  dex_idx INTEGER NOT NULL,
  descriptor TEXT NOT NULL,
  simple_name TEXT NOT NULL,
  package TEXT NOT NULL,
  access_flags INTEGER NOT NULL,
  super_descriptor TEXT,
  interfaces_json TEXT NOT NULL DEFAULT '[]',
  source TEXT NOT NULL DEFAULT 'app',      -- app | library | system
  origin_file TEXT,
  kind TEXT NOT NULL DEFAULT 'class',
  source_file TEXT,
  UNIQUE (session_id, descriptor)
);
CREATE INDEX IF NOT EXISTS ix_classes_simple ON classes(simple_name);
CREATE INDEX IF NOT EXISTS ix_classes_pkg    ON classes(package);
CREATE INDEX IF NOT EXISTS ix_classes_super  ON classes(super_descriptor);
CREATE INDEX IF NOT EXISTS ix_classes_source ON classes(source);

CREATE TABLE IF NOT EXISTS methods (
  id INTEGER PRIMARY KEY,
  class_id INTEGER NOT NULL REFERENCES classes(id),
  name TEXT NOT NULL,
  params_descriptor TEXT NOT NULL,
  return_descriptor TEXT NOT NULL,
  access_flags INTEGER NOT NULL,
  is_static INTEGER NOT NULL DEFAULT 0,
  is_constructor INTEGER NOT NULL DEFAULT 0,
  declares_string_refs INTEGER NOT NULL DEFAULT 0,
  param_count INTEGER NOT NULL DEFAULT 0,
  shorty TEXT,
  regs INTEGER, ins_size INTEGER, unit_count INTEGER, partial INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_methods_class ON methods(class_id);
CREATE INDEX IF NOT EXISTS ix_methods_name  ON methods(name);
CREATE UNIQUE INDEX IF NOT EXISTS ux_methods_sig
  ON methods(class_id, name, params_descriptor, return_descriptor);

CREATE TABLE IF NOT EXISTS fields (
  id INTEGER PRIMARY KEY,
  class_id INTEGER NOT NULL REFERENCES classes(id),
  name TEXT NOT NULL,
  type_descriptor TEXT NOT NULL,
  access_flags INTEGER NOT NULL,
  is_static INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_fields_class ON fields(class_id);
CREATE INDEX IF NOT EXISTS ix_fields_name  ON fields(name);
CREATE UNIQUE INDEX IF NOT EXISTS ux_fields_name ON fields(class_id, name);

CREATE TABLE IF NOT EXISTS strings (
  id INTEGER PRIMARY KEY,
  session_id TEXT NOT NULL,
  value TEXT NOT NULL,
  lc TEXT NOT NULL,
  len INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_strings_value ON strings(session_id, value);
CREATE INDEX IF NOT EXISTS ix_strings_lc ON strings(session_id, lc);

CREATE TABLE IF NOT EXISTS string_refs (
  method_id INTEGER NOT NULL REFERENCES methods(id),
  string_id INTEGER NOT NULL REFERENCES strings(id),
  PRIMARY KEY (method_id, string_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS ix_strrefs_str ON string_refs(string_id);

-- callee identity, de-duplicated (kind + full descriptor + parts)
CREATE TABLE IF NOT EXISTS refs (
  id INTEGER PRIMARY KEY,
  kind INTEGER NOT NULL,
  descriptor TEXT NOT NULL,        -- method smali id / field id / type descriptor
  owner TEXT, name TEXT, params TEXT, ret TEXT,
  UNIQUE (kind, descriptor)
);

CREATE TABLE IF NOT EXISTS xref_edges (
  caller_method_id INTEGER NOT NULL REFERENCES methods(id),
  callee_ref INTEGER NOT NULL REFERENCES refs(id),
  hits INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (caller_method_id, callee_ref)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS ix_xref_callee ON xref_edges(callee_ref);

CREATE TABLE IF NOT EXISTS annotations (
  id INTEGER PRIMARY KEY,
  class_id INTEGER NOT NULL REFERENCES classes(id),
  method_id INTEGER,
  descriptor TEXT NOT NULL,
  visibility INTEGER,
  args_json TEXT NOT NULL DEFAULT '{{}}'
);
CREATE INDEX IF NOT EXISTS ix_anno_class  ON annotations(class_id);
CREATE INDEX IF NOT EXISTS ix_anno_desc   ON annotations(descriptor);
CREATE INDEX IF NOT EXISTS ix_anno_method ON annotations(method_id);

CREATE VIEW IF NOT EXISTS xrefs AS
  SELECT e.caller_method_id AS caller_method_id,
         r.descriptor       AS callee_descriptor,
         r.kind             AS kind_code,
         CASE r.kind
           WHEN 1 THEN 'invoke-virtual'
           WHEN 2 THEN 'invoke-super'
           WHEN 3 THEN 'invoke-direct'
           WHEN 4 THEN 'invoke-static'
           WHEN 5 THEN 'invoke-interface'
           WHEN 6 THEN 'invoke-dynamic'
           WHEN 7 THEN 'invoke-polymorphic'
           WHEN 8 THEN 'invoke-custom'
           WHEN 9 THEN 'const-class'
           WHEN 10 THEN 'iput'
           WHEN 11 THEN 'iget'
           WHEN 12 THEN 'sput'
           WHEN 13 THEN 'sget'
           WHEN 14 THEN 'check-cast'
           WHEN 15 THEN 'instance-of'
           WHEN 16 THEN 'new-instance'
           WHEN 17 THEN 'new-array'
           ELSE 'other' END AS kind,
         r.owner AS callee_owner, r.name AS callee_name,
         r.params AS callee_params, r.ret AS callee_ret,
         e.hits  AS hits
  FROM xref_edges e JOIN refs r ON r.id = e.callee_ref;
"""

# refs.kind is the integer code, xrefs.kind the documented text form.

SESSION_KEYS = ("session_id", "kind", "sha256", "pkg", "version_name", "version_code",
                "created_at", "index_ms", "db_path", "backend", "packed", "roots_json",
                "schema_version", "label", "meta_json")


def _heal_if_broken(path: str) -> None:
    """会话库打开前先 quick_check。

    索引期写库用 journal_mode=OFF + synchronous=OFF（大包提速必需），代价是
    中途抛异常会留下"database disk image is malformed"的半截库。而会话按 dex
    内容 sha 去重，坏库会被反复复用 —— 那个包就永远索引不了了。检测到就整个扔掉
    重建，让下一次 load 自愈。
    """
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return
    try:
        probe = sqlite3.connect(path, timeout=5.0)
        try:
            ok = probe.execute("PRAGMA quick_check").fetchone()
        finally:
            probe.close()
        if ok and str(ok[0]).strip().lower() == "ok":
            return
    except sqlite3.Error:
        pass
    for suffix in ("", "-wal", "-shm", "-journal"):
        try:
            os.remove(path + suffix)
        except OSError:
            pass


def _kv(conn, key, value):
    conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)",
                 (key, _san(json.dumps(value, ensure_ascii=False))))


def meta_get(conn, key, default=None):
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    if not row:
        return default
    try:
        return json.loads(row[0])
    except Exception:
        return row[0]


def connect(db_path: str, readonly: bool = False) -> sqlite3.Connection:
    if readonly and os.path.exists(db_path):
        uri = f"file:{db_path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=15.0, check_same_thread=False)
    else:
        conn = sqlite3.connect(db_path, timeout=15.0, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA cache_size=-65536")
    return conn


def init_db(db_path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = connect(db_path)
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def db_path_for(session_id: str) -> str:
    return settings().safe_index_path(session_id)


# ---------------------------------------------------------------- catalog
MAX_ARG_JSON = 4096          # 单条注解 args_json 的总预算
MAX_ARG_STR = 200            # 元素值超过这么多字符就不当可读值存


def _shrink(v, depth: int = 0):
    """注解元素值封顶：可读就留，二进制或超长就换成 长度+sha1 摘要。
    真实注解元素不会是几 KB 的 \x00\x0a 串——那是解析跑偏的症状。"""
    if isinstance(v, str):
        head = v[:64]
        ctrl = sum(1 for ch in head
                   if ord(ch) < 9 or ord(ch) in (11, 12) or 14 <= ord(ch) < 32)
        if len(v) > MAX_ARG_STR or (v and ctrl * 3 > len(head)):
            digest = hashlib.sha1(v.encode("utf-8", "replace")).hexdigest()[:12]
            return {"_blob": len(v), "_sha1": digest}
        return v
    if depth >= 4:
        return {"_depth": True}
    if isinstance(v, (list, tuple)):
        return [_shrink(x, depth + 1) for x in list(v)[:64]]
    if isinstance(v, dict):
        return {str(k)[:64]: _shrink(x, depth + 1) for k, x in list(v.items())[:64]}
    return v


def _clip_args(vals) -> str:
    """args_json 的总闸门：先逐元素封顶，整体还超预算就只留键名与原始长度。"""
    try:
        out = json.dumps(_shrink(vals), ensure_ascii=False, default=str)
    except Exception:
        keys = [str(k)[:64] for k in (vals.keys() if isinstance(vals, dict) else [])][:32]
        return json.dumps({"_unserialisable": True, "keys": keys}, ensure_ascii=False)
    if len(out) > MAX_ARG_JSON:
        keys = [str(k)[:64] for k in (vals.keys() if isinstance(vals, dict) else [])][:32]
        return json.dumps({"_truncated": len(out), "keys": keys}, ensure_ascii=False)
    return out



class Catalog:
    """Tiny registry of sessions; per-session heavy data lives in its own db."""

    def __init__(self, path: str | None = None):
        self.path = path or os.path.join(settings().cache_dir, "catalog.db")
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=15.0,
                                    check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=MEMORY")
        self.conn.execute("""
          CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            sha256 TEXT NOT NULL,
            kind TEXT NOT NULL,
            label TEXT,
            pkg TEXT,
            version_name TEXT,
            version_code INTEGER,
            db_path TEXT NOT NULL,
            created_at TEXT,
            updated_at TEXT,
            index_ms REAL,
            backend TEXT,
            packed INTEGER DEFAULT 0,
            sources_json TEXT DEFAULT '[]',
            meta_json TEXT DEFAULT '{}'
          )""")
        self.conn.execute("CREATE INDEX IF NOT EXISTS ix_sessions_sha ON sessions(sha256)")

    def find_by_sha(self, sha: str):
        row = self.conn.execute(
            "SELECT session_id FROM sessions WHERE sha256=? LIMIT 1", (sha,)).fetchone()
        return row[0] if row else None

    def find_by_id(self, session_id: str):
        row = self.conn.execute(
            "SELECT * FROM sessions WHERE session_id=?", (session_id,)).fetchone()
        if not row:
            return None
        cols = [d[0] for d in self.conn.execute(
            "SELECT * FROM sessions LIMIT 0").description]
        out = dict(zip(cols, row))
        # expose both snake_case and camelCase aliases: loaders read a handful
        # of fields and the public contract is camelCase.
        for k, v in list(out.items()):
            if "_" in k:
                cc = re.sub(r"_(\w)", lambda m: m.group(1).upper(), k)
                out.setdefault(cc, v)
        try:
            out.setdefault("sources", json.loads(out.get("sources_json") or "[]"))
        except Exception:
            out.setdefault("sources", [])
        return out

    def upsert(self, **kw):
        kw.setdefault("created_at", iso())
        kw["updated_at"] = iso()
        for k, v in list(kw.items()):
            if isinstance(v, str):
                kw[k] = _san(v)
        cols = list(kw)
        placeholders = ",".join("?" * len(cols))
        conflict = ",".join(f"{c}=excluded.{c}" for c in cols if c != "session_id")
        self.conn.execute(
            f"INSERT INTO sessions ({','.join(cols)}) VALUES ({placeholders}) "
            f"ON CONFLICT(session_id) DO UPDATE SET {conflict}",
            [kw[c] for c in cols])
        self.conn.commit()

    def list(self):
        cur = self.conn.execute(
            "SELECT session_id, sha256, kind, label, pkg, version_name, version_code,"
            " db_path, created_at, index_ms, backend, packed, sources_json "
            "FROM sessions ORDER BY created_at DESC")
        out = []
        for r in cur.fetchall():
            d = dict(zip(["sessionId", "sha256", "kind", "label", "pkg",
                          "versionName", "versionCode", "dbPath", "createdAt",
                          "indexMs", "backend", "packed", "sources"], r))
            try:
                d["sources"] = json.loads(d.get("sources") or "[]")
            except Exception:
                d["sources"] = []
            d["packed"] = bool(d.get("packed"))
            out.append(d)
        return out

    def delete(self, session_id: str):
        self.conn.execute("DELETE FROM sessions WHERE session_id=?", (session_id,))
        self.conn.commit()

    def close(self):
        self.conn.close()


_CAT: Catalog | None = None


def catalog() -> Catalog:
    global _CAT
    if _CAT is None:
        _CAT = Catalog()
    return _CAT


# ------------------------------------------------------------ index writer
@dataclass
class BuildTotals:
    classes: int = 0
    methods: int = 0
    fields: int = 0
    strings: int = 0
    xrefs: int = 0
    string_refs: int = 0
    annotations: int = 0
    dexes: int = 0
    duplicates: int = 0


def _san(s):
    """dex 用 mUTF-8，代理对可能落成正则意义上的 lone surrogate，
    这类字符串无法写进 sqlite（UnicodeEncodeError: surrogates not allowed）。
    统一用 utf-8/replace 往返一次，把不可编码码位换成 U+FFFD，保证索引不中断。
    非字符串（refs 表里 owner/name/params 可为 NULL）原样返回。"""
    if not isinstance(s, str):
        return s
    try:
        s.encode("utf-8")
        return s
    except UnicodeEncodeError:
        # 先 surrogatepass 保字节，再按 utf-8 解码：非法/断对的代理位会变成标准 U+FFFD，
        # 而不是 encode(errors="replace") 留下的 '?'（那个和原文里的问号混淆）。
        return s.encode("utf-8", "surrogatepass").decode("utf-8", "replace")


class IndexWriter:
    """Turns backend-independent DexFileData records into SQLite rows."""

    def __init__(self, session_id: str, backend: str = "builtin"):
        self.session_id = session_id
        self.backend = backend
        self.db_path = db_path_for(session_id)
        self.t0 = time.time()
        _heal_if_broken(self.db_path)   # journal=OFF 提速的代价：半截崩溃会留下坏库
        self.conn = init_db(self.db_path)
        self.conn.execute("PRAGMA journal_mode=OFF")
        self.conn.execute("PRAGMA synchronous=OFF")
        self.totals = BuildTotals()
        self._string_ids: dict[str, int] = {}
        self._ref_ids: dict[tuple, int] = {}
        self._next_string = self._max_id("strings")
        self._next_ref = self._max_id("refs")
        self._load_existing_strings()

    def _max_id(self, table: str) -> int:
        r = self.conn.execute(f"SELECT COALESCE(MAX(id),0) FROM {table}").fetchone()
        return int(r[0] or 0)

    def _load_existing_strings(self):
        for sid, val in self.conn.execute("SELECT id, value FROM strings"):
            self._string_ids[val] = sid

    # ------------------------------------------------------------- dex rows
    def add_dex(self, dex_idx: int, dd, source: str, origin: str) -> dict:
        conn = self.conn
        conn.execute(
            "INSERT OR REPLACE INTO dex(idx,name,origin,size,version,source,counts_json)"
            " VALUES(?,?,?,?,?,?,?)",
            (dex_idx, _san(dd.name), _san(origin), dd.size_bytes, dd.version,
             _san(source), _san(json.dumps(dd.counts, ensure_ascii=False))))
        self.totals.dexes += 1
        cls_rows, meth_rows, field_rows = [], [], []
        sref_rows, xref_rows, anno_rows = [], [], []
        desc_to_id: dict[str, int] = {}
        new_strings: list[str] = []
        for s in dd.strings:
            if s not in self._string_ids:
                self._string_ids[s] = None
                new_strings.append(s)
        base_s = self._next_string
        for i, s in enumerate(new_strings):
            self._string_ids[s] = base_s + i
        self._next_string += len(new_strings)
        self.totals.strings += len(new_strings)
        if new_strings:
            conn.executemany(
                "INSERT OR IGNORE INTO strings(id,session_id,value,lc,len) VALUES(?,?,?,?,?)",
                [(base_s + i, self.session_id, _san(s), _san(s).lower(), len(_san(s)))
                 for i, s in enumerate(new_strings)])

        cid = self.conn.execute(
            "SELECT COALESCE(MAX(id),0) FROM classes").fetchone()[0]
        mid = self.conn.execute(
            "SELECT COALESCE(MAX(id),0) FROM methods").fetchone()[0]
        fid = self.conn.execute(
            "SELECT COALESCE(MAX(id),0) FROM fields").fetchone()[0]
        aid = self.conn.execute(
            "SELECT COALESCE(MAX(id),0) FROM annotations").fetchone()[0]
        from .dex import ACC_STATIC, ACC_INTERFACE, ACC_ANNOTATION, ACC_ENUM, ACC_ABSTRACT

        def cls_kind(acc):
            if acc & ACC_INTERFACE:
                return "interface"
            if acc & ACC_ANNOTATION:
                return "annotation"
            if acc & ACC_ENUM:
                return "enum"
            if acc & ACC_ABSTRACT:
                return "abstract"
            return "class"

        sig_seen: set[tuple] = set()
        for c in dd.classes:
            cid += 1
            desc_to_id[c.descriptor] = cid
            cls_rows.append((cid, self.session_id, dex_idx, c.descriptor,
                             c.simple_name, c.package, c.access,
                             c.super_descriptor,
                             json.dumps(c.interfaces, ensure_ascii=False),
                             source, origin, cls_kind(c.access), c.source_file))
            for f in c.fields:
                fid += 1
                field_rows.append((fid, cid, f.name, f.type, f.access,
                                   1 if f.static else 0))
            for m in c.methods:
                key = (c.descriptor, m.name, m.params_descriptor, m.returns)
                if key in sig_seen:
                    self.totals.duplicates += 1
                    continue
                sig_seen.add(key)
                mid += 1
                code = m.code
                pd = m.params_descriptor
                has_refs = bool(code and (code.strings or code.calls or
                                          code.reads or code.writes or
                                          code.const_classes))
                meth_rows.append((
                    mid, cid, m.name, pd, m.returns, m.access,
                    1 if m.access & ACC_STATIC else 0,
                    1 if m.is_constructor else 0,
                    1 if has_refs else 0,
                    len(m.params), m.shorty,
                    code.registers if code else None,
                    code.ins_size if code else None,
                    code.unit_count if code else 0,
                    1 if (code and code.partial) else 0))
                if code:
                    for s in set(code.strings):
                        sid_ = self._string_ids.get(s)
                        if sid_:
                            sref_rows.append((mid, sid_))
                    for call in code.calls:
                        xref_rows.append((mid, self._ref_for_call(call)[0]))
                    for owner, nm, typ in code.reads:
                        xref_rows.append(
                            (mid, self._ref_for_field("iget", owner, nm, typ)[0]))
                    for owner, nm, typ in code.writes:
                        xref_rows.append(
                            (mid, self._ref_for_field("iput", owner, nm, typ)[0]))
                    for t in set(code.const_classes):
                        xref_rows.append(
                            (mid, self._ref_for_type("const-class", t)[0]))

            for a in c.annotations:
                aid += 1
                anno_rows.append((aid, cid, None, a.descriptor, a.visibility,
                                  _clip_args(a.values)))
        self._bulk("INSERT OR IGNORE INTO classes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   cls_rows)
        self._bulk("""INSERT OR IGNORE INTO methods
             (id,class_id,name,params_descriptor,return_descriptor,access_flags,
              is_static,is_constructor,declares_string_refs,param_count,shorty,
              regs,ins_size,unit_count,partial)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", meth_rows)
        self._bulk("INSERT OR IGNORE INTO fields VALUES (?,?,?,?,?,?)", field_rows)
        self._bulk("INSERT OR IGNORE INTO string_refs VALUES (?,?)", sref_rows)
        self._bulk("INSERT OR IGNORE INTO xref_edges(caller_method_id,callee_ref) "
                   "VALUES (?,?)", xref_rows)
        self._bulk("""INSERT OR IGNORE INTO annotations
             (id,class_id,method_id,descriptor,visibility,args_json)
             VALUES (?,?,?,?,?,?)""", anno_rows)
        # method-scoped annotations: descriptor rows already carry on_method
        mrows = []
        for c in dd.classes:
            if not c.annotations:
                continue
            cid2 = desc_to_id.get(c.descriptor)
            if not cid2:
                continue
            for a in c.annotations:
                if a.on_method:
                    mrows.append((a.on_method, cid2, a.descriptor, a.visibility,
                                  _clip_args(a.values)))
        for nm, cid2, desc, vis, args in mrows:
            for r in self.conn.execute(
                    "SELECT id FROM methods WHERE class_id=? AND name=?",
                    (cid2, nm)).fetchall():
                self.conn.execute(
                    "INSERT OR IGNORE INTO annotations"
                    "(class_id,method_id,descriptor,visibility,args_json)"
                    " VALUES(?,?,?,?,?)",
                    (cid2, r[0], _san(desc), vis, _san(args)))
                self.totals.annotations += 1

        self.totals.classes += len(cls_rows)
        self.totals.methods += len(meth_rows)
        self.totals.fields += len(field_rows)
        self.totals.string_refs += len(sref_rows)
        self.totals.xrefs += len(xref_rows)
        self.totals.annotations += len(anno_rows)
        conn.commit()
        return {"dex_idx": dex_idx, "classes": len(cls_rows),
                "methods": len(meth_rows), "fields": len(field_rows),
                "newStrings": len(new_strings), "xrefs": len(xref_rows),
                "stringRefs": len(sref_rows), "notes": list(dd.parse_notes)[:5]}

    def _bulk(self, sql, rows):
        if not rows:
            return
        cur = self.conn
        step = 50000
        # 消毒放在咽喉处：dex 的 mUTF-8 可以合法地落下 lone surrogate，
        # 漏一处就整条索引 UnicodeEncodeError 崩掉（曾因 annotations.args_json 踩过）。
        clean = [tuple(_san(v) if isinstance(v, str) else v for v in r) for r in rows]
        for i in range(0, len(clean), step):
            cur.executemany(sql, clean[i:i + step])

    # -------------------------------------------------------- ref interning
    def _ref_id(self, kind: str, descriptor: str, owner=None, name=None,
                params=None, ret=None) -> int:
        key = (KIND_TO_CODE.get(kind, 0), descriptor)
        rid = self._ref_ids.get(key)
        if rid:
            return rid
        rid = self._next_ref
        self._next_ref += 1
        self._ref_ids[key] = rid
        self.conn.execute(
            "INSERT OR IGNORE INTO refs(id,kind,descriptor,owner,name,params,ret)"
            " VALUES(?,?,?,?,?,?,?)",
            (rid, KIND_TO_CODE.get(kind, 0),
             _san(descriptor), _san(owner), _san(name),
             _san(params), _san(ret)))
        return rid

    def _ref_for_call(self, x):
        kind, owner, nm, params, ret = x
        pd = "(" + "".join(params) + ")"
        desc = f"{owner}->{nm}{pd}{ret}"
        return self._ref_id(kind, desc, owner, nm, pd, ret), desc

    def _ref_for_field(self, kind, owner, nm, typ):
        desc = f"{owner}->{nm}:{typ}"
        return self._ref_id(kind, desc, owner, nm, None, typ), desc

    def _ref_for_type(self, kind, t):
        return self._ref_id(kind, t, t, None, None, None), t

    # ------------------------------------------------------------- finalize
    def set_meta(self, mapping: dict):
        for k, v in mapping.items():
            _kv(self.conn, k, v)

    def meta(self, key, default=None):
        return meta_get(self.conn, key, default)

    def vacuum_light(self):
        self.conn.commit()
        try:
            self.conn.execute("PRAGMA optimize")
        except Exception:
            pass

    def close(self):
        self.conn.commit()
        self.conn.close()


# --------------------------------------------------------------- session db
class SessionDB:
    """Read-side handle for an already built session."""

    def __init__(self, session_id: str, row: dict):
        self.session_id = session_id
        self.row = row
        self.db_path = row["dbPath"]
        if not os.path.exists(self.db_path):
            raise ApkIndexError(
                ErrorCode.INDEX_STALE,
                f"索引文件缺失: {self.db_path}",
                "源文件 sha256 未变但索引被删除，重新 loadApk 即可重建。")
        self.conn = connect(self.db_path, readonly=False)
        try:
            self.conn.execute("PRAGMA query_only=ON")
        except Exception:
            pass

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass

    def q(self, sql, params=()):
        cur = self.conn.execute(sql, params)
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    def scalar(self, sql, params=()):
        r = self.conn.execute(sql, params).fetchone()
        return r[0] if r else None

    def counts(self) -> dict:
        def n(table, where=""):
            return int(self.scalar(f"SELECT COUNT(*) FROM {table} {where}") or 0)
        return {
            "dex": n("dex"),
            "classes": n("classes"),
            "methods": n("methods"),
            "fields": n("fields"),
            "strings": n("strings"),
            "stringRefs": n("string_refs"),
            "xrefEdges": n("xref_edges"),
            "refs": n("refs"),
            "annotations": n("annotations"),
        }
