import json
import sqlite3
from config import DATABASE

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
 id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL, classification TEXT NOT NULL,
 threat_score REAL NOT NULL, confidence REAL NOT NULL, ssl_status TEXT NOT NULL,
 domain_age TEXT NOT NULL, reputation TEXT NOT NULL, blacklist_status TEXT NOT NULL,
 reasons_json TEXT NOT NULL, recommendations_json TEXT NOT NULL, details_json TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_classification ON scans(classification);
"""

def connect():
    con = sqlite3.connect(DATABASE)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with connect() as con: con.executescript(SCHEMA)

def save_scan(r):
    sql = """INSERT INTO scans(url,classification,threat_score,confidence,ssl_status,domain_age,reputation,
             blacklist_status,reasons_json,recommendations_json,details_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)"""
    values = (r["url"], r["classification"], r["threat_score"], r["confidence"], r["ssl"]["status"],
              r["domain"]["age_display"], r["reputation"], r["blacklist"]["status"], json.dumps(r["reasons"]),
              json.dumps(r["recommendations"]), json.dumps(r))
    with connect() as con:
        cur = con.execute(sql, values)
        return cur.lastrowid

def get_scan(scan_id):
    with connect() as con: row = con.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row: return None
    return {**dict(row), **json.loads(row["details_json"])}

def dashboard_data():
    with connect() as con:
        total = con.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        counts = {r[0]: r[1] for r in con.execute("SELECT classification,COUNT(*) FROM scans GROUP BY classification")}
        recent = [dict(r) for r in con.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 20")]
        avg = con.execute("SELECT COALESCE(AVG(threat_score),0) FROM scans").fetchone()[0]
    return {"total": total, "counts": counts, "recent": recent, "average": round(avg, 1)}

