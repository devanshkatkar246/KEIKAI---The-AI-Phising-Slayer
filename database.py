import sqlite3
import json
import os
from pathlib import Path
from typing import Dict, Any, List, Optional

DB_PATH = Path(os.getenv("DATABASE_PATH", "./brand_protection.db")).resolve()
DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def get_db_connection():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Initializes SQLite database schema for fingerprint store and case timeline event logs.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_type TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            ip_address TEXT,
            registrar TEXT,
            phash TEXT,
            dhash TEXT,
            target_brand TEXT,
            confidence REAL,
            intent_label TEXT,
            intent_confidence REAL,
            investigation_id TEXT,
            organisation_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            metadata_json TEXT
        )
    """)

    # Check for migration if columns do not exist in existing table
    cursor.execute("PRAGMA table_info(assets)")
    columns = [row["name"] for row in cursor.fetchall()]
    if "intent_label" not in columns:
        cursor.execute("ALTER TABLE assets ADD COLUMN intent_label TEXT")
    if "intent_confidence" not in columns:
        cursor.execute("ALTER TABLE assets ADD COLUMN intent_confidence REAL")
    if "investigation_id" not in columns:
        cursor.execute("ALTER TABLE assets ADD COLUMN investigation_id TEXT")
    if "organisation_id" not in columns:
        cursor.execute("ALTER TABLE assets ADD COLUMN organisation_id TEXT")
    if "sources_json" not in columns:
        cursor.execute("ALTER TABLE assets ADD COLUMN sources_json TEXT")
    if "is_known_phishing" not in columns:
        cursor.execute("ALTER TABLE assets ADD COLUMN is_known_phishing INTEGER DEFAULT 0")
    if "provenance_json" not in columns:
        cursor.execute("ALTER TABLE assets ADD COLUMN provenance_json TEXT")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_asset_id ON assets(asset_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip ON assets(ip_address)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_phash ON assets(phash)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_brand ON assets(target_brand)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_investigation ON assets(investigation_id)")

    # Timeline event audit log table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS case_timeline_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            description TEXT NOT NULL,
            metadata_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_case_events ON case_timeline_events(case_id)")
    # Analyst Feedback & Training Signal Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analyst_feedback (
            feedback_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            analysis_id TEXT,
            original_verdict TEXT,
            analyst_label TEXT NOT NULL,
            reason_category TEXT,
            comment TEXT,
            features_json TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_feedback_case ON analyst_feedback(case_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_feedback_label ON analyst_feedback(analyst_label)")

    # Check for migration in analyst_feedback table
    cursor.execute("PRAGMA table_info(analyst_feedback)")
    feedback_cols = [row["name"] for row in cursor.fetchall()]
    if feedback_cols:
        if "actor_id" not in feedback_cols:
            cursor.execute("ALTER TABLE analyst_feedback ADD COLUMN actor_id TEXT DEFAULT 'analyst'")
        if "actor_role" not in feedback_cols:
            cursor.execute("ALTER TABLE analyst_feedback ADD COLUMN actor_role TEXT DEFAULT 'ANALYST'")
        if "has_conflict" not in feedback_cols:
            cursor.execute("ALTER TABLE analyst_feedback ADD COLUMN has_conflict INTEGER DEFAULT 0")
        if "feedback_schema_version" not in feedback_cols:
            cursor.execute("ALTER TABLE analyst_feedback ADD COLUMN feedback_schema_version TEXT DEFAULT '1.0.0'")
        if "decision_engine_version" not in feedback_cols:
            cursor.execute("ALTER TABLE analyst_feedback ADD COLUMN decision_engine_version TEXT DEFAULT '1.0.0'")
        if "feature_schema_version" not in feedback_cols:
            cursor.execute("ALTER TABLE analyst_feedback ADD COLUMN feature_schema_version TEXT DEFAULT '1.0.0'")

    conn.commit()
    conn.close()

def abuse_execute(sql, values=()):
    init_db(); conn=get_db_connection(); cur=conn.cursor(); cur.execute(sql, values); conn.commit(); conn.close()

def abuse_one(sql, values=()):
    init_db(); conn=get_db_connection(); cur=conn.cursor(); cur.execute(sql, values); row=cur.fetchone(); conn.close(); return dict(row) if row else None


def insert_scanned_asset(
    asset_type: str,
    asset_id: str,
    ip_address: Optional[str] = None,
    registrar: Optional[str] = None,
    phash: Optional[str] = None,
    dhash: Optional[str] = None,
    target_brand: Optional[str] = None,
    confidence: Optional[float] = None,
    intent_label: Optional[str] = None,
    intent_confidence: Optional[float] = None,
    metadata: Optional[Dict[str, Any]] = None,
    investigation_id: Optional[str] = None,
    organisation_id: Optional[str] = None
):
    """
    Inserts or updates a scanned asset fingerprint in SQLite, scoped by investigation_id and organisation_id.
    """
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if investigation_id:
        cursor.execute("SELECT id FROM assets WHERE asset_id = ? AND asset_type = ? AND (investigation_id = ? OR investigation_id IS NULL)", (asset_id, asset_type, investigation_id))
    else:
        cursor.execute("SELECT id FROM assets WHERE asset_id = ? AND asset_type = ?", (asset_id, asset_type))
    row = cursor.fetchone()

    meta_str = json.dumps(metadata or {})

    if row:
        cursor.execute("""
            UPDATE assets SET
                ip_address = COALESCE(?, ip_address),
                registrar = COALESCE(?, registrar),
                phash = COALESCE(?, phash),
                dhash = COALESCE(?, dhash),
                target_brand = COALESCE(?, target_brand),
                confidence = COALESCE(?, confidence),
                intent_label = COALESCE(?, intent_label),
                intent_confidence = COALESCE(?, intent_confidence),
                investigation_id = COALESCE(?, investigation_id),
                organisation_id = COALESCE(?, organisation_id),
                metadata_json = ?
            WHERE id = ?
        """, (ip_address, registrar, phash, dhash, target_brand, confidence, intent_label, intent_confidence, investigation_id, organisation_id, meta_str, row["id"]))
    else:
        cursor.execute("""
            INSERT INTO assets (asset_type, asset_id, ip_address, registrar, phash, dhash, target_brand, confidence, intent_label, intent_confidence, investigation_id, organisation_id, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (asset_type, asset_id, ip_address, registrar, phash, dhash, target_brand, confidence, intent_label, intent_confidence, investigation_id, organisation_id, meta_str))

    conn.commit()
    conn.close()


def fetch_all_assets(investigation_id: Optional[str] = None, organisation_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Fetches recorded asset fingerprints from SQLite.
    If investigation_id is provided, filters strictly to assets belonging to that investigation.
    """
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    if investigation_id and organisation_id:
        cursor.execute("SELECT * FROM assets WHERE investigation_id = ? AND organisation_id = ? ORDER BY id DESC", (investigation_id, organisation_id))
    elif investigation_id:
        cursor.execute("SELECT * FROM assets WHERE investigation_id = ? ORDER BY id DESC", (investigation_id,))
    elif organisation_id:
        cursor.execute("SELECT * FROM assets WHERE organisation_id = ? ORDER BY id DESC", (organisation_id,))
    else:
        cursor.execute("SELECT * FROM assets ORDER BY id DESC")

    rows = cursor.fetchall()
    conn.close()

    results = []
    for r in rows:
        r_keys = r.keys()
        results.append({
            "id": r["id"],
            "asset_type": r["asset_type"],
            "asset_id": r["asset_id"],
            "ip_address": r["ip_address"],
            "registrar": r["registrar"],
            "phash": r["phash"],
            "dhash": r["dhash"],
            "target_brand": r["target_brand"],
            "confidence": r["confidence"],
            "intent_label": r["intent_label"] if "intent_label" in r_keys else None,
            "intent_confidence": r["intent_confidence"] if "intent_confidence" in r_keys else None,
            "investigation_id": r["investigation_id"] if "investigation_id" in r_keys else None,
            "organisation_id": r["organisation_id"] if "organisation_id" in r_keys else None,
            "created_at": r["created_at"],
            "metadata": json.loads(r["metadata_json"] or "{}")
        })
    return results


def log_case_event(case_id: str, event_type: str, description: str, metadata: Optional[Dict[str, Any]] = None):
    """
    Logs an append-only timeline event for a case.
    """
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    meta_str = json.dumps(metadata or {})
    cursor.execute("""
        INSERT INTO case_timeline_events (case_id, event_type, description, metadata_json)
        VALUES (?, ?, ?, ?)
    """, (case_id, event_type, description, meta_str))
    conn.commit()
    conn.close()


def fetch_case_timeline(case_id: str) -> List[Dict[str, Any]]:
    """
    Fetches chronological timeline events for a given case_id.
    """
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM case_timeline_events
        WHERE case_id = ? OR case_id = 'default'
        ORDER BY id ASC
    """, (case_id,))
    rows = cursor.fetchall()
    conn.close()

    events = []
    for r in rows:
        events.append({
            "id": r["id"],
            "case_id": r["case_id"],
            "event_type": r["event_type"],
            "description": r["description"],
            "metadata": json.loads(r["metadata_json"] or "{}"),
            "created_at": r["created_at"]
        })
    return events


def insert_analyst_feedback(
    feedback_id: str,
    case_id: str,
    analysis_id: Optional[str],
    original_verdict: Optional[str],
    analyst_label: str,
    reason_category: Optional[str],
    comment: Optional[str],
    features: Dict[str, Any],
    actor_id: str = "analyst",
    actor_role: str = "ANALYST",
    feedback_schema_version: str = "1.0.0",
    decision_engine_version: str = "1.0.0",
    feature_schema_version: str = "1.0.0"
):
    """
    Inserts a persistent analyst/user feedback decision & training signal snapshot into SQLite.
    Enforces immutability, conflict detection, duplicate poisoning prevention, and schema versioning.
    """
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check for exact duplicate submission within same case/actor/label
    cursor.execute("""
        SELECT feedback_id FROM analyst_feedback 
        WHERE case_id = ? AND actor_id = ? AND analyst_label = ?
    """, (case_id, actor_id, analyst_label))
    if cursor.fetchone():
        conn.close()
        return  # Duplicate submission prevented (poisoning protection)

    # Detect conflicts with existing feedback records for the same case_id
    cursor.execute("SELECT analyst_label FROM analyst_feedback WHERE case_id = ?", (case_id,))
    existing_rows = cursor.fetchall()
    
    positives = {"ANALYST_CONFIRMED_PHISHING", "CONFIRMED_PHISHING", "USER_REPORTED_PHISHING"}
    negatives = {"ANALYST_FALSE_POSITIVE", "FALSE_POSITIVE", "USER_MARKED_SAFE", "ANALYST_CONFIRMED_BENIGN", "BENIGN"}

    is_curr_pos = analyst_label in positives
    is_curr_neg = analyst_label in negatives

    has_conflict = False
    for row in existing_rows:
        prev_label = row["analyst_label"]
        if (is_curr_pos and prev_label in negatives) or (is_curr_neg and prev_label in positives):
            has_conflict = True
            break

    if has_conflict:
        # Mark all existing entries for this case as conflicting
        cursor.execute("UPDATE analyst_feedback SET has_conflict = 1 WHERE case_id = ?", (case_id,))

    features_str = json.dumps(features or {})
    cursor.execute("""
        INSERT INTO analyst_feedback (
            feedback_id, case_id, analysis_id, original_verdict, analyst_label, 
            reason_category, comment, features_json, actor_id, actor_role, 
            has_conflict, feedback_schema_version, decision_engine_version, feature_schema_version
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        feedback_id, case_id, analysis_id, original_verdict, analyst_label,
        reason_category, comment, features_str, actor_id, actor_role,
        1 if has_conflict else 0, feedback_schema_version, decision_engine_version, feature_schema_version
    ))
    conn.commit()
    conn.close()


def fetch_all_analyst_feedback() -> List[Dict[str, Any]]:
    """
    Fetches all persistent analyst feedback records & training signal datasets.
    """
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM analyst_feedback ORDER BY rowid DESC")
    rows = cursor.fetchall()
    conn.close()

    results = []
    for r in rows:
        r_dict = dict(r)
        results.append({
            "feedback_id": r_dict.get("feedback_id"),
            "case_id": r_dict.get("case_id"),
            "analysis_id": r_dict.get("analysis_id"),
            "original_verdict": r_dict.get("original_verdict"),
            "analyst_label": r_dict.get("analyst_label"),
            "reason_category": r_dict.get("reason_category"),
            "comment": r_dict.get("comment"),
            "created_at": r_dict.get("created_at"),
            "actor_id": r_dict.get("actor_id", "analyst"),
            "actor_role": r_dict.get("actor_role", "ANALYST"),
            "has_conflict": bool(r_dict.get("has_conflict", 0)),
            "feedback_schema_version": r_dict.get("feedback_schema_version", "1.0.0"),
            "decision_engine_version": r_dict.get("decision_engine_version", "1.0.0"),
            "feature_schema_version": r_dict.get("feature_schema_version", "1.0.0"),
            "features": json.loads(r_dict.get("features_json") or "{}")
        })
    return results
