"""
Red Team Database
Stores scan results, attack history, and vulnerability trends
"""

import sqlite3
import json
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional
from dataclasses import asdict

IST = timezone(timedelta(hours=5, minutes=30))

DB_FILE = "redteam_data.db"


def init_redteam_db():
    """Initialize red team database tables."""
    conn = sqlite3.connect(DB_FILE)

    # Scans table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT PRIMARY KEY,
            target_url TEXT NOT NULL,
            provider TEXT,
            model TEXT,
            status TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            total_attacks INTEGER DEFAULT 0,
            completed_attacks INTEGER DEFAULT 0,
            vulnerabilities_found INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            risk_score REAL DEFAULT 0,
            risk_level TEXT,
            summary_json TEXT,
            recommendations_json TEXT,
            created_by TEXT DEFAULT 'system'
        )
    """)

    # Attack results table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS attack_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            attack_id TEXT NOT NULL,
            attack_name TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            prompt TEXT,
            response TEXT,
            response_time_ms INTEGER,
            is_vulnerable BOOLEAN DEFAULT FALSE,
            vulnerability_score REAL DEFAULT 0,
            matched_indicators_json TEXT,
            error TEXT,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
        )
    """)

    # Vulnerability trends table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vulnerability_trends (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            target_url TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            count INTEGER DEFAULT 0,
            UNIQUE(date, target_url, category, severity)
        )
    """)

    # Scheduled scans table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scheduled_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            target_url TEXT NOT NULL,
            provider TEXT,
            model TEXT,
            categories_json TEXT,
            schedule_cron TEXT NOT NULL,
            enabled BOOLEAN DEFAULT TRUE,
            last_run TEXT,
            next_run TEXT,
            created_at TEXT NOT NULL,
            created_by TEXT DEFAULT 'system'
        )
    """)

    # Create indexes
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_url)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_attack_results_scan ON attack_results(scan_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_attack_results_vulnerable ON attack_results(is_vulnerable)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_trends_date ON vulnerability_trends(date)")

    conn.commit()
    conn.close()


class RedTeamDatabase:
    """Database operations for red team module."""

    def __init__(self):
        init_redteam_db()

    def save_scan(self, scan_result) -> bool:
        """Save scan result to database."""
        try:
            conn = sqlite3.connect(DB_FILE)

            # Insert scan record
            conn.execute("""
                INSERT OR REPLACE INTO scans
                (scan_id, target_url, provider, model, status, started_at, completed_at,
                 total_attacks, completed_attacks, vulnerabilities_found,
                 critical_count, high_count, medium_count, low_count,
                 risk_score, risk_level, summary_json, recommendations_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_result.scan_id,
                scan_result.target_url,
                scan_result.provider,
                scan_result.model,
                scan_result.status.value if hasattr(scan_result.status, 'value') else scan_result.status,
                scan_result.started_at,
                scan_result.completed_at,
                scan_result.total_attacks,
                scan_result.completed_attacks,
                scan_result.vulnerabilities_found,
                scan_result.critical_count,
                scan_result.high_count,
                scan_result.medium_count,
                scan_result.low_count,
                scan_result.summary.get("risk_score", 0),
                scan_result.summary.get("risk_level", "UNKNOWN"),
                json.dumps(scan_result.summary),
                json.dumps(scan_result.recommendations)
            ))

            # Insert attack results
            for attack_result in scan_result.attack_results:
                conn.execute("""
                    INSERT INTO attack_results
                    (scan_id, attack_id, attack_name, category, severity, prompt, response,
                     response_time_ms, is_vulnerable, vulnerability_score, matched_indicators_json,
                     error, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_result.scan_id,
                    attack_result.attack_id,
                    attack_result.attack_name,
                    attack_result.category,
                    attack_result.severity,
                    attack_result.prompt,
                    attack_result.response,
                    attack_result.response_time_ms,
                    attack_result.is_vulnerable,
                    attack_result.vulnerability_score,
                    json.dumps(attack_result.matched_indicators),
                    attack_result.error,
                    attack_result.timestamp
                ))

            # Update vulnerability trends
            date_str = datetime.now(IST).strftime("%Y-%m-%d")
            for attack_result in scan_result.attack_results:
                if attack_result.is_vulnerable:
                    conn.execute("""
                        INSERT INTO vulnerability_trends (date, target_url, category, severity, count)
                        VALUES (?, ?, ?, ?, 1)
                        ON CONFLICT(date, target_url, category, severity)
                        DO UPDATE SET count = count + 1
                    """, (date_str, scan_result.target_url, attack_result.category, attack_result.severity))

            conn.commit()
            conn.close()
            return True

        except Exception as e:
            print(f"Error saving scan: {e}")
            return False

    def get_scan(self, scan_id: str) -> Optional[Dict]:
        """Get scan by ID."""
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row

        cursor = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
        row = cursor.fetchone()

        if not row:
            conn.close()
            return None

        scan = dict(row)
        scan["summary"] = json.loads(scan.get("summary_json", "{}"))
        scan["recommendations"] = json.loads(scan.get("recommendations_json", "[]"))

        # Get attack results
        cursor = conn.execute(
            "SELECT * FROM attack_results WHERE scan_id = ? ORDER BY timestamp",
            (scan_id,)
        )
        scan["attack_results"] = [dict(r) for r in cursor.fetchall()]
        for ar in scan["attack_results"]:
            ar["matched_indicators"] = json.loads(ar.get("matched_indicators_json", "[]"))

        conn.close()
        return scan

    def list_scans(self, target_url: str = None, status: str = None,
                   limit: int = 50, offset: int = 0) -> List[Dict]:
        """List scans with optional filters."""
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row

        query = "SELECT * FROM scans WHERE 1=1"
        params = []

        if target_url:
            query += " AND target_url = ?"
            params.append(target_url)

        if status:
            query += " AND status = ?"
            params.append(status)

        query += " ORDER BY started_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor = conn.execute(query, params)
        scans = []
        for row in cursor.fetchall():
            scan = dict(row)
            scan["summary"] = json.loads(scan.get("summary_json", "{}"))
            scans.append(scan)

        conn.close()
        return scans

    def get_vulnerability_trends(self, target_url: str = None, days: int = 30) -> Dict[str, Any]:
        """Get vulnerability trends over time."""
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row

        start_date = (datetime.now(IST) - timedelta(days=days)).strftime("%Y-%m-%d")

        query = """
            SELECT date, category, severity, SUM(count) as total
            FROM vulnerability_trends
            WHERE date >= ?
        """
        params = [start_date]

        if target_url:
            query += " AND target_url = ?"
            params.append(target_url)

        query += " GROUP BY date, category, severity ORDER BY date"

        cursor = conn.execute(query, params)
        rows = cursor.fetchall()

        # Organize by date
        trends = {}
        for row in rows:
            date = row["date"]
            if date not in trends:
                trends[date] = {"by_category": {}, "by_severity": {}}

            category = row["category"]
            severity = row["severity"]
            total = row["total"]

            if category not in trends[date]["by_category"]:
                trends[date]["by_category"][category] = 0
            trends[date]["by_category"][category] += total

            if severity not in trends[date]["by_severity"]:
                trends[date]["by_severity"][severity] = 0
            trends[date]["by_severity"][severity] += total

        conn.close()
        return {
            "period_days": days,
            "start_date": start_date,
            "trends": trends
        }

    def get_scan_statistics(self, target_url: str = None) -> Dict[str, Any]:
        """Get overall scan statistics."""
        conn = sqlite3.connect(DB_FILE)

        query = "SELECT * FROM scans WHERE status = 'completed'"
        params = []

        if target_url:
            query += " AND target_url = ?"
            params.append(target_url)

        cursor = conn.execute(query, params)
        scans = cursor.fetchall()

        if not scans:
            conn.close()
            return {
                "total_scans": 0,
                "total_attacks": 0,
                "total_vulnerabilities": 0,
                "avg_risk_score": 0,
                "vulnerability_rate": 0
            }

        total_scans = len(scans)
        total_attacks = sum(s[7] for s in scans)  # total_attacks column
        total_vulnerabilities = sum(s[9] for s in scans)  # vulnerabilities_found column
        total_critical = sum(s[10] for s in scans)
        total_high = sum(s[11] for s in scans)

        # Get average risk score
        cursor = conn.execute(
            "SELECT AVG(risk_score) FROM scans WHERE status = 'completed'" +
            (" AND target_url = ?" if target_url else ""),
            params
        )
        avg_risk = cursor.fetchone()[0] or 0

        conn.close()

        return {
            "total_scans": total_scans,
            "total_attacks": total_attacks,
            "total_vulnerabilities": total_vulnerabilities,
            "critical_vulnerabilities": total_critical,
            "high_vulnerabilities": total_high,
            "avg_risk_score": round(avg_risk, 1),
            "vulnerability_rate": round(total_vulnerabilities / max(1, total_attacks) * 100, 1)
        }

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and its results."""
        try:
            conn = sqlite3.connect(DB_FILE)
            conn.execute("DELETE FROM attack_results WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error deleting scan: {e}")
            return False

    def save_scheduled_scan(self, name: str, target_url: str, schedule_cron: str,
                            provider: str = None, model: str = None,
                            categories: List[str] = None) -> int:
        """Save a scheduled scan configuration."""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.execute("""
            INSERT INTO scheduled_scans
            (name, target_url, provider, model, categories_json, schedule_cron, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            name, target_url, provider, model,
            json.dumps(categories) if categories else None,
            schedule_cron,
            datetime.now(IST).isoformat()
        ))
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return scan_id

    def list_scheduled_scans(self, enabled_only: bool = True) -> List[Dict]:
        """List scheduled scans."""
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row

        query = "SELECT * FROM scheduled_scans"
        if enabled_only:
            query += " WHERE enabled = 1"

        cursor = conn.execute(query)
        scans = [dict(row) for row in cursor.fetchall()]

        for scan in scans:
            if scan.get("categories_json"):
                scan["categories"] = json.loads(scan["categories_json"])

        conn.close()
        return scans
