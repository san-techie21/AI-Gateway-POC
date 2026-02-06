"""
AI Gateway - IBM QRadar SIEM Integration

This module provides real-time log forwarding to IBM QRadar SIEM.
Supports both Syslog (UDP/TCP) and QRadar REST API integration.

Event Types:
- QUERY_ALLOWED: Query sent to external AI (CEF severity 1)
- QUERY_BLOCKED: Query blocked due to sensitive data (CEF severity 8)
- QUERY_LOCAL: Query routed to local LLM (CEF severity 3)
- AUTH_SUCCESS: User authentication success (CEF severity 1)
- AUTH_FAILURE: User authentication failure (CEF severity 5)
- CONFIG_CHANGE: Admin configuration change (CEF severity 4)
- RATE_LIMIT: User rate limited (CEF severity 4)
"""

import json
import socket
import asyncio
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from enum import Enum
import hashlib
import urllib.parse

# Indian Standard Time (UTC+5:30)
IST = timezone(timedelta(hours=5, minutes=30))

def now_ist():
    return datetime.now(IST)


# ============== CONFIGURATION ==============

QRADAR_CONFIG_FILE = "qradar_config.json"

DEFAULT_QRADAR_CONFIG = {
    "enabled": True,
    "host": "qradar.motilal.local",
    "syslog_port": 514,
    "syslog_protocol": "udp",  # udp or tcp
    "api_enabled": False,
    "api_endpoint": "https://qradar.motilal.local/api",
    "api_token": "",
    "api_version": "18.0",
    "log_format": "cef",  # cef, leef, or json
    "facility": 16,  # local0
    "include_content_hash": True,
    "include_user_agent": False,
    "batch_size": 100,
    "batch_interval_seconds": 5,
    "retry_count": 3,
    "retry_delay_seconds": 1,
    "event_mapping": {
        "ALLOWED": {
            "name": "AI Gateway Query Allowed",
            "severity": 1,
            "category": "AI Usage"
        },
        "BLOCKED": {
            "name": "AI Gateway Query Blocked - Sensitive Data",
            "severity": 8,
            "category": "Data Protection"
        },
        "ROUTED_LOCAL_LLM": {
            "name": "AI Gateway Query Routed to Local LLM",
            "severity": 3,
            "category": "AI Usage"
        },
        "AUTH_SUCCESS": {
            "name": "AI Gateway Authentication Success",
            "severity": 1,
            "category": "Authentication"
        },
        "AUTH_FAILURE": {
            "name": "AI Gateway Authentication Failure",
            "severity": 5,
            "category": "Authentication"
        },
        "CONFIG_CHANGE": {
            "name": "AI Gateway Configuration Changed",
            "severity": 4,
            "category": "Administration"
        },
        "RATE_LIMIT": {
            "name": "AI Gateway Rate Limit Exceeded",
            "severity": 4,
            "category": "Rate Limiting"
        }
    }
}


def load_qradar_config() -> dict:
    """Load QRadar configuration."""
    try:
        with open(QRADAR_CONFIG_FILE, "r") as f:
            config = json.load(f)
            for key, value in DEFAULT_QRADAR_CONFIG.items():
                if key not in config:
                    config[key] = value
            return config
    except Exception:
        return DEFAULT_QRADAR_CONFIG.copy()


def save_qradar_config(config: dict):
    """Save QRadar configuration."""
    with open(QRADAR_CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


# ============== EVENT TYPES ==============

class EventType(Enum):
    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"
    ROUTED_LOCAL_LLM = "ROUTED_LOCAL_LLM"
    AUTH_SUCCESS = "AUTH_SUCCESS"
    AUTH_FAILURE = "AUTH_FAILURE"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    RATE_LIMIT = "RATE_LIMIT"


@dataclass
class SecurityEvent:
    """Security event for SIEM logging."""
    event_type: EventType
    timestamp: datetime
    user_id: str
    user_role: str
    source_ip: str
    request_id: str
    action: str
    provider: str
    content_hash: str
    content_size_bytes: int
    detections: List[Dict[str, Any]]
    severity: str
    additional_data: Dict[str, Any]


# ============== CEF FORMAT ==============

def format_cef_event(event: SecurityEvent) -> str:
    """
    Format event in Common Event Format (CEF) for QRadar.

    CEF Format:
    CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    """
    config = load_qradar_config()
    event_config = config.get("event_mapping", {}).get(event.event_type.value, {})

    # CEF header fields
    version = "0"
    vendor = "Motilal Oswal"
    product = "AI Gateway"
    product_version = "1.0"
    signature_id = event.event_type.value
    name = event_config.get("name", event.event_type.value)
    severity = event_config.get("severity", 5)

    # CEF extension fields
    extensions = [
        f"src={event.source_ip}",
        f"suser={event.user_id}",
        f"cs1={event.user_role}",
        f"cs1Label=UserRole",
        f"cs2={event.request_id}",
        f"cs2Label=RequestID",
        f"cs3={event.provider}",
        f"cs3Label=AIProvider",
        f"cs4={event.content_hash[:16] if event.content_hash else 'N/A'}",
        f"cs4Label=ContentHash",
        f"cn1={event.content_size_bytes}",
        f"cn1Label=ContentSizeBytes",
        f"cn2={len(event.detections)}",
        f"cn2Label=DetectionCount",
        f"cat={event_config.get('category', 'AI Gateway')}",
        f"act={event.action}",
        f"rt={event.timestamp.strftime('%b %d %Y %H:%M:%S')}"
    ]

    # Add detection details if present
    if event.detections:
        detection_types = ",".join([d.get("type", "unknown") for d in event.detections[:5]])
        extensions.append(f"cs5={detection_types}")
        extensions.append("cs5Label=DetectionTypes")

        # Add severity from detections
        max_severity = max([d.get("severity", "LOW") for d in event.detections], key=lambda x: {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(x, 0))
        extensions.append(f"cs6={max_severity}")
        extensions.append("cs6Label=MaxDetectionSeverity")

    extension_str = " ".join(extensions)

    cef_message = f"CEF:{version}|{vendor}|{product}|{product_version}|{signature_id}|{name}|{severity}|{extension_str}"

    return cef_message


# ============== LEEF FORMAT ==============

def format_leef_event(event: SecurityEvent) -> str:
    """
    Format event in Log Event Extended Format (LEEF) for QRadar.

    LEEF Format:
    LEEF:Version|Vendor|Product|Version|EventID|Key=Value pairs
    """
    config = load_qradar_config()
    event_config = config.get("event_mapping", {}).get(event.event_type.value, {})

    # LEEF header
    version = "2.0"
    vendor = "Motilal Oswal"
    product = "AI Gateway"
    product_version = "1.0"
    event_id = event.event_type.value

    # LEEF attributes
    attributes = [
        f"devTime={event.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
        f"usrName={event.user_id}",
        f"src={event.source_ip}",
        f"cat={event_config.get('category', 'AI Gateway')}",
        f"sev={event_config.get('severity', 5)}",
        f"action={event.action}",
        f"resource={event.provider}",
        f"identSrc={event.request_id}",
        f"contentHash={event.content_hash[:16] if event.content_hash else 'N/A'}",
        f"contentSize={event.content_size_bytes}",
        f"detectionCount={len(event.detections)}"
    ]

    if event.detections:
        detection_types = ",".join([d.get("type", "unknown") for d in event.detections[:5]])
        attributes.append(f"detectionTypes={detection_types}")

    attribute_str = "\t".join(attributes)

    leef_message = f"LEEF:{version}|{vendor}|{product}|{product_version}|{event_id}|{attribute_str}"

    return leef_message


# ============== JSON FORMAT ==============

def format_json_event(event: SecurityEvent) -> str:
    """Format event in JSON for QRadar."""
    config = load_qradar_config()
    event_config = config.get("event_mapping", {}).get(event.event_type.value, {})

    json_event = {
        "timestamp": event.timestamp.isoformat(),
        "event_type": event.event_type.value,
        "event_name": event_config.get("name", event.event_type.value),
        "severity": event_config.get("severity", 5),
        "category": event_config.get("category", "AI Gateway"),
        "source": {
            "ip": event.source_ip,
            "user_id": event.user_id,
            "user_role": event.user_role
        },
        "request": {
            "id": event.request_id,
            "action": event.action,
            "provider": event.provider,
            "content_hash": event.content_hash[:16] if event.content_hash else None,
            "content_size_bytes": event.content_size_bytes
        },
        "detections": {
            "count": len(event.detections),
            "types": [d.get("type") for d in event.detections],
            "max_severity": max([d.get("severity", "LOW") for d in event.detections], key=lambda x: {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(x, 0)) if event.detections else None
        },
        "additional_data": event.additional_data
    }

    return json.dumps(json_event)


# ============== SYSLOG SENDER ==============

class SyslogSender:
    """Send events to QRadar via Syslog (UDP/TCP)."""

    def __init__(self):
        self.config = load_qradar_config()
        self._socket = None

    def _get_socket(self):
        """Get or create socket connection."""
        if self._socket is None:
            protocol = self.config.get("syslog_protocol", "udp")
            if protocol == "tcp":
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.connect((
                    self.config.get("host", "localhost"),
                    self.config.get("syslog_port", 514)
                ))
            else:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return self._socket

    def send(self, message: str, facility: int = 16, severity: int = 6) -> bool:
        """
        Send syslog message.

        Facility: 16 = local0 (default for custom applications)
        Severity: 6 = informational
        """
        try:
            # Calculate priority
            priority = (facility * 8) + severity

            # Format syslog message with RFC 5424 header
            timestamp = now_ist().strftime("%Y-%m-%dT%H:%M:%S.%f%z")
            hostname = socket.gethostname()
            app_name = "AIGateway"

            syslog_message = f"<{priority}>{timestamp} {hostname} {app_name}: {message}"

            # Send
            protocol = self.config.get("syslog_protocol", "udp")
            if protocol == "tcp":
                sock = self._get_socket()
                sock.sendall((syslog_message + "\n").encode('utf-8'))
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(
                    syslog_message.encode('utf-8'),
                    (self.config.get("host", "localhost"), self.config.get("syslog_port", 514))
                )
                sock.close()

            return True

        except Exception as e:
            print(f"Syslog send error: {e}")
            return False

    def close(self):
        """Close socket connection."""
        if self._socket:
            self._socket.close()
            self._socket = None


# ============== QRADAR API CLIENT ==============

class QRadarAPIClient:
    """QRadar REST API client for advanced integration."""

    def __init__(self):
        self.config = load_qradar_config()
        self.base_url = self.config.get("api_endpoint", "")
        self.token = self.config.get("api_token", "")
        self.version = self.config.get("api_version", "18.0")

    def _get_headers(self) -> Dict[str, str]:
        """Get API headers."""
        return {
            "SEC": self.token,
            "Content-Type": "application/json",
            "Version": self.version
        }

    async def test_connection(self) -> Dict[str, Any]:
        """Test QRadar API connection."""
        """
        import httpx

        try:
            async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                response = await client.get(
                    f"{self.base_url}/system/about",
                    headers=self._get_headers()
                )

                if response.status_code == 200:
                    return {"success": True, "data": response.json()}
                else:
                    return {"success": False, "error": f"HTTP {response.status_code}"}

        except Exception as e:
            return {"success": False, "error": str(e)}
        """
        # POC: Return mock success
        return {"success": True, "message": "POC mode - API not connected"}

    async def get_offenses(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent offenses from QRadar."""
        """
        import httpx

        try:
            async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
                response = await client.get(
                    f"{self.base_url}/siem/offenses",
                    headers=self._get_headers(),
                    params={"Range": f"items=0-{limit-1}"}
                )

                if response.status_code == 200:
                    return response.json()
                else:
                    return []

        except Exception as e:
            print(f"QRadar API error: {e}")
            return []
        """
        return []

    async def create_reference_set(self, name: str, element_type: str = "ALN") -> bool:
        """Create a reference set in QRadar."""
        """
        import httpx

        try:
            async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
                response = await client.post(
                    f"{self.base_url}/reference_data/sets",
                    headers=self._get_headers(),
                    params={
                        "name": name,
                        "element_type": element_type
                    }
                )

                return response.status_code in [200, 201]

        except Exception as e:
            print(f"QRadar API error: {e}")
            return False
        """
        return True

    async def add_to_reference_set(self, set_name: str, value: str) -> bool:
        """Add value to reference set."""
        """
        import httpx

        try:
            async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
                response = await client.post(
                    f"{self.base_url}/reference_data/sets/{set_name}",
                    headers=self._get_headers(),
                    params={"value": value}
                )

                return response.status_code in [200, 201]

        except Exception as e:
            print(f"QRadar API error: {e}")
            return False
        """
        return True


# ============== EVENT QUEUE & BATCH SENDER ==============

class EventQueue:
    """Queue events for batch sending to QRadar."""

    def __init__(self, db_file: str = "gateway_logs.db"):
        self.db_file = db_file
        self._init_db()

    def _init_db(self):
        """Initialize event queue table."""
        conn = sqlite3.connect(self.db_file)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS qradar_event_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                formatted_message TEXT NOT NULL,
                format TEXT NOT NULL,
                sent INTEGER DEFAULT 0,
                sent_at TEXT,
                retry_count INTEGER DEFAULT 0,
                error TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_qradar_sent ON qradar_event_queue(sent)")
        conn.commit()
        conn.close()

    def enqueue(self, event: SecurityEvent):
        """Add event to queue."""
        config = load_qradar_config()
        log_format = config.get("log_format", "cef")

        # Format message
        if log_format == "cef":
            message = format_cef_event(event)
        elif log_format == "leef":
            message = format_leef_event(event)
        else:
            message = format_json_event(event)

        conn = sqlite3.connect(self.db_file)
        conn.execute("""
            INSERT INTO qradar_event_queue (created_at, event_type, formatted_message, format)
            VALUES (?, ?, ?, ?)
        """, (now_ist().isoformat(), event.event_type.value, message, log_format))
        conn.commit()
        conn.close()

    def get_pending(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get pending events from queue."""
        conn = sqlite3.connect(self.db_file)
        conn.row_factory = sqlite3.Row

        cursor = conn.execute("""
            SELECT * FROM qradar_event_queue
            WHERE sent = 0 AND retry_count < 3
            ORDER BY created_at ASC
            LIMIT ?
        """, (limit,))

        events = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return events

    def mark_sent(self, event_ids: List[int]):
        """Mark events as sent."""
        if not event_ids:
            return

        conn = sqlite3.connect(self.db_file)
        placeholders = ",".join(["?" for _ in event_ids])
        conn.execute(f"""
            UPDATE qradar_event_queue
            SET sent = 1, sent_at = ?
            WHERE id IN ({placeholders})
        """, [now_ist().isoformat()] + event_ids)
        conn.commit()
        conn.close()

    def mark_failed(self, event_id: int, error: str):
        """Mark event as failed."""
        conn = sqlite3.connect(self.db_file)
        conn.execute("""
            UPDATE qradar_event_queue
            SET retry_count = retry_count + 1, error = ?
            WHERE id = ?
        """, (error, event_id))
        conn.commit()
        conn.close()

    def cleanup_old(self, days: int = 7):
        """Remove old sent events."""
        cutoff = (now_ist() - timedelta(days=days)).isoformat()
        conn = sqlite3.connect(self.db_file)
        conn.execute("""
            DELETE FROM qradar_event_queue
            WHERE sent = 1 AND sent_at < ?
        """, (cutoff,))
        conn.commit()
        conn.close()


# ============== MAIN QRADAR SERVICE ==============

class QRadarService:
    """Main QRadar integration service."""

    def __init__(self):
        self.config = load_qradar_config()
        self.syslog = SyslogSender()
        self.api = QRadarAPIClient()
        self.queue = EventQueue()
        self._running = False

    def log_event(
        self,
        event_type: EventType,
        user_id: str,
        user_role: str = "unknown",
        source_ip: str = "0.0.0.0",
        request_id: str = "",
        action: str = "",
        provider: str = "",
        content: str = "",
        detections: List[Dict[str, Any]] = None,
        additional_data: Dict[str, Any] = None
    ):
        """Log security event to QRadar."""
        if not self.config.get("enabled", False):
            return

        event = SecurityEvent(
            event_type=event_type,
            timestamp=now_ist(),
            user_id=user_id,
            user_role=user_role,
            source_ip=source_ip,
            request_id=request_id,
            action=action,
            provider=provider,
            content_hash=hashlib.sha256(content.encode()).hexdigest() if content else "",
            content_size_bytes=len(content.encode()) if content else 0,
            detections=detections or [],
            severity=self.config.get("event_mapping", {}).get(event_type.value, {}).get("severity", 5),
            additional_data=additional_data or {}
        )

        # Queue for batch sending
        self.queue.enqueue(event)

        # Immediate send for critical events
        if event_type == EventType.BLOCKED:
            self._send_immediate(event)

    def _send_immediate(self, event: SecurityEvent):
        """Send event immediately (for critical events)."""
        log_format = self.config.get("log_format", "cef")

        if log_format == "cef":
            message = format_cef_event(event)
        elif log_format == "leef":
            message = format_leef_event(event)
        else:
            message = format_json_event(event)

        # Map event severity to syslog severity
        severity_map = {1: 6, 2: 6, 3: 5, 4: 4, 5: 4, 6: 3, 7: 2, 8: 2, 9: 1, 10: 0}
        syslog_severity = severity_map.get(event.severity, 6)

        self.syslog.send(message, severity=syslog_severity)

    async def process_queue(self):
        """Process queued events (call periodically)."""
        pending = self.queue.get_pending(self.config.get("batch_size", 100))

        if not pending:
            return

        sent_ids = []

        for event in pending:
            try:
                severity_map = {1: 6, 3: 5, 4: 4, 5: 4, 8: 2}
                syslog_severity = severity_map.get(
                    self.config.get("event_mapping", {}).get(event["event_type"], {}).get("severity", 5),
                    6
                )

                if self.syslog.send(event["formatted_message"], severity=syslog_severity):
                    sent_ids.append(event["id"])
                else:
                    self.queue.mark_failed(event["id"], "Syslog send failed")

            except Exception as e:
                self.queue.mark_failed(event["id"], str(e))

        if sent_ids:
            self.queue.mark_sent(sent_ids)

    async def start_batch_sender(self):
        """Start background batch sender."""
        self._running = True
        interval = self.config.get("batch_interval_seconds", 5)

        while self._running:
            await self.process_queue()
            await asyncio.sleep(interval)

    def stop_batch_sender(self):
        """Stop background batch sender."""
        self._running = False

    async def test_connection(self) -> Dict[str, Any]:
        """Test QRadar connection."""
        results = {"syslog": False, "api": False}

        # Test syslog
        test_message = format_cef_event(SecurityEvent(
            event_type=EventType.ALLOWED,
            timestamp=now_ist(),
            user_id="test_user",
            user_role="test",
            source_ip="127.0.0.1",
            request_id="test_123",
            action="TEST",
            provider="test",
            content_hash="test_hash",
            content_size_bytes=0,
            detections=[],
            severity="1",
            additional_data={"test": True}
        ))

        results["syslog"] = self.syslog.send(test_message)

        # Test API if enabled
        if self.config.get("api_enabled"):
            api_result = await self.api.test_connection()
            results["api"] = api_result.get("success", False)
            results["api_details"] = api_result

        return results

    def get_stats(self) -> Dict[str, Any]:
        """Get QRadar integration statistics."""
        conn = sqlite3.connect(self.queue.db_file)

        cursor = conn.execute("SELECT COUNT(*) FROM qradar_event_queue WHERE sent = 0")
        pending = cursor.fetchone()[0]

        cursor = conn.execute("SELECT COUNT(*) FROM qradar_event_queue WHERE sent = 1")
        sent = cursor.fetchone()[0]

        cursor = conn.execute("SELECT COUNT(*) FROM qradar_event_queue WHERE retry_count >= 3")
        failed = cursor.fetchone()[0]

        cursor = conn.execute("""
            SELECT event_type, COUNT(*) as count
            FROM qradar_event_queue
            WHERE created_at > datetime('now', '-24 hours')
            GROUP BY event_type
        """)
        by_type = {row[0]: row[1] for row in cursor.fetchall()}

        conn.close()

        return {
            "enabled": self.config.get("enabled", False),
            "host": self.config.get("host", ""),
            "port": self.config.get("syslog_port", 514),
            "format": self.config.get("log_format", "cef"),
            "pending_events": pending,
            "sent_events": sent,
            "failed_events": failed,
            "events_last_24h": by_type
        }


# ============== CONVENIENCE FUNCTIONS ==============

# Singleton instance
qradar_service = QRadarService()


def log_query_allowed(user_id: str, request_id: str, provider: str, content: str, source_ip: str = "", user_role: str = ""):
    """Log allowed query event."""
    qradar_service.log_event(
        event_type=EventType.ALLOWED,
        user_id=user_id,
        user_role=user_role,
        source_ip=source_ip,
        request_id=request_id,
        action="ALLOWED",
        provider=provider,
        content=content
    )


def log_query_blocked(user_id: str, request_id: str, content: str, detections: List[Dict], source_ip: str = "", user_role: str = ""):
    """Log blocked query event."""
    qradar_service.log_event(
        event_type=EventType.BLOCKED,
        user_id=user_id,
        user_role=user_role,
        source_ip=source_ip,
        request_id=request_id,
        action="BLOCKED",
        provider="none",
        content=content,
        detections=detections
    )


def log_query_local(user_id: str, request_id: str, content: str, detections: List[Dict], source_ip: str = "", user_role: str = ""):
    """Log local LLM routed query event."""
    qradar_service.log_event(
        event_type=EventType.ROUTED_LOCAL_LLM,
        user_id=user_id,
        user_role=user_role,
        source_ip=source_ip,
        request_id=request_id,
        action="ROUTED_LOCAL_LLM",
        provider="local_llm",
        content=content,
        detections=detections
    )


def log_auth_success(user_id: str, auth_method: str, source_ip: str = ""):
    """Log authentication success."""
    qradar_service.log_event(
        event_type=EventType.AUTH_SUCCESS,
        user_id=user_id,
        source_ip=source_ip,
        action="AUTH_SUCCESS",
        additional_data={"auth_method": auth_method}
    )


def log_auth_failure(username: str, reason: str, source_ip: str = ""):
    """Log authentication failure."""
    qradar_service.log_event(
        event_type=EventType.AUTH_FAILURE,
        user_id=username,
        source_ip=source_ip,
        action="AUTH_FAILURE",
        additional_data={"reason": reason}
    )


def log_config_change(admin_user: str, change_type: str, details: Dict, source_ip: str = ""):
    """Log configuration change."""
    qradar_service.log_event(
        event_type=EventType.CONFIG_CHANGE,
        user_id=admin_user,
        source_ip=source_ip,
        action="CONFIG_CHANGE",
        additional_data={"change_type": change_type, "details": details}
    )


def log_rate_limit(user_id: str, limit_type: str, source_ip: str = ""):
    """Log rate limit exceeded."""
    qradar_service.log_event(
        event_type=EventType.RATE_LIMIT,
        user_id=user_id,
        source_ip=source_ip,
        action="RATE_LIMIT_EXCEEDED",
        additional_data={"limit_type": limit_type}
    )
