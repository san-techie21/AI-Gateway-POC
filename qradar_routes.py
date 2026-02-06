"""
AI Gateway - QRadar SIEM API Routes

FastAPI routes for QRadar integration management.
"""

from fastapi import APIRouter, HTTPException, Request, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any, List

from qradar import (
    qradar_service,
    load_qradar_config,
    save_qradar_config,
    EventType
)
from auth_routes import require_admin, Session

router = APIRouter(prefix="/api/qradar", tags=["QRadar SIEM"])


# ============== REQUEST MODELS ==============

class QRadarConfigUpdate(BaseModel):
    enabled: Optional[bool] = None
    host: Optional[str] = None
    syslog_port: Optional[int] = None
    syslog_protocol: Optional[str] = None
    api_enabled: Optional[bool] = None
    api_endpoint: Optional[str] = None
    api_token: Optional[str] = None
    log_format: Optional[str] = None
    batch_size: Optional[int] = None
    batch_interval_seconds: Optional[int] = None


class TestEventRequest(BaseModel):
    event_type: str = "ALLOWED"
    user_id: str = "test_user"
    content: str = "Test content for QRadar"


# ============== CONFIGURATION ENDPOINTS ==============

@router.get("/config")
async def get_qradar_config(session: Session = Depends(require_admin)):
    """Get QRadar configuration (admin only)."""
    config = load_qradar_config()

    # Hide sensitive data
    safe_config = config.copy()
    if safe_config.get("api_token"):
        safe_config["api_token"] = "***CONFIGURED***"

    return safe_config


@router.post("/config")
async def update_qradar_config(update: QRadarConfigUpdate, session: Session = Depends(require_admin)):
    """Update QRadar configuration (admin only)."""
    config = load_qradar_config()

    if update.enabled is not None:
        config["enabled"] = update.enabled

    if update.host:
        config["host"] = update.host

    if update.syslog_port:
        config["syslog_port"] = update.syslog_port

    if update.syslog_protocol:
        if update.syslog_protocol not in ["udp", "tcp"]:
            raise HTTPException(status_code=400, detail="Protocol must be 'udp' or 'tcp'")
        config["syslog_protocol"] = update.syslog_protocol

    if update.api_enabled is not None:
        config["api_enabled"] = update.api_enabled

    if update.api_endpoint:
        config["api_endpoint"] = update.api_endpoint

    if update.api_token:
        config["api_token"] = update.api_token

    if update.log_format:
        if update.log_format not in ["cef", "leef", "json"]:
            raise HTTPException(status_code=400, detail="Format must be 'cef', 'leef', or 'json'")
        config["log_format"] = update.log_format

    if update.batch_size:
        config["batch_size"] = update.batch_size

    if update.batch_interval_seconds:
        config["batch_interval_seconds"] = update.batch_interval_seconds

    save_qradar_config(config)

    # Reload service config
    qradar_service.config = config

    return {"status": "updated"}


# ============== STATUS & STATS ENDPOINTS ==============

@router.get("/status")
async def get_qradar_status(session: Session = Depends(require_admin)):
    """Get QRadar integration status."""
    stats = qradar_service.get_stats()

    return {
        "enabled": stats["enabled"],
        "host": stats["host"],
        "port": stats["port"],
        "format": stats["format"],
        "queue": {
            "pending": stats["pending_events"],
            "sent": stats["sent_events"],
            "failed": stats["failed_events"]
        },
        "events_last_24h": stats["events_last_24h"]
    }


@router.get("/stats")
async def get_qradar_stats(session: Session = Depends(require_admin)):
    """Get detailed QRadar statistics."""
    return qradar_service.get_stats()


# ============== TEST ENDPOINTS ==============

@router.post("/test-connection")
async def test_qradar_connection(session: Session = Depends(require_admin)):
    """Test QRadar connection."""
    results = await qradar_service.test_connection()

    return {
        "status": "success" if results.get("syslog") else "partial",
        "results": results
    }


@router.post("/test-event")
async def send_test_event(request: TestEventRequest, session: Session = Depends(require_admin)):
    """Send a test event to QRadar."""
    try:
        event_type = EventType[request.event_type.upper()]
    except KeyError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid event type. Valid types: {[e.value for e in EventType]}"
        )

    qradar_service.log_event(
        event_type=event_type,
        user_id=request.user_id,
        user_role="test",
        source_ip="127.0.0.1",
        request_id="test_" + str(hash(request.content))[:8],
        action=request.event_type,
        provider="test",
        content=request.content,
        additional_data={"test": True, "admin": session.user_id}
    )

    return {
        "status": "sent",
        "event_type": event_type.value,
        "note": "Event queued for delivery"
    }


# ============== QUEUE MANAGEMENT ==============

@router.get("/queue")
async def get_queue_status(session: Session = Depends(require_admin)):
    """Get event queue status."""
    pending = qradar_service.queue.get_pending(10)

    return {
        "pending_count": len(pending),
        "recent_pending": [
            {
                "id": e["id"],
                "event_type": e["event_type"],
                "created_at": e["created_at"],
                "retry_count": e["retry_count"]
            }
            for e in pending[:5]
        ]
    }


@router.post("/queue/process")
async def process_queue(session: Session = Depends(require_admin)):
    """Manually trigger queue processing."""
    await qradar_service.process_queue()

    return {"status": "processed"}


@router.post("/queue/cleanup")
async def cleanup_queue(days: int = 7, session: Session = Depends(require_admin)):
    """Clean up old sent events from queue."""
    qradar_service.queue.cleanup_old(days)

    return {"status": "cleaned", "removed_older_than_days": days}


# ============== EVENT MAPPING ==============

@router.get("/event-mapping")
async def get_event_mapping(session: Session = Depends(require_admin)):
    """Get event type to severity mapping."""
    config = load_qradar_config()

    return {
        "event_mapping": config.get("event_mapping", {}),
        "available_types": [e.value for e in EventType]
    }


@router.post("/event-mapping/{event_type}")
async def update_event_mapping(
    event_type: str,
    name: str = None,
    severity: int = None,
    category: str = None,
    session: Session = Depends(require_admin)
):
    """Update event mapping for a specific event type."""
    try:
        EventType[event_type.upper()]
    except KeyError:
        raise HTTPException(status_code=400, detail="Invalid event type")

    config = load_qradar_config()

    if "event_mapping" not in config:
        config["event_mapping"] = {}

    if event_type not in config["event_mapping"]:
        config["event_mapping"][event_type] = {}

    if name:
        config["event_mapping"][event_type]["name"] = name

    if severity is not None:
        if not 1 <= severity <= 10:
            raise HTTPException(status_code=400, detail="Severity must be 1-10")
        config["event_mapping"][event_type]["severity"] = severity

    if category:
        config["event_mapping"][event_type]["category"] = category

    save_qradar_config(config)

    return {"status": "updated", "event_type": event_type}


# ============== LOG FORMAT EXAMPLES ==============

@router.get("/format-examples")
async def get_format_examples():
    """Get example log formats for QRadar configuration."""
    from qradar import format_cef_event, format_leef_event, format_json_event, SecurityEvent
    from datetime import datetime, timezone, timedelta

    IST = timezone(timedelta(hours=5, minutes=30))

    sample_event = SecurityEvent(
        event_type=EventType.BLOCKED,
        timestamp=datetime.now(IST),
        user_id="sample_user",
        user_role="general",
        source_ip="192.168.1.100",
        request_id="req_12345",
        action="BLOCKED",
        provider="none",
        content_hash="abc123def456",
        content_size_bytes=1024,
        detections=[
            {"type": "aadhaar", "severity": "CRITICAL"},
            {"type": "pan", "severity": "CRITICAL"}
        ],
        severity="8",
        additional_data={}
    )

    return {
        "cef": format_cef_event(sample_event),
        "leef": format_leef_event(sample_event),
        "json": format_json_event(sample_event),
        "note": "These are example formats for a BLOCKED event with PII detections"
    }


# ============== API INTEGRATION ==============

@router.get("/api/status")
async def get_api_status(session: Session = Depends(require_admin)):
    """Check QRadar API status."""
    config = load_qradar_config()

    if not config.get("api_enabled"):
        return {"enabled": False, "status": "API integration disabled"}

    result = await qradar_service.api.test_connection()

    return {
        "enabled": True,
        "connected": result.get("success", False),
        "details": result
    }


@router.get("/api/offenses")
async def get_recent_offenses(limit: int = 10, session: Session = Depends(require_admin)):
    """Get recent offenses from QRadar (requires API integration)."""
    config = load_qradar_config()

    if not config.get("api_enabled"):
        raise HTTPException(status_code=400, detail="QRadar API integration not enabled")

    offenses = await qradar_service.api.get_offenses(limit)

    return {"offenses": offenses, "count": len(offenses)}
