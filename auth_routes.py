"""
AI Gateway - Authentication API Routes

FastAPI routes for authentication endpoints.
Supports SAML 2.0, OAuth 2.0, LDAP, and mock authentication.
"""

from fastapi import APIRouter, HTTPException, Request, Response, Depends, Header
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import json

from auth import (
    auth_service,
    load_auth_config,
    save_auth_config,
    generate_saml_request,
    parse_saml_response,
    generate_oauth_authorization_url,
    exchange_oauth_code,
    Session,
    MOCK_USERS
)
from qradar import log_auth_success, log_auth_failure

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


# ============== REQUEST MODELS ==============

class LoginRequest(BaseModel):
    username: str
    password: str


class LogoutRequest(BaseModel):
    session_id: Optional[str] = None


class RoleUpdate(BaseModel):
    role: str
    permissions: Dict[str, Any]


class AuthConfigUpdate(BaseModel):
    auth_method: Optional[str] = None
    session_timeout_minutes: Optional[int] = None
    ldap: Optional[Dict[str, Any]] = None
    saml: Optional[Dict[str, Any]] = None
    oauth: Optional[Dict[str, Any]] = None
    role_mapping: Optional[Dict[str, str]] = None
    role_permissions: Optional[Dict[str, Dict[str, Any]]] = None


# ============== HELPER FUNCTIONS ==============

def get_client_ip(request: Request) -> str:
    """Get client IP from request."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


def get_session_from_cookie(request: Request) -> Optional[Session]:
    """Get session from cookie."""
    session_id = request.cookies.get("session_id")
    if session_id:
        return auth_service.validate_session(session_id)
    return None


def get_session_from_header(authorization: str = Header(None)) -> Optional[Session]:
    """Get session from Authorization header."""
    if authorization and authorization.startswith("Bearer "):
        session_id = authorization[7:]
        return auth_service.validate_session(session_id)
    return None


async def require_auth(request: Request) -> Session:
    """Dependency that requires authentication."""
    session = get_session_from_cookie(request)
    if not session:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            session = auth_service.validate_session(auth_header[7:])

    if not session:
        raise HTTPException(status_code=401, detail="Authentication required")

    return session


async def require_admin(request: Request) -> Session:
    """Dependency that requires admin access."""
    session = await require_auth(request)

    if not session.permissions.get("admin_dashboard", False):
        raise HTTPException(status_code=403, detail="Admin access required")

    return session


# ============== LOGIN ENDPOINTS ==============

@router.post("/login")
async def login(request: Request, login_data: LoginRequest):
    """
    Authenticate user with username/password.

    Supports mock and LDAP authentication based on configuration.
    """
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "")

    config = load_auth_config()
    auth_method = config.get("auth_method", "mock")

    session = auth_service.authenticate(
        username=login_data.username,
        password=login_data.password,
        auth_method=auth_method,
        ip_address=client_ip,
        user_agent=user_agent
    )

    if not session:
        log_auth_failure(login_data.username, "Invalid credentials", client_ip)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    log_auth_success(session.user_id, auth_method, client_ip)

    response = JSONResponse(content={
        "status": "success",
        "session_id": session.session_id,
        "user": {
            "user_id": session.user_id,
            "email": session.user_email,
            "role": session.user_role,
            "permissions": session.permissions
        },
        "expires_at": session.expires_at.isoformat()
    })

    # Set session cookie
    response.set_cookie(
        key="session_id",
        value=session.session_id,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=config.get("session_timeout_minutes", 30) * 60
    )

    return response


@router.post("/logout")
async def logout(request: Request, logout_data: LogoutRequest = None):
    """Logout user and invalidate session."""
    session_id = None

    if logout_data and logout_data.session_id:
        session_id = logout_data.session_id
    else:
        session_id = request.cookies.get("session_id")

    if session_id:
        auth_service.logout(session_id)

    response = JSONResponse(content={"status": "logged_out"})
    response.delete_cookie("session_id")

    return response


@router.get("/session")
async def get_session(request: Request):
    """Get current session info."""
    session = get_session_from_cookie(request)

    if not session:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            session = auth_service.validate_session(auth_header[7:])

    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")

    return {
        "user_id": session.user_id,
        "email": session.user_email,
        "role": session.user_role,
        "groups": session.user_groups,
        "permissions": session.permissions,
        "auth_method": session.auth_method,
        "created_at": session.created_at.isoformat(),
        "expires_at": session.expires_at.isoformat()
    }


@router.post("/session/extend")
async def extend_session(request: Request):
    """Extend session expiration."""
    session_id = request.cookies.get("session_id")

    if not session_id:
        raise HTTPException(status_code=401, detail="No session to extend")

    if auth_service.session_manager.extend_session(session_id):
        session = auth_service.validate_session(session_id)
        return {
            "status": "extended",
            "expires_at": session.expires_at.isoformat() if session else None
        }
    else:
        raise HTTPException(status_code=400, detail="Could not extend session")


# ============== SAML ENDPOINTS ==============

@router.get("/saml/login")
async def saml_login():
    """
    Initiate SAML authentication.

    Redirects to IdP with SAML AuthnRequest.
    """
    saml_request = generate_saml_request()

    return RedirectResponse(
        url=saml_request["redirect_url"],
        status_code=302
    )


@router.post("/saml/acs")
async def saml_acs(request: Request):
    """
    SAML Assertion Consumer Service (ACS).

    Receives and processes SAML response from IdP.
    """
    form_data = await request.form()
    saml_response = form_data.get("SAMLResponse")

    if not saml_response:
        raise HTTPException(status_code=400, detail="No SAML response received")

    user_info = parse_saml_response(saml_response)

    if not user_info:
        log_auth_failure("saml_user", "Invalid SAML response", get_client_ip(request))
        raise HTTPException(status_code=401, detail="Invalid SAML response")

    session = auth_service.authenticate_saml(
        user_info=user_info,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("User-Agent", "")
    )

    if not session:
        raise HTTPException(status_code=401, detail="Could not create session")

    log_auth_success(session.user_id, "saml", get_client_ip(request))

    # Redirect to dashboard with session cookie
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(
        key="session_id",
        value=session.session_id,
        httponly=True,
        secure=True,
        samesite="lax"
    )

    return response


@router.get("/saml/metadata")
async def saml_metadata():
    """
    Return SAML SP metadata.

    Used for IdP configuration.
    """
    config = load_auth_config()
    saml_config = config.get("saml", {})

    metadata = f"""<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  entityID="{saml_config.get('sp_entity_id', '')}">
    <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
        <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                  Location="{saml_config.get('sp_acs_url', '')}"
                                  index="0"/>
        <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                             Location="{saml_config.get('sp_slo_url', '')}"/>
    </SPSSODescriptor>
</EntityDescriptor>"""

    return Response(
        content=metadata,
        media_type="application/xml"
    )


# ============== OAUTH ENDPOINTS ==============

@router.get("/oauth/login")
async def oauth_login(request: Request):
    """
    Initiate OAuth 2.0 authentication.

    Redirects to authorization server.
    """
    state = request.cookies.get("oauth_state")
    auth_data = generate_oauth_authorization_url(state)

    response = RedirectResponse(url=auth_data["authorization_url"], status_code=302)
    response.set_cookie(
        key="oauth_state",
        value=auth_data["state"],
        httponly=True,
        secure=True,
        max_age=600
    )

    return response


@router.get("/oauth/callback")
async def oauth_callback(request: Request, code: str = None, state: str = None, error: str = None):
    """
    OAuth 2.0 callback.

    Exchanges authorization code for tokens.
    """
    if error:
        log_auth_failure("oauth_user", f"OAuth error: {error}", get_client_ip(request))
        raise HTTPException(status_code=401, detail=f"OAuth error: {error}")

    if not code:
        raise HTTPException(status_code=400, detail="No authorization code received")

    # Verify state
    stored_state = request.cookies.get("oauth_state")
    if state != stored_state:
        raise HTTPException(status_code=400, detail="Invalid state parameter")

    # Exchange code for user info
    user_info = await exchange_oauth_code(code)

    if not user_info:
        log_auth_failure("oauth_user", "Token exchange failed", get_client_ip(request))
        raise HTTPException(status_code=401, detail="Could not exchange authorization code")

    session = auth_service.authenticate_oauth(
        user_info=user_info,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("User-Agent", "")
    )

    if not session:
        raise HTTPException(status_code=401, detail="Could not create session")

    log_auth_success(session.user_id, "oauth", get_client_ip(request))

    # Redirect to dashboard with session cookie
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(
        key="session_id",
        value=session.session_id,
        httponly=True,
        secure=True,
        samesite="lax"
    )
    response.delete_cookie("oauth_state")

    return response


# ============== ADMIN ENDPOINTS ==============

@router.get("/config")
async def get_auth_config(session: Session = Depends(require_admin)):
    """Get authentication configuration (admin only)."""
    config = load_auth_config()

    # Hide sensitive data
    safe_config = config.copy()

    if "ldap" in safe_config and safe_config["ldap"].get("bind_password"):
        safe_config["ldap"]["bind_password"] = "***CONFIGURED***"

    if "oauth" in safe_config and safe_config["oauth"].get("client_secret"):
        safe_config["oauth"]["client_secret"] = "***CONFIGURED***"

    if "saml" in safe_config and safe_config["saml"].get("idp_certificate"):
        safe_config["saml"]["idp_certificate"] = "***CONFIGURED***"

    return safe_config


@router.post("/config")
async def update_auth_config(update: AuthConfigUpdate, session: Session = Depends(require_admin)):
    """Update authentication configuration (admin only)."""
    config = load_auth_config()

    if update.auth_method:
        config["auth_method"] = update.auth_method

    if update.session_timeout_minutes:
        config["session_timeout_minutes"] = update.session_timeout_minutes

    if update.ldap:
        for key, value in update.ldap.items():
            if value is not None:
                config["ldap"][key] = value

    if update.saml:
        for key, value in update.saml.items():
            if value is not None:
                config["saml"][key] = value

    if update.oauth:
        for key, value in update.oauth.items():
            if value is not None:
                config["oauth"][key] = value

    if update.role_mapping:
        config["role_mapping"] = update.role_mapping

    if update.role_permissions:
        config["role_permissions"] = update.role_permissions

    save_auth_config(config)

    return {"status": "updated"}


@router.get("/roles")
async def get_roles(session: Session = Depends(require_admin)):
    """Get role configurations."""
    config = load_auth_config()

    return {
        "role_mapping": config.get("role_mapping", {}),
        "role_permissions": config.get("role_permissions", {})
    }


@router.post("/roles/{role}")
async def update_role(role: str, update: RoleUpdate, session: Session = Depends(require_admin)):
    """Update role permissions."""
    config = load_auth_config()

    if "role_permissions" not in config:
        config["role_permissions"] = {}

    config["role_permissions"][role] = update.permissions

    save_auth_config(config)

    return {"status": "updated", "role": role}


@router.get("/users/mock")
async def get_mock_users(session: Session = Depends(require_admin)):
    """Get mock users for testing (POC only)."""
    safe_users = {}
    for username, data in MOCK_USERS.items():
        safe_users[username] = {
            "email": data["email"],
            "role": data["role"],
            "groups": data["groups"]
            # Password intentionally excluded
        }

    return {"users": safe_users, "note": "POC mock users - passwords hidden"}


@router.get("/sessions")
async def get_active_sessions(session: Session = Depends(require_admin), limit: int = 100):
    """Get active sessions (admin only)."""
    import sqlite3

    conn = sqlite3.connect("gateway_logs.db")
    conn.row_factory = sqlite3.Row

    cursor = conn.execute("""
        SELECT session_id, user_id, user_role, auth_method, created_at, expires_at, ip_address
        FROM auth_sessions
        WHERE is_active = 1
        ORDER BY created_at DESC
        LIMIT ?
    """, (limit,))

    sessions = [dict(row) for row in cursor.fetchall()]
    conn.close()

    # Truncate session IDs for security
    for s in sessions:
        s["session_id"] = s["session_id"][:8] + "..."

    return {"sessions": sessions, "count": len(sessions)}


@router.delete("/sessions/{user_id}")
async def invalidate_user_sessions(user_id: str, session: Session = Depends(require_admin)):
    """Invalidate all sessions for a user (admin only)."""
    auth_service.session_manager.invalidate_user_sessions(user_id)

    return {"status": "invalidated", "user_id": user_id}


# ============== PERMISSION CHECK ENDPOINTS ==============

@router.get("/check/external-ai")
async def check_external_ai(request: Request):
    """Check if current user can access external AI."""
    session = get_session_from_cookie(request)

    if not session:
        return {"allowed": False, "reason": "Not authenticated"}

    allowed = session.permissions.get("external_ai", False)

    return {
        "allowed": allowed,
        "user_id": session.user_id,
        "role": session.user_role
    }


@router.get("/check/local-llm")
async def check_local_llm(request: Request):
    """Check if current user can access local LLM."""
    session = get_session_from_cookie(request)

    if not session:
        return {"allowed": False, "reason": "Not authenticated"}

    allowed = session.permissions.get("local_llm", False)

    return {
        "allowed": allowed,
        "user_id": session.user_id,
        "role": session.user_role
    }


@router.get("/check/admin")
async def check_admin(request: Request):
    """Check if current user has admin access."""
    session = get_session_from_cookie(request)

    if not session:
        return {"allowed": False, "reason": "Not authenticated"}

    allowed = session.permissions.get("admin_dashboard", False)

    return {
        "allowed": allowed,
        "user_id": session.user_id,
        "role": session.user_role
    }
