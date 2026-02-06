"""
AI Gateway - Authentication Module
SAML 2.0 / OAuth 2.0 / LDAP Authentication

This module provides enterprise authentication for the AI Gateway.
Supports Active Directory integration via LDAP, SAML 2.0 SSO, and OAuth 2.0.
"""

import os
import json
import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from enum import Enum
import base64
import urllib.parse

# Indian Standard Time (UTC+5:30)
IST = timezone(timedelta(hours=5, minutes=30))

def now_ist():
    return datetime.now(IST)


# ============== CONFIGURATION ==============

AUTH_CONFIG_FILE = "auth_config.json"

DEFAULT_AUTH_CONFIG = {
    "auth_method": "mock",  # mock, ldap, saml, oauth
    "session_timeout_minutes": 30,
    "ldap": {
        "server": "ldap://dc.motilal.local:389",
        "base_dn": "DC=motilal,DC=local",
        "bind_user": "CN=svc_aigateway,OU=ServiceAccounts,DC=motilal,DC=local",
        "bind_password": "",
        "user_search_filter": "(sAMAccountName={username})",
        "group_search_filter": "(member={user_dn})"
    },
    "saml": {
        "idp_entity_id": "https://adfs.motilal.local/adfs/services/trust",
        "idp_sso_url": "https://adfs.motilal.local/adfs/ls/",
        "idp_slo_url": "https://adfs.motilal.local/adfs/ls/?wa=wsignout1.0",
        "idp_certificate": "",
        "sp_entity_id": "https://aigateway.motilal.local",
        "sp_acs_url": "https://aigateway.motilal.local/api/auth/saml/acs",
        "sp_slo_url": "https://aigateway.motilal.local/api/auth/saml/slo",
        "attribute_mapping": {
            "user_id": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
            "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
            "groups": "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
        }
    },
    "oauth": {
        "provider": "azure_ad",
        "client_id": "",
        "client_secret": "",
        "tenant_id": "",
        "authorization_endpoint": "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize",
        "token_endpoint": "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        "userinfo_endpoint": "https://graph.microsoft.com/v1.0/me",
        "redirect_uri": "https://aigateway.motilal.local/api/auth/oauth/callback",
        "scope": "openid profile email User.Read GroupMember.Read.All"
    },
    "role_mapping": {
        "CN=AllEmployees,OU=Groups,DC=motilal,DC=local": "general",
        "CN=Research,OU=Groups,DC=motilal,DC=local": "research",
        "CN=Strategy,OU=Groups,DC=motilal,DC=local": "strategy",
        "CN=Compliance,OU=Groups,DC=motilal,DC=local": "compliance",
        "CN=ITAdmins,OU=Groups,DC=motilal,DC=local": "it_admin",
        "CN=Security,OU=Groups,DC=motilal,DC=local": "security_admin"
    },
    "role_permissions": {
        "general": {
            "external_ai": True,
            "local_llm": False,
            "admin_dashboard": False,
            "rate_limit_per_hour": 20,
            "rate_limit_per_day": 100
        },
        "research": {
            "external_ai": True,
            "local_llm": True,
            "admin_dashboard": False,
            "rate_limit_per_hour": 50,
            "rate_limit_per_day": 500
        },
        "strategy": {
            "external_ai": True,
            "local_llm": True,
            "admin_dashboard": False,
            "rate_limit_per_hour": 50,
            "rate_limit_per_day": 500
        },
        "compliance": {
            "external_ai": True,
            "local_llm": False,
            "admin_dashboard": False,
            "rate_limit_per_hour": 20,
            "rate_limit_per_day": 100
        },
        "it_admin": {
            "external_ai": True,
            "local_llm": False,
            "admin_dashboard": False,
            "rate_limit_per_hour": 20,
            "rate_limit_per_day": 100
        },
        "security_admin": {
            "external_ai": True,
            "local_llm": False,
            "admin_dashboard": True,
            "rate_limit_per_hour": 100,
            "rate_limit_per_day": 1000
        }
    }
}


def load_auth_config() -> dict:
    """Load authentication configuration."""
    try:
        with open(AUTH_CONFIG_FILE, "r") as f:
            config = json.load(f)
            # Merge with defaults
            for key, value in DEFAULT_AUTH_CONFIG.items():
                if key not in config:
                    config[key] = value
            return config
    except Exception:
        return DEFAULT_AUTH_CONFIG.copy()


def save_auth_config(config: dict):
    """Save authentication configuration."""
    with open(AUTH_CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


# ============== SESSION MANAGEMENT ==============

@dataclass
class Session:
    session_id: str
    user_id: str
    user_email: str
    user_role: str
    user_groups: List[str]
    auth_method: str
    created_at: datetime
    expires_at: datetime
    is_active: bool
    permissions: Dict[str, Any]


class SessionManager:
    """Manages user sessions with database persistence."""

    def __init__(self, db_file: str = "gateway_logs.db"):
        self.db_file = db_file
        self._init_db()

    def _init_db(self):
        """Initialize session tables."""
        conn = sqlite3.connect(self.db_file)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS auth_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE NOT NULL,
                user_id TEXT NOT NULL,
                user_email TEXT,
                user_role TEXT NOT NULL,
                user_groups_json TEXT,
                auth_method TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                permissions_json TEXT,
                ip_address TEXT,
                user_agent TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_auth_session ON auth_sessions(session_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_auth_user ON auth_sessions(user_id)")
        conn.commit()
        conn.close()

    def create_session(
        self,
        user_id: str,
        user_email: str,
        user_role: str,
        user_groups: List[str],
        auth_method: str,
        ip_address: str = "",
        user_agent: str = ""
    ) -> Session:
        """Create a new session."""
        config = load_auth_config()
        timeout_minutes = config.get("session_timeout_minutes", 30)

        session = Session(
            session_id=secrets.token_urlsafe(32),
            user_id=user_id,
            user_email=user_email,
            user_role=user_role,
            user_groups=user_groups,
            auth_method=auth_method,
            created_at=now_ist(),
            expires_at=now_ist() + timedelta(minutes=timeout_minutes),
            is_active=True,
            permissions=config.get("role_permissions", {}).get(user_role, {})
        )

        conn = sqlite3.connect(self.db_file)
        conn.execute("""
            INSERT INTO auth_sessions
            (session_id, user_id, user_email, user_role, user_groups_json, auth_method,
             created_at, expires_at, is_active, permissions_json, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session.session_id,
            session.user_id,
            session.user_email,
            session.user_role,
            json.dumps(session.user_groups),
            session.auth_method,
            session.created_at.isoformat(),
            session.expires_at.isoformat(),
            1,
            json.dumps(session.permissions),
            ip_address,
            user_agent
        ))
        conn.commit()
        conn.close()

        return session

    def get_session(self, session_id: str) -> Optional[Session]:
        """Get session by ID."""
        conn = sqlite3.connect(self.db_file)
        conn.row_factory = sqlite3.Row

        cursor = conn.execute(
            "SELECT * FROM auth_sessions WHERE session_id = ? AND is_active = 1",
            (session_id,)
        )
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        session = Session(
            session_id=row["session_id"],
            user_id=row["user_id"],
            user_email=row["user_email"],
            user_role=row["user_role"],
            user_groups=json.loads(row["user_groups_json"] or "[]"),
            auth_method=row["auth_method"],
            created_at=datetime.fromisoformat(row["created_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]),
            is_active=bool(row["is_active"]),
            permissions=json.loads(row["permissions_json"] or "{}")
        )

        # Check expiration
        if session.expires_at < now_ist():
            self.invalidate_session(session_id)
            return None

        return session

    def invalidate_session(self, session_id: str):
        """Invalidate a session."""
        conn = sqlite3.connect(self.db_file)
        conn.execute(
            "UPDATE auth_sessions SET is_active = 0 WHERE session_id = ?",
            (session_id,)
        )
        conn.commit()
        conn.close()

    def invalidate_user_sessions(self, user_id: str):
        """Invalidate all sessions for a user."""
        conn = sqlite3.connect(self.db_file)
        conn.execute(
            "UPDATE auth_sessions SET is_active = 0 WHERE user_id = ?",
            (user_id,)
        )
        conn.commit()
        conn.close()

    def cleanup_expired(self):
        """Clean up expired sessions."""
        conn = sqlite3.connect(self.db_file)
        conn.execute(
            "UPDATE auth_sessions SET is_active = 0 WHERE expires_at < ?",
            (now_ist().isoformat(),)
        )
        conn.commit()
        conn.close()

    def extend_session(self, session_id: str) -> bool:
        """Extend session expiration."""
        config = load_auth_config()
        timeout_minutes = config.get("session_timeout_minutes", 30)
        new_expires = now_ist() + timedelta(minutes=timeout_minutes)

        conn = sqlite3.connect(self.db_file)
        cursor = conn.execute(
            "UPDATE auth_sessions SET expires_at = ? WHERE session_id = ? AND is_active = 1",
            (new_expires.isoformat(), session_id)
        )
        conn.commit()
        result = cursor.rowcount > 0
        conn.close()
        return result


# ============== MOCK AUTHENTICATION ==============

MOCK_USERS = {
    "admin": {
        "password": "admin123",
        "email": "admin@motilal.local",
        "role": "security_admin",
        "groups": ["CN=Security,OU=Groups,DC=motilal,DC=local"]
    },
    "analyst": {
        "password": "analyst123",
        "email": "analyst@motilal.local",
        "role": "research",
        "groups": ["CN=Research,OU=Groups,DC=motilal,DC=local"]
    },
    "strategy": {
        "password": "strategy123",
        "email": "strategy@motilal.local",
        "role": "strategy",
        "groups": ["CN=Strategy,OU=Groups,DC=motilal,DC=local"]
    },
    "employee": {
        "password": "employee123",
        "email": "employee@motilal.local",
        "role": "general",
        "groups": ["CN=AllEmployees,OU=Groups,DC=motilal,DC=local"]
    },
    "compliance": {
        "password": "compliance123",
        "email": "compliance@motilal.local",
        "role": "compliance",
        "groups": ["CN=Compliance,OU=Groups,DC=motilal,DC=local"]
    }
}


def authenticate_mock(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Mock authentication for POC testing."""
    user = MOCK_USERS.get(username.lower())
    if user and user["password"] == password:
        return {
            "user_id": username,
            "email": user["email"],
            "role": user["role"],
            "groups": user["groups"]
        }
    return None


# ============== LDAP AUTHENTICATION ==============

def authenticate_ldap(username: str, password: str) -> Optional[Dict[str, Any]]:
    """
    Authenticate user against Active Directory via LDAP.

    In production, this would use the ldap3 library:
    pip install ldap3
    """
    config = load_auth_config()
    ldap_config = config.get("ldap", {})

    # For POC, return mock data
    # In production, uncomment and use the ldap3 implementation below

    """
    from ldap3 import Server, Connection, ALL, SUBTREE

    try:
        server = Server(ldap_config["server"], get_info=ALL)

        # First bind with service account to search for user
        conn = Connection(
            server,
            ldap_config["bind_user"],
            ldap_config["bind_password"],
            auto_bind=True
        )

        # Search for user
        search_filter = ldap_config["user_search_filter"].format(username=username)
        conn.search(
            ldap_config["base_dn"],
            search_filter,
            attributes=['cn', 'mail', 'memberOf', 'distinguishedName']
        )

        if not conn.entries:
            return None

        user_entry = conn.entries[0]
        user_dn = str(user_entry.distinguishedName)

        # Try to bind as user to validate password
        user_conn = Connection(server, user_dn, password)
        if not user_conn.bind():
            return None

        # Get user groups
        groups = [str(g) for g in user_entry.memberOf] if hasattr(user_entry, 'memberOf') else []

        # Determine role based on group membership
        role_mapping = config.get("role_mapping", {})
        user_role = "general"
        for group_dn, role in role_mapping.items():
            if group_dn in groups:
                user_role = role
                break

        return {
            "user_id": username,
            "email": str(user_entry.mail) if hasattr(user_entry, 'mail') else f"{username}@motilal.local",
            "role": user_role,
            "groups": groups
        }

    except Exception as e:
        print(f"LDAP authentication error: {e}")
        return None
    """

    # POC: Fall back to mock
    return authenticate_mock(username, password)


# ============== SAML 2.0 AUTHENTICATION ==============

def generate_saml_request() -> Dict[str, str]:
    """
    Generate SAML authentication request.

    Returns URL to redirect user to IdP.
    """
    config = load_auth_config()
    saml_config = config.get("saml", {})

    request_id = f"_{''.join(secrets.token_hex(16))}"
    issue_instant = now_ist().strftime("%Y-%m-%dT%H:%M:%SZ")

    # SAML AuthnRequest template
    saml_request = f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{request_id}"
    Version="2.0"
    IssueInstant="{issue_instant}"
    Destination="{saml_config['idp_sso_url']}"
    AssertionConsumerServiceURL="{saml_config['sp_acs_url']}"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
    <saml:Issuer>{saml_config['sp_entity_id']}</saml:Issuer>
    <samlp:NameIDPolicy
        Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
        AllowCreate="true"/>
</samlp:AuthnRequest>"""

    # Encode request
    encoded = base64.b64encode(saml_request.encode()).decode()

    # Build redirect URL
    redirect_url = (
        f"{saml_config['idp_sso_url']}?"
        f"SAMLRequest={urllib.parse.quote(encoded)}&"
        f"RelayState={urllib.parse.quote(saml_config['sp_acs_url'])}"
    )

    return {
        "request_id": request_id,
        "redirect_url": redirect_url
    }


def parse_saml_response(saml_response: str) -> Optional[Dict[str, Any]]:
    """
    Parse SAML response from IdP.

    In production, use python3-saml library for proper validation:
    pip install python3-saml
    """
    config = load_auth_config()
    attribute_mapping = config.get("saml", {}).get("attribute_mapping", {})
    role_mapping = config.get("role_mapping", {})

    try:
        # Decode response
        decoded = base64.b64decode(saml_response).decode()

        # In production, use proper XML parsing and signature validation
        # For POC, we'll simulate extracting attributes

        """
        from onelogin.saml2.response import OneLogin_Saml2_Response
        from onelogin.saml2.settings import OneLogin_Saml2_Settings

        settings = OneLogin_Saml2_Settings(settings=get_saml_settings())
        response = OneLogin_Saml2_Response(settings, saml_response)

        if not response.is_valid():
            return None

        attributes = response.get_attributes()
        user_id = attributes.get(attribute_mapping["user_id"], [""])[0]
        email = attributes.get(attribute_mapping["email"], [""])[0]
        groups = attributes.get(attribute_mapping["groups"], [])

        # Determine role
        user_role = "general"
        for group_dn, role in role_mapping.items():
            if group_dn in groups:
                user_role = role
                break

        return {
            "user_id": user_id,
            "email": email,
            "role": user_role,
            "groups": groups
        }
        """

        # POC: Return mock data
        return {
            "user_id": "saml_user",
            "email": "saml_user@motilal.local",
            "role": "general",
            "groups": ["CN=AllEmployees,OU=Groups,DC=motilal,DC=local"]
        }

    except Exception as e:
        print(f"SAML response parsing error: {e}")
        return None


# ============== OAUTH 2.0 AUTHENTICATION ==============

def generate_oauth_authorization_url(state: str = None) -> Dict[str, str]:
    """Generate OAuth 2.0 authorization URL."""
    config = load_auth_config()
    oauth_config = config.get("oauth", {})

    if not state:
        state = secrets.token_urlsafe(32)

    tenant_id = oauth_config.get("tenant_id", "common")
    auth_endpoint = oauth_config["authorization_endpoint"].format(tenant_id=tenant_id)

    params = {
        "client_id": oauth_config["client_id"],
        "response_type": "code",
        "redirect_uri": oauth_config["redirect_uri"],
        "scope": oauth_config["scope"],
        "state": state,
        "response_mode": "query"
    }

    authorization_url = f"{auth_endpoint}?{urllib.parse.urlencode(params)}"

    return {
        "authorization_url": authorization_url,
        "state": state
    }


async def exchange_oauth_code(code: str) -> Optional[Dict[str, Any]]:
    """
    Exchange OAuth authorization code for tokens and get user info.

    In production, use httpx or aiohttp for async requests.
    """
    config = load_auth_config()
    oauth_config = config.get("oauth", {})
    role_mapping = config.get("role_mapping", {})

    """
    import httpx

    try:
        tenant_id = oauth_config.get("tenant_id", "common")
        token_endpoint = oauth_config["token_endpoint"].format(tenant_id=tenant_id)

        async with httpx.AsyncClient() as client:
            # Exchange code for token
            token_response = await client.post(
                token_endpoint,
                data={
                    "client_id": oauth_config["client_id"],
                    "client_secret": oauth_config["client_secret"],
                    "code": code,
                    "redirect_uri": oauth_config["redirect_uri"],
                    "grant_type": "authorization_code"
                }
            )

            if token_response.status_code != 200:
                return None

            tokens = token_response.json()
            access_token = tokens["access_token"]

            # Get user info
            userinfo_response = await client.get(
                oauth_config["userinfo_endpoint"],
                headers={"Authorization": f"Bearer {access_token}"}
            )

            if userinfo_response.status_code != 200:
                return None

            userinfo = userinfo_response.json()

            # Get group membership (Azure AD)
            groups_response = await client.get(
                "https://graph.microsoft.com/v1.0/me/memberOf",
                headers={"Authorization": f"Bearer {access_token}"}
            )

            groups = []
            if groups_response.status_code == 200:
                group_data = groups_response.json()
                groups = [g.get("displayName", "") for g in group_data.get("value", [])]

            # Determine role
            user_role = "general"
            for group_dn, role in role_mapping.items():
                if any(g in group_dn for g in groups):
                    user_role = role
                    break

            return {
                "user_id": userinfo.get("userPrincipalName", userinfo.get("mail", "")),
                "email": userinfo.get("mail", ""),
                "role": user_role,
                "groups": groups
            }

    except Exception as e:
        print(f"OAuth token exchange error: {e}")
        return None
    """

    # POC: Return mock data
    return {
        "user_id": "oauth_user",
        "email": "oauth_user@motilal.local",
        "role": "general",
        "groups": ["CN=AllEmployees,OU=Groups,DC=motilal,DC=local"]
    }


# ============== UNIFIED AUTHENTICATION INTERFACE ==============

class AuthenticationService:
    """Unified authentication service supporting multiple auth methods."""

    def __init__(self):
        self.session_manager = SessionManager()

    def authenticate(
        self,
        username: str = None,
        password: str = None,
        auth_method: str = None,
        ip_address: str = "",
        user_agent: str = ""
    ) -> Optional[Session]:
        """Authenticate user and create session."""
        config = load_auth_config()
        method = auth_method or config.get("auth_method", "mock")

        user_info = None

        if method == "mock":
            user_info = authenticate_mock(username, password)
        elif method == "ldap":
            user_info = authenticate_ldap(username, password)
        # SAML and OAuth are handled separately via their specific endpoints

        if not user_info:
            return None

        return self.session_manager.create_session(
            user_id=user_info["user_id"],
            user_email=user_info["email"],
            user_role=user_info["role"],
            user_groups=user_info["groups"],
            auth_method=method,
            ip_address=ip_address,
            user_agent=user_agent
        )

    def authenticate_saml(
        self,
        user_info: Dict[str, Any],
        ip_address: str = "",
        user_agent: str = ""
    ) -> Optional[Session]:
        """Create session from SAML authentication."""
        if not user_info:
            return None

        return self.session_manager.create_session(
            user_id=user_info["user_id"],
            user_email=user_info["email"],
            user_role=user_info["role"],
            user_groups=user_info["groups"],
            auth_method="saml",
            ip_address=ip_address,
            user_agent=user_agent
        )

    def authenticate_oauth(
        self,
        user_info: Dict[str, Any],
        ip_address: str = "",
        user_agent: str = ""
    ) -> Optional[Session]:
        """Create session from OAuth authentication."""
        if not user_info:
            return None

        return self.session_manager.create_session(
            user_id=user_info["user_id"],
            user_email=user_info["email"],
            user_role=user_info["role"],
            user_groups=user_info["groups"],
            auth_method="oauth",
            ip_address=ip_address,
            user_agent=user_agent
        )

    def validate_session(self, session_id: str) -> Optional[Session]:
        """Validate session and return session object."""
        return self.session_manager.get_session(session_id)

    def logout(self, session_id: str):
        """Logout user by invalidating session."""
        self.session_manager.invalidate_session(session_id)

    def check_permission(self, session: Session, permission: str) -> bool:
        """Check if session has a specific permission."""
        if not session:
            return False
        return session.permissions.get(permission, False)

    def get_rate_limits(self, session: Session) -> Dict[str, int]:
        """Get rate limits for session."""
        if not session:
            return {"per_hour": 10, "per_day": 50}

        return {
            "per_hour": session.permissions.get("rate_limit_per_hour", 20),
            "per_day": session.permissions.get("rate_limit_per_day", 100)
        }


# ============== RBAC HELPER FUNCTIONS ==============

def get_user_permissions(role: str) -> Dict[str, Any]:
    """Get permissions for a role."""
    config = load_auth_config()
    return config.get("role_permissions", {}).get(role, {})


def can_access_external_ai(role: str) -> bool:
    """Check if role can access external AI."""
    permissions = get_user_permissions(role)
    return permissions.get("external_ai", False)


def can_access_local_llm(role: str) -> bool:
    """Check if role can access local LLM."""
    permissions = get_user_permissions(role)
    return permissions.get("local_llm", False)


def can_access_admin_dashboard(role: str) -> bool:
    """Check if role can access admin dashboard."""
    permissions = get_user_permissions(role)
    return permissions.get("admin_dashboard", False)


# Singleton instance
auth_service = AuthenticationService()
