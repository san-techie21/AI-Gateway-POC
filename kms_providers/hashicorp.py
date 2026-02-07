"""
HashiCorp Vault Integration
AI Gateway Enterprise

Uses HashiCorp Vault for secrets management.
Ideal for on-premise or multi-cloud deployments.
"""

import json
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta, timezone

from .base import SecretsManager, SecretType

# Indian Standard Time
IST = timezone(timedelta(hours=5, minutes=30))

def now_ist():
    return datetime.now(IST)


class HashiCorpVaultManager(SecretsManager):
    """
    HashiCorp Vault for secrets management.

    Requires:
        pip install hvac

    Configuration:
        - VAULT_ADDR (env var or parameter)
        - VAULT_TOKEN (env var or parameter)
    """

    def __init__(self, vault_addr: str = None, vault_token: str = None,
                 mount_point: str = "secret", path_prefix: str = "ai-gateway/"):
        """
        Initialize HashiCorp Vault client.

        Args:
            vault_addr: Vault server address (or VAULT_ADDR env var)
            vault_token: Vault token (or VAULT_TOKEN env var)
            mount_point: Secrets engine mount point
            path_prefix: Path prefix for all secrets
        """
        try:
            import hvac
            import os
        except ImportError:
            raise ImportError("hvac is required. Install with: pip install hvac")

        self.vault_addr = vault_addr or os.environ.get("VAULT_ADDR", "http://localhost:8200")
        self.vault_token = vault_token or os.environ.get("VAULT_TOKEN", "")
        self.mount_point = mount_point
        self.path_prefix = path_prefix

        self.client = hvac.Client(url=self.vault_addr, token=self.vault_token)

    def _full_path(self, key: str) -> str:
        """Get full path with prefix."""
        return f"{self.path_prefix}{key}"

    def get_secret(self, key: str) -> Optional[str]:
        """Retrieve a secret from HashiCorp Vault."""
        try:
            response = self.client.secrets.kv.v2.read_secret_version(
                path=self._full_path(key),
                mount_point=self.mount_point
            )

            data = response.get("data", {}).get("data", {})
            return data.get("value")

        except Exception as e:
            if "permission denied" in str(e).lower() or "not found" in str(e).lower():
                return None
            print(f"Error getting secret {key}: {e}")
            return None

    def set_secret(self, key: str, value: str, secret_type: SecretType = SecretType.API_KEY,
                   metadata: Dict[str, Any] = None) -> bool:
        """Store a secret in HashiCorp Vault."""
        try:
            secret_data = {
                "value": value,
                "type": secret_type.value,
                "updated_at": now_ist().isoformat(),
                "metadata": json.dumps(metadata or {})
            }

            self.client.secrets.kv.v2.create_or_update_secret(
                path=self._full_path(key),
                secret=secret_data,
                mount_point=self.mount_point
            )
            return True

        except Exception as e:
            print(f"Error setting secret {key}: {e}")
            return False

    def delete_secret(self, key: str) -> bool:
        """Delete a secret from HashiCorp Vault."""
        try:
            self.client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=self._full_path(key),
                mount_point=self.mount_point
            )
            return True
        except Exception as e:
            print(f"Error deleting secret {key}: {e}")
            return False

    def list_secrets(self, secret_type: Optional[SecretType] = None) -> List[str]:
        """List all secrets under the prefix."""
        secrets = []
        try:
            response = self.client.secrets.kv.v2.list_secrets(
                path=self.path_prefix.rstrip("/"),
                mount_point=self.mount_point
            )

            for key in response.get("data", {}).get("keys", []):
                secrets.append(key.rstrip("/"))

        except Exception as e:
            print(f"Error listing secrets: {e}")

        return secrets

    def rotate_secret(self, key: str, new_value: str) -> bool:
        """Rotate a secret (Vault automatically versions)."""
        existing = self.get_secret(key)
        if existing is None:
            return False
        return self.set_secret(key, new_value)

    def get_secret_versions(self, key: str) -> List[Dict[str, Any]]:
        """Get metadata about secret versions."""
        try:
            response = self.client.secrets.kv.v2.read_secret_metadata(
                path=self._full_path(key),
                mount_point=self.mount_point
            )

            versions = response.get("data", {}).get("versions", {})
            return [
                {
                    "version": int(v),
                    "created_time": data.get("created_time"),
                    "destroyed": data.get("destroyed", False),
                    "deleted": data.get("deletion_time", "") != ""
                }
                for v, data in versions.items()
            ]

        except Exception as e:
            print(f"Error listing versions for {key}: {e}")
            return []

    def health_check(self) -> Dict[str, Any]:
        """Check HashiCorp Vault connectivity."""
        try:
            if self.client.is_authenticated():
                return {
                    "status": "healthy",
                    "provider": "HashiCorp Vault",
                    "vault_addr": self.vault_addr,
                    "mount_point": self.mount_point
                }
            else:
                return {
                    "status": "unhealthy",
                    "provider": "HashiCorp Vault",
                    "error": "Not authenticated"
                }
        except Exception as e:
            return {
                "status": "unhealthy",
                "provider": "HashiCorp Vault",
                "error": str(e)
            }
