"""
Azure Key Vault Integration
AI Gateway Enterprise

Uses Azure Key Vault for secure secret storage.
"""

import json
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta, timezone

from .base import SecretsManager, SecretType

# Indian Standard Time
IST = timezone(timedelta(hours=5, minutes=30))

def now_ist():
    return datetime.now(IST)


class AzureKeyVaultManager(SecretsManager):
    """
    Azure Key Vault for secrets management.

    Requires:
        pip install azure-keyvault-secrets azure-identity

    Configuration:
        - AZURE_TENANT_ID (env var)
        - AZURE_CLIENT_ID (env var)
        - AZURE_CLIENT_SECRET (env var)
        Or use Managed Identity (recommended for Azure-hosted apps)
    """

    def __init__(self, vault_url: str, use_managed_identity: bool = True):
        """
        Initialize Azure Key Vault client.

        Args:
            vault_url: Key Vault URL (e.g., https://mygateway-vault.vault.azure.net/)
            use_managed_identity: Use Azure Managed Identity (default True)
        """
        try:
            from azure.keyvault.secrets import SecretClient
            from azure.identity import DefaultAzureCredential, ManagedIdentityCredential
        except ImportError:
            raise ImportError(
                "Azure SDK is required. Install with: "
                "pip install azure-keyvault-secrets azure-identity"
            )

        self.vault_url = vault_url

        # Use appropriate credential
        if use_managed_identity:
            try:
                credential = ManagedIdentityCredential()
            except Exception:
                # Fall back to default credential chain
                credential = DefaultAzureCredential()
        else:
            credential = DefaultAzureCredential()

        self.client = SecretClient(vault_url=vault_url, credential=credential)

    def _normalize_key(self, key: str) -> str:
        """
        Normalize key name for Azure Key Vault.
        Azure doesn't allow '/' in secret names, so we replace with '--'.
        """
        return key.replace("/", "--")

    def _denormalize_key(self, key: str) -> str:
        """Convert Azure key back to original format."""
        return key.replace("--", "/")

    def get_secret(self, key: str) -> Optional[str]:
        """Retrieve a secret from Azure Key Vault."""
        try:
            secret = self.client.get_secret(self._normalize_key(key))

            # Try to parse as JSON
            try:
                parsed = json.loads(secret.value)
                return parsed.get("value", secret.value)
            except json.JSONDecodeError:
                return secret.value

        except Exception as e:
            if "SecretNotFound" in str(e):
                return None
            print(f"Error getting secret {key}: {e}")
            return None

    def set_secret(self, key: str, value: str, secret_type: SecretType = SecretType.API_KEY,
                   metadata: Dict[str, Any] = None) -> bool:
        """Store a secret in Azure Key Vault."""
        try:
            secret_data = json.dumps({
                "value": value,
                "type": secret_type.value,
                "updated_at": now_ist().isoformat(),
                "metadata": metadata or {}
            })

            self.client.set_secret(
                name=self._normalize_key(key),
                value=secret_data,
                content_type="application/json",
                tags={
                    "application": "ai-gateway",
                    "secret_type": secret_type.value,
                    "original_key": key
                }
            )
            return True

        except Exception as e:
            print(f"Error setting secret {key}: {e}")
            return False

    def delete_secret(self, key: str) -> bool:
        """Delete a secret from Azure Key Vault."""
        try:
            # Start deletion (soft delete by default)
            poller = self.client.begin_delete_secret(self._normalize_key(key))
            poller.result()  # Wait for completion
            return True
        except Exception as e:
            print(f"Error deleting secret {key}: {e}")
            return False

    def list_secrets(self, secret_type: Optional[SecretType] = None) -> List[str]:
        """List all secrets in the vault."""
        secrets = []

        try:
            for secret_properties in self.client.list_properties_of_secrets():
                original_key = self._denormalize_key(secret_properties.name)

                # Filter by type if specified
                if secret_type:
                    tags = secret_properties.tags or {}
                    if tags.get("secret_type") != secret_type.value:
                        continue

                secrets.append(original_key)

        except Exception as e:
            print(f"Error listing secrets: {e}")

        return secrets

    def rotate_secret(self, key: str, new_value: str) -> bool:
        """Rotate a secret (Azure automatically versions)."""
        existing = self.get_secret(key)
        if existing is None:
            return False
        return self.set_secret(key, new_value)

    def get_secret_versions(self, key: str) -> List[Dict[str, Any]]:
        """Get all versions of a secret."""
        versions = []
        try:
            for version in self.client.list_properties_of_secret_versions(
                self._normalize_key(key)
            ):
                versions.append({
                    "version": version.version,
                    "created_on": version.created_on.isoformat() if version.created_on else None,
                    "enabled": version.enabled,
                    "expires_on": version.expires_on.isoformat() if version.expires_on else None
                })
        except Exception as e:
            print(f"Error listing versions for {key}: {e}")

        return versions

    def health_check(self) -> Dict[str, Any]:
        """Check Azure Key Vault connectivity."""
        try:
            # Try to list secrets (just checking connectivity)
            next(self.client.list_properties_of_secrets(), None)
            return {
                "status": "healthy",
                "provider": "Azure Key Vault",
                "vault_url": self.vault_url
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "provider": "Azure Key Vault",
                "error": str(e)
            }

    def purge_deleted_secret(self, key: str) -> bool:
        """
        Permanently delete a soft-deleted secret.
        Only use if you're sure you want to permanently remove it.
        """
        try:
            self.client.purge_deleted_secret(self._normalize_key(key))
            return True
        except Exception as e:
            print(f"Error purging secret {key}: {e}")
            return False

    def recover_deleted_secret(self, key: str) -> bool:
        """Recover a soft-deleted secret."""
        try:
            poller = self.client.begin_recover_deleted_secret(self._normalize_key(key))
            poller.result()
            return True
        except Exception as e:
            print(f"Error recovering secret {key}: {e}")
            return False
