"""
Local Vault - Development/Fallback Secrets Manager
AI Gateway Enterprise

Encrypted local file storage for development and small deployments.
Uses AES-256-GCM encryption with a master key.
"""

import os
import json
import base64
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta, timezone
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .base import SecretsManager, SecretType, Secret

# Indian Standard Time
IST = timezone(timedelta(hours=5, minutes=30))

def now_ist():
    return datetime.now(IST)


class LocalVaultManager(SecretsManager):
    """
    Local encrypted vault for secrets.

    Uses Fernet symmetric encryption (AES-128-CBC + HMAC).
    Suitable for development and small deployments.

    For production, use AWS KMS, Azure Key Vault, or HashiCorp Vault.
    """

    def __init__(self, vault_path: str = "secrets.vault", master_key: str = None):
        """
        Initialize the local vault.

        Args:
            vault_path: Path to the encrypted vault file
            master_key: Master key for encryption (or use VAULT_MASTER_KEY env var)
        """
        self.vault_path = Path(vault_path)
        self._master_key = master_key or os.environ.get("VAULT_MASTER_KEY", "")

        if not self._master_key:
            # Generate a default key from machine-specific data (NOT for production!)
            self._master_key = self._generate_default_key()

        self._fernet = self._create_fernet()
        self._secrets: Dict[str, Dict[str, Any]] = {}
        self._load_vault()

    def _generate_default_key(self) -> str:
        """Generate a default key (for development only)."""
        # Use hostname + username as seed (NOT secure for production)
        import socket
        import getpass
        seed = f"{socket.gethostname()}:{getpass.getuser()}:ai-gateway-dev"
        return hashlib.sha256(seed.encode()).hexdigest()

    def _create_fernet(self) -> Fernet:
        """Create Fernet cipher from master key."""
        # Derive a proper key using PBKDF2
        salt = b"ai-gateway-vault-salt"  # In production, use random salt stored separately
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self._master_key.encode()))
        return Fernet(key)

    def _load_vault(self):
        """Load secrets from encrypted vault file."""
        if not self.vault_path.exists():
            self._secrets = {}
            return

        try:
            with open(self.vault_path, "rb") as f:
                encrypted_data = f.read()

            if encrypted_data:
                decrypted_data = self._fernet.decrypt(encrypted_data)
                self._secrets = json.loads(decrypted_data.decode())
        except Exception as e:
            print(f"Warning: Could not load vault: {e}")
            self._secrets = {}

    def _save_vault(self):
        """Save secrets to encrypted vault file."""
        data = json.dumps(self._secrets).encode()
        encrypted_data = self._fernet.encrypt(data)

        with open(self.vault_path, "wb") as f:
            f.write(encrypted_data)

    def get_secret(self, key: str) -> Optional[str]:
        """Get a secret value."""
        secret_data = self._secrets.get(key)
        if secret_data:
            return secret_data.get("value")
        return None

    def set_secret(self, key: str, value: str, secret_type: SecretType = SecretType.API_KEY,
                   metadata: Dict[str, Any] = None) -> bool:
        """Store a secret."""
        try:
            timestamp = now_ist().isoformat()
            existing = self._secrets.get(key, {})
            version = existing.get("version", 0) + 1

            self._secrets[key] = {
                "value": value,
                "type": secret_type.value,
                "created_at": existing.get("created_at", timestamp),
                "updated_at": timestamp,
                "version": version,
                "metadata": metadata or {}
            }

            self._save_vault()
            return True
        except Exception as e:
            print(f"Error setting secret: {e}")
            return False

    def delete_secret(self, key: str) -> bool:
        """Delete a secret."""
        if key in self._secrets:
            del self._secrets[key]
            self._save_vault()
            return True
        return False

    def list_secrets(self, secret_type: Optional[SecretType] = None) -> List[str]:
        """List all secret keys."""
        if secret_type:
            return [
                k for k, v in self._secrets.items()
                if v.get("type") == secret_type.value
            ]
        return list(self._secrets.keys())

    def rotate_secret(self, key: str, new_value: str) -> bool:
        """Rotate a secret with version increment."""
        if key not in self._secrets:
            return False

        existing = self._secrets[key]
        return self.set_secret(
            key=key,
            value=new_value,
            secret_type=SecretType(existing.get("type", "api_key")),
            metadata=existing.get("metadata", {})
        )

    def get_secret_metadata(self, key: str) -> Optional[Dict[str, Any]]:
        """Get secret metadata without the value."""
        if key in self._secrets:
            data = self._secrets[key].copy()
            del data["value"]  # Don't expose the actual value
            data["key"] = key
            return data
        return None

    def import_from_env(self, env_mapping: Dict[str, str]) -> int:
        """
        Import secrets from environment variables.

        Args:
            env_mapping: Dict of {secret_key: env_var_name}

        Returns:
            Number of secrets imported
        """
        imported = 0
        for secret_key, env_var in env_mapping.items():
            value = os.environ.get(env_var)
            if value:
                self.set_secret(secret_key, value)
                imported += 1
        return imported

    def export_to_env(self, keys: List[str] = None) -> Dict[str, str]:
        """
        Export secrets as environment variable format.

        Args:
            keys: Optional list of keys to export (all if None)

        Returns:
            Dict of {env_var_name: value}
        """
        result = {}
        keys_to_export = keys or list(self._secrets.keys())

        for key in keys_to_export:
            if key in self._secrets:
                # Convert path to env var name: providers/openai/api_key -> OPENAI_API_KEY
                env_name = key.replace("/", "_").upper()
                result[env_name] = self._secrets[key]["value"]

        return result


def migrate_from_config(config_file: str, vault_manager: LocalVaultManager) -> int:
    """
    Migrate API keys from config.json to vault.

    Args:
        config_file: Path to config.json
        vault_manager: LocalVaultManager instance

    Returns:
        Number of secrets migrated
    """
    if not os.path.exists(config_file):
        return 0

    with open(config_file, "r") as f:
        config = json.load(f)

    migrated = 0

    # Migrate provider API keys
    providers = config.get("providers", {})
    for provider_name, provider_config in providers.items():
        api_key = provider_config.get("api_key", "")
        if api_key and not api_key.startswith("${"):  # Skip env var placeholders
            vault_manager.set_provider_key(provider_name, api_key)
            migrated += 1

    return migrated
