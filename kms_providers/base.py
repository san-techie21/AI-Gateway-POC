"""
Secrets Manager - Base Interface
AI Gateway Enterprise

Abstract base class for all secrets management implementations.
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from datetime import datetime


class SecretType(str, Enum):
    """Types of secrets managed by the gateway."""
    API_KEY = "api_key"              # Provider API keys
    DATABASE = "database"            # Database credentials
    OAUTH = "oauth"                  # OAuth client secrets
    CERTIFICATE = "certificate"      # SSL/TLS certificates
    ENCRYPTION_KEY = "encryption"    # Encryption keys
    WEBHOOK = "webhook"              # Webhook secrets
    INTEGRATION = "integration"      # Third-party integrations


@dataclass
class Secret:
    """Represents a secret with metadata."""
    key: str
    value: str
    secret_type: SecretType
    provider: str = ""               # Which AI provider this belongs to
    created_at: str = ""
    updated_at: str = ""
    expires_at: Optional[str] = None
    version: int = 1
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

    @property
    def is_expired(self) -> bool:
        """Check if secret has expired."""
        if not self.expires_at:
            return False
        return datetime.fromisoformat(self.expires_at) < datetime.now()


class SecretsManager(ABC):
    """
    Abstract base class for secrets management.

    All KMS implementations must inherit from this class and implement
    the abstract methods.
    """

    @abstractmethod
    def get_secret(self, key: str) -> Optional[str]:
        """
        Retrieve a secret value by key.

        Args:
            key: The secret key/name

        Returns:
            The secret value, or None if not found
        """
        pass

    @abstractmethod
    def set_secret(self, key: str, value: str, secret_type: SecretType = SecretType.API_KEY,
                   metadata: Dict[str, Any] = None) -> bool:
        """
        Store a secret.

        Args:
            key: The secret key/name
            value: The secret value
            secret_type: Type of secret
            metadata: Additional metadata

        Returns:
            True if successful
        """
        pass

    @abstractmethod
    def delete_secret(self, key: str) -> bool:
        """
        Delete a secret.

        Args:
            key: The secret key/name

        Returns:
            True if deleted successfully
        """
        pass

    @abstractmethod
    def list_secrets(self, secret_type: Optional[SecretType] = None) -> List[str]:
        """
        List all secret keys (not values).

        Args:
            secret_type: Optional filter by type

        Returns:
            List of secret key names
        """
        pass

    @abstractmethod
    def rotate_secret(self, key: str, new_value: str) -> bool:
        """
        Rotate a secret with a new value.

        This should maintain version history where supported.

        Args:
            key: The secret key/name
            new_value: The new secret value

        Returns:
            True if rotation successful
        """
        pass

    def get_provider_key(self, provider: str) -> Optional[str]:
        """
        Convenience method to get an AI provider's API key.

        Args:
            provider: Provider name (e.g., "openai", "anthropic")

        Returns:
            The API key or None
        """
        return self.get_secret(f"providers/{provider}/api_key")

    def set_provider_key(self, provider: str, api_key: str) -> bool:
        """
        Convenience method to set an AI provider's API key.

        Args:
            provider: Provider name
            api_key: The API key value

        Returns:
            True if successful
        """
        return self.set_secret(
            key=f"providers/{provider}/api_key",
            value=api_key,
            secret_type=SecretType.API_KEY,
            metadata={"provider": provider}
        )

    def health_check(self) -> Dict[str, Any]:
        """
        Check if the secrets manager is healthy and accessible.

        Returns:
            Health status dictionary
        """
        try:
            # Try to list secrets as a health check
            secrets = self.list_secrets()
            return {
                "status": "healthy",
                "provider": self.__class__.__name__,
                "secrets_count": len(secrets)
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "provider": self.__class__.__name__,
                "error": str(e)
            }


# Standard secret key paths
SECRET_PATHS = {
    # AI Provider API Keys
    "openai": "providers/openai/api_key",
    "anthropic": "providers/anthropic/api_key",
    "gemini": "providers/google/api_key",
    "deepseek": "providers/deepseek/api_key",
    "mistral": "providers/mistral/api_key",
    "groq": "providers/groq/api_key",
    "cohere": "providers/cohere/api_key",
    "together": "providers/together/api_key",
    "fireworks": "providers/fireworks/api_key",
    "perplexity": "providers/perplexity/api_key",

    # Azure OpenAI (needs endpoint + key)
    "azure_openai_key": "providers/azure_openai/api_key",
    "azure_openai_endpoint": "providers/azure_openai/endpoint",

    # AWS Bedrock (needs region + credentials)
    "aws_access_key": "providers/aws/access_key",
    "aws_secret_key": "providers/aws/secret_key",
    "aws_region": "providers/aws/region",

    # Database
    "database_url": "database/connection_string",

    # Integrations
    "siem_token": "integrations/siem/token",
    "ad_bind_password": "integrations/active_directory/bind_password",
    "webhook_secret": "integrations/webhook/secret",
}
