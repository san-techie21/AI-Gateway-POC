"""
Secrets Management Module
AI Gateway Enterprise - Motilal Oswal Financial Services

Secure API key and credentials management with support for:
- AWS KMS
- Azure Key Vault
- HashiCorp Vault
- Local encrypted vault (development)
"""

from .base import SecretsManager, SecretType
from .local_vault import LocalVaultManager

# Conditional imports for cloud providers
try:
    from .aws_kms import AWSKMSManager
except ImportError:
    AWSKMSManager = None

try:
    from .azure_vault import AzureKeyVaultManager
except ImportError:
    AzureKeyVaultManager = None

try:
    from .hashicorp import HashiCorpVaultManager
except ImportError:
    HashiCorpVaultManager = None

__all__ = [
    "SecretsManager",
    "SecretType",
    "LocalVaultManager",
    "AWSKMSManager",
    "AzureKeyVaultManager",
    "HashiCorpVaultManager",
    "get_secrets_manager"
]


def get_secrets_manager(provider: str = "local", **kwargs) -> SecretsManager:
    """
    Factory function to get the appropriate secrets manager.

    Args:
        provider: One of "local", "aws", "azure", "hashicorp"
        **kwargs: Provider-specific configuration

    Returns:
        Configured SecretsManager instance
    """
    if provider == "local":
        return LocalVaultManager(**kwargs)

    elif provider == "aws":
        if AWSKMSManager is None:
            raise ImportError("boto3 is required for AWS KMS. Install with: pip install boto3")
        return AWSKMSManager(**kwargs)

    elif provider == "azure":
        if AzureKeyVaultManager is None:
            raise ImportError("azure-keyvault-secrets is required. Install with: pip install azure-keyvault-secrets azure-identity")
        return AzureKeyVaultManager(**kwargs)

    elif provider == "hashicorp":
        if HashiCorpVaultManager is None:
            raise ImportError("hvac is required for HashiCorp Vault. Install with: pip install hvac")
        return HashiCorpVaultManager(**kwargs)

    else:
        raise ValueError(f"Unknown secrets provider: {provider}")
