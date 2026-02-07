"""
Secrets Integration Helper
AI Gateway Enterprise

Simple integration to load API keys from KMS instead of config.json.
This is a minimal change that plugs into the existing system.

Usage in main.py:
    from secrets_integration import get_api_key, init_secrets_manager

    # Initialize once at startup
    init_secrets_manager(provider="local")  # or "aws", "azure", "hashicorp"

    # Then in call_external_api(), replace:
    api_key = provider_config.get("api_key", "")
    # With:
    api_key = get_api_key(provider) or provider_config.get("api_key", "")
"""

import os
from typing import Optional, Dict, Any

# The secrets manager instance (singleton)
_secrets_manager = None


def init_secrets_manager(
    provider: str = "local",
    vault_path: str = "secrets.vault",
    vault_url: str = None,
    region: str = "ap-south-1"
) -> bool:
    """
    Initialize the secrets manager.

    Args:
        provider: "local", "aws", "azure", or "hashicorp"
        vault_path: Path for local vault file
        vault_url: URL for Azure Key Vault
        region: AWS region for KMS

    Returns:
        True if initialized successfully
    """
    global _secrets_manager

    try:
        if provider == "local":
            from secrets.local_vault import LocalVaultManager
            _secrets_manager = LocalVaultManager(vault_path=vault_path)

        elif provider == "aws":
            from secrets.aws_kms import AWSKMSManager
            _secrets_manager = AWSKMSManager(region=region)

        elif provider == "azure":
            if not vault_url:
                vault_url = os.environ.get("AZURE_KEYVAULT_URL", "")
            if not vault_url:
                print("Warning: AZURE_KEYVAULT_URL not set")
                return False
            from secrets.azure_vault import AzureKeyVaultManager
            _secrets_manager = AzureKeyVaultManager(vault_url=vault_url)

        elif provider == "hashicorp":
            from secrets.hashicorp import HashiCorpVaultManager
            _secrets_manager = HashiCorpVaultManager()

        else:
            print(f"Unknown secrets provider: {provider}")
            return False

        print(f"Secrets manager initialized: {provider}")
        return True

    except ImportError as e:
        print(f"Failed to initialize {provider} secrets manager: {e}")
        return False
    except Exception as e:
        print(f"Error initializing secrets manager: {e}")
        return False


def get_api_key(provider_name: str) -> Optional[str]:
    """
    Get API key for a provider from the secrets manager.

    Falls back to None if secrets manager is not initialized or key not found.
    The caller should fall back to config.json.

    Args:
        provider_name: Provider name (e.g., "openai", "anthropic")

    Returns:
        API key string or None
    """
    global _secrets_manager

    if _secrets_manager is None:
        return None

    try:
        return _secrets_manager.get_provider_key(provider_name)
    except Exception:
        return None


def set_api_key(provider_name: str, api_key: str) -> bool:
    """
    Store API key for a provider in the secrets manager.

    Args:
        provider_name: Provider name
        api_key: The API key to store

    Returns:
        True if stored successfully
    """
    global _secrets_manager

    if _secrets_manager is None:
        return False

    try:
        return _secrets_manager.set_provider_key(provider_name, api_key)
    except Exception:
        return False


def get_secrets_health() -> Dict[str, Any]:
    """
    Get health status of the secrets manager.

    Returns:
        Health status dictionary
    """
    global _secrets_manager

    if _secrets_manager is None:
        return {
            "status": "not_initialized",
            "provider": None
        }

    return _secrets_manager.health_check()


def list_configured_providers() -> list:
    """
    Get list of providers that have API keys in the vault.

    Returns:
        List of provider names
    """
    global _secrets_manager

    if _secrets_manager is None:
        return []

    try:
        all_secrets = _secrets_manager.list_secrets()
        # Filter for provider API keys
        providers = []
        for key in all_secrets:
            if key.startswith("providers/") and key.endswith("/api_key"):
                # Extract provider name: providers/openai/api_key -> openai
                parts = key.split("/")
                if len(parts) >= 2:
                    providers.append(parts[1])
        return providers
    except Exception:
        return []


def migrate_config_to_vault(config_file: str = "config.json") -> Dict[str, Any]:
    """
    Migrate API keys from config.json to the secrets vault.

    This is a one-time operation. After migration, you can remove
    API keys from config.json (or keep them as fallback).

    Args:
        config_file: Path to config.json

    Returns:
        Migration result with counts
    """
    global _secrets_manager

    if _secrets_manager is None:
        return {"success": False, "error": "Secrets manager not initialized"}

    import json

    try:
        with open(config_file, "r") as f:
            config = json.load(f)
    except Exception as e:
        return {"success": False, "error": f"Could not read config: {e}"}

    migrated = 0
    skipped = 0
    errors = []

    providers = config.get("providers", {})
    for provider_name, provider_config in providers.items():
        api_key = provider_config.get("api_key", "")

        # Skip placeholder keys
        if not api_key or api_key.startswith("YOUR_"):
            skipped += 1
            continue

        # Try to store in vault
        if set_api_key(provider_name, api_key):
            migrated += 1
        else:
            errors.append(provider_name)

    return {
        "success": True,
        "migrated": migrated,
        "skipped": skipped,
        "errors": errors
    }


# Auto-initialize from environment variable if set
def _auto_init():
    """Auto-initialize secrets manager from environment."""
    secrets_provider = os.environ.get("AI_GATEWAY_SECRETS_PROVIDER", "")

    if secrets_provider:
        init_secrets_manager(provider=secrets_provider)


# Try auto-init on module load
_auto_init()
