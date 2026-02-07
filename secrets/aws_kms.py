"""
AWS KMS / Secrets Manager Integration
AI Gateway Enterprise

Uses AWS Secrets Manager for secure secret storage with KMS encryption.
"""

import json
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta, timezone

from .base import SecretsManager, SecretType

# Indian Standard Time
IST = timezone(timedelta(hours=5, minutes=30))

def now_ist():
    return datetime.now(IST)


class AWSKMSManager(SecretsManager):
    """
    AWS Secrets Manager with KMS encryption.

    Requires:
        pip install boto3

    Configuration:
        - AWS_ACCESS_KEY_ID (env var or IAM role)
        - AWS_SECRET_ACCESS_KEY (env var or IAM role)
        - AWS_REGION (default: ap-south-1 for Mumbai)
    """

    def __init__(self, region: str = "ap-south-1", prefix: str = "ai-gateway/"):
        """
        Initialize AWS Secrets Manager.

        Args:
            region: AWS region (default: Mumbai)
            prefix: Secret name prefix for organization
        """
        try:
            import boto3
        except ImportError:
            raise ImportError("boto3 is required. Install with: pip install boto3")

        self.region = region
        self.prefix = prefix
        self.client = boto3.client("secretsmanager", region_name=region)

    def _full_key(self, key: str) -> str:
        """Get full secret name with prefix."""
        return f"{self.prefix}{key}"

    def get_secret(self, key: str) -> Optional[str]:
        """Retrieve a secret from AWS Secrets Manager."""
        try:
            response = self.client.get_secret_value(SecretId=self._full_key(key))

            # Handle both string and binary secrets
            if "SecretString" in response:
                secret_data = response["SecretString"]
                # Try to parse as JSON (common pattern)
                try:
                    parsed = json.loads(secret_data)
                    return parsed.get("value", secret_data)
                except json.JSONDecodeError:
                    return secret_data
            else:
                # Binary secret
                import base64
                return base64.b64decode(response["SecretBinary"]).decode()

        except self.client.exceptions.ResourceNotFoundException:
            return None
        except Exception as e:
            print(f"Error getting secret {key}: {e}")
            return None

    def set_secret(self, key: str, value: str, secret_type: SecretType = SecretType.API_KEY,
                   metadata: Dict[str, Any] = None) -> bool:
        """Store a secret in AWS Secrets Manager."""
        try:
            secret_data = json.dumps({
                "value": value,
                "type": secret_type.value,
                "updated_at": now_ist().isoformat(),
                "metadata": metadata or {}
            })

            full_key = self._full_key(key)

            try:
                # Try to update existing secret
                self.client.put_secret_value(
                    SecretId=full_key,
                    SecretString=secret_data
                )
            except self.client.exceptions.ResourceNotFoundException:
                # Create new secret
                self.client.create_secret(
                    Name=full_key,
                    SecretString=secret_data,
                    Description=f"AI Gateway - {secret_type.value}",
                    Tags=[
                        {"Key": "Application", "Value": "AI-Gateway"},
                        {"Key": "SecretType", "Value": secret_type.value},
                    ]
                )

            return True

        except Exception as e:
            print(f"Error setting secret {key}: {e}")
            return False

    def delete_secret(self, key: str) -> bool:
        """Delete a secret from AWS Secrets Manager."""
        try:
            self.client.delete_secret(
                SecretId=self._full_key(key),
                ForceDeleteWithoutRecovery=False,  # 30-day recovery window
                RecoveryWindowInDays=7
            )
            return True
        except Exception as e:
            print(f"Error deleting secret {key}: {e}")
            return False

    def list_secrets(self, secret_type: Optional[SecretType] = None) -> List[str]:
        """List all secrets with the gateway prefix."""
        secrets = []
        paginator = self.client.get_paginator("list_secrets")

        for page in paginator.paginate():
            for secret in page.get("SecretList", []):
                name = secret.get("Name", "")
                if name.startswith(self.prefix):
                    # Remove prefix for clean key name
                    clean_name = name[len(self.prefix):]
                    secrets.append(clean_name)

        return secrets

    def rotate_secret(self, key: str, new_value: str) -> bool:
        """Rotate a secret (creates new version)."""
        # AWS Secrets Manager automatically versions secrets
        # Just update the value
        existing = self.get_secret(key)
        if existing is None:
            return False

        return self.set_secret(key, new_value)

    def get_secret_versions(self, key: str) -> List[Dict[str, Any]]:
        """Get all versions of a secret."""
        try:
            response = self.client.list_secret_version_ids(
                SecretId=self._full_key(key)
            )
            return [
                {
                    "version_id": v.get("VersionId"),
                    "stages": v.get("VersionStages", []),
                    "created_date": v.get("CreatedDate").isoformat() if v.get("CreatedDate") else None
                }
                for v in response.get("Versions", [])
            ]
        except Exception as e:
            print(f"Error listing versions for {key}: {e}")
            return []

    def health_check(self) -> Dict[str, Any]:
        """Check AWS Secrets Manager connectivity."""
        try:
            # Try to list secrets (limited to 1)
            self.client.list_secrets(MaxResults=1)
            return {
                "status": "healthy",
                "provider": "AWS Secrets Manager",
                "region": self.region,
                "prefix": self.prefix
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "provider": "AWS Secrets Manager",
                "error": str(e)
            }
