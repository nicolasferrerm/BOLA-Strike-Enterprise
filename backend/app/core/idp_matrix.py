"""BOLA Strike Enterprise — Multi-IdP Ephemeral Token Matrix (v12.0).

Generates and cycles through matrices of JWTs to validate Zero Trust
Architecture (ZTA) and cross-tenant authorization boundaries.

The signing secret MUST be provided externally (environment variable or
constructor argument).  No default secrets are embedded in source code.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class IdPMatrixFuzzer:
    """Generates cross-tenant JWT attack matrices for ZTA validation.

    Args:
        signing_secret: HMAC-SHA256 signing key.  Read from
            ``IDP_MATRIX_SECRET`` env var if not provided.
        tenant_pool: List of tenant IDs to generate tokens for.
        role_pool: List of roles to iterate.
    """

    def __init__(
        self,
        signing_secret: str | None = None,
        tenant_pool: List[str] | None = None,
        role_pool: List[str] | None = None,
    ) -> None:
        self.signing_secret = (
            signing_secret
            or os.environ.get("IDP_MATRIX_SECRET")
            or "CHANGE_ME_IN_PRODUCTION"
        )
        if self.signing_secret == "CHANGE_ME_IN_PRODUCTION":
            logger.warning(
                "[IdPMatrix] Using default signing secret! "
                "Set IDP_MATRIX_SECRET env var for production."
            )
        self.tenant_pool = tenant_pool or [
            "tenant-A-corp",
            "tenant-B-vendor",
            "tenant-C-admin",
        ]
        self.role_pool = role_pool or [
            "user",
            "manager",
            "auditor",
            "system_admin",
        ]
        self.generated_tokens: List[Dict[str, Any]] = []

    def _b64encode(self, data: Dict[str, Any]) -> str:
        """Base64url-encode a JSON dict (no padding)."""
        raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

    def generate_ephemeral_jwt(self, tenant_id: str, role: str, subject: str) -> str:
        """Forge a valid HS256 JWT for a specific tenant and role.

        Args:
            tenant_id: Target tenant identifier.
            role: Role claim to embed.
            subject: Subject (``sub``) claim value.

        Returns:
            Compact JWS string (``header.payload.signature``).
        """
        header = {"alg": "HS256", "typ": "JWT", "kid": "ephemeral-key-1"}
        payload = {
            "sub": subject,
            "tenant_id": tenant_id,
            "roles": [role],
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "iss": "https://bola-strike.idp.local",
            "aud": "enterprise-api",
        }

        h_b64 = self._b64encode(header)
        p_b64 = self._b64encode(payload)

        signature = hmac.new(
            self.signing_secret.encode("utf-8"),
            f"{h_b64}.{p_b64}".encode("utf-8"),
            hashlib.sha256,
        ).digest()
        s_b64 = base64.urlsafe_b64encode(signature).decode("utf-8").rstrip("=")

        return f"{h_b64}.{p_b64}.{s_b64}"

    def build_attack_matrix(self) -> List[Dict[str, Any]]:
        """Generate the full cross-tenant token matrix for ZTA validation.

        Returns:
            List of dicts, each containing tenant, role, token, and header.
        """
        matrix: List[Dict[str, Any]] = []
        for tenant in self.tenant_pool:
            for role in self.role_pool:
                subject = f"{role}@{tenant}.local"
                token = self.generate_ephemeral_jwt(tenant, role, subject)
                matrix.append(
                    {
                        "tenant": tenant,
                        "role": role,
                        "token": token,
                        "auth_header": f"Bearer {token}",
                    }
                )

        logger.info(
            "[IdPMatrix] Generated %d ephemeral tokens across %d tenants.",
            len(matrix),
            len(self.tenant_pool),
        )
        self.generated_tokens = matrix
        return matrix
