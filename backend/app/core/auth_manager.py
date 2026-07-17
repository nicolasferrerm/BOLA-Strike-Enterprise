"""
BOLA Strike Enterprise — Multi-Role Identity Manager (v7.0)
Addresses: Audit v2.0 Task 2.2

Supports N configurable roles (not just attacker/victim) for NxN access matrix testing.
Automatically renews OAuth2/OIDC tokens with anti-stampede distributed locking.
"""

import time
import os
import requests
import logging
import threading
from typing import Dict, Any

logger = logging.getLogger(__name__)


class AuthManager:
    """
    Enterprise Identity Manager supporting arbitrary roles for cross-role BOLA matrix testing.

    Example config:
        users:
          admin: {auth_url: "...", client_id: "admin_app", client_secret_env: "ADMIN_SECRET"}
          editor: {token: "Bearer eyJ..."}
          viewer: {headers: {Authorization: "Bearer ..."}}
          guest: {}
    """

    def __init__(self, users_config: Dict[str, Any]):
        self.roles: Dict[str, Dict[str, Any]] = {}
        self.local_locks: Dict[str, threading.Lock] = {}

        for role, config in users_config.items():
            # Read client_secret from env var if specified (Vault-compatible)
            client_secret = config.get("client_secret")
            secret_env = config.get("client_secret_env")
            if secret_env:
                client_secret = os.environ.get(secret_env, client_secret or "")

            self.roles[role] = {
                "name": config.get("name", role),
                "auth_url": config.get("auth_url", ""),
                "client_id": config.get("client_id", f"bola_{role}"),
                "client_secret": client_secret or "",
                "token": config.get("token", None),
                "static_headers": config.get("headers", {}),
                "expires_at": time.time() + 300 if config.get("token") else 0,
            }
            self.local_locks[role] = threading.Lock()

        # Optional Redis for distributed lock
        self.redis = None
        try:
            import redis as redis_lib

            redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
            self.redis = redis_lib.from_url(redis_url, socket_timeout=1)
            self.redis.ping()
        except Exception:
            self.redis = None

    @property
    def role_names(self):
        """Return all configured role names."""
        return list(self.roles.keys())

    def get_role_pairs(self):
        """
        Generate all NxN cross-role pairs for matrix testing.
        Each pair is (requester_role, resource_owner_role) where requester != owner.
        """
        pairs = []
        for requester in self.role_names:
            for owner in self.role_names:
                if requester != owner:
                    pairs.append((requester, owner))
        return pairs

    def get_headers(
        self, role: str, base_headers: Dict[str, str] = None
    ) -> Dict[str, str]:
        """Get authenticated headers for a given role, refreshing token if needed."""
        headers = dict(base_headers or {})
        role_data = self.roles.get(role)
        if not role_data:
            return headers

        # Apply static headers first
        headers.update(role_data.get("static_headers", {}))

        # Dynamic token refresh if auth_url is configured
        if role_data["auth_url"]:
            if time.time() >= role_data["expires_at"] or not role_data["token"]:
                if self._acquire_lock(role):
                    try:
                        if (
                            time.time() >= role_data["expires_at"]
                            or not role_data["token"]
                        ):
                            self._refresh_token(role)
                    finally:
                        self._release_lock(role)
                else:
                    # Wait for another thread to finish refreshing
                    waited = 0.0
                    while waited < 5.0 and (
                        time.time() >= role_data["expires_at"] or not role_data["token"]
                    ):
                        time.sleep(0.1)
                        waited += 0.1

        if role_data["token"]:
            token = role_data["token"]
            if not token.startswith("Bearer "):
                token = f"Bearer {token}"
            headers["Authorization"] = token

        return headers

    def _acquire_lock(self, role: str) -> bool:
        if self.redis:
            return bool(
                self.redis.set(f"auth_refresh_lock_{role}", "locked", nx=True, ex=10)
            )
        return self.local_locks[role].acquire(blocking=False)

    def _release_lock(self, role: str):
        if self.redis:
            self.redis.delete(f"auth_refresh_lock_{role}")
        else:
            try:
                self.local_locks[role].release()
            except RuntimeError:
                pass

    def _refresh_token(self, role: str):
        role_data = self.roles[role]
        try:
            res = requests.post(
                role_data["auth_url"],
                json={
                    "client_id": role_data["client_id"],
                    "client_secret": role_data["client_secret"],
                },
                timeout=5,
            )
            if res.status_code == 200:
                data = res.json()
                role_data["token"] = data.get("access_token")
                role_data["expires_at"] = time.time() + data.get("expires_in", 3600)
                logger.info(f"[AuthManager] Token refreshed for role: {role}")
            else:
                logger.warning(
                    f"[AuthManager] Token renewal failed for {role}: HTTP {res.status_code}"
                )
        except Exception as e:
            logger.error(f"[AuthManager] Critical auth failure for {role}: {e}")
