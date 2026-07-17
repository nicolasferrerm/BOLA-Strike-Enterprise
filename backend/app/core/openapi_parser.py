"""
BOLA Strike Enterprise — OpenAPI/Swagger v3 Parser (v7.0)
Autonomously discovers endpoints, parameters, bodies, and admin roles (BFLA context).

SECURITY HARDENING (F-003, F-004):
- SSRF: DNS resolution + ipaddress.is_private validation (replaces trivially-bypassable blocklist).
- LFI: Canonical path allowlist via os.path.realpath().startswith(BASE_DIR).
- HTTP redirects disabled to prevent SSRF via 302 chains.
"""

import json
import os
import socket
import ipaddress
import requests
import yaml
import logging
import urllib.parse
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# The base directory from which local spec files are allowed to be read.
# This prevents path traversal attacks (LFI).
ALLOWED_BASE_DIR = os.path.realpath(os.environ.get("BOLA_SPEC_BASE_DIR", os.getcwd()))


class OpenAPIParser:
    """
    Enterprise OpenAPI/Swagger v3 Parser for BOLA Strike.
    Autonomously discovers endpoints, required parameters, bodies, and administrative roles (BFLA context).
    """

    def __init__(self, source: str):
        self.source = source
        self.spec = self._load_spec()
        self.endpoints = []

    def _validate_url_safe(self, url: str) -> None:
        """
        SSRF Protection (F-003 Hardened):
        1. Parse the URL and extract the hostname.
        2. Resolve the hostname via DNS to get the actual IP.
        3. Verify the resolved IP is NOT private, loopback, reserved, or link-local.
        4. Block known metadata endpoints (AWS, GCP, Azure).

        This replaces the trivially-bypassable blocklist approach.
        """
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            raise ValueError("SSRF Protection: No hostname found in URL.")

        # Resolve the hostname to an IP address BEFORE making the request
        try:
            resolved_ip = socket.gethostbyname(hostname)
        except socket.gaierror:
            raise ValueError(f"SSRF Protection: Cannot resolve hostname '{hostname}'.")

        ip_obj = ipaddress.ip_address(resolved_ip)

        # Block all non-public IP ranges
        if ip_obj.is_private:
            raise ValueError(
                f"SSRF Protection: Resolved IP {resolved_ip} is in a private range (RFC1918). Blocked."
            )
        if ip_obj.is_loopback:
            raise ValueError(
                f"SSRF Protection: Resolved IP {resolved_ip} is a loopback address. Blocked."
            )
        if ip_obj.is_reserved:
            raise ValueError(
                f"SSRF Protection: Resolved IP {resolved_ip} is a reserved address. Blocked."
            )
        if ip_obj.is_link_local:
            raise ValueError(
                f"SSRF Protection: Resolved IP {resolved_ip} is a link-local address. Blocked."
            )

        # Block cloud metadata endpoints explicitly (defense-in-depth)
        metadata_ips = {"169.254.169.254", "100.100.100.200", "169.254.170.2"}
        if resolved_ip in metadata_ips:
            raise ValueError(
                f"SSRF Protection: Resolved IP {resolved_ip} is a cloud metadata endpoint. Blocked."
            )

        logger.info(
            f"[SSRF Guard] URL validated: {hostname} -> {resolved_ip} (public, allowed)"
        )

    def _validate_path_safe(self, path: str) -> str:
        """
        LFI Protection (F-004 Hardened):
        1. Resolve the canonical (real) path, following all symlinks.
        2. Verify it starts with the allowed base directory.

        This replaces the trivially-bypassable keyword blocklist approach.
        """
        canonical_path = os.path.realpath(path)

        try:
            is_within_base = os.path.commonpath(
                [canonical_path, ALLOWED_BASE_DIR]
            ) == os.path.commonpath([ALLOWED_BASE_DIR])
        except ValueError:
            is_within_base = False

        if not is_within_base:
            raise ValueError(
                f"LFI Protection: Path '{path}' resolves to '{canonical_path}', "
                f"which is outside the allowed base directory '{ALLOWED_BASE_DIR}'. Blocked."
            )

        if not os.path.isfile(canonical_path):
            raise ValueError(
                f"LFI Protection: Path '{canonical_path}' is not a file or does not exist."
            )

        logger.info(
            f"[LFI Guard] Path validated: {canonical_path} (within {ALLOWED_BASE_DIR})"
        )
        return canonical_path

    def _load_spec(self) -> Dict[str, Any]:
        try:
            if self.source.startswith("http://") or self.source.startswith("https://"):
                # Validate URL is safe (SSRF Protection)
                self._validate_url_safe(self.source)

                allow_insecure_tls = (
                    os.environ.get("BOLA_ALLOW_INSECURE_TLS", "false").lower() == "true"
                )
                response = requests.get(
                    self.source,
                    verify=not allow_insecure_tls,
                    timeout=15,
                    allow_redirects=False,  # F-003: Prevent SSRF via redirect chains
                )

                # If server responds with a redirect, block it
                if response.is_redirect or response.is_permanent_redirect:
                    raise ValueError(
                        f"SSRF Protection: Server responded with redirect to '{response.headers.get('Location')}'. "
                        f"Redirects are disabled for security. Use the direct URL instead."
                    )

                response.raise_for_status()
                content = response.text
            else:
                # Validate file path is safe (LFI Protection)
                safe_path = self._validate_path_safe(self.source)
                with open(safe_path, "r", encoding="utf-8") as f:
                    content = f.read()

            if self.source.endswith(".yaml") or self.source.endswith(".yml"):
                return yaml.safe_load(content)
            else:
                return json.loads(content)
        except ValueError:
            # Re-raise security validation errors without wrapping
            raise
        except Exception as e:
            raise ValueError(f"Failed to load OpenAPI spec from {self.source}: {e}")

    def _resolve_ref(self, ref: str) -> Dict[str, Any]:
        parts = ref.split("/")
        if parts[0] == "#":
            current = self.spec
            for part in parts[1:]:
                current = current.get(part, {})
            return current
        return {}

    def _generate_dummy_body(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        if not schema:
            return {}

        if "$ref" in schema:
            schema = self._resolve_ref(schema["$ref"])

        dummy = {}
        properties = schema.get("properties", {})
        for prop_name, prop_details in properties.items():
            prop_type = prop_details.get("type", "string")
            if prop_type == "string":
                if "format" in prop_details and prop_details["format"] == "uuid":
                    dummy[prop_name] = "00000000-0000-0000-0000-000000000000"
                elif "format" in prop_details and prop_details["format"] == "email":
                    dummy[prop_name] = "test@example.com"
                else:
                    dummy[prop_name] = "string_value"
            elif prop_type == "integer":
                dummy[prop_name] = 1
            elif prop_type == "boolean":
                dummy[prop_name] = True
            elif prop_type == "array":
                dummy[prop_name] = []
            elif prop_type == "object":
                dummy[prop_name] = {}
            else:
                dummy[prop_name] = None
        return dummy

    def parse(self) -> List[Dict[str, Any]]:
        paths = self.spec.get("paths", {})
        base_path = self.spec.get("servers", [{}])[0].get("url", "")
        # Normalize base path
        if base_path.endswith("/"):
            base_path = base_path[:-1]

        for path, path_item in paths.items():
            for method, operation in path_item.items():
                if method.lower() not in ["get", "post", "put", "delete", "patch"]:
                    continue

                tags = operation.get("tags", [])
                is_admin = any("admin" in tag.lower() for tag in tags)
                if "admin" in path.lower():
                    is_admin = True

                body = {}
                if "requestBody" in operation:
                    content = operation["requestBody"].get("content", {})
                    json_content = content.get("application/json", {})
                    schema = json_content.get("schema", {})
                    body = self._generate_dummy_body(schema)

                # We format path variables like {id} into something the mutator recognizes,
                # e.g., if Mutator expects {{ID}}, we convert it, but Mutator actually works on regex for UUIDs.
                # Let's keep {id} as is, Mutator will fuzz it.

                self.endpoints.append(
                    {
                        "path": f"{base_path}{path}",
                        "method": method.upper(),
                        "body": body if body else None,
                        "is_admin": is_admin,
                        "tags": tags,
                    }
                )

        return self.endpoints
