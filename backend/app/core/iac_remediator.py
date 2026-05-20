"""
BOLA Strike Enterprise — Gateway-Native IaC Auto-Remediation (v10.0)
Automatically generates Infrastructure-as-Code (IaC) patches (e.g., Terraform/AWS WAF JSON) 
to remediate detected BOLA vulnerabilities at the API Gateway level before patching the code.
"""
import json
import uuid
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class IaCRemediator:
    def __init__(self, output_dir: str = "iac_patches"):
        self.output_dir = output_dir

    def generate_aws_waf_rule(self, finding: Dict[str, Any]) -> str:
        """
        Generates an AWS WAFv2 JSON rule to block the exact BOLA attack vector.
        Creates a regex pattern match on the vulnerable URI path to enforce strict UUID/ID matching
        or block known malicious payloads identified during fuzzing.
        """
        method = finding.get("method", "GET")
        path = finding.get("path", "/")
        
        # Simple heuristic: If it's a BOLA, block the specific malicious ID or enforce strict regex on the path
        rule_name = f"BOLAStrike-Block-{method}-{uuid.uuid4().hex[:8]}"
        
        waf_rule = {
            "Name": rule_name,
            "Priority": 0, # Placeholder, CI/CD pipeline should adjust
            "Statement": {
                "AndStatement": {
                    "Statements": [
                        {
                            "ByteMatchStatement": {
                                "SearchString": method,
                                "FieldToMatch": {
                                    "Method": {}
                                },
                                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                                "PositionalConstraint": "EXACTLY"
                            }
                        },
                        {
                            "RegexMatchStatement": {
                                # Replace trailing ID with generic matcher to protect the entire route
                                "RegexString": f"^{path.rsplit('/', 1)[0]}/[^/]+/?$",
                                "FieldToMatch": {
                                    "UriPath": {}
                                },
                                "TextTransformations": [{"Priority": 0, "Type": "URL_DECODE"}]
                            }
                        }
                    ]
                }
            },
            "Action": {
                "Block": {}
            },
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": rule_name
            }
        }
        
        return json.dumps(waf_rule, indent=2)

    def remediate(self, finding: Dict[str, Any], platform: str = "aws_waf") -> str:
        """Factory for generating platform-specific IaC patches."""
        if platform == "aws_waf":
            patch = self.generate_aws_waf_rule(finding)
            logger.info(f"[IaC] Generated AWS WAF auto-remediation rule for {finding.get('method')} {finding.get('path')}")
            return patch
        else:
            raise NotImplementedError(f"Platform {platform} is not yet supported for Auto-Remediation.")
