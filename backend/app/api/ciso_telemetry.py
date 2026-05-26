"""
BOLA Strike Enterprise — FAIR-Model Executive Telemetry Pipeline (v12.0)

Translates technical vulnerability findings into quantifiable financial risk (USD/CAD)
using the Factor Analysis of Information Risk (FAIR) methodology.
Exposes a REST interface for the CISO Dashboard.
"""
import os
import logging

import jwt  # PyJWT implementation
from typing import Dict, Any
from fastapi import APIRouter, HTTPException, Header

logger = logging.getLogger(__name__)
router = APIRouter()

class FAIRRiskCalculator:
    """Factor Analysis of Information Risk (FAIR) engine.
    
    Computes Annualized Loss Expectancy (ALE) by crossing vulnerability
    severity with asset criticality from a simulated CMDB.
    """

    def __init__(self) -> None:
        # Simulated CMDB (Configuration Management Database) integrations
        self.asset_criticality = {
            "payments-api": {"value_at_risk_cad": 5000000, "regulatory_fines_cad": 10000000},
            "user-profile-api": {"value_at_risk_cad": 500000, "regulatory_fines_cad": 2000000},
            "default": {"value_at_risk_cad": 50000, "regulatory_fines_cad": 0}
        }

    def compute_financial_risk(self, finding: Dict[str, Any], service_name: str = "default") -> Dict[str, Any]:
        """
        Computes Annualized Loss Expectancy (ALE) based on severity and asset criticality.
        FAIR Simplified: Risk = Probable Event Frequency (PEF) * Probable Loss Magnitude (PLM)
        """
        asset = self.asset_criticality.get(service_name, self.asset_criticality["default"])
        
        severity = finding.get("severity", "INFO").upper()
        # PEF (Events per year based on severity/exploitability)
        pef_map = {"CRITICAL": 12.0, "HIGH": 4.0, "MEDIUM": 1.0, "LOW": 0.1, "INFO": 0.0}
        pef = pef_map.get(severity, 0.0)
        
        # Threat Intel Context (e.g., CISA KEV increases PEF)
        if (finding.get("threat_intel") or {}).get("actively_exploited"):
            pef *= 5.0 

        # PLM (Financial loss per event)
        plm = asset["value_at_risk_cad"] * (0.1 if severity == "HIGH" else 0.2 if severity == "CRITICAL" else 0.01)
        
        ale = pef * plm
        
        return {
            "asset_name": service_name,
            "probable_event_frequency_annual": pef,
            "probable_loss_magnitude_cad": plm,
            "annualized_loss_expectancy_cad": ale,
            "regulatory_exposure_cad": asset["regulatory_fines_cad"] if severity in ["HIGH", "CRITICAL"] else 0
        }

# Global Instance
fair_engine = FAIRRiskCalculator()

@router.post("/api/v1/telemetry/fair-risk")
async def calculate_risk(finding_data: Dict[str, Any], authorization: str = Header(None)):
    """
    REST endpoint for CISO Dashboard Data Lake.
    Enforces strict Zero-Trust with PyJWT cryptographic validation.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Zero-Trust Policy Violation: Missing Bearer Token")
        
    token = authorization.split(" ")[1]
    # JWT Verification — secret MUST be set via environment variable
    JWT_SECRET = os.environ.get("CISO_JWT_SECRET", "CHANGE_ME_IN_PRODUCTION")
    try:
        jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],
            audience="ciso_dashboard",
        )
        logger.info("CISO telemetry: JWT verified successfully.")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token Expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Cryptographic Verification Failed")
        
    service = finding_data.get("service_name", "default")
    risk_metrics = fair_engine.compute_financial_risk(finding_data, service_name=service)
    
    # Configurable Risk Appetite logic (Locked Server-Side)
    # The threshold is no longer trusted from the client. It is hardcoded or fetched from a secure ConfigMap.
    CORPORATE_RISK_APPETITE_CAD_LIMIT = 50000.0 
    
    breaches_appetite = risk_metrics["annualized_loss_expectancy_cad"] > CORPORATE_RISK_APPETITE_CAD_LIMIT
    
    return {
        "status": "success", 
        "fair_metrics": risk_metrics,
        "policy_evaluation": {
            "appetite_threshold_cad": CORPORATE_RISK_APPETITE_CAD_LIMIT,
            "breaches_appetite": breaches_appetite,
            "action": "BLOCK_PIPELINE" if breaches_appetite else "PASS"
        }
    }
