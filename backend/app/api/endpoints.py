"""
BOLA Strike Enterprise — API Endpoints (v12.0)

Hardened: Auth required, rate limited, timing-safe IdP mock.
Addresses: F-001, F-002
"""

import os
import hmac
import time
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.workers.fuzzer import run_bola_fuzz
from app.core.security import verify_api_key, check_scan_rate_limit

logger = logging.getLogger(__name__)

router = APIRouter()


class ScanTarget(BaseModel):
    target_url: str
    target_id: str
    swagger_url: Optional[str] = None
    manual_endpoints: Optional[List[Dict[str, Any]]] = None
    users_config: Dict[str, Any]


class ScanResponse(BaseModel):
    task_id: str
    status: str


@router.post(
    "/scan/start",
    response_model=ScanResponse,
    dependencies=[Depends(verify_api_key), Depends(check_scan_rate_limit)],
)
def start_scan(target: ScanTarget) -> Dict[str, str]:
    """
    Launch a distributed BOLA fuzzing scan.
    Requires X-API-Key header. Rate limited to 10 scans/hour per IP.
    """
    target_dict = target.model_dump()
    task = run_bola_fuzz.delay(target_dict)
    logger.info(f"[API] Scan enqueued: task_id={task.id}, target={target.target_url}")
    return {"task_id": task.id, "status": "queued"}


@router.get("/scan/status/{task_id}", dependencies=[Depends(verify_api_key)])
def get_scan_status(task_id: str) -> Dict[str, Any]:
    """
    Poll the status of a running or completed fuzzing task.
    Requires X-API-Key header.
    """
    task = run_bola_fuzz.AsyncResult(task_id)
    if task.state == "PENDING":
        return {"task_id": task_id, "state": task.state, "status": "Pending..."}
    elif task.state != "FAILURE":
        return {"task_id": task_id, "state": task.state, "result": task.result}
    else:
        return {"task_id": task_id, "state": task.state, "status": str(task.info)}


class TokenRequest(BaseModel):
    client_id: str
    client_secret: str


@router.post("/mock-idp/token")
def mock_idp_token(request: TokenRequest):
    """
    Simulated OAuth2 Identity Provider endpoint for development/testing.

    SECURITY HARDENING (F-001):
    - Client secret read from environment variable (not hardcoded).
    - Comparison uses hmac.compare_digest() to prevent timing attacks.
    - Returns proper HTTP 401 on failure.
    """
    expected_secret = os.environ.get("IDP_CLIENT_SECRET")
    if not expected_secret:
        raise ValueError("IDP_CLIENT_SECRET environment variable must be set.")

    # Timing-safe comparison to prevent side-channel attacks
    if hmac.compare_digest(request.client_secret, expected_secret):
        return {
            "access_token": f"mocked_token_{request.client_id}_{int(time.time())}",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

    logger.warning(
        f"[Mock-IdP] Failed authentication attempt for client_id: {request.client_id}"
    )
    return JSONResponse(
        status_code=401,
        content={
            "error": "invalid_client",
            "error_description": "Client authentication failed.",
        },
    )
