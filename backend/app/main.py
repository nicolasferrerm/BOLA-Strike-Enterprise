"""BOLA Strike Enterprise — FastAPI Application Entry Point."""
import os
from typing import Dict

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator

from app.api import endpoints
from app.api import ciso_telemetry
from app.version import __version__, __codename__

app = FastAPI(
    title="BOLA Strike Enterprise API",
    description="Distributed DevSecOps engine for API business logic vulnerability analysis",
    version=__version__
)

# CORS Configuration (F-011): Read allowed origins from environment for production flexibility.
# Default restricts to the local frontend dev server.
allowed_origins = [
    origin.strip()
    for origin in os.environ.get("CORS_ALLOWED_ORIGINS", "http://localhost:5173").split(",")
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],  # Restricted to only needed methods
    allow_headers=["X-API-Key", "Content-Type", "Authorization"],  # Restricted to needed headers
)

app.include_router(endpoints.router, prefix="/api/v1")
app.include_router(ciso_telemetry.router, prefix="/api/v1", tags=["CISO Telemetry"])

# Prometheus Metrics Instrumentation
Instrumentator().instrument(app).expose(app)

@app.get("/")
def read_root() -> Dict[str, str]:
    """Health check endpoint returning engine status."""
    return {
        "message": "BOLA Strike Engine is running",
        "version": __version__,
        "codename": __codename__
    }

