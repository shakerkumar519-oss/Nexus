from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import models
from .database import engine
from .routers import (
    auth_router, devices, configs, findings, compliance,
    attackpaths, dna, remediation, simulator, trainer, reports,
)

models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="NEXUS-GUARD X API",
    description="AI-Driven Multi-Vendor Network Security Compliance Auditor — backend for SIH26155. "
                "AI assists with interpreting unfamiliar syntax; deterministic rules issue every "
                "final compliance verdict.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten this to your frontend origin before any real deployment
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router.router)
app.include_router(devices.router)
app.include_router(configs.router)
app.include_router(findings.router)
app.include_router(compliance.router)
app.include_router(attackpaths.router)
app.include_router(dna.router)
app.include_router(remediation.router)
app.include_router(simulator.router)
app.include_router(trainer.router)
app.include_router(reports.router)


@app.get("/")
def root():
    return {
        "service": "NEXUS-GUARD X API",
        "status": "online",
        "docs": "/docs",
        "note": "Prototype backend for SIH26155 — see README for demo seed instructions.",
    }


@app.get("/health")
def health():
    return {"status": "ok"}
