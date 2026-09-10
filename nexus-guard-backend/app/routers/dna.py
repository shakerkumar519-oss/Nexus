from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, security_rules
from ..database import get_db

router = APIRouter(prefix="/dna", tags=["Security DNA"])

DIMENSIONS = ["Exposure", "Access Control", "Encryption", "Logging", "Segmentation", "Authentication"]

CONCEPT_TO_DIMENSION = {
    "management_protocol": "Exposure",
    "exposed_service": "Exposure",
    "acl": "Access Control",
    "administrative_access": "Access Control",
    "encryption": "Encryption",
    "monitoring": "Logging",
    "logging": "Logging",
    "segmentation": "Segmentation",
    "session_timeout": "Authentication",
    "password_policy": "Authentication",
}

KEY_TO_CONCEPT = {rule["key"]: rule["concept"] for rule in security_rules.RISK_RULES}
SEVERITY_PENALTY = {"Critical": 30, "High": 20, "Medium": 12, "Low": 5}


def compute_dna(findings) -> dict:
    scores = {d: 100.0 for d in DIMENSIONS}
    for f in findings:
        concept = KEY_TO_CONCEPT.get(f.finding_key)
        dimension = CONCEPT_TO_DIMENSION.get(concept)
        if not dimension:
            continue
        scores[dimension] = max(0.0, scores[dimension] - SEVERITY_PENALTY.get(f.severity, 8))
    return {k: round(v, 1) for k, v in scores.items()}


@router.get("/device/{device_id}")
def device_dna(device_id: int, db: Session = Depends(get_db)):
    device = db.query(models.Device).get(device_id)
    if not device:
        raise HTTPException(404, "Device not found")
    findings = db.query(models.Finding).filter(
        models.Finding.device_id == device_id, models.Finding.status == "open"
    ).all()
    dna = compute_dna(findings)
    return {"device": device.name, "dimensions": dna, "overall": round(sum(dna.values()) / len(dna), 1)}


@router.get("/organization")
def organization_dna(db: Session = Depends(get_db)):
    findings = db.query(models.Finding).filter(models.Finding.status == "open").all()
    dna = compute_dna(findings)
    return {"scope": "organization", "dimensions": dna, "overall": round(sum(dna.values()) / len(dna), 1)}
