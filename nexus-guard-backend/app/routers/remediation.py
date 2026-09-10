from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import models
from ..database import get_db

router = APIRouter(prefix="/remediation", tags=["Remediation"])


@router.get("/ranked")
def remediation_ranking(db: Session = Depends(get_db)):
    """Which single fix reduces the most risk — sorted by estimated_impact,
    not by severity, so the highest-leverage action surfaces first."""
    findings = db.query(models.Finding).filter(models.Finding.status == "open").all()
    ranked = sorted(findings, key=lambda f: f.estimated_impact, reverse=True)
    return [{
        "finding_id": f.id, "title": f.title, "device_id": f.device_id,
        "severity": f.severity, "estimated_impact_pct": f.estimated_impact,
        "risk_score": f.risk_score,
    } for f in ranked]


@router.post("/{finding_id}/mark-fixed")
def mark_fixed(finding_id: int, db: Session = Depends(get_db)):
    """Marks a finding as fixed for real (distinct from the What-if
    Simulator, which never writes to the database)."""
    f = db.query(models.Finding).get(finding_id)
    if not f:
        return {"error": "Finding not found"}
    f.status = "fixed"
    db.commit()
    return {"finding_id": finding_id, "status": "fixed"}
