from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, schemas
from ..database import get_db

router = APIRouter(prefix="/findings", tags=["Findings"])


@router.get("", response_model=List[schemas.FindingOut])
def list_findings(
    severity: Optional[str] = None,
    framework: Optional[str] = None,
    device_id: Optional[int] = None,
    attack_path_only: bool = False,
    sort_by_risk: bool = True,
    db: Session = Depends(get_db),
):
    q = db.query(models.Finding)
    if severity:
        q = q.filter(models.Finding.severity == severity)
    if framework:
        q = q.filter(models.Finding.framework.ilike(f"%{framework}%"))
    if device_id:
        q = q.filter(models.Finding.device_id == device_id)
    if attack_path_only:
        q = q.filter(models.Finding.attack_path_involved.is_(True))
    results = q.all()
    if sort_by_risk:
        results.sort(key=lambda f: f.risk_score, reverse=True)
    return results


@router.get("/{finding_id}", response_model=schemas.FindingOut)
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    f = db.query(models.Finding).get(finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    return f


@router.get("/priority/ranked")
def risk_prioritization(db: Session = Depends(get_db)):
    """Groups open findings into Critical/High/Medium/Low tiers, each
    ordered by risk score — this is the Risk Prioritization Engine view."""
    findings = db.query(models.Finding).filter(models.Finding.status == "open").all()
    tiers = {"Critical": [], "High": [], "Medium": [], "Low": []}
    for f in sorted(findings, key=lambda x: x.risk_score, reverse=True):
        tiers.setdefault(f.severity, []).append({
            "id": f.id, "title": f.title, "device_id": f.device_id,
            "asset": f.asset, "risk_score": f.risk_score,
            "attack_path_involved": f.attack_path_involved,
        })
    return tiers
