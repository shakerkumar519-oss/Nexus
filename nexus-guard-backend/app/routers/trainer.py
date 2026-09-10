from typing import List
from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.orm import Session

from .. import models, schemas, security_rules
from ..database import get_db

router = APIRouter(prefix="/trainer", tags=["AI Configuration Trainer"])


@router.post("/submit-unknown", response_model=schemas.UnknownMappingOut)
def submit_unknown_command(raw_command: str = Body(..., embed=True), db: Session = Depends(get_db)):
    """A parser hit a command it doesn't recognize. Get a heuristic
    interpretation (never a final verdict) and queue it for human review."""
    suggestion = security_rules.ai_assist_unknown_command(raw_command)
    mapping = models.UnknownMapping(raw_command=raw_command, **suggestion)
    db.add(mapping)
    db.commit()
    db.refresh(mapping)
    return mapping


@router.get("/queue", response_model=List[schemas.UnknownMappingOut])
def get_queue(db: Session = Depends(get_db)):
    return db.query(models.UnknownMapping).filter(models.UnknownMapping.status == "pending").all()


@router.post("/{mapping_id}/decision", response_model=schemas.UnknownMappingOut)
def decide_mapping(mapping_id: int, decision: schemas.MappingDecision, db: Session = Depends(get_db)):
    mapping = db.query(models.UnknownMapping).get(mapping_id)
    if not mapping:
        raise HTTPException(404, "Mapping not found")
    if decision.status not in {"accepted", "rejected", "edited"}:
        raise HTTPException(400, "status must be accepted, rejected, or edited")
    mapping.status = decision.status
    if decision.status == "edited":
        if decision.corrected_concept:
            mapping.suggested_concept = decision.corrected_concept
        if decision.corrected_label:
            mapping.suggested_label = decision.corrected_label
        mapping.confidence = 1.0  # human-confirmed
    if decision.status == "accepted":
        mapping.confidence = max(mapping.confidence, 0.95)
    db.commit()
    db.refresh(mapping)
    return mapping


@router.get("/stats")
def trainer_stats(db: Session = Depends(get_db)):
    accepted = db.query(models.UnknownMapping).filter(models.UnknownMapping.status.in_(["accepted", "edited"])).all()
    pending = db.query(models.UnknownMapping).filter(models.UnknownMapping.status == "pending").count()
    vendor_patterns = len({m.suggested_concept for m in accepted})
    avg_conf = round(sum(m.confidence for m in accepted) / len(accepted) * 100, 1) if accepted else 0.0
    return {
        "learned_mappings": len(accepted),
        "vendor_patterns": vendor_patterns,
        "pending_review": pending,
        "avg_confidence_pct": avg_conf,
    }
