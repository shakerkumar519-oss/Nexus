from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, schemas
from ..database import get_db

router = APIRouter(prefix="/devices", tags=["Devices"])


@router.get("", response_model=List[schemas.DeviceOut])
def list_devices(db: Session = Depends(get_db)):
    return db.query(models.Device).order_by(models.Device.id).all()


@router.post("", response_model=schemas.DeviceOut)
def create_device(payload: schemas.DeviceCreate, db: Session = Depends(get_db)):
    device = models.Device(**payload.model_dump())
    db.add(device)
    db.commit()
    db.refresh(device)
    return device


@router.get("/{device_id}", response_model=schemas.DeviceOut)
def get_device(device_id: int, db: Session = Depends(get_db)):
    device = db.query(models.Device).get(device_id)
    if not device:
        raise HTTPException(404, "Device not found")
    return device


@router.get("/{device_id}/risk-summary")
def device_risk_summary(device_id: int, db: Session = Depends(get_db)):
    device = db.query(models.Device).get(device_id)
    if not device:
        raise HTTPException(404, "Device not found")
    findings = db.query(models.Finding).filter(models.Finding.device_id == device_id).all()
    if not findings:
        return {"device": device.name, "risk_score": 0, "open_findings": 0, "attack_path_findings": 0}
    top_risk = max(f.risk_score for f in findings)
    return {
        "device": device.name,
        "risk_score": top_risk,
        "open_findings": len([f for f in findings if f.status == "open"]),
        "attack_path_findings": len([f for f in findings if f.attack_path_involved]),
    }
