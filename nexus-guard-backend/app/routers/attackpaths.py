from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import models
from ..database import get_db

router = APIRouter(prefix="/attack-paths", tags=["Attack Paths"])

# Demo topology: a fixed reference topology used to describe *where* an
# attack-path finding sits, since the prototype does not yet ingest real
# routing/topology data. Swap this for a discovered topology in production.
TOPOLOGY_CHAIN = ["Internet", "Firewall", "Web Server", "Application Server", "Database"]

MITRE_MAP = {
    "TELNET_ENABLED": "T1557 — Adversary-in-the-Middle",
    "SNMP_DEFAULT_COMMUNITY": "T1590 — Gather Victim Network Information",
    "ACL_ANY_ANY": "T1190 — Exploit Public-Facing Application",
    "HTTP_MGMT_EXPOSED": "T1190 — Exploit Public-Facing Application",
    "SUPERUSER_SPRAWL": "T1078 — Valid Accounts",
    "SEGMENTATION_GAP": "T1210 — Exploitation of Remote Services",
}


@router.get("")
def list_attack_paths(db: Session = Depends(get_db)):
    findings = db.query(models.Finding).filter(
        models.Finding.attack_path_involved.is_(True),
        models.Finding.status == "open",
    ).all()

    paths = []
    for f in findings:
        device = db.query(models.Device).get(f.device_id)
        paths.append({
            "finding_id": f.id,
            "name": f"Entry → {device.name if device else 'Unknown device'} → {f.asset}",
            "entry_point": f"{f.title} on {device.name if device else 'unknown device'}",
            "chain": TOPOLOGY_CHAIN,
            "weakness": f.title,
            "affected_asset": f.asset,
            "risk_score": f.risk_score,
            "mitre_technique": MITRE_MAP.get(f.finding_key, "T1595 — Active Scanning"),
            "mitigation": f.recommendation,
        })
    paths.sort(key=lambda p: p["risk_score"], reverse=True)
    return paths
