"""
Run this once after installing requirements to populate the database with
the same demo dataset used in the frontend prototype, so /docs and the UI
have something to show immediately.

    python seed.py
"""
import datetime
from app.database import SessionLocal, engine, Base
from app import models, security_rules, auth

Base.metadata.create_all(bind=engine)
db = SessionLocal()

SAMPLE_CONFIGS = {
    "Cisco-Router-01": dict(vendor="Cisco", device_type="Router", criticality="High", text="""
interface GigabitEthernet0/1
 ip address 10.10.2.1 255.255.255.0
!
line vty 0 4
 transport input telnet
 timeout 0
!
ip ssh server algorithm encryption aes128-cbc 3des-cbc
no service password-encryption
snmp-server community public RO
"""),
    "Fortinet-FW-01": dict(vendor="Fortinet", device_type="Firewall", criticality="Critical", text="""
config firewall policy
    edit 27
        set srcintf "wan1"
        set dstintf "internal"
        set srcaddr "all"
        set dstaddr "internal-web"
        set action accept
        set logtraffic disable
    next
end
config system interface
    edit "dmz"
        set allowaccess ping https ssh
    next
end
"""),
    "PaloAlto-FW-01": dict(vendor="Palo Alto", device_type="Firewall", criticality="Critical", text="""
set mgt-config users admin permissions role-based superuser yes
set deviceconfig system timeout 0
set ssl-tls-service-profile min-version tls1-0
"""),
    "Generic-EdgeAppliance-04": dict(vendor="Unknown", device_type="Appliance", criticality="Medium", text="""
auth-profile local-db min-complexity low
mgmt-service http enable port 80
"""),
}

print("Seeding devices + configurations + findings...")
for name, meta in SAMPLE_CONFIGS.items():
    device = db.query(models.Device).filter(models.Device.name == name).first()
    if not device:
        device = models.Device(name=name, vendor=meta["vendor"], device_type=meta["device_type"], criticality=meta["criticality"])
        db.add(device)
        db.commit()
        db.refresh(device)

    config = models.Configuration(
        device_id=device.id,
        raw_text=meta["text"],
        detected_vendor=security_rules.detect_vendor(meta["text"]),
        line_count=len([l for l in meta["text"].splitlines() if l.strip()]),
        is_baseline=True,
    )
    db.add(config)
    db.commit()
    db.refresh(config)

    for concept in security_rules.normalize_configuration(meta["text"]):
        db.add(models.NormalizedConcept(configuration_id=config.id, **concept))

    for f in security_rules.run_compliance_rules(meta["text"], device.criticality):
        db.add(models.Finding(device_id=device.id, configuration_id=config.id, **f))
    db.commit()

print("Seeding compliance snapshot history (for regression timeline demo)...")
history = [91, 89, 93, 84, 78]
base_time = datetime.datetime.utcnow() - datetime.timedelta(days=len(history))
for i, score in enumerate(history):
    snap = models.ComplianceSnapshot(score=score, taken_at=base_time + datetime.timedelta(days=i))
    db.add(snap)
db.commit()

print("Seeding AI Configuration Trainer queue...")
UNKNOWN = [
    "set idle-timer session-expire 0",
    "policy-object acl-bind zone-trust any-any permit",
]
for cmd in UNKNOWN:
    if not db.query(models.UnknownMapping).filter(models.UnknownMapping.raw_command == cmd).first():
        suggestion = security_rules.ai_assist_unknown_command(cmd)
        db.add(models.UnknownMapping(raw_command=cmd, **suggestion))
db.commit()

print("Seeding demo user (username: admin / password: nexusguard123)...")
if not db.query(models.User).filter(models.User.username == "admin").first():
    db.add(models.User(username="admin", hashed_password=auth.hash_password("nexusguard123"), role="admin"))
    db.commit()

db.close()
print("Done. Start the API with: uvicorn app.main:app --reload")
