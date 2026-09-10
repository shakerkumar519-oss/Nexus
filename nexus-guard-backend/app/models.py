import datetime
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, Text, DateTime, ForeignKey
)
from sqlalchemy.orm import relationship
from .database import Base


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="analyst")  # analyst | admin


class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True, nullable=False)
    vendor = Column(String, default="Unknown")
    device_type = Column(String, default="Unclassified")
    os_version = Column(String, default="")
    criticality = Column(String, default="Medium")  # Critical | High | Medium | Low
    ip_address = Column(String, default="")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    configurations = relationship("Configuration", back_populates="device", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="device", cascade="all, delete-orphan")


class Configuration(Base):
    """A single ingested/versioned raw configuration for a device."""
    __tablename__ = "configurations"
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"))
    raw_text = Column(Text, nullable=False)
    detected_vendor = Column(String, default="Unknown")
    line_count = Column(Integer, default=0)
    uploaded_at = Column(DateTime, default=datetime.datetime.utcnow)
    is_baseline = Column(Boolean, default=False)  # first ingested version for the device

    device = relationship("Device", back_populates="configurations")
    concepts = relationship("NormalizedConcept", back_populates="configuration", cascade="all, delete-orphan")


class NormalizedConcept(Base):
    """A single vendor-neutral security concept extracted from a configuration."""
    __tablename__ = "normalized_concepts"
    id = Column(Integer, primary_key=True, index=True)
    configuration_id = Column(Integer, ForeignKey("configurations.id"))
    concept = Column(String, nullable=False)   # e.g. management_protocol, firewall_rule, acl ...
    raw_line = Column(Text, default="")
    verdict = Column(String, default="review")  # compliant | non_compliant | review
    confidence = Column(Float, default=1.0)      # 1.0 = deterministic rule, <1.0 = AI-assisted guess

    configuration = relationship("Configuration", back_populates="concepts")


class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"))
    configuration_id = Column(Integer, ForeignKey("configurations.id"), nullable=True)
    finding_key = Column(String, index=True)     # rule key, e.g. TELNET_ENABLED
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False)     # Critical | High | Medium | Low
    framework = Column(String, default="")        # e.g. "CIS 9.2"
    evidence = Column(Text, default="")
    why_it_matters = Column(Text, default="")
    recommendation = Column(Text, default="")
    asset = Column(String, default="")
    attack_path_involved = Column(Boolean, default=False)
    risk_score = Column(Float, default=0.0)
    estimated_impact = Column(Float, default=0.0)  # % risk reduction if fixed
    status = Column(String, default="open")        # open | accepted_risk | fixed
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    device = relationship("Device", back_populates="findings")


class UnknownMapping(Base):
    """AI Configuration Trainer queue — unfamiliar syntax awaiting human review."""
    __tablename__ = "unknown_mappings"
    id = Column(Integer, primary_key=True, index=True)
    raw_command = Column(Text, nullable=False)
    suggested_concept = Column(String, default="")
    suggested_label = Column(String, default="")
    confidence = Column(Float, default=0.0)
    status = Column(String, default="pending")  # pending | accepted | rejected | edited
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class ComplianceSnapshot(Base):
    """Daily org-wide compliance score, used for regression monitoring."""
    __tablename__ = "compliance_snapshots"
    id = Column(Integer, primary_key=True, index=True)
    score = Column(Float, nullable=False)
    taken_at = Column(DateTime, default=datetime.datetime.utcnow)
    note = Column(String, default="")
