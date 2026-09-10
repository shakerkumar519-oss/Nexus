"""
Deterministic security rule engine.

Design principle (per the product brief): AI may assist with interpreting
unfamiliar syntax (see `ai_assist_unknown_command` and the AI Configuration
Trainer flow), but the final compliance verdict for known patterns is always
produced by these deterministic, auditable rules — never by a model guess.
"""
import re
from typing import List, Dict

VENDOR_SIGNATURES = [
    (re.compile(r"config firewall|fortios|fortinet", re.I), "Fortinet"),
    (re.compile(r"set mgt-config|panorama|pan-os", re.I), "Palo Alto"),
    (re.compile(r"ios[\s-]xe|interface GigabitEthernet|line vty", re.I), "Cisco"),
    (re.compile(r"junos|set interfaces|set security", re.I), "Juniper"),
]

# Each rule maps a regex pattern -> a vendor-neutral concept + a deterministic
# compliance verdict + framework mapping + risk inputs. Framework control IDs
# below are DEMO mappings for prototype purposes, not verified official text.
RISK_RULES: List[Dict] = [
    dict(
        key="TELNET_ENABLED", concept="management_protocol",
        pattern=re.compile(r"transport input telnet", re.I),
        title="Telnet Management Enabled", severity="Critical",
        framework="STIG V-3000", asset="Management Plane", attack_path=True,
        why="Telnet transmits credentials and session data in clear text, allowing on-path credential capture on any intermediate segment.",
        recommendation="Disable Telnet and enforce SSHv2 with key-based authentication on all management lines.",
    ),
    dict(
        key="SNMP_DEFAULT_COMMUNITY", concept="monitoring",
        pattern=re.compile(r"community\s+public", re.I),
        title="SNMP Default Community String", severity="High",
        framework="NIST SP 800-53 CM-7", asset="Management Plane", attack_path=True,
        why="A default/public SNMP community string exposes device configuration data to any host that can reach the management network.",
        recommendation="Migrate to SNMPv3 with authPriv and remove default community strings.",
    ),
    dict(
        key="ACL_ANY_ANY", concept="acl",
        pattern=re.compile(r"permit\s+ip\s+any\s+any|srcaddr\s+\"?all\"?", re.I),
        title="Overly Permissive Firewall Rule / ACL", severity="Critical",
        framework="CIS 9.2", asset="Internal Network", attack_path=True,
        why="An unrestricted source/destination rule removes the intended access boundary and materially increases exposure of everything behind it.",
        recommendation="Scope source and destination address objects to only the required ranges and services.",
    ),
    dict(
        key="SESSION_TIMEOUT_DISABLED", concept="session_timeout",
        pattern=re.compile(r"timeout\s+0\b", re.I),
        title="Session / Idle Timeout Disabled", severity="Medium",
        framework="DISA STIG V-4212", asset="Management Plane", attack_path=False,
        why="A disabled idle timeout leaves authenticated management sessions open indefinitely on unattended terminals.",
        recommendation="Set an idle session timeout of 10 minutes or less on all administrative interfaces.",
    ),
    dict(
        key="WEAK_TLS", concept="encryption",
        pattern=re.compile(r"tls1[-_.]?0|sslv[23]", re.I),
        title="Outdated TLS/SSL Version Permitted", severity="Low",
        framework="NIST SP 800-53 SC-8", asset="Perimeter", attack_path=False,
        why="Deprecated TLS/SSL versions permit weak cipher suites vulnerable to downgrade-style attacks.",
        recommendation="Set the minimum TLS version to 1.2 or higher on all service profiles.",
    ),
    dict(
        key="PASSWORD_WEAK_ENCRYPTION", concept="password_policy",
        pattern=re.compile(r"password\s+7\s", re.I),
        title="Weak / Reversible Password Encryption Type", severity="High",
        framework="CIS 5.2", asset="Management Plane", attack_path=False,
        why="Type-7 password encoding is trivially reversible and does not protect stored credentials.",
        recommendation="Enable strong secret hashing (e.g. type 9/scrypt) for all local credentials.",
    ),
    dict(
        key="PASSWORD_ENCRYPTION_DISABLED", concept="password_policy",
        pattern=re.compile(r"no\s+service\s+password-encryption", re.I),
        title="Password Encryption Service Disabled", severity="High",
        framework="CIS 5.2", asset="Management Plane", attack_path=False,
        why="Disabling password encryption stores local secrets in a more easily readable form within the configuration file.",
        recommendation="Re-enable the password encryption service on the device.",
    ),
    dict(
        key="HTTP_MGMT_EXPOSED", concept="exposed_service",
        pattern=re.compile(r"http\s+enable|allowaccess[^\n]*\bhttp\b(?!s)", re.I),
        title="Unencrypted HTTP Management Service Exposed", severity="High",
        framework="CIS 9.2", asset="Management Plane", attack_path=True,
        why="An HTTP (non-TLS) management interface exposes session data and credentials to network-level interception.",
        recommendation="Disable HTTP management access and require HTTPS only.",
    ),
    dict(
        key="LOGGING_DISABLED", concept="logging",
        pattern=re.compile(r"logtraffic\s+disable|no\s+logging", re.I),
        title="Traffic / Event Logging Disabled", severity="Medium",
        framework="ISO 27001 A.12.4", asset="Segment", attack_path=False,
        why="Without logging, lateral movement or exploitation through this device cannot be reconstructed during incident response.",
        recommendation="Enable logging with forwarding to the central SIEM at an appropriate severity threshold.",
    ),
    dict(
        key="SUPERUSER_SPRAWL", concept="administrative_access",
        pattern=re.compile(r"role-based superuser yes|privilege\s+15", re.I),
        title="Excessive Administrative Access Assigned", severity="High",
        framework="CIS 5.1", asset="Management Plane", attack_path=True,
        why="Multiple accounts holding full administrative privilege widen the blast radius of a single compromised credential.",
        recommendation="Apply role-based access control and reduce standing superuser membership to break-glass accounts only.",
    ),
    dict(
        key="SEGMENTATION_GAP", concept="segmentation",
        pattern=re.compile(r"allowaccess[^\n]*\bssh\b[^\n]*\bhttps\b|dmz[^\n]*allowaccess", re.I),
        title="Segmentation Gap Between Untrusted and Internal Zone", severity="Critical",
        framework="ISO 27001 A.13.1", asset="Production Database", attack_path=True,
        why="A DMZ or untrusted interface that can directly reach internal management access removes the intended containment boundary.",
        recommendation="Insert an explicit deny rule between the untrusted zone and internal management ranges by default.",
    ),
]

# Severity -> base risk points (out of 100 scale contribution)
SEVERITY_WEIGHT = {"Critical": 40, "High": 28, "Medium": 16, "Low": 8}
CRITICALITY_WEIGHT = {"Critical": 25, "High": 18, "Medium": 10, "Low": 4}
ATTACK_PATH_WEIGHT = 20
CONFIDENCE_WEIGHT = 15  # scaled by confidence 0..1


def detect_vendor(raw_text: str) -> str:
    for pattern, vendor in VENDOR_SIGNATURES:
        if pattern.search(raw_text):
            return vendor
    return "Unknown / Generic"


def normalize_configuration(raw_text: str) -> List[Dict]:
    """Vendor-neutral concept extraction. Every matched rule becomes a
    normalized concept row; concepts with no rule match are not fabricated."""
    concepts = []
    for rule in RISK_RULES:
        m = rule["pattern"].search(raw_text)
        if m:
            line = raw_text[max(0, m.start() - 20): m.end() + 40].strip().splitlines()
            concepts.append(dict(
                concept=rule["concept"],
                raw_line=line[0] if line else m.group(0),
                verdict="non_compliant",
                confidence=1.0,  # deterministic rule match
            ))
    return concepts


def calculate_risk_score(severity: str, criticality: str, attack_path: bool, confidence: float = 1.0) -> float:
    score = SEVERITY_WEIGHT.get(severity, 10)
    score += CRITICALITY_WEIGHT.get(criticality, 8)
    score += ATTACK_PATH_WEIGHT if attack_path else 0
    score += CONFIDENCE_WEIGHT * confidence
    return round(min(score, 100), 1)


def estimate_remediation_impact(severity: str, attack_path: bool) -> float:
    base = {"Critical": 32, "High": 18, "Medium": 9, "Low": 4}.get(severity, 5)
    if attack_path:
        base += 10
    return round(min(base, 60), 1)


def run_compliance_rules(raw_text: str, device_criticality: str = "Medium") -> List[Dict]:
    """Deterministic verdicts: returns one finding dict per matched rule."""
    findings = []
    for rule in RISK_RULES:
        m = rule["pattern"].search(raw_text)
        if not m:
            continue
        snippet_lines = raw_text.splitlines()
        # grab a short evidence window around the match for readability
        match_line_idx = raw_text[:m.start()].count("\n")
        start = max(0, match_line_idx - 1)
        evidence = "\n".join(snippet_lines[start:match_line_idx + 2]).strip()

        risk = calculate_risk_score(rule["severity"], device_criticality, rule["attack_path"])
        impact = estimate_remediation_impact(rule["severity"], rule["attack_path"])

        findings.append(dict(
            finding_key=rule["key"],
            title=rule["title"],
            severity=rule["severity"],
            framework=rule["framework"],
            evidence=evidence or m.group(0),
            why_it_matters=rule["why"],
            recommendation=rule["recommendation"],
            asset=rule["asset"],
            attack_path_involved=rule["attack_path"],
            risk_score=risk,
            estimated_impact=impact,
        ))
    return findings


# ---- AI-assisted interpretation for UNFAMILIAR syntax only ----
# This is a heuristic keyword matcher standing in for a model call. It never
# issues a final compliance verdict — it only proposes a concept + label for
# a human to Accept / Edit / Reject in the AI Configuration Trainer.
CONCEPT_KEYWORDS = {
    "session_timeout": ["timeout", "idle", "session-expire"],
    "acl": ["acl", "any-any", "zone-trust", "policy-object"],
    "password_policy": ["complexity", "password", "auth-profile", "min-length"],
    "exposed_service": ["http", "port 80", "mgmt-service", "enable port"],
    "encryption": ["tls", "ssl", "cipher"],
    "logging": ["log", "syslog", "audit"],
    "administrative_access": ["superuser", "privilege", "admin-role"],
}


def ai_assist_unknown_command(raw_command: str):
    text = raw_command.lower()
    best_concept, best_hits = "uncategorized", 0
    for concept, keywords in CONCEPT_KEYWORDS.items():
        hits = sum(1 for kw in keywords if kw in text)
        if hits > best_hits:
            best_concept, best_hits = concept, hits

    if best_hits == 0:
        return dict(suggested_concept="uncategorized",
                     suggested_label="No confident interpretation — needs manual review",
                     confidence=0.0)

    confidence = round(min(0.55 + best_hits * 0.18, 0.97), 2)
    labels = {
        "session_timeout": "Possible administrative session timeout setting",
        "acl": "Possible access-control / zone policy binding",
        "password_policy": "Possible local authentication complexity policy",
        "exposed_service": "Possible unencrypted management service exposure",
        "encryption": "Possible TLS/SSL configuration parameter",
        "logging": "Possible logging/audit configuration",
        "administrative_access": "Possible administrative privilege assignment",
    }
    return dict(suggested_concept=best_concept,
                suggested_label=labels.get(best_concept, "Possible security-relevant setting"),
                confidence=confidence)
