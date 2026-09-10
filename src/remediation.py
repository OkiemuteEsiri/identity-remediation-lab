"""Defensive identity remediation assessment engine using synthetic inventory only."""
from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from hashlib import sha256
from typing import Iterable

SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}

@dataclass(frozen=True)
class Identity:
    identity_id: str
    identity_type: str
    privileged: bool
    mfa_enabled: bool
    enabled: bool
    last_signin_days: int
    credential_age_days: int
    owner: str
    standing_privilege: bool
    break_glass: bool = False

    def __post_init__(self):
        if self.identity_type not in {"user", "service", "workload"}: raise ValueError("unsupported identity_type")
        if self.last_signin_days < 0 or self.credential_age_days < 0: raise ValueError("age values must be non-negative")
        if not self.identity_id.strip(): raise ValueError("identity_id required")

@dataclass(frozen=True)
class Finding:
    control_id: str
    title: str
    severity: str
    identity_id: str
    evidence: str
    remediation: str
    validation: str
    attack_techniques: tuple[str, ...]

    @property
    def finding_id(self) -> str:
        raw = f"{self.control_id}|{self.identity_id}".encode()
        return "IDR-" + sha256(raw).hexdigest()[:12].upper()

def _finding(control_id, title, severity, identity, evidence, remediation, validation, techniques):
    return Finding(control_id,title,severity,identity.identity_id,evidence,remediation,validation,tuple(techniques))

def assess(identity: Identity) -> list[Finding]:
    out=[]
    if identity.privileged and not identity.mfa_enabled and not identity.break_glass:
        out.append(_finding("ID-001","Privileged identity without MFA","critical",identity,"Privileged access is enabled without MFA.","Require phishing-resistant MFA for privileged access.","Reassess and confirm MFA is enforced before privilege use.",("T1078",)))
    if identity.privileged and identity.standing_privilege and not identity.break_glass:
        out.append(_finding("ID-002","Standing privileged access","high",identity,"Privileged rights are permanently assigned.","Replace standing access with eligible/JIT elevation where feasible.","Confirm privilege is inactive by default and activation is governed.",("T1078","T1098")))
    if identity.enabled and identity.last_signin_days >= 90:
        out.append(_finding("ID-003","Dormant enabled identity","high" if identity.privileged else "medium",identity,f"No sign-in for {identity.last_signin_days} days.","Validate business need; disable or remove stale identity.","Confirm identity is disabled/removed or exception is approved and time-bounded.",("T1078",)))
    if identity.identity_type in {"service","workload"} and identity.credential_age_days >= 180:
        out.append(_finding("ID-004","Aged non-human credential","high",identity,f"Credential age is {identity.credential_age_days} days.","Rotate credential and prefer managed/workload identity where supported.","Confirm old credential is revoked and replacement follows policy.",("T1552.001","T1078")))
    if not identity.owner.strip():
        out.append(_finding("ID-005","Identity missing accountable owner","medium",identity,"No owner is recorded.","Assign an accountable owner and review lifecycle controls.","Confirm ownership metadata is populated and review cadence established.",("T1098",)))
    return out

def assess_all(identities: Iterable[Identity]) -> list[Finding]:
    findings=[]
    for identity in identities: findings.extend(assess(identity))
    return sorted(findings,key=lambda f:(-SEVERITY_WEIGHT[f.severity],f.finding_id))

def posture_score(findings: Iterable[Finding], identity_count: int) -> float:
    findings=list(findings)
    if identity_count <= 0: return 100.0
    penalty=sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    return round(max(0.0,100-(penalty/(identity_count*4))*100),1)

def summary(findings: Iterable[Finding], identity_count: int) -> dict:
    rows=list(findings)
    return {"identity_count":identity_count,"finding_count":len(rows),"posture_score":posture_score(rows,identity_count),"by_severity":{s:sum(f.severity==s for f in rows) for s in SEVERITY_WEIGHT},"generated_at":datetime.now(timezone.utc).isoformat()}
