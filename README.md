# Identity Remediation Lab

A defensive Active Directory / Identity Security portfolio project focused on converting identity posture findings into prioritized remediation actions with explicit revalidation criteria.

## Problem statement

Identity findings often fail operationally for a simple reason: detection and remediation are treated as separate activities. Security teams may identify MFA gaps, stale identities, standing privilege or aged service credentials, but closure quality degrades when ownership, remediation intent and validation evidence are not modeled together.

This lab demonstrates a provider-neutral remediation workflow using synthetic identity data only.

## Architecture

```text
Synthetic identity inventory
        |
        v
Validation
        |
        v
Identity control engine
        |
        v
Deterministic findings
        |
        v
Severity-weighted posture scoring
        |
        v
Prioritized remediation plan
        |
        v
Revalidation / closure evidence
```

## Implemented controls

- privileged identity without MFA
- standing privileged access
- dormant enabled identity
- aged service/workload credential
- missing accountable owner
- break-glass exception handling for selected controls

## Repository structure

```text
src/remediation.py                  assessment models, controls, scoring and summary logic
data/synthetic_identities.json      realistic synthetic identity inventory
tests/test_remediation.py           10 unit tests
docs/architecture-methodology.md    architecture, control model and validation methodology
reports/example-assessment.md       recruiter-facing synthetic assessment example
.github/workflows/security-quality.yml
README.md
```

## Risk model

Findings use Critical, High, Medium and Low severity levels. The engine applies deterministic severity weights and calculates a bounded posture score across the assessed identity population. The score is intended for prioritization and reporting, not as proof of compromise.

## MITRE ATT&CK context

Relevant mappings include:

- **T1078 — Valid Accounts**
- **T1098 — Account Manipulation**
- **T1552.001 — Credentials In Files**

ATT&CK mappings describe plausible adversary relevance only. A configuration weakness does not prove that an ATT&CK technique occurred.

## Example remediation workflow

1. Validate the source identity record.
2. Confirm owner and business need.
3. Classify privilege and authentication exposure.
4. Prioritize remediation based on impact and severity.
5. Apply the durable control change through approved identity processes.
6. Re-run the same assessment logic.
7. Retain evidence proving the secure state.
8. Monitor for regression through recurring access review or CI-style policy validation.

## Running the tests

```bash
python -m unittest discover -s tests -v
```

The GitHub Actions workflow compiles the Python modules and executes the unit suite on pushes and pull requests with read-only repository permissions.

## Skills demonstrated

Identity Security Engineering, IAM governance, privileged-access remediation, MFA control analysis, stale-account governance, non-human identity risk, security data modeling, deterministic risk scoring, MITRE ATT&CK contextualization, Python testing, remediation validation, CI/CD security checks and recruiter-facing technical documentation.

## Limitations

This project deliberately does not connect to Active Directory, Entra ID, Okta or any live identity provider. It does not disable accounts, modify groups, rotate real credentials, assign roles, enforce MFA or perform offensive identity actions. All examples are synthetic.

## Roadmap

- provider adapter abstraction for sanitized exports
- exception/risk-acceptance lifecycle model
- due-date and SLA reporting
- privileged-access review metrics
- workload-identity migration recommendations
- Markdown/JSON remediation plan generation
- historical posture trend analysis

## Safety

No production identities, credentials, client/employer data, access tokens, directory exports, privilege-escalation tooling or live targeting are included.
