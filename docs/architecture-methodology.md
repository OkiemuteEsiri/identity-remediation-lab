# Architecture and Methodology

## Objective

This lab models a defensive identity-remediation program that converts identity posture observations into prioritized corrective actions and explicit revalidation criteria. All records are synthetic and provider-neutral.

## Pipeline

```text
Synthetic identity inventory
        |
        v
Schema validation
        |
        v
Control evaluation
        |
        v
Deterministic findings
        |
        v
Severity-weighted posture score
        |
        v
Remediation owner / action / due date
        |
        v
Revalidation and closure evidence
```

## Implemented controls

- `ID-001` — privileged identity without MFA
- `ID-002` — standing privileged access
- `ID-003` — dormant enabled identity
- `ID-004` — aged non-human credential
- `ID-005` — missing accountable owner

The engine distinguishes emergency break-glass identities from ordinary privileged identities so that remediation logic does not blindly apply the same policy to every account. Break-glass accounts still require separate governance, monitoring and periodic validation outside the simplified controls implemented here.

## Risk model

Findings use Critical, High, Medium and Low severities with deterministic weights. A bounded posture score is derived from aggregate control failures relative to the number of identities assessed. The score is a prioritization and reporting aid; it is not a compromise score and should not be interpreted as evidence of malicious activity.

## MITRE ATT&CK context

Relevant defensive mappings include:

- `T1078` — Valid Accounts
- `T1098` — Account Manipulation
- `T1552.001` — Credentials In Files, used here as context for long-lived/static non-human credential exposure

ATT&CK mappings describe adversary relevance only. A control failure does not prove that the technique occurred.

## Remediation lifecycle

1. Confirm the identity record and evidence quality.
2. Assign an accountable owner.
3. Validate business need and privilege scope.
4. Apply the least disruptive durable control change.
5. Remove or reduce standing privilege where possible.
6. Enforce stronger authentication for privileged access.
7. Disable stale identities after ownership/business validation.
8. Rotate aged service credentials and prefer workload identity where available.
9. Re-run the assessment using the same control definition.
10. Retain closure evidence and monitor for regression.

## Validation standard

A ticket or remediation claim is not closure evidence. Suitable evidence may include a sanitized identity-policy export, access-review result, MFA enforcement state, privileged-role activation configuration, disabled-object state, credential rotation record, or repeatable test output. Public repositories should never contain real directory exports, credentials, access tokens, customer identity data or employer/client configuration.

## Limitations

This project does not connect to Active Directory, Entra ID, Okta or another live identity provider. It does not change accounts, disable users, rotate credentials, assign MFA, modify groups or perform privilege escalation. Its purpose is to demonstrate assessment, prioritization, governance and revalidation logic safely.
