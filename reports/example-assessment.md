# Example Identity Remediation Assessment

> Synthetic demonstration output. This report does not represent a production tenant or confirmed compromise.

## Executive summary

The synthetic inventory contains privileged, dormant and non-human identities with deliberately mixed control maturity. The assessment is intended to show how identity findings can be converted into remediation actions with explicit validation criteria.

## Example prioritized findings

| Priority | Control | Example observation | Remediation direction |
|---|---|---|---|
| Critical | ID-001 | Privileged account without MFA | Require strong MFA for privileged access and validate enforcement |
| High | ID-002 | Standing privileged assignment | Replace standing privilege with eligible/JIT activation where feasible |
| High | ID-004 | Non-human credential older than policy target | Rotate and revoke old credential; prefer managed/workload identity |
| Medium | ID-003 | Enabled account inactive for more than 90 days | Validate business need then disable/remove or document exception |
| Medium | ID-005 | Identity lacks accountable owner | Assign owner and establish access-review cadence |

## ATT&CK relevance

- T1078 — Valid Accounts
- T1098 — Account Manipulation
- T1552.001 — Credentials In Files

These mappings provide threat context only. No ATT&CK technique is asserted as observed in this synthetic dataset.

## Closure criteria

A finding should not be treated as closed merely because a ticket exists. Revalidation should demonstrate the intended control state: MFA enforced, privilege no longer standing, identity disabled or justified, old credential revoked, or ownership recorded. Evidence should be retained through an approved enterprise process rather than committed to this public lab.
