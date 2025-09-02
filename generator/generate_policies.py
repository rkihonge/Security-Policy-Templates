#!/usr/bin/env python3
import argparse, os, textwrap, yaml
from datetime import datetime

PASSWORD_TEMPLATE = """\
# {ORG_NAME} Password & Authentication Policy
**Version:** {CURRENT_VERSION} | **Effective date:** {EFFECTIVE_DATE} | **Owner:** {POLICY_OWNER} | **Review frequency:** {REVIEW_FREQUENCY}

## 1. Purpose
This policy defines requirements for the creation, protection, and use of authentication information to reduce the risk of unauthorized access.

## 2. Scope
This policy applies to all workforce members, contractors, third parties, service accounts, applications, and systems operated by or on behalf of {ORG_NAME}.

## 3. Roles & Responsibilities
- **Policy Owner:** {POLICY_OWNER} — maintains and reviews this policy.
- **IT Operations / IAM:** Implements technical controls (directory policies, SSO, MFA).
- **Managers:** Ensure staff compliance.
- **All Users:** Follow this policy and complete required training.

## 4. Policy Statements
- **Minimum length:** Passwords must be at least **{PASSWORD_MIN_LENGTH}** characters.
- **Complexity:** Encourage passphrases; avoid common or breached passwords.
- **MFA:** Multi-factor authentication is **{"required" if MFA_REQUIRED else "recommended"}** for all accounts supporting it, and required for admin access.
- **Storage:** Passwords must be stored using strong, salted, adaptive hashing (e.g., Argon2, scrypt, or bcrypt).
- **Rotation:** Routine rotation is not required unless risk indicates; however, administrative and service account secrets must be rotated at least every **{SERVICE_ACCOUNT_ROTATION_DAYS}** days and upon compromise or role change.
- **Reuse:** Disallow reuse of the last **{PASSWORD_REUSE_HISTORY}** passwords.
- **Default credentials:** Must be changed or disabled prior to production use.
- **Lockout:** After **{LOCKOUT_THRESHOLD}** failed attempts, lock account for **{LOCKOUT_DURATION_MIN}** minutes (or require admin unlock).
- **Password managers:** {ORG_NAME} {"permits" if PASSWORD_MANAGER_ALLOWED else "does not permit"} approved password managers for storing secrets.
- **Service accounts:** Use non-interactive credentials, least privilege, and managed secrets (vault). Rotate at least every **{SERVICE_ACCOUNT_ROTATION_DAYS}** days.

## 5. Technical Enforcement
Directory policies, identity provider (IdP), PAM, and vaulting solutions must enforce the requirements above wherever technically feasible.

## 6. Exceptions
Exceptions require risk assessment, written approval by the Policy Owner, and an expiry date.

## 7. Monitoring & Metrics
Track MFA coverage, lockout events, compromised password blocks, and exceptions.

## 8. Review & Maintenance
This policy is reviewed {REVIEW_FREQUENCY} and after material incidents or changes.

## 9. References & Control Mapping (indicative)
- ISO/IEC 27001:2022: Clause 5.2 (Policy), Annex A (e.g., **A.5.17 Authentication information**), and related access control objectives.

## 10. Document Control
- Version: {CURRENT_VERSION}
- Effective date: {EFFECTIVE_DATE}
- Approved by: {POLICY_OWNER}
"""

IR_TEMPLATE = """\
# {ORG_NAME} Incident Response (IR) Policy
**Version:** {CURRENT_VERSION} | **Effective date:** {EFFECTIVE_DATE} | **Owner:** {POLICY_OWNER} | **Review frequency:** {REVIEW_FREQUENCY}

## 1. Purpose
Define how {ORG_NAME} prepares for, detects, analyzes, responds to, and learns from information security incidents.

## 2. Scope
All information systems, data, employees, contractors, and third-party providers.

## 3. Definitions
- **Event:** Observable occurrence.
- **Incident:** Event that compromises confidentiality, integrity, or availability.
- **Severity:** Levels 1–4 (Critical to Low) defined in the IR playbook.

## 4. Roles & RACI
- **Incident Manager:** {INCIDENT_MANAGER}
- **Policy Owner:** {POLICY_OWNER}
- **Legal:** {LEGAL_CONTACT}
- **Comms/PR, HR, Forensics, IT Ops:** As per IR playbook.

## 5. IR Lifecycle
1. **Preparation:** Tools, access, playbooks, exercises (**{IR_EXERCISE_FREQUENCY}**).
2. **Detection & Reporting:** SIEM alerts, user reports, supplier notices.
3. **Triage & Analysis:** Classify severity, scope impact, forensics.
4. **Containment, Eradication, Recovery:** Short/long-term containment, clean-up, validated recovery.
5. **Post-Incident:** Lessons learned within 10 business days; update controls.

## 6. Communications & Escalation
Internal leadership, regulators, customers, law enforcement as applicable; follow pre-approved templates and notification SLAs.

## 7. Evidence Handling
Follow chain of custody; preserve volatile data; coordinate with Legal.

## 8. Testing & Exercises
Tabletop and technical exercises at least **{IR_EXERCISE_FREQUENCY}**; track action items.

## 9. Metrics
MTTD, MTTR, incidents by severity, repeat incident classes.

## 10. Review & Maintenance
Review {REVIEW_FREQUENCY} and after major incidents.

## 11. References & Control Mapping (indicative)
ISO/IEC 27001:2022: Clause 8 (Operation), Clause 9 (Performance), Annex A (e.g., **A.5.24–A.5.28** incident management series).

## 12. Document Control
- Version: {CURRENT_VERSION}
- Effective date: {EFFECTIVE_DATE}
- Approved by: {POLICY_OWNER}
"""

AUDIT_CHECKLIST_TEMPLATE = """\
# {ORG_NAME} ISO/IEC 27001:2022 Internal Audit Checklist
**Version:** {CURRENT_VERSION} | **Effective date:** {EFFECTIVE_DATE} | **Owner:** {POLICY_OWNER} | **Review frequency:** {REVIEW_FREQUENCY}

> Use this checklist to verify conformity of the ISMS (Clauses 4–10) and sample Annex A controls. Record **Status (Yes/No/Partial)** and **Evidence**.

## Clause 4 — Context of the Organization
- 4.1 Understanding org & context — Status: ___ Evidence: ___
- 4.2 Interested parties & requirements — Status: ___ Evidence: ___
- 4.3 ISMS scope documented — Status: ___ Evidence: ___
- 4.4 ISMS established, implemented, maintained — Status: ___ Evidence: ___

## Clause 5 — Leadership
- 5.1 Leadership & commitment demonstrated — Status: ___ Evidence: ___
- 5.2 Information security policy approved & communicated — Status: ___ Evidence: ___
- 5.3 Roles, responsibilities assigned — Status: ___ Evidence: ___

## Clause 6 — Planning
- 6.1 Risk assessment methodology applied — Status: ___ Evidence: ___
- 6.2 Information security objectives set & tracked — Status: ___ Evidence: ___
- SoA approved & maintained — Status: ___ Evidence: ___

## Clause 7 — Support
- 7.1 Resources adequate — Status: ___ Evidence: ___
- 7.2 Competence & training — Status: ___ Evidence: ___
- 7.3 Awareness activities — Status: ___ Evidence: ___
- 7.4 Communication plan — Status: ___ Evidence: ___
- 7.5 Documented information controlled — Status: ___ Evidence: ___

## Clause 8 — Operation
- Risk treatment plan executed — Status: ___ Evidence: ___
- Change management & operational controls — Status: ___ Evidence: ___
- Supplier/outsourcing controls applied — Status: ___ Evidence: ___

## Clause 9 — Performance Evaluation
- 9.1 Monitoring, measurement, analysis — Status: ___ Evidence: ___
- 9.2 Internal audits conducted per plan — Status: ___ Evidence: ___
- 9.3 Management review minutes & actions — Status: ___ Evidence: ___

## Clause 10 — Improvement
- 10.1 Nonconformities documented — Status: ___ Evidence: ___
- 10.2 Corrective actions tracked to closure — Status: ___ Evidence: ___

---

## Annex A — Spot Checks (indicative)
- Access & authentication (e.g., **A.5.17**) — Status: ___ Evidence: ___
- Logging & monitoring — Status: ___ Evidence: ___
- Vulnerability & patch management — Status: ___ Evidence: ___
- Backup & recovery — Status: ___ Evidence: ___
- Incident management (A.5.24–A.5.28) — Status: ___ Evidence: ___
- Supplier & cloud security — Status: ___ Evidence: ___
- Data classification & handling — Status: ___ Evidence: ___

## Findings & Actions
| Finding | Severity | Owner | Action | Due date | Status |
|--------|----------|-------|--------|----------|--------|
|        |          |       |        |          |        |

"""

README_TEMPLATE = """\
# Security Policy Templates (ISO/IEC 27001:2022)

This repo generates ready-to-customize **Password/Authentication Policy**, **Incident Response Policy**, and an **ISO 27001 Internal Audit Checklist** for {ORG_NAME}.

## How to use
1. Edit `config/org_config.yaml` to match your organization.
2. Run the generator:
   ```bash
   python3 generator/generate_policies.py --config config/org_config.yaml --out output
