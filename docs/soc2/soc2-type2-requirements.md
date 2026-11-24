# SOC 2 Type 2: policies and evidence

Research notes for building audit-evidence-kit's policy generator.
Researched 2026-11-24. Sources are listed at the end. Vendor guides (Drata,
Secureframe, Vanta, Bastion and others) were cross-checked against each other
where possible; the AICPA's 2017 Trust Services Criteria (revised points of
focus, 2022) remain the authoritative text.

## 1. Basics that shape everything else

| Topic | What applies |
|---|---|
| **Framework** | AICPA 2017 Trust Services Criteria (TSC), points of focus revised in 2022. The criteria didn't change in 2022, only the points of focus. Points of focus are guidance: an auditor doesn't require every one to be addressed. |
| **Categories** | **Security** (the Common Criteria, CC1–CC9) is mandatory. **Availability** (A1), **Confidentiality** (C1), **Processing Integrity** (PI1) and **Privacy** (P1–P8) are optional; the company picks them based on what customers need. |
| **Type 1 vs Type 2** | Type 1 checks that controls are *designed* properly on one date. Type 2 checks that they *operated effectively* over a period. Type 2 is what most enterprise customers ask for. |
| **Observation period** | There's no AICPA minimum. Reports usually cover 6–12 months; first audits often use 3–6 months. The period must be long enough for each control to run enough times to be sampled. |
| **Evidence timing** | Evidence must come from *inside* the period. A screenshot taken in November proves November only. |
| **Sampling** | The auditor takes the full *population* of each control's events (e.g. every new hire), then tests a *sample*. Vendor guidance ranges from about 25–40 samples for recurring controls; exact sizes are the auditor's judgment. |
| **Bridge letter** | Covers the gap between the end of the last report and today. Signed by **management**, not the auditor. Usually limited to about 3 months. |
| **No fixed policy list** | SOC 2 doesn't name required documents. Policies must cover the criteria, be **approved**, **reviewed** (annually in practice) and **acknowledged by employees**, and in a Type 2 there must be evidence that they're actually **followed**. |
| **Subservice organizations** | Cloud providers (AWS, GCP, Azure) are usually *carved out*: their own SOC 2 reports cover their controls, and the company must show it reviewed those reports. |

## 2. Common Criteria at a glance

| Group | Topic | What the auditor looks for (in short) |
|---|---|---|
| CC1 | Control environment | Integrity and ethics, oversight body, org structure and authority, competence, accountability |
| CC2 | Communication and information | Internal communication of policies and responsibilities; external communication (customers, reporting channel) |
| CC3 | Risk assessment | Objectives, risk identification and analysis, fraud risk, change impact |
| CC4 | Monitoring activities | Ongoing/periodic evaluation of controls; reporting and fixing deficiencies |
| CC5 | Control activities | Controls selected to reduce risks; technology controls; policies that put controls into action |
| CC6 | Logical and physical access | Access provisioning, removal, reviews, authentication, encryption, network boundaries, endpoint/malware protection, physical access |
| CC7 | System operations | Vulnerability management, monitoring and detection, incident response and recovery |
| CC8 | Change management | Changes authorized, tested, approved, documented |
| CC9 | Risk mitigation | Business disruption risk; vendor and business-partner risk |

## 3. Policies to create

20 policies cover the Security criteria for a typical SaaS company. Small
companies can merge related policies (for example, Password into Access
Control) as long as every criterion is still covered. The mapping column is a
typical mapping, to be confirmed with the chosen auditor.

| # | Policy | Covers | Main criteria |
|---|---|---|---|
| 1 | **Information Security Policy** (umbrella) | Security program, roles, governance, policy lifecycle | CC1.1–CC1.5, CC2.1–CC2.2, CC5.3 |
| 2 | **Code of Conduct** | Ethics, integrity, disciplinary process | CC1.1, CC1.5 |
| 3 | **Acceptable Use Policy** | Allowed use of devices, systems, data | CC1.4, CC2.2, CC5.3 |
| 4 | **Access Control Policy** (incl. password/MFA) | Provisioning, least privilege, reviews, removal, authentication | CC6.1–CC6.3 |
| 5 | **Asset Management Policy** | Hardware/software/data inventory, ownership, disposal | CC6.1, CC6.5 |
| 6 | **Data Classification Policy** | Sensitivity levels and handling rules | CC6.1, C1.1 |
| 7 | **Data Retention and Disposal Policy** | Retention periods, secure deletion | CC6.5, C1.2 |
| 8 | **Encryption Policy** | At rest, in transit, key management | CC6.1, CC6.7 |
| 9 | **Human Resources Security Policy** | Background checks, onboarding, training, offboarding | CC1.3–CC1.5, CC2.2, CC6.2 |
| 10 | **Endpoint / Workstation and Remote Work Policy** | Device security, MDM, disk encryption, remote access | CC6.6–CC6.8 |
| 11 | **Physical Security Policy** | Offices and equipment (often minimal for remote companies; data centers carved out) | CC6.4 |
| 12 | **Secure Development (SDLC) Policy** | Secure coding, code review, testing, secrets handling | CC8.1, CC7.1 |
| 13 | **Change Management Policy** | Request, review, approval, testing, deployment, rollback, emergency changes | CC8.1 |
| 14 | **Vulnerability and Patch Management Policy** | Scanning, severity SLAs, patching, penetration testing | CC7.1 |
| 15 | **Logging and Monitoring Policy** | What's logged, retention, alerting, review | CC7.2–CC7.3 |
| 16 | **Incident Response Plan** | Roles, severity, response steps, customer notification, post-mortems | CC7.3–CC7.5, CC2.3 |
| 17 | **Business Continuity and Disaster Recovery Plan** | RTO/RPO, recovery steps, annual test | CC7.5, CC9.1, A1.2–A1.3 |
| 18 | **Backup Policy** | Frequency, retention, restore testing | A1.2–A1.3, CC7.5 |
| 19 | **Risk Assessment and Management Policy** | Annual risk assessment, risk register, treatment, fraud risk | CC3.1–CC3.4, CC9.1 |
| 20 | **Vendor Management Policy** | Vendor inventory, risk tiers, due diligence, SOC report review, contracts | CC9.2 |

Add when the scope requires it:
- **Privacy Policy / Privacy Notice** if the Privacy category is in scope (P1–P8), or for GDPR and Israeli privacy law in any case.
- **Network Security Policy** for companies running their own networks.
- **Responsible Disclosure Policy**, a public channel for security reports (supports CC2.3).

Every policy needs: owner, approver, version, effective date, next review
date, change history. Employees must acknowledge the policies they're bound
by, at hire and after significant changes.

## 4. Evidence for a Type 2

Grouped by how often the control runs. "Population" means the auditor
expects the complete list for the period, then picks samples from it.

### Once a year (at least)
| Evidence | Criteria |
|---|---|
| Policies reviewed and approved (approval record with date and approver) | CC1, CC2, CC5.3 |
| Risk assessment and updated risk register | CC3.1–CC3.4 |
| Security awareness training completion for all staff | CC1.4, CC2.2 |
| Penetration test report and remediation tickets | CC4.1, CC7.1 |
| BC/DR plan test results; backup restore test | CC7.5, A1.3 |
| Vendor reviews: SOC 2 reports of critical vendors reviewed, including the cloud provider | CC9.2 |
| Oversight meeting minutes (board, advisory board or management) where security was discussed | CC1.2, CC4.2 |
| Org chart and job descriptions with security responsibilities | CC1.3 |
| Performance reviews completed (sampled) | CC1.4–CC1.5 |

### Quarterly
| Evidence | Criteria |
|---|---|
| User access reviews (all systems in scope), with sign-off and resulting changes | CC6.2–CC6.3 |
| Review of privileged / admin accounts | CC6.3 |
| Review of vulnerability scan results and open findings (monthly is also common) | CC7.1 |

### Every time it happens (population + sample)
| Evidence | Criteria |
|---|---|
| New hires: background check, signed policies, training, access request approved | CC1.4, CC6.2 |
| Terminations: access removed within the policy deadline (often 24 hours) | CC6.2 |
| Access changes: request and approval before access is granted | CC6.2–CC6.3 |
| Production changes: ticket, code review/approval, tests passing, deployment record | CC8.1 |
| Security incidents: ticket, timeline, response, post-mortem | CC7.3–CC7.5 |
| New vendors: risk assessment before onboarding | CC9.2 |

### Continuous (configuration + sample logs)
| Evidence | Criteria |
|---|---|
| MFA enforced on identity provider and critical systems | CC6.1 |
| Encryption at rest and in transit configuration | CC6.1, CC6.7 |
| Endpoint protection: MDM, disk encryption, screen lock, EDR | CC6.8 |
| Logging and alerting configuration; log retention | CC7.2 |
| Vulnerability scanning schedule and reports | CC7.1 |
| Backup configuration and job logs | A1.2 |
| Branch protection / required reviews on code repositories | CC8.1 |
| Firewall / security group rules, network segmentation | CC6.6 |

## 5. Roles: what if the company has no CISO?

SOC 2 doesn't require a CISO. It requires that responsibilities are
**assigned to named people with the authority to act**, and that someone
independent of day-to-day management oversees the controls (CC1.2).

| Role SOC 2 needs | Common holder in a small company | Notes |
|---|---|---|
| **Security owner** (accountable for the program) | CTO, VP Engineering, or a vCISO | Must be named in the Information Security Policy |
| **Policy approver** | CEO (or management team) | Approval must be recorded; the approver shouldn't be the only author of every control |
| **Oversight body** (CC1.2) | Board of directors; if none: advisory board with an independent member, or documented owner/founder oversight | Needs dated minutes showing security and risk were discussed |
| **Compliance coordinator** (runs the program day to day) | Ops, engineering lead, or the security owner | Often the same person as the security owner |
| **Incident commander** | Security owner or on-call engineering lead | Named in the Incident Response Plan, with a backup |
| **HR owner** | HR, people ops, or COO/CEO | Onboarding, offboarding, background checks, training |
| **IT / identity admin** | IT, DevOps, or CTO | Access provisioning and removal |
| **Privacy contact / DPO** | Legal counsel or security owner | Required under GDPR in some cases; Israeli law also defines related roles |
| **Risk owner(s)** | Each department head | Named per risk in the risk register |

**Segregation of duties** is the usual problem in small teams: the person who
writes code shouldn't be the only one who approves and deploys it, and the
person who grants access shouldn't be the only one who reviews it. When a
team is too small for that, the policy must describe a **compensating
control** (for example, a monthly review of all merged changes by a second
person, or an external reviewer).

## 6. What audit-evidence-kit already provides

| Evidence | Criteria | Provided by |
|---|---|---|
| Vulnerability scanning of code, dependencies, IaC | CC7.1 | `run_all_scans` + report |
| Secrets in code and git history | CC6.1 | gitleaks |
| Tracked remediation | CC7.1, CC4.2 | Ticket exports with stable IDs |
| Dated, versioned scan results | CC7.1 (Type 2 population) | `scanned_at`, scanner versions |

Gaps the policy generator should fill: written policies (section 3),
the governance and role assignments (section 5), and an evidence calendar
(section 4) adapted to the company's tools.

## Sources

- [AICPA: 2017 Trust Services Criteria (with revised points of focus, 2022)](https://www.aicpa-cima.com/resources/article/2017-trust-services-criteria-with-revised-points-of-focus-2022)
- [Deloitte DART: TSP Section 100, 2017 Trust Services Criteria](https://dart.deloitte.com/USDART/home/auditing/aicpa/trust-services-principles-criteria-illustrations/aicpa-trust-services-principles-criteria/trust-services-criteria/tsp-section-100-2017-trust-services)
- [Linford & Co: Trust Services Criteria for SOC 2](https://linfordco.com/blog/2017-tsp-section-100-trust-services-criteria-soc-2/)
- [Linford & Co: Is a board of directors required for SOC 2?](https://linfordco.com/blog/is-board-of-directors-required-for-soc-2/)
- [Linford & Co: Audit sampling in SOC examinations](https://linfordco.com/blog/audit-sampling/)
- [Secureframe: SOC 2 policies and procedures](https://secureframe.com/hub/soc-2/policies-and-procedures)
- [Secureframe: SOC 2 bridge letter](https://secureframe.com/hub/soc-2/bridge-letter)
- [Drata: Top SOC 2 policies](https://drata.com/learn/soc-2/top-policies)
- [Drata: Revised points of focus](https://drata.com/learn/soc-2/trust-services-criteria-revised-points)
- [Bastion: SOC 2 evidence collection](https://bastion.tech/learn/soc2/evidence-collection/)
- [Strike Graph: Type 2 population and sampling](https://help.strikegraph.com/articles/4056301-soc-2-type-2-population-and-sampling-guide)
- [SmartSuite: Observation window and bridge letters](https://www.smartsuite.com/grc-foundation/soc-2-audit-timeline-readiness-observation-window-bridge-letters)
- [ISMS.online: CC1.2 explained](https://www.isms.online/soc-2/controls/control-environment-cc1-2-explained/)
