# Company questionnaire for SOC 2 policies

The policy generator asks these questions before writing any policy. The
answers decide **who** is named in each policy, **which tools** the
procedures refer to, and **which policies or sections** apply at all.

Rules for asking:
- Ask one section at a time, with the interactive multiple-choice tool
  (see readiness-assessment.md, step 3), never as a printed table.
- Offer the listed options, but always accept a free-text answer.
- "Don't know" is a valid answer. Use the default, and list the item as an
  open decision in the summary.
- Questions marked ★ are required to generate anything; the rest can use
  defaults.
- Policy numbers (P1–P20) refer to section 3 of
  [soc2-requirements.md](soc2-requirements.md).

---

## A. Company and scope

| ID | Question | Options / format | Affects | Why it matters |
|---|---|---|---|---|
| A1 ★ | Company legal name and short name used in documents | text | all | Appears in every policy |
| A2 ★ | How many people work at the company (employees + contractors)? | 1–10 / 11–50 / 51–200 / 200+ | all | Sets how formal the policies are and whether segregation of duties is realistic |
| A3 | Do you use contractors or outsourced developers with system access? | yes / no | P4, P9, P20 | Contractors need the same onboarding, access and offboarding controls |
| A4 ★ | Where does the team work? | one office / several offices / fully remote / hybrid | P10, P11 | Fully remote: physical security policy becomes short; remote-work rules matter more |
| A5 ★ | Which countries are employees in? | list | P9, P2 | Background checks are legally limited in some countries (e.g. Israel, much of the EU) |
| A6 ★ | What does the product do, and which system is in scope for the audit? | text (product name, main components) | system description, all | The audit covers a defined system, not the whole company |
| A7 ★ | What data do you store about customers? | none / business contact data / personal data (PII) / health data / payment cards / other sensitive | P6, P7, P8, privacy | Drives data classification levels, encryption and retention |
| A8 | Where are your customers? | EU / US / other (multi-select) | privacy, P16 | GDPR and US state laws change breach-notification rules; other regions (typed under "Other") may add their own |
| A9 ★ | Which Trust Services categories do customers expect besides Security? | none / Availability / Confidentiality / Processing Integrity / Privacy | P17, P18, privacy | Each extra category adds criteria and evidence |
| A10 | Type 1 first, or straight to Type 2? Target report date? | Type 1 / Type 2 / not decided + date | evidence calendar | Sets the observation period and when evidence must start |
| A11 | Have you chosen an audit firm? | name / not yet | all | Auditors differ on sample sizes and policy expectations |

## B. Governance and roles

The most important section: every policy names an owner and an approver.

| ID | Question | Options / format | Affects | If the answer is... |
|---|---|---|---|---|
| B1 ★ | Who is the CEO / most senior executive? | name + title | P1, all approvals | Default policy approver |
| B2 ★ | Is there a person responsible for security (CISO, security lead)? | yes, full-time / yes, part of another role / vCISO (external) / no one | P1, P16 | **No one:** the generator proposes naming the CTO (or most senior technical person) as "Security Officer" and lists it as a decision for the CEO |
| B3 ★ | If not a dedicated CISO: who will be the Security Officer? | name + title | P1, P4, P14, P16 | That person owns most technical policies |
| B4 ★ | Who approves policies? | CEO / management team / board / Security Officer | all | Approver must be a different person from the author where possible. If the CEO is also the Security Officer, a second approver (co-founder or board member) is suggested |
| B5 ★ | Do you have a board of directors? | yes, with independent members / yes, founders/investors only / no | P1 (CC1.2) | **No board:** propose an advisory board with at least one independent member, or a documented quarterly management security review with minutes |
| B6 | How often does leadership discuss security and risk? | never / ad hoc / quarterly / monthly | P1, P19 | SOC 2 needs dated evidence of oversight; quarterly is the usual minimum |
| B7 | Who runs compliance day to day (collects evidence, tracks tasks)? | name | evidence calendar | Often the Security Officer in small companies |
| B8 | Who handles HR (hiring, onboarding, offboarding)? | name / HR team / CEO / outsourced | P9 | Owner of the HR Security Policy |
| B9 | Who administers user accounts and access (IT)? | name / IT team / DevOps / CTO | P4, P5 | Access provisioning owner; must not be the only reviewer of access |
| B10 | Who leads during a security incident? Who is the backup? | 2 names | P16 | Named incident commander plus a backup is required |
| B11 | Do you have legal counsel (in-house or external)? | in-house / external firm / none | P16, privacy | Breach notification decisions and contract reviews |
| B12 | Is someone responsible for privacy (DPO / privacy officer)? | name / no one | privacy, P7 | May be required under GDPR or Israeli privacy regulations depending on data and size |
| B13 | Can any single person both make a change and approve it without anyone else seeing it? (code, access, payments) | yes / no / not sure | P4, P13 | **Yes:** the generator adds a compensating control (e.g. monthly second-person review) |

## C. People and HR

| ID | Question | Options / format | Affects | If the answer is... |
|---|---|---|---|---|
| C1 | Do you run background checks on new hires? | yes, all / some roles / no | P9 | **No / restricted by law:** document the legal limit and the alternative (reference checks, verified identity and education) |
| C2 | Is there an employee handbook or code of conduct today? | yes / no | P2 | Reuse it rather than duplicating |
| C3 | Do new hires sign confidentiality/NDA agreements? | yes / no | P9, C1 | Required evidence for every new hire |
| C4 | Do you have an onboarding checklist? Where is it tracked? | HRIS name / Jira / spreadsheet / none | P9 | Becomes the population source for new hires |
| C5 | Do you have an offboarding checklist? How fast is access removed? | same day / 24h / within a week / no process | P9, P4 | Policy deadline, typically 24 hours; must be met in every sample |
| C6 | Do you run security awareness training? Which platform? | platform name / none | P9 | Annual training is expected; the generator can suggest free options |
| C7 | Do you do performance reviews? How often? | annual / semi-annual / none | P2, P9 | Evidence for CC1.4–CC1.5 |
| C8 | Which HR system do you use? | BambooHR / HiBob / Rippling / Gusto / spreadsheet / other | P9 | Named as the source of employee lists |

## D. Infrastructure and environment

| ID | Question | Options / format | Affects | If the answer is... |
|---|---|---|---|---|
| D1 ★ | Where does production run? | AWS / GCP / Azure / other cloud / on-prem / mixed | P5, P8, P11, P17, P20 | Cloud provider is a **subservice organization**: its SOC 2 report must be reviewed yearly |
| D2 | Which regions host production and customer data? | list | P7, privacy | Data residency commitments |
| D3 | Do you use infrastructure as code? | Terraform / CloudFormation / Pulumi / none | P13 | IaC changes go through the same change management |
| D4 | Containers / Kubernetes? | Docker / Kubernetes / serverless / VMs | P12, P14 | Image scanning and base-image rules |
| D5 | Is there a separate staging/test environment? Is production data used in it? | yes / no; yes / no | P12, P13 | **Production data in test:** policy must require masking or approval |
| D6 | Do you have an office with equipment or servers? | no office / office, no servers / office with servers | P11 | **No office:** physical security covers home working and devices only |

## E. Identity and access

| ID | Question | Options / format | Affects | If the answer is... |
|---|---|---|---|---|
| E1 ★ | Which identity provider do people sign in with? | Google Workspace / Microsoft Entra ID / Okta / JumpCloud / none | P4 | Named as the central access control system |
| E2 ★ | Is MFA enforced for everyone? | yes, enforced / encouraged only / no | P4 | **Not enforced:** flagged as a gap to fix before the observation period |
| E3 | Is SSO used for most business apps? | yes / partly / no | P4 | Without SSO, access reviews must cover each app separately |
| E4 | Is a password manager provided? | 1Password / Bitwarden / LastPass / none | P4 | Password rules refer to it |
| E5 | Who has production / admin access? How is it granted? | number of people + process | P4 | Privileged access gets stricter rules and quarterly review |
| E6 | Do you review user access today? How often? | quarterly / yearly / never | P4 | Quarterly is the common expectation for Type 2 |

## F. Endpoints

| ID | Question | Options / format | Affects | If the answer is... |
|---|---|---|---|---|
| F1 | Are company laptops managed (MDM)? | Jamf / Kandji / Intune / Google endpoint / none | P10 | **None:** policy relies on self-attestation, weaker evidence; flagged |
| F2 | Is disk encryption enforced? | yes / no / not sure | P10, P8 | Required evidence |
| F3 | Antivirus / EDR? | product name / built-in only / none | P10 | CC6.8 malware protection |
| F4 | Are personal devices (BYOD) allowed to access company data? | yes / phones only / no | P3, P10 | **Yes:** policy adds BYOD rules |

## G. Engineering and change management

| ID | Question | Options / format | Affects | If the answer is... |
|---|---|---|---|---|
| G1 ★ | Where is source code hosted? | GitHub / GitLab / Bitbucket / other | P12, P13 | Named in the procedures |
| G2 ★ | Is a pull request + review required before merging to the main branch? | enforced / by convention / no | P13 | **Not enforced:** flagged; branch protection is primary evidence for CC8.1 |
| G3 ★ | How many engineers can approve code? | 1 / 2–3 / 4+ | P13 | **1:** compensating control required (see B13) |
| G4 | How do deployments happen? | CI/CD automatic / manual by engineers / mixed | P13 | Deployment logs become the change population |
| G5 | Is there an emergency change process? | yes / no | P13 | Policy defines after-the-fact approval |
| G6 | Do you scan code and dependencies for vulnerabilities? | audit-evidence-kit / other tool / none | P12, P14 | audit-evidence-kit reports become the CC7.1 evidence |
| G7 | Penetration test: done before? By whom? How often? | yes, annual / once / never | P14 | Annual test expected; generator notes it if missing |

## H. Operations, monitoring and incidents

| ID | Question | Options / format | Affects | If the answer is... |
|---|---|---|---|---|
| H1 | Where are logs collected? | Datadog / CloudWatch / Grafana / ELK / none | P15 | Named as the logging system; retention period from it |
| H2 | Do alerts go to someone 24/7 (on-call)? | yes, rota / business hours only / no | P15, P16 | Response-time commitments must match reality |
| H3 | Ticketing system for incidents and tasks? | Jira / Linear / Asana / monday.com / other | P13, P14, P16 | Same choice as the security audit export |
| H4 | Have you had a security incident in the last 12 months? | yes / no | P16 | Past incidents are often requested |
| H5 | Customer notification commitments for incidents? | hours/days in contracts / none | P16 | Plan timelines must match contracts and laws |
| H6 | Do you have cyber insurance? | yes / no | P16 | Insurer contact goes into the plan |

## I. Data, backups and continuity

| ID | Question | Options / format | Affects | If the answer is... |
|---|---|---|---|---|
| I1 | How many data classification levels do you want? | 3 (Public / Internal / Confidential) / 4 (+ Restricted) | P6 | Default: 4 levels if personal or sensitive data is stored |
| I2 | Is data encrypted at rest and in transit? | yes / partly / not sure | P8 | Gaps flagged |
| I3 | How long do you keep customer data after a contract ends? | days / never deleted / not defined | P7 | Policy sets the period; contracts must match |
| I4 | How are backups done? How often? | provider-managed / custom; daily / hourly | P18 | Backup policy details |
| I5 | Have you ever tested restoring from backup? | yes, regularly / once / never | P18, P17 | Annual restore test is expected evidence |
| I6 | Acceptable downtime (RTO) and data loss (RPO)? | hours / not defined | P17 | Defaults suggested by company size |

## J. Vendors

| ID | Question | Options / format | Affects | If the answer is... |
|---|---|---|---|---|
| J1 ★ | List the main vendors that store or process customer data | list (cloud, email, CRM, support, analytics, AI) | P20 | Becomes the vendor inventory |
| J2 | Do you check vendors' security (SOC 2 reports, questionnaires) before using them? | yes / sometimes / no | P20 | Process plus yearly review |
| J3 | Do contracts with vendors include data protection terms (DPA)? | yes / some / no | P20, privacy | Required for personal data |

## K. Risk

| ID | Question | Options / format | Affects | If the answer is... |
|---|---|---|---|---|
| K1 | Do you have a risk register or risk assessment today? | yes / no | P19 | **No:** the generator creates a starter register from the answers |
| K2 | What are the top 3 things that would hurt the business most? | free text | P19, P17 | Seeds the risk register and BC/DR priorities |

## L. Existing documents and preferences

| ID | Question | Options / format | Affects | If the answer is... |
|---|---|---|---|---|
| L1 | Do you already have security policies? | yes (where) / some / no | all | Reuse and fill gaps, don't overwrite |
| L2 | Do you use a compliance platform? | Vanta / Drata / Secureframe / Sprinto / none | all | Format policies for import there |
| L3 | How will employees acknowledge policies? | e-signature tool / HR system / compliance platform / form | P1, P9 | Acknowledgment evidence source |
| L4 | Where will policies be stored and versioned? | git repo / Google Drive / Notion / Confluence / compliance platform | P1 | Version history is required evidence |
| L5 | Output format for the policies? | Word (.docx, default) / Markdown | all | .docx supports logo, colors and page headers; Markdown is plain text for git-based review |
| L6 | Company logo | path to a PNG or JPG file (wide logos work best, e.g. 600×150 px) / none | all (branding) | Placed in the header of every page. SVG must be converted to PNG first |
| L7 | Brand colors | primary hex (e.g. `#1F4E79`), optional secondary hex / default | all (branding) | Primary: headings and table headers. Secondary: accents. Contrast is checked so text stays readable |
| L8 | Font | Calibri / Arial / Inter / other installed font / default | all (branding) | Body and heading font |
| L9 | Footer text | default: "{company} · Confidential · {policy} v{version} · Page X of Y" / custom | all (branding) | A classification label on every page is a common auditor expectation |

---

## M. ISO 27001 only

Ask this section only when ISO 27001 readiness was selected. Clause numbers
refer to [iso27001-requirements.md](iso27001-requirements.md).

| ID | Question | Options / format | Clause | If the answer is... |
|---|---|---|---|---|
| M1 ★ | Is the ISMS scope defined in writing (which teams, locations, systems, and what's excluded)? | yes / draft / no | 4.3 | **No:** high gap; the generator proposes a scope from A6 and D1 |
| M2 | Have you listed internal and external issues and interested parties (customers, regulators, investors) with their requirements? | yes / no | 4.1, 4.2 | **No:** medium gap |
| M3 | Have you decided whether climate change is relevant to your ISMS? | yes, relevant / yes, not relevant (recorded) / not considered | 4.1 (Amd 1:2024) | **Not considered:** medium gap; a short recorded decision is usually enough |
| M4 ★ | Is there a documented risk assessment method, and has a risk assessment been done? | both / method only / neither | 6.1.2, 8.2 | **Neither:** high gap |
| M5 ★ | Do you have a Statement of Applicability (all 93 Annex A controls, included or excluded with reasons)? | yes / in progress / no | 6.1.3 | **No:** high gap |
| M6 | Is there a risk treatment plan with owners and dates? | yes / no | 6.1.3 e, 8.3 | **No:** high gap |
| M7 | Are there measurable information security objectives (e.g. "100% MFA by Q2")? | yes / no | 6.2 | **No:** medium gap |
| M8 ★ | Has an internal audit of the ISMS been planned or done? Who does it? | done / planned / no; name or external firm | 9.2 | **No:** high gap. **Done by the person who runs the ISMS:** not independent; suggest an external or cross-team auditor |
| M9 ★ | Has top management held a management review of the ISMS? | yes, with minutes / planned / no | 9.3 | **No:** high gap |
| M10 | Is there a log of nonconformities and corrective actions? | yes / no | 10.2 | **No:** medium gap; the ticket export can serve as this log |
| M11 | Is there a register of legal, regulatory and contractual requirements (privacy laws, customer contracts)? | yes / no | A.5.31 | **No:** medium gap |
| M12 | Have you chosen an accredited certification body? Target date for Stage 1? | name / not yet; date | Certification | Sets the timeline for the readiness plan |

Sections A–L apply to both frameworks, except A9 and A10, which are SOC 2
only.

## Templates created when the answer is "No"

A "no" usually means a control is missing, so a policy alone won't pass:
the auditor will ask for the *record* (signed NDA, completed checklist,
review sign-off). For these answers the generator also writes a starter
template, saved in `templates/` next to the policies, and lists it in the
readiness gaps with the action needed.

| Answer | Template created | Action for the company |
|---|---|---|
| C3 = no (no NDA) | **Employee confidentiality agreement (NDA)** | Have a lawyer review it, then have every current employee and all new hires sign it |
| C2 = no (no code of conduct) | Code of conduct + acknowledgment form | Approve, then collect acknowledgments |
| C4 = none (no onboarding checklist) | Onboarding checklist (accounts, training, policy acknowledgment, NDA) | Use it for every new hire; it becomes the evidence |
| C5 = no process (no offboarding) | Offboarding checklist with the access-removal deadline | Use it for every departure |
| C6 = none (no training) | Security awareness training outline + completion log | Run it yearly and at hire |
| E6 = never (no access reviews) | Quarterly access review template (system, user, role, keep/remove, reviewer, date) | Run the first review before the observation period |
| H4/P16 (no incident process) | Incident report and post-mortem template | Use for every incident |
| I5 = never (no restore test) | Backup restore test record | Run a test and record it |
| J2 = no (no vendor checks) | Vendor security questionnaire + vendor inventory | Fill in for every vendor in J1 |
| K1 = no (no risk register) | Risk register pre-filled from K2 and the scan findings | Review and assign owners |
| B5 = no (no board) | Management security review: agenda + minutes template | Hold it quarterly and keep the minutes |

Legal documents (NDA, code of conduct) are clearly marked **"Template: review
with legal counsel before use"**, because employment law differs by country
(answer A5).

## How the answers will be used

1. The answers are saved as a **company profile** (planned file:
   `audit-results/company-profile.json`), so they're asked once and reused.
2. Every policy template has placeholders filled from the profile, e.g.
   `{security_officer.name}`, `{identity_provider}`, `{offboarding_deadline}`.
3. Answers that create a gap (for example E2 = MFA not enforced) are listed in
   a **readiness gaps** section, with the criterion and a fix.
4. Answers marked "don't know" are listed as **open decisions** with the
   default that was used.
