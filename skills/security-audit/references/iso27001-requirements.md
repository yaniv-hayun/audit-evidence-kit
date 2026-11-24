# ISO/IEC 27001:2022 readiness: what's required

Reference for the ISO 27001 readiness assessment. Researched 2026-11-24 from
the sources listed at the end. The standard itself (sold by ISO and national
bodies) is the authoritative text; confirm details with the certification
body.

## 1. How ISO 27001 differs from SOC 2

| | SOC 2 Type II | ISO 27001 |
|---|---|---|
| Result | An auditor's **report** (attestation) | A **certificate** from an accredited certification body |
| What's assessed | Controls for the chosen Trust Services Criteria, over a period | A whole **management system** (ISMS): how security is planned, run, measured and improved, plus the Annex A controls you selected |
| Audits | One examination per period | **Stage 1** (documents and readiness), **Stage 2** (implementation). Then surveillance audits in years 2 and 3, recertification in year 3 |
| Unique requirements | Observation-period evidence and sampling | **ISMS scope**, **Statement of Applicability**, **internal audit**, **management review**, measurable **objectives**, **corrective actions** |
| Overlap | | Most Annex A technical and people controls match SOC 2 evidence (access, change, incidents, vendors, backups). One set of policies can serve both |

Missing mandatory documents are typically a **major nonconformity**, which
blocks certification until fixed.

## 2. The management system: clauses 4–10 (all mandatory)

| Clause | Requirement | Mandatory documented information |
|---|---|---|
| 4.1 | Understand internal and external issues. **Since Amd 1:2024: decide whether climate change is a relevant issue** | Not required as a document, but auditors expect a record of the decision |
| 4.2 | Interested parties and their requirements (customers, regulators, employees). Amd 1 adds a note that they can have climate-related requirements | Usually a register |
| 4.3 | **Scope of the ISMS**: which organization, locations, systems, and what's excluded | **ISMS scope document** |
| 5.1 | Top management leadership and commitment | Evidence of involvement (minutes, approvals) |
| 5.2 | **Information security policy** | **Policy** |
| 5.3 | Roles, responsibilities and authorities assigned and communicated | Usually documented (org chart, RACI) |
| 6.1.2 | **Risk assessment process** (criteria, method) | **Risk assessment methodology** |
| 6.1.3 | **Risk treatment process**; compare against Annex A; produce SoA | **Risk treatment process**, **Statement of Applicability (SoA)** |
| 6.1.3 e | **Risk treatment plan** | **Risk treatment plan** |
| 6.2 | **Information security objectives**, measurable, with plans | **Objectives** |
| 6.3 | Planned changes to the ISMS | |
| 7.2 | **Competence** of people doing security work | **Records of competence** (training, qualifications) |
| 7.3–7.4 | Awareness; internal and external communication | |
| 7.5 | Control of documented information (versions, approval, access) | Document control procedure (usually) |
| 8.1 | Operational planning and control | **Evidence that processes ran as planned** |
| 8.2 | Risk assessments performed at planned intervals | **Risk assessment results** |
| 8.3 | Risk treatment implemented | **Risk treatment results** |
| 9.1 | Monitoring, measurement, analysis, evaluation | **Monitoring and measurement results** |
| 9.2 | **Internal audit** programme, by auditors who are objective and impartial | **Audit programme** and **internal audit results** |
| 9.3 | **Management review** at planned intervals | **Management review results** |
| 10.1–10.2 | Continual improvement; nonconformities and corrective action | **Records of nonconformities and corrective actions** |

## 3. Annex A: 93 controls in 4 themes

| Theme | Controls | Examples |
|---|---|---|
| Organizational | 5.1–5.37 (37) | Policies, roles, threat intelligence, asset inventory, access control, supplier security, incident management, business continuity, legal requirements, privacy |
| People | 6.1–6.8 (8) | Screening, employment terms, awareness training, disciplinary process, termination, NDAs, remote working, event reporting |
| Physical | 7.1–7.14 (14) | Perimeters, entry, offices, monitoring, equipment, clear desk, secure disposal |
| Technological | 8.1–8.34 (34) | Endpoints, privileged access, authentication, malware, vulnerabilities, configuration, backup, logging, monitoring, network security, cryptography, secure development, change management |

Controls are **not all mandatory**: each is included or excluded in the
**Statement of Applicability**, with a justification. Documents required by
Annex A controls are mandatory only when the control applies.

## 4. What the readiness assessment checks (ISO only)

On top of the shared questionnaire (governance, HR, access, engineering, etc.),
an ISO readiness assessment must cover:

| Gap if missing | Clause | Typical severity |
|---|---|---|
| No defined ISMS scope | 4.3 | High |
| No risk assessment methodology or no risk assessment results | 6.1.2, 8.2 | High |
| No Statement of Applicability | 6.1.3 | High |
| No risk treatment plan | 6.1.3 e, 8.3 | High |
| No internal audit planned or performed (or auditor not independent of the work) | 9.2 | High |
| No management review held | 9.3 | High |
| No measurable security objectives | 6.2 | Medium |
| No context / interested-parties analysis, or no climate-change decision | 4.1, 4.2 | Medium |
| No corrective action process / log | 10.2 | Medium |
| No document control (versions, approvals) | 7.5 | Medium |
| No competence records | 7.2 | Medium |
| No register of legal and contractual requirements | A.5.31 | Medium |

## Sources

- [ISO: ISO/IEC 27001:2022/Amd 1:2024 (climate action changes)](https://www.iso.org/standard/88435.html)
- [BIS: text of Amendment 1 (identical national adoption)](https://services.bis.gov.in/tmp/LITD23425400_06092024_1.pdf)
- [Advisera: list of mandatory documents required by ISO 27001](https://advisera.com/27001academy/knowledgebase/list-of-mandatory-documents-required-by-iso-27001-revision/)
- [ISO27k Forum: ISMS mandatory documentation checklist (2024)](https://www.ISO27001security.com/ISO27k_ISMS_4.4_mandatory_documentation_checklist_2024.pdf)
- [Sprinto: ISO 27001 mandatory documents](https://sprinto.com/blog/iso-27001-mandatory-documents/)
- [Scrut: ISO 27001 mandatory documents](https://www.scrut.io/hub/iso-27001/iso-27001-mandatory-documents)
- [Centraleyes: ISO 27001 mandatory documents guide](https://www.centraleyes.com/iso-27001-1/iso-27001-mandatory-documents-a-guide-to-achieving-compliance/)
