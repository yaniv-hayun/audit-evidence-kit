# Branding and policy documents

Part of the readiness assessment: after the gaps are exported, the user gets
branded Word documents for every policy, plus a template for every missing
record. Code does the formatting (`generate_document`); you write the content.

## 1. Branding (ask once, save once)

If `<results>/branding/branding.json` already exists, show the saved logo
and colors and ask whether to keep them. Otherwise ask with the
multiple-choice tool:

> **Branding for your documents?**
> - **Detect from our website (Recommended)** (they type the URL in "Other",
>   or you ask for it next)
> - **I'll give you a logo file**
> - **No logo, plain documents**

**From the website:**
1. Call `detect_branding(url, results_dir)`.
2. **Look at each candidate file yourself** with the Read tool (they're PNG
   images) before proposing anything. Drop candidates that aren't the
   company's logo (photos, customer logos, generic icons) and say why.
3. Ask the user to choose, with the multiple-choice tool: up to 3 logo
   candidates (label: what it looks like + size, e.g. "Wide logo with name,
   580×164"; description: the file path so they can open it), and
   "None of these, I'll give a file".
4. Ask about colors the same way: the top 2–3 detected colors with their
   source (e.g. "#533AFD, from your logo"), and "Other" for their own hex.
5. If detection fails (blocked site, SVG-only logo, nothing found), say what
   happened in one line and ask for a PNG/JPG file instead.

**From a file:** ask for the path (PNG or JPG; SVG must be exported to PNG
first).

Then call `save_branding` with the confirmed logo, primary and secondary
colors, font (default Calibri) and footer (default is fine). If the notes say
a color was darkened for readability, tell the user.

## 2. Which documents to create

Create every document that applies, using the company profile.

### SOC 2 (if selected): policies
From section 3 of `soc2-requirements.md`, `kind: "policy"` unless noted:
1. Information Security Policy (umbrella)
2. Code of Conduct
3. Acceptable Use Policy
4. Access Control Policy (incl. passwords and MFA)
5. Asset Management Policy
6. Data Classification Policy
7. Data Retention and Disposal Policy
8. Encryption Policy
9. Human Resources Security Policy
10. Endpoint, Workstation and Remote Work Policy
11. Physical Security Policy (short if fully remote)
12. Secure Development (SDLC) Policy
13. Change Management Policy
14. Vulnerability and Patch Management Policy
15. Logging and Monitoring Policy
16. Incident Response Plan (`kind: "plan"`)
17. Business Continuity and Disaster Recovery Plan (`kind: "plan"`)
18. Backup Policy
19. Risk Assessment and Management Policy
20. Vendor Management Policy
- Privacy Policy, if Privacy is in scope (A9) or personal data is stored (A7).

Companies of 1–10 people (A2) may merge 2+3, 5+6+7, 13+12, 17+18. Say which
were merged and why; never drop a topic.

### ISO 27001 (if selected): ISMS documents
Shared policies above serve both frameworks. Add:
- ISMS Scope (clause 4.3)
- Context and Interested Parties, including the climate-change decision (4.1, 4.2)
- Risk Assessment and Treatment Methodology (6.1.2, 6.1.3)
- Statement of Applicability (`kind: "register"`): all 93 Annex A controls
  as a table (ID, control, included yes/no, justification, how implemented).
  Base each decision on the answers; mark uncertain ones `[TO CONFIRM: ...]`.
- Information Security Objectives (6.2), measurable, with owners and dates
- Internal Audit Procedure and Programme (9.2)
- Management Review Procedure (9.3)
- Nonconformity and Corrective Action Procedure (10.2)
- Legal, Regulatory and Contractual Requirements Register (`kind: "register"`, A.5.31)

### Templates for missing records (`kind: "template"`)
For every answer listed in "Templates created when the answer is No" in
`company-questionnaire.md`, create that template (NDA, onboarding and
offboarding checklists, access review, incident report, restore test, vendor
questionnaire, risk register, management review minutes, ...). Set
`legal_review: true` for the NDA, code of conduct and any contract text.

### Index
Last, create a **Policy Index** (`kind: "register"`, filename
`00-policy-index`): a table of every document created with title, file,
owner, approver, criteria and next review date.

## 3. How to write each document

- **Don't write** the title, company name, document-control table, approval
  block, version history, or (with `legal_review: true`) the "review with
  legal counsel" warning: `generate_document` adds all of them. Start the
  body at `# 1. ...`.
- Structure for policies: `# 1. Purpose`, `# 2. Scope`, `# 3. Roles and
  responsibilities` (a table with real names from section B), `# 4. Policy`
  (numbered sub-sections, "must"/"must not" statements), `# 5. Procedures`
  (concrete steps using the company's real tools), `# 6. Exceptions`,
  `# 7. Enforcement`, `# 8. Review` (annual review by the owner).
- **Tailor everything to the answers**: real names and roles, the actual
  tools (e.g. "Google Workspace", "GitHub", "1Password", "Datadog"), the
  actual cloud, team size, and countries. A generic policy is a weak policy.
- **Policy describes the target, not today's gaps.** Write "MFA is enforced
  for all users", even if it isn't yet; the gap and its ticket track the
  work. Never claim something is already done in a policy.
- **Unknowns:** never invent a fact. Use `[TO CONFIRM: what's needed]`
  (highlighted yellow) for decisions the company must still make, e.g.
  `[TO CONFIRM: RTO, suggested 8 hours]`.
- **Compensating controls:** where the answers show one person can act alone
  (B13, G3), write the compensating control into the policy.
- Owner and approver: from section B (owner = role responsible, usually the
  Security Officer; approver = B4). `criteria`: the SOC 2 criteria and/or ISO
  clauses the document supports, only for the selected frameworks.
- Plain, direct English. Short sentences. One requirement per bullet.

## 4. After generating

In the readiness report, add a **Documents** section listing every file
created (from the index), and the number of `[TO CONFIRM]` items left to
decide. Remind the user that policies must be **approved** (signature block)
and **acknowledged by employees** before they count as evidence.
