# Readiness assessment (SOC 2 Type II and/or ISO 27001)

Goal: find what the company is **missing** before an auditor does, and turn
each gap into a ticket. This is not an audit and doesn't produce a
certification or attestation; say so in the report.

## 1. Load the references
- Always: `company-questionnaire.md`
- SOC 2 selected: `soc2-requirements.md`
- ISO 27001 selected: `iso27001-requirements.md`

## 2. Check for a saved company profile
Look for `company-profile.md` in the results folder. If it exists, show the
user a short summary of the saved answers and ask whether anything changed.
Re-ask only what changed. Otherwise start the questionnaire.

## 3. Ask the questionnaire
Go in order A → L, then M if ISO 27001 is selected. Skip A9 and A10 unless
SOC 2 is selected.

**How to ask: interactive, never as a table.** Don't print a section as a
table and ask the user to type answers. Use the multiple-choice question
tool (AskUserQuestion in Claude Code) for every question that has options:
- Up to **4 questions per call**, from the same section. A section with 11
  questions takes 3 calls.
- Each question: the full question text, a short header (e.g. "A2 Team size"),
  and its options as clickable choices, 2–4 per question. The tool adds an
  "Other" choice automatically, so the user can always type their own answer.
- **Multi-select** (`multiSelect: true`) when more than one answer can be
  true: A7 (data types), A8 (customer regions), A9 (Trust Services
  categories), J1-style lists, and any question whose options aren't mutually
  exclusive. Single-select otherwise.
- **More than 4 options:** keep the 3–4 most common as choices and rely on
  "Other" for the rest, or split the question in two (e.g. A7: "personal
  data?" and "health or payment card data?").
- Put the recommended or most common option first; add "(Recommended)" only
  when one choice is clearly better for compliance (e.g. "Enforced for
  everyone (Recommended)" for MFA).
- Always include **"Don't know"** as an option where the user might not know.
  It uses the default and becomes an **open decision**.
- **Free-text questions** (A1 company name, A5 countries, A6 product,
  B1/B3 names, J1 vendor list, K2 top risks): the tool needs options, so ask
  these in a short plain message instead, a few at a time, one line each.
- Before the first question of each section, say in one line what the
  section is about and how many questions it has.

If the multiple-choice tool isn't available (e.g. another client), ask one
question per line with numbered options, and accept the number as an answer.
- If the user wants to go faster, ask only the ★ questions and use defaults
  for the rest; list the defaults used in the report.
- Treat the answers as the user's statements, not verified facts. The report
  must say "based on answers given by <name/role> on <date>".
- If the security scan (option 1) ran in this session, use its results where
  relevant (e.g. secrets found → access control and SDLC gaps, vulnerable
  dependencies → vulnerability management gap), and say so.

After the last section, save all answers to `company-profile.md` in the
results folder (question ID, question, answer, date) so the next run can
reuse them.

## 4. Decide the gaps
A gap is a required control, document or record that the answers show is
missing, partial, or not evidenced. Use the "If the answer is..." column of
the questionnaire, and the gap tables in the requirement files.

Severity:
- **High:** an auditor will almost certainly raise it, or it blocks the audit.
  Examples: MFA not enforced, no offboarding process, no code review, no
  access reviews, no risk assessment; ISO: no scope, no SoA, no internal
  audit, no management review.
- **Medium:** a control exists but isn't documented, isn't regular, or lacks
  evidence. Examples: access reviews yearly instead of quarterly, training
  with no completion records, policies never formally approved.
- **Low:** improvements an auditor might note but rarely fails on.

One gap per missing item. Map each gap to SOC 2 criteria and/or ISO clauses
or Annex A controls, only for the frameworks selected.

## 5. Export the gaps
Call `export_findings` with `kind: "readiness-gaps"`, the ticketing system
and results folder chosen at the start, and one entry per gap:
- `title`: what's missing, e.g. "MFA not enforced for all users"
- `issue_type`: `readiness-gap`
- `file`: `organization`, `line`: null
- `source`: `questionnaire <ID>` (e.g. `questionnaire E2`)
- `evidence`: the answer, e.g. `E2 = encouraged only` (stable wording, so
  re-runs keep the same ID)
- `why`: one sentence on what the auditor will ask for
- `fix`: the concrete action, including any template to use
- `soc2` / `iso27001`: criteria or clauses, e.g. `["CC6.1"]`, `["A.8.5"]`

## 6. Write the readiness report
Save as `readiness-report.md` in the results folder:

```
# Readiness Assessment — <company> — <YYYY-MM-DD>

**Frameworks:** SOC 2 Type II | ISO/IEC 27001:2022
**Based on:** answers given by <name, role> on <date>; <security scan results if run>
**This is a readiness assessment, not an audit or certification.**

## Summary
<n> gaps: <x> high, <y> medium, <z> low. <k> open decisions.
Readiness: <one honest sentence, e.g. "About 3–4 months of work before a
Type II observation period can start.">

## Gaps
| # | ID | Gap | Severity | SOC 2 | ISO 27001 | Owner (from answers) |
|---|---|---|---|---|---|---|

### 1. <gap> — Severity: High
- **ID:** <from export_findings>
- **Based on:** questionnaire <ID>: "<answer>"
- **What the auditor will ask for:** <evidence>
- **Action:** <fix, template to use>
- **Suggested owner:** <role/name from section B>

## Roles to assign
<table from section B: role, proposed person, decision needed by whom>

## Open decisions
<"don't know" answers and the defaults used>

## Suggested timeline
<ordered plan: fix high gaps → policies → start evidence collection →
SOC 2 observation period / ISO Stage 1>
```

Never present a gap as compliant because the user said so; if an answer
can't be checked (e.g. "we do access reviews"), note the evidence the
auditor will need to see.
