"""Run open-source scanners and normalize their output.

Every scanner speaks its own JSON dialect. This module translates all of them
into one Finding shape, so the skill only has to understand one format:

    {
      "scanner":    "gitleaks" | "semgrep" | "osv-scanner" | "trivy",
      "rule":       scanner's rule id,
      "issue_type": one of the issue types in references/control-mapping.md,
      "severity":   "high" | "medium" | "low",
      "file":       path relative to the scanned folder,
      "line":       int or None,
      "message":    one-line description,
      "evidence":   offending code or package (secrets always masked),
    }

No MCP code lives here, so you can test it with plain Python.
"""

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from packaging.version import InvalidVersion, Version

INSTALL_HINTS = {
    "gitleaks": "brew install gitleaks",
    "semgrep": "brew install semgrep",
    "osv-scanner": "brew install osv-scanner",
    "trivy": "brew install trivy",
}


# ---------------------------------------------------------------- helpers

def find_binary(name: str) -> str:
    """Look next to the running Python first (for tools pip-installed into the
    venv, like semgrep), then on PATH."""
    venv_bin = Path(sys.executable).parent / name
    if venv_bin.exists():
        return str(venv_bin)
    if found := shutil.which(name):
        return found
    raise RuntimeError(f"{name} is not installed. Install it with: {INSTALL_HINTS[name]}")


def scanner_versions() -> dict[str, str]:
    """Version of each installed scanner. Auditors need this: evidence must
    say which tool, which version, produced it."""
    commands = {
        "gitleaks": ["version"],
        "semgrep": ["--version"],
        "osv-scanner": ["--version"],
        "trivy": ["--version"],
    }
    versions = {}
    for name, args in commands.items():
        try:
            out = subprocess.run([find_binary(name), *args], capture_output=True,
                                 text=True, timeout=30).stdout
            versions[name] = out.strip().splitlines()[0].split()[-1]
        except Exception:
            versions[name] = "not installed"
    return versions


def mask(value: str) -> str:
    """Keep the first 4 characters, hide the rest. Never return a full secret."""
    return value[:4] + "*" * max(len(value) - 4, 4)


def read_line(file: Path, line_no: int) -> str:
    try:
        return file.read_text(errors="ignore").splitlines()[line_no - 1].strip()
    except (OSError, IndexError):
        return ""


def dedupe(findings: list[dict]) -> list[dict]:
    """Merge the same bug reported by different scanners. Keeps the first
    finding for each (file, line, issue_type) and records who else saw it."""
    kept: dict[tuple, dict] = {}
    for f in findings:
        # Findings without a line (dependencies) are told apart by evidence,
        # otherwise every package in requirements.txt would collapse into one.
        key = (f["file"], f["line"] or f["evidence"], f["issue_type"])
        if key in kept and f["scanner"] not in kept[key]["scanner"].split("+"):
            kept[key]["scanner"] += f"+{f['scanner']}"  # another scanner, same bug
        elif key in kept:
            # Same scanner, same line, different rule: a different problem
            # (e.g. three Terraform rules all pointing at a resource's line 1).
            kept[key + (f["rule"],)] = dict(f)
        else:
            kept[key] = dict(f)
    return list(kept.values())


def fingerprint(issue_type: str, file: str, rule: str, evidence: str) -> str:
    """A stable ID for a finding, e.g. "AEK-3f9a1c02b7".

    Built from WHAT the problem is and WHERE, but not the line number: adding a
    line at the top of a file shouldn't turn every finding into a "new" ticket.
    Same problem on a re-run -> same ID -> ticketing tools can skip it.
    """
    import hashlib
    raw = "|".join([issue_type, file, rule, " ".join(evidence.split())])
    return "AEK-" + hashlib.sha256(raw.encode()).hexdigest()[:10]


def add_ids(findings: list[dict]) -> list[dict]:
    for f in findings:
        f["id"] = fingerprint(f["issue_type"], f["file"], f["rule"], f["evidence"])
    return findings


def resolve_root(path: str) -> Path:
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Not a folder: {root}")
    return root


# CWE -> issue type. CWE is the industry's shared vocabulary for weakness
# types, so mapping by CWE works across scanners and languages.
CWE_TO_ISSUE = {
    "CWE-78": "injection", "CWE-89": "injection", "CWE-94": "injection",
    "CWE-95": "injection", "CWE-77": "injection",
    "CWE-327": "weak-crypto", "CWE-328": "weak-crypto", "CWE-916": "weak-crypto",
    "CWE-295": "weak-crypto",
    "CWE-532": "sensitive-data-in-logs",
    "CWE-489": "insecure-defaults", "CWE-668": "insecure-defaults",
    "CWE-798": "hardcoded-secret",
    "CWE-942": "cors",
    "CWE-502": "unsafe-deserialization",
    "CWE-306": "missing-auth", "CWE-862": "missing-auth", "CWE-285": "missing-auth",
    "CWE-250": "iac-misconfiguration",  # running with unnecessary privileges (root)
}
# Fallback when a rule's CWE is missing or wrong: keywords in the rule id.
KEYWORD_TO_ISSUE = {
    "sql": "injection", "subprocess": "injection", "exec": "injection",
    "eval": "injection", "md5": "weak-crypto", "sha1": "weak-crypto",
    "debug": "insecure-defaults", "cors": "cors", "secret": "hardcoded-secret",
    "dockerfile": "iac-misconfiguration", "terraform": "iac-misconfiguration",
    "kubernetes": "iac-misconfiguration",
}


def classify(rule_id: str, cwes: list[str]) -> str:
    for cwe in cwes:
        if issue := CWE_TO_ISSUE.get(cwe.split(":")[0].strip()):
            return issue
    for keyword, issue in KEYWORD_TO_ISSUE.items():
        if keyword in rule_id.lower():
            return issue
    return "other"


# ---------------------------------------------------------------- gitleaks

def run_gitleaks(path: str) -> list[dict]:
    root = resolve_root(path)
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "gitleaks.json"
        subprocess.run(
            [find_binary("gitleaks"), "dir", ".", "--report-format", "json",
             "--report-path", str(report), "--no-banner", "--exit-code", "0"],
            cwd=root, capture_output=True, text=True, check=True,
        )
        raw = json.loads(report.read_text() or "[]")

    return [{
        "scanner": "gitleaks",
        "rule": item["RuleID"],
        "issue_type": "hardcoded-secret",
        "severity": "high",
        "file": item["File"],
        "line": item["StartLine"],
        "message": item["Description"],
        # The full secret never leaves this function.
        "evidence": mask(item["Secret"]),
    } for item in raw]


# ---------------------------------------------------------------- semgrep

SEMGREP_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def run_semgrep(path: str, config: str = "p/default") -> list[dict]:
    root = resolve_root(path)
    proc = subprocess.run(
        [find_binary("semgrep"), "scan", "--config", config, "--json",
         "--quiet", "--metrics", "off", "."],
        cwd=root, capture_output=True, text=True,
    )
    if not proc.stdout:
        raise RuntimeError(f"semgrep failed: {proc.stderr[-500:]}")
    raw = json.loads(proc.stdout)["results"]

    # Several rules often fire on the same line for the same bug.
    # Keep one finding per (file, line, issue_type): the most severe one.
    rank = {"high": 0, "medium": 1, "low": 2}
    merged: dict[tuple, dict] = {}
    for item in raw:
        meta = item["extra"].get("metadata", {})
        cwes = meta.get("cwe", [])
        cwes = [cwes] if isinstance(cwes, str) else cwes
        issue_type = classify(item["check_id"], cwes)
        line_no = item["start"]["line"]
        # Free semgrep hides the snippet ("requires login"), so read it ourselves.
        evidence = read_line(root / item["path"], line_no)
        if issue_type == "hardcoded-secret":
            evidence = mask(evidence)
        finding = {
            "scanner": "semgrep",
            "rule": item["check_id"].split(".")[-1],
            "issue_type": issue_type,
            "severity": SEMGREP_SEVERITY.get(item["extra"]["severity"], "low"),
            "file": item["path"],
            "line": line_no,
            "message": item["extra"]["message"].split("\n")[0][:300],
            "evidence": evidence[:200],
        }
        key = (finding["file"], finding["line"], finding["issue_type"])
        if key not in merged or rank[finding["severity"]] < rank[merged[key]["severity"]]:
            merged[key] = finding
    return list(merged.values())


# ---------------------------------------------------------------- osv-scanner

def cvss_to_severity(score: str | None) -> str:
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "medium"  # unknown score: don't hide it, don't overstate it
    return "high" if value >= 7 else "medium" if value >= 4 else "low"


def first_fixed_version(vulns: list[dict]) -> str | None:
    """The lowest version that fixes *every* listed vulnerability."""
    needed = []
    for vuln in vulns:
        fixes = [
            event["fixed"]
            for affected in vuln.get("affected", [])
            for rng in affected.get("ranges", [])
            for event in rng.get("events", [])
            if "fixed" in event
        ]
        try:
            if fixes:
                needed.append(min(Version(f) for f in fixes))
        except InvalidVersion:
            continue
    return str(max(needed)) if needed else None


# Licenses that let you use a package in closed-source commercial software.
PERMISSIVE = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC",
              "0BSD", "Unlicense", "CC0-1.0", "PSF-2.0", "Python-2.0", "Zlib"}
# Strong copyleft: distributing your product may require releasing its source.
STRONG_COPYLEFT = ("GPL", "AGPL", "SSPL", "EUPL", "OSL")
# Weak copyleft: obligations apply mainly to changes in the package itself.
WEAK_COPYLEFT = ("LGPL", "MPL", "EPL", "CDDL")


def license_findings(raw: dict, root: Path) -> list[dict]:
    """Turn osv-scanner's license data into findings.

    Strong copyleft -> medium, weak copyleft -> low (one finding per package).
    Unknown/non-standard metadata -> one grouped low finding, because old
    packages often have messy metadata and 5 separate "verify this" findings
    would bury the real ones.
    """
    findings, unknown, seen = [], [], set()
    for result in raw.get("results", []):
        source = Path(result["source"]["path"])
        file = str(source.relative_to(root)) if source.is_relative_to(root) else str(source)
        for pkg in result.get("packages", []):
            name, version = pkg["package"]["name"], pkg["package"]["version"]
            if (name, version) in seen:
                continue
            seen.add((name, version))
            licenses = pkg.get("licenses") or ["UNKNOWN"]
            if all(lic in PERMISSIVE for lic in licenses):
                continue
            joined = " AND ".join(licenses)
            # LGPL contains "GPL", so test weak copyleft first.
            if any(lic.startswith(WEAK_COPYLEFT) for lic in licenses):
                kind, severity = "weak copyleft", "low"
            elif any(lic.startswith(STRONG_COPYLEFT) for lic in licenses):
                kind, severity = "strong copyleft", "medium"
            else:
                unknown.append((file, f"{name}=={version} ({joined})"))
                continue
            findings.append({
                "scanner": "osv-scanner",
                "rule": f"license:{joined}",
                "issue_type": "license-risk",
                "severity": severity,
                "file": file,
                "line": None,
                "message": f"{name} {version} is licensed {joined} ({kind}); check it is compatible with how you distribute your product",
                "evidence": f"{name}=={version}  license: {joined}",
            })
    if unknown:
        findings.append({
            "scanner": "osv-scanner",
            "rule": "license:unknown",
            "issue_type": "license-risk",
            "severity": "low",
            "file": unknown[0][0],
            "line": None,
            "message": f"{len(unknown)} packages have missing or non-standard license metadata; verify their licenses manually",
            "evidence": "; ".join(item for _, item in unknown)[:400],
        })
    return findings


def run_osv(path: str) -> list[dict]:
    """Vulnerable dependencies AND license risks, from one osv-scanner run."""
    root = resolve_root(path)
    proc = subprocess.run(
        [find_binary("osv-scanner"), "scan", "source", "--format", "json",
         "--licenses=" + ",".join(sorted(PERMISSIVE)), "-r", "."],
        cwd=root, capture_output=True, text=True,
    )
    # osv-scanner exits 1 when it finds vulnerabilities; that's not an error.
    if proc.returncode not in (0, 1) or not proc.stdout:
        if "No package sources found" in proc.stderr:
            return []
        raise RuntimeError(f"osv-scanner failed: {proc.stderr[-500:]}")
    raw = json.loads(proc.stdout)

    findings, seen = [], set()
    for result in raw.get("results", []):
        source = Path(result["source"]["path"])
        file = str(source.relative_to(root)) if source.is_relative_to(root) else str(source)
        for pkg in result.get("packages", []):
            name, version = pkg["package"]["name"], pkg["package"]["version"]
            if (name, version) in seen:
                continue
            seen.add((name, version))
            vulns = pkg.get("vulnerabilities", [])
            if not vulns:  # listed only for its license; no CVEs
                continue
            groups = pkg.get("groups", [])
            max_score = max((g.get("max_severity") or "0" for g in groups), key=float, default=None)
            cves = sorted({a for v in vulns for a in v.get("aliases", []) if a.startswith("CVE-")})
            fixed = first_fixed_version(vulns)
            findings.append({
                "scanner": "osv-scanner",
                "rule": ", ".join(v["id"] for v in vulns[:5]),
                "issue_type": "vulnerable-dependency",
                "severity": cvss_to_severity(max_score),
                "file": file,
                "line": None,
                "message": (f"{name} {version} has {len(vulns)} known vulnerabilities"
                            + (f"; upgrade to {fixed} or later" if fixed else "")),
                "evidence": f"{name}=={version}  CVEs: {', '.join(cves[:8]) or 'none listed'}",
            })
    return findings + license_findings(raw, root)


# ---------------------------------------------------------------- gitleaks (git history)

def run_gitleaks_history(path: str) -> list[dict]:
    """Secrets in past commits. A key deleted from the code is still leaked if
    it's in history: anyone who clones the repo can read it."""
    root = resolve_root(path)
    git = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=root,
                         capture_output=True, text=True)
    if git.returncode != 0:
        return []  # not a git repo: nothing to scan
    repo = Path(git.stdout.strip()).resolve()
    subdir = root.relative_to(repo)

    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "history.json"
        cmd = [find_binary("gitleaks"), "git", str(repo), "--report-format", "json",
               "--report-path", str(report), "--no-banner", "--exit-code", "0"]
        if str(subdir) != ".":
            cmd += [f"--log-opts=-- {subdir}"]  # only commits touching the audited folder
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        raw = json.loads(report.read_text() or "[]")

    # The same secret usually appears in many commits: one finding per (file, rule).
    grouped: dict[tuple, dict] = {}
    for item in raw:
        file = Path(item["File"])
        file = str(file.relative_to(subdir)) if file.is_relative_to(subdir) else str(file)
        key = (file, item["RuleID"])
        commit = f"{item['Commit'][:8]} ({item['Date'][:10]})"
        if key in grouped:
            grouped[key]["commits"].append(commit)
            continue
        grouped[key] = {"item": item, "file": file, "commits": [commit]}

    return [{
        "scanner": "gitleaks",
        "rule": g["item"]["RuleID"],
        "issue_type": "secret-in-git-history",
        "severity": "high",
        "file": g["file"],
        "line": None,  # line numbers differ per commit
        "message": (f"{g['item']['Description']} Present in git history in "
                    f"{len(g['commits'])} commit(s): {', '.join(g['commits'][:5])}"),
        "evidence": mask(g["item"]["Secret"]),
    } for g in grouped.values()]


# ---------------------------------------------------------------- trivy (IaC / containers)

TRIVY_SEVERITY = {"CRITICAL": "high", "HIGH": "high", "MEDIUM": "medium",
                  "LOW": "low", "UNKNOWN": "low"}


def run_trivy_config(path: str) -> list[dict]:
    """Misconfigurations in Dockerfiles, Terraform, Kubernetes, CloudFormation
    and Helm charts."""
    root = resolve_root(path)
    proc = subprocess.run(
        [find_binary("trivy"), "config", "--format", "json", "--quiet", "."],
        cwd=root, capture_output=True, text=True,
    )
    if proc.returncode != 0 or not proc.stdout:
        raise RuntimeError(f"trivy failed: {proc.stderr[-500:]}")
    raw = json.loads(proc.stdout)

    findings = []
    for result in raw.get("Results", []) or []:
        for m in result.get("Misconfigurations", []) or []:
            if m.get("Status") != "FAIL":
                continue
            cause = m.get("CauseMetadata", {})
            lines = cause.get("Code", {}).get("Lines") or []
            evidence = next((ln["Content"].strip() for ln in lines if ln.get("IsCause")), "")
            findings.append({
                "scanner": "trivy",
                "rule": m["ID"],
                "issue_type": "iac-misconfiguration",
                "severity": TRIVY_SEVERITY.get(m.get("Severity", "UNKNOWN"), "low"),
                "file": result["Target"],
                "line": cause.get("StartLine"),
                "message": f"{m['Title']}. {m.get('Resolution', '')}".strip()[:300],
                "evidence": evidence[:200] or m.get("Message", "")[:200],
            })
    return findings
