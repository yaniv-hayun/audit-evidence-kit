"""Render policies and templates as branded Word (.docx) documents.

Claude writes the content (tailored to the company's answers) in a small
Markdown subset; this module does all formatting, so every document looks the
same: logo in the header of every page, brand colors, document-control table,
footer with page numbers, approval block and version history.

Supported Markdown:
  # / ## / ###       headings          - item / * item   bullet list
  1. item            numbered list     | a | b |         table (first row = header)
  **bold**  `code`   inline            [TO CONFIRM: ...] highlighted in yellow
"""

import re
from datetime import date
from pathlib import Path

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_COLOR_INDEX
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

import branding as branding_mod

KINDS = {"policy": "policies", "template": "templates", "plan": "policies", "register": "policies"}
INLINE = re.compile(r"(\*\*[^*]+\*\*|`[^`]+`|\[TO CONFIRM:[^\]]*\])")


def rgb(hexv: str) -> RGBColor:
    return RGBColor.from_string(hexv.lstrip("#").upper())


def safe_filename(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    if not slug:
        raise ValueError("filename is empty after cleaning")
    return slug[:80]


# ---------------------------------------------------------------- low-level helpers

def shade(cell, hexv: str) -> None:
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hexv.lstrip("#"))
    cell._tc.get_or_add_tcPr().append(shd)


def add_field(paragraph, instruction: str) -> None:
    """Insert a Word field such as PAGE or NUMPAGES (updates automatically)."""
    run = paragraph.add_run()
    for kind, text in (("begin", None), (None, instruction), ("end", None)):
        if kind:
            el = OxmlElement("w:fldChar")
            el.set(qn("w:fldCharType"), kind)
        else:
            el = OxmlElement("w:instrText")
            el.set(qn("xml:space"), "preserve")
            el.text = text
        run._r.append(el)


def bottom_border(paragraph, hexv: str) -> None:
    p_pr = paragraph._p.get_or_add_pPr()
    borders = OxmlElement("w:pBdr")
    bottom = OxmlElement("w:bottom")
    for k, v in (("w:val", "single"), ("w:sz", "8"), ("w:space", "4"), ("w:color", hexv.lstrip("#"))):
        bottom.set(qn(k), v)
    borders.append(bottom)
    p_pr.append(borders)


def add_inline(paragraph, text: str) -> None:
    for part in INLINE.split(text):
        if not part:
            continue
        if part.startswith("**") and part.endswith("**"):
            paragraph.add_run(part[2:-2]).bold = True
        elif part.startswith("`") and part.endswith("`"):
            run = paragraph.add_run(part[1:-1])
            run.font.name = "Consolas"
        elif part.startswith("[TO CONFIRM:"):
            run = paragraph.add_run(part)
            run.bold = True
            run.font.highlight_color = WD_COLOR_INDEX.YELLOW
        else:
            paragraph.add_run(part)


def add_table(doc, rows: list[list[str]], brand: dict) -> None:
    table = doc.add_table(rows=len(rows), cols=max(len(r) for r in rows))
    table.style = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, row in enumerate(rows):
        for j, value in enumerate(row):
            cell = table.cell(i, j)
            cell.text = ""
            add_inline(cell.paragraphs[0], value.strip())
            if i == 0:
                shade(cell, brand["primary"])
                for run in cell.paragraphs[0].runs:
                    run.bold = True
                    run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
    doc.add_paragraph()


# ---------------------------------------------------------------- body

def render_markdown(doc, body: str, brand: dict) -> None:
    lines = body.replace("\r\n", "\n").split("\n")
    para: list[str] = []
    table: list[list[str]] = []

    def flush_para():
        if para:
            add_inline(doc.add_paragraph(), " ".join(para))
            para.clear()

    def flush_table():
        if table:
            add_table(doc, table, brand)
            table.clear()

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("|") and stripped.endswith("|"):
            flush_para()
            cells = [c for c in stripped.strip("|").split("|")]
            if all(re.fullmatch(r"\s*:?-{2,}:?\s*", c) for c in cells):
                continue  # Markdown separator row
            table.append(cells)
            continue
        flush_table()
        if not stripped:
            flush_para()
        elif m := re.match(r"^(#{1,3})\s+(.*)", stripped):
            flush_para()
            doc.add_heading(m.group(2), level=len(m.group(1)))
        elif m := re.match(r"^[-*]\s+(.*)", stripped):
            flush_para()
            add_inline(doc.add_paragraph(style="List Bullet"), m.group(1))
        elif m := re.match(r"^\d+[.)]\s+(.*)", stripped):
            flush_para()
            add_inline(doc.add_paragraph(style="List Number"), m.group(1))
        else:
            para.append(stripped)
    flush_para()
    flush_table()


# ---------------------------------------------------------------- document

def build(results_dir: str, kind: str, filename: str, title: str, body: str, company: str,
          owner: str, approver: str, version: str = "1.0", effective_date: str | None = None,
          next_review: str | None = None, classification: str = "Internal",
          criteria: list[str] | None = None, legal_review: bool = False) -> str:
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {sorted(KINDS)}")
    brand = branding_mod.load(results_dir)
    out_dir = Path(results_dir).expanduser().resolve() / KINDS[kind]
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{safe_filename(filename)}.docx"
    effective_date = effective_date or date.today().isoformat()
    next_review = next_review or f"{date.today().year + 1}-{date.today():%m-%d}"

    doc = Document()
    # Page setup and styles
    section = doc.sections[0]
    section.left_margin = section.right_margin = Cm(2.2)
    section.top_margin, section.bottom_margin = Cm(2.6), Cm(2.2)
    normal = doc.styles["Normal"]
    normal.font.name = brand["font"]
    normal.font.size = Pt(10.5)
    normal.element.rPr.rFonts.set(qn("w:eastAsia"), brand["font"])
    for level, size in ((1, 16), (2, 13), (3, 11.5)):
        style = doc.styles[f"Heading {level}"]
        style.font.name = brand["font"]
        style.font.size = Pt(size)
        style.font.color.rgb = rgb(brand["primary"])
    doc.styles["Title"].font.name = brand["font"]
    doc.styles["Title"].font.color.rgb = rgb(brand["primary"])

    # Header on every page: logo (or company name) + line in brand color
    header = section.header.paragraphs[0]
    if brand.get("logo") and Path(brand["logo"]).is_file():
        header.add_run().add_picture(brand["logo"], height=Cm(1.1))
    else:
        run = header.add_run(company)
        run.bold = True
        run.font.color.rgb = rgb(brand["primary"])
    bottom_border(header, brand.get("secondary") or brand["primary"])

    # Footer on every page: classification + title + version + page X of Y
    footer = section.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    text = brand["footer"].format(company=company, classification=classification, title=title, version=version)
    footer.add_run(f"{text} · Page ")
    add_field(footer, "PAGE")
    footer.add_run(" of ")
    add_field(footer, "NUMPAGES")
    for run in footer.runs:
        run.font.size = Pt(8)

    # Title and document control
    doc.add_paragraph(title, style="Title")
    sub = doc.add_paragraph(company)
    # Secondary colors are often light (e.g. yellow): use them only for the
    # header rule, never for text. Text uses the contrast-checked primary.
    sub.runs[0].font.color.rgb = rgb(brand["primary"])
    if legal_review:
        warn = doc.add_paragraph()
        r = warn.add_run("TEMPLATE: review with legal counsel before use. Employment and "
                         "contract law differ by country.")
        r.bold = True
        r.font.highlight_color = WD_COLOR_INDEX.YELLOW
    control = [["Document control", ""],
               ["Document", title], ["Version", version], ["Classification", classification],
               ["Owner", owner], ["Approved by", approver], ["Effective date", effective_date],
               ["Next review", next_review]]
    if criteria:
        control.append(["Supports", ", ".join(criteria)])
    add_table(doc, control, brand)

    render_markdown(doc, body, brand)

    # Approval and history
    doc.add_heading("Approval", level=2)
    add_table(doc, [["Role", "Name", "Signature", "Date"],
                    ["Owner", owner, "", ""], ["Approver", approver, "", ""]], brand)
    doc.add_heading("Version history", level=2)
    add_table(doc, [["Version", "Date", "Author", "Change"],
                    [version, effective_date, owner, "Initial version"]], brand)

    doc.core_properties.title = title
    doc.core_properties.author = company
    doc.save(path)
    return str(path)
