"""Shared Word formatting helpers for the PhishGuard-HDV dissertation and paper.

The helpers follow the UTP FYP Guidelines 2024:
  * A4, top/bottom/right 25 mm, left 40 mm (dissertation)
  * Times New Roman 12, 1.5 line spacing, justified body text
  * up to three numbered heading levels
  * page numbers bottom centre, roman for front matter, arabic for main text
  * table captions above, figure captions below
"""
from __future__ import annotations

import re
from pathlib import Path

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_ALIGN_VERTICAL, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

FONT = "Times New Roman"
BLACK = RGBColor(0, 0, 0)

# Citation registry: key -> IEEE number, filled in document order.
_CITE_RE = re.compile(r"\[{1,2}CITE:([^\]]+)\]{1,2}")
CITATION_ORDER: list[str] = []


def cite(*keys: str) -> str:
    """Return a citation marker that is resolved in document order."""
    return "[[" + "CITE:" + "|".join(keys) + "]]"


_CITE_RUN_RE = re.compile(r"(?:\[{1,2}CITE:[^\]]+\]{1,2}){2,}")


def resolve_citations(text: str) -> str:
    def merge(match: re.Match) -> str:
        keys = _CITE_RE.findall(match.group(0))
        return "[[CITE:" + "|".join(
            k for group in keys for k in group.split("|")) + "]]"

    def repl(match: re.Match) -> str:
        nums = []
        for key in match.group(1).split("|"):
            if key not in CITATION_ORDER:
                CITATION_ORDER.append(key)
            nums.append(CITATION_ORDER.index(key) + 1)
        return ", ".join(f"[{n}]" for n in sorted(set(nums)))

    text = _CITE_RUN_RE.sub(merge, text)
    return _CITE_RE.sub(repl, text)


def reset_citations() -> None:
    CITATION_ORDER.clear()


# ---------------------------------------------------------------------------
# low-level XML helpers
# ---------------------------------------------------------------------------

def _set_font(run, size=None, bold=None, italic=None, name=FONT):
    run.font.name = name
    run.font.size = Pt(size) if size else run.font.size
    if bold is not None:
        run.bold = bold
    if italic is not None:
        run.italic = italic
    rpr = run._element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = OxmlElement("w:rFonts")
        rpr.append(rfonts)
    for attr in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"):
        rfonts.set(qn(attr), name)


def add_field(paragraph, instruction: str, result: str = "") -> None:
    """Insert a Word field (PAGE, TOC, SEQ ...)."""
    r1 = paragraph.add_run()
    fld = OxmlElement("w:fldChar")
    fld.set(qn("w:fldCharType"), "begin")
    r1._r.append(fld)

    r2 = paragraph.add_run()
    instr = OxmlElement("w:instrText")
    instr.set(qn("xml:space"), "preserve")
    instr.text = instruction
    r2._r.append(instr)

    r3 = paragraph.add_run()
    fld = OxmlElement("w:fldChar")
    fld.set(qn("w:fldCharType"), "separate")
    r3._r.append(fld)

    if result:
        r4 = paragraph.add_run(result)
        _set_font(r4, size=12)

    r5 = paragraph.add_run()
    fld = OxmlElement("w:fldChar")
    fld.set(qn("w:fldCharType"), "end")
    r5._r.append(fld)


def add_tc(paragraph, entry: str, identifier: str, level: int = 1) -> None:
    """Insert a hidden TC field so a TOC \\f list can collect this caption.

    This keeps chapter-based caption numbers (Figure 3.2) while letting Word
    produce an accurate List of Figures/Tables with page numbers.
    """
    r1 = paragraph.add_run()
    fld = OxmlElement("w:fldChar")
    fld.set(qn("w:fldCharType"), "begin")
    r1._r.append(fld)

    r2 = paragraph.add_run()
    instr = OxmlElement("w:instrText")
    instr.set(qn("xml:space"), "preserve")
    safe = entry.replace('"', "'")
    instr.text = f' TC "{safe}" \\f {identifier} \\l {level} '
    r2._r.append(instr)

    r3 = paragraph.add_run()
    fld = OxmlElement("w:fldChar")
    fld.set(qn("w:fldCharType"), "end")
    r3._r.append(fld)


def add_bookmark(paragraph, name: str, bookmark_id: int) -> None:
    start = OxmlElement("w:bookmarkStart")
    start.set(qn("w:id"), str(bookmark_id))
    start.set(qn("w:name"), name)
    end = OxmlElement("w:bookmarkEnd")
    end.set(qn("w:id"), str(bookmark_id))
    paragraph._p.insert(0, start)
    paragraph._p.append(end)


def set_cell_shading(cell, fill: str) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    tc_pr.append(shd)


def set_cell_margins(table, top=40, bottom=40, left=70, right=70) -> None:
    tbl_pr = table._tbl.tblPr
    mar = OxmlElement("w:tblCellMar")
    for side, value in (("top", top), ("left", left), ("bottom", bottom),
                        ("right", right)):
        node = OxmlElement(f"w:{side}")
        node.set(qn("w:w"), str(value))
        node.set(qn("w:type"), "dxa")
        mar.append(node)
    tbl_pr.append(mar)


def repeat_header(row) -> None:
    tr_pr = row._tr.get_or_add_trPr()
    header = OxmlElement("w:tblHeader")
    header.set(qn("w:val"), "true")
    tr_pr.append(header)


def keep_table_together(table) -> None:
    """Best-effort: stop a short table splitting across pages."""
    for row in table.rows:
        tr_pr = row._tr.get_or_add_trPr()
        cant = OxmlElement("w:cantSplit")
        cant.set(qn("w:val"), "true")
        tr_pr.append(cant)


# ---------------------------------------------------------------------------
# document setup
# ---------------------------------------------------------------------------

def _style_font(style, size, bold=False, italic=False):
    style.font.name = FONT
    style.font.size = Pt(size)
    style.font.bold = bold
    style.font.italic = italic
    style.font.color.rgb = BLACK
    rpr = style.element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = OxmlElement("w:rFonts")
        rpr.append(rfonts)
    for attr in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"):
        rfonts.set(qn(attr), FONT)


def setup_document(left_margin_cm=4.0, body_size=12, line_spacing=1.5):
    doc = Document()
    section = doc.sections[0]
    section.page_width = Cm(21.0)
    section.page_height = Cm(29.7)
    section.top_margin = Cm(2.5)
    section.bottom_margin = Cm(2.5)
    section.right_margin = Cm(2.5)
    section.left_margin = Cm(left_margin_cm)
    section.header_distance = Cm(1.25)
    section.footer_distance = Cm(1.25)

    normal = doc.styles["Normal"]
    _style_font(normal, body_size)
    pf = normal.paragraph_format
    pf.line_spacing = line_spacing
    pf.space_before = Pt(0)
    pf.space_after = Pt(6)
    pf.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    pf.widow_control = True

    h1 = doc.styles["Heading 1"]
    _style_font(h1, 14, bold=True)
    h1.paragraph_format.space_before = Pt(0)
    h1.paragraph_format.space_after = Pt(18)
    h1.paragraph_format.line_spacing = 1.5
    h1.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    h1.paragraph_format.keep_with_next = True

    h2 = doc.styles["Heading 2"]
    _style_font(h2, 12, bold=True)
    h2.paragraph_format.space_before = Pt(12)
    h2.paragraph_format.space_after = Pt(6)
    h2.paragraph_format.line_spacing = 1.5
    h2.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.LEFT
    h2.paragraph_format.keep_with_next = True

    h3 = doc.styles["Heading 3"]
    _style_font(h3, 12, bold=True)
    h3.paragraph_format.space_before = Pt(8)
    h3.paragraph_format.space_after = Pt(3)
    h3.paragraph_format.line_spacing = 1.5
    h3.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.LEFT
    h3.paragraph_format.keep_with_next = True

    for name in ("List Bullet", "List Number"):
        st = doc.styles[name]
        _style_font(st, body_size)
        st.paragraph_format.line_spacing = line_spacing
        st.paragraph_format.space_after = Pt(3)
        st.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY

    # Caption style (10 pt, single spacing, centred).
    try:
        cap = doc.styles["Caption"]
    except KeyError:
        from docx.enum.style import WD_STYLE_TYPE
        cap = doc.styles.add_style("Caption", WD_STYLE_TYPE.PARAGRAPH)
    _style_font(cap, 10)
    cap.paragraph_format.line_spacing = 1.0
    cap.paragraph_format.space_before = Pt(3)
    cap.paragraph_format.space_after = Pt(9)
    cap.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER

    # Ask Word to refresh all fields when the file is opened.
    settings = doc.settings.element
    update = OxmlElement("w:updateFields")
    update.set(qn("w:val"), "true")
    settings.append(update)
    return doc


def set_page_number_format(section, fmt: str, start: int | None = 1) -> None:
    sect_pr = section._sectPr
    pg = sect_pr.find(qn("w:pgNumType"))
    if pg is None:
        pg = OxmlElement("w:pgNumType")
        sect_pr.append(pg)
    pg.set(qn("w:fmt"), fmt)
    if start is None:
        if qn("w:start") in pg.attrib:
            del pg.attrib[qn("w:start")]
    else:
        pg.set(qn("w:start"), str(start))


def add_footer_page_number(section, size=12, hide_first=False) -> None:
    section.different_first_page_header_footer = hide_first
    footer = section.footer
    footer.is_linked_to_previous = False
    p = footer.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Pt(0)
    add_field(p, " PAGE ", "1")
    for run in p.runs:
        _set_font(run, size=size)

    if hide_first:
        first = section.first_page_footer
        first.is_linked_to_previous = False
        fp = first.paragraphs[0]
        fp.text = ""


# ---------------------------------------------------------------------------
# content helpers
# ---------------------------------------------------------------------------

def add_par(doc, text="", *, align=None, bold=False, italic=False, size=None,
            space_after=None, space_before=None, style=None, keep_next=False,
            line_spacing=None, left_indent=None, first_line=None):
    p = doc.add_paragraph(style=style) if style else doc.add_paragraph()
    text = resolve_citations(text)
    if text:
        run = p.add_run(text)
        _set_font(run, size=size, bold=bold, italic=italic)
    if align is not None:
        p.alignment = align
    if space_after is not None:
        p.paragraph_format.space_after = Pt(space_after)
    if space_before is not None:
        p.paragraph_format.space_before = Pt(space_before)
    if keep_next:
        p.paragraph_format.keep_with_next = True
    if line_spacing is not None:
        p.paragraph_format.line_spacing = line_spacing
    if left_indent is not None:
        p.paragraph_format.left_indent = Cm(left_indent)
    if first_line is not None:
        p.paragraph_format.first_line_indent = Cm(first_line)
    return p


def body(doc, text):
    return add_par(doc, text, align=WD_ALIGN_PARAGRAPH.JUSTIFY)


def heading(doc, text, level, *, page_break=False, bookmark=None,
            bookmark_id=None):
    if page_break:
        doc.add_page_break()
    p = doc.add_heading(resolve_citations(text), level=level)
    for run in p.runs:
        _set_font(run, size=14 if level == 1 else 12, bold=True)
    if bookmark and bookmark_id is not None:
        add_bookmark(p, bookmark, bookmark_id)
    return p


def chapter(doc, text, bookmark=None, bookmark_id=None):
    return heading(doc, text, 1, page_break=True, bookmark=bookmark,
                   bookmark_id=bookmark_id)


def page_break(doc):
    doc.add_page_break()


def bullets(doc, items):
    for item in items:
        add_par(doc, item, style="List Bullet", align=WD_ALIGN_PARAGRAPH.JUSTIFY)


def numbered(doc, items):
    for item in items:
        add_par(doc, item, style="List Number", align=WD_ALIGN_PARAGRAPH.JUSTIFY)


def table_caption(doc, text):
    p = doc.add_paragraph(style="Caption")
    run = p.add_run(text)
    _set_font(run, size=10)
    add_tc(p, text, "T")
    return p


def figure_caption(doc, text):
    p = doc.add_paragraph(style="Caption")
    run = p.add_run(text)
    _set_font(run, size=10)
    add_tc(p, text, "F")
    return p


def add_table(doc, headers, rows, *, font_size=9, widths=None,
              center_cols=None, first_col_bold=False):
    center_cols = set(center_cols or [])
    if widths:
        total = float(sum(widths))
        widths = [w * 14.5 / total for w in widths]
    table = doc.add_table(rows=1, cols=len(headers))
    table.style = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    set_cell_margins(table)

    hdr = table.rows[0]
    repeat_header(hdr)
    for i, text in enumerate(headers):
        cell = hdr.cells[i]
        cell.text = ""
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_after = Pt(0)
        p.paragraph_format.line_spacing = 1.0
        run = p.add_run(resolve_citations(str(text)))
        _set_font(run, size=font_size, bold=True)
        set_cell_shading(cell, "DCE6F1")
        cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
        if widths:
            cell.width = Cm(widths[i])

    for row in rows:
        cells = table.add_row().cells
        for i, value in enumerate(row):
            cell = cells[i]
            cell.text = ""
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            p.paragraph_format.line_spacing = 1.0
            p.alignment = (WD_ALIGN_PARAGRAPH.CENTER if i in center_cols
                           else WD_ALIGN_PARAGRAPH.LEFT)
            run = p.add_run(resolve_citations(str(value)))
            _set_font(run, size=font_size,
                      bold=(first_col_bold and i == 0))
            cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
            if widths:
                cell.width = Cm(widths[i])

    if widths:
        for i, width in enumerate(widths):
            table.columns[i].width = Cm(width)
    keep_table_together(table)
    add_par(doc, "", space_after=0, line_spacing=1.0)
    return table


def add_figure(doc, path, caption, width_cm=15.0):
    doc.add_picture(str(path), width=Cm(width_cm))
    pic_par = doc.paragraphs[-1]
    pic_par.alignment = WD_ALIGN_PARAGRAPH.CENTER
    pic_par.paragraph_format.space_before = Pt(6)
    pic_par.paragraph_format.space_after = Pt(3)
    figure_caption(doc, caption)


def add_section_break(doc):
    return doc.add_section(WD_SECTION.NEW_PAGE)


# ---------------------------------------------------------------------------
# Word post-processing
# ---------------------------------------------------------------------------

def finalize_with_word(docx_path: Path, pdf_path: Path | None = None):
    """Update all TOC/TC fields, repaginate, save and optionally export PDF.

    Returns a dict with the physical page numbers of the START_MAIN and
    START_APPENDIX bookmarks plus total pages.
    """
    import win32com.client as win32

    word = win32.gencache.EnsureDispatch("Word.Application")
    word.Visible = False
    word.DisplayAlerts = 0
    doc = None
    info = {"pages": None, "main_start": None, "appendix_start": None}
    try:
        doc = word.Documents.Open(str(docx_path))
        # Two passes: the first TOC build changes pagination, the second keeps
        # every page number consistent.
        for _ in range(2):
            doc.Fields.Update()
            for i in range(1, doc.TablesOfContents.Count + 1):
                doc.TablesOfContents(i).Update()
            doc.Repaginate()
        info["pages"] = int(doc.ComputeStatistics(2))
        for name, key in (("START_MAIN", "main_start"),
                          ("START_APPENDIX", "appendix_start")):
            if doc.Bookmarks.Exists(name):
                info[key] = int(
                    doc.Bookmarks(name).Range.Information(3))
        doc.Save()
        if pdf_path is not None:
            doc.ExportAsFixedFormat(str(pdf_path), 17)
    finally:
        if doc is not None:
            doc.Close(False)
        word.Quit()
    return info
