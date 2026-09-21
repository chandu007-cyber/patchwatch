"""Minimal .docx writer using only the standard library.

A .docx is a ZIP of XML parts. Writing the handful we need directly keeps the whole
pipeline dependency-free, which matters more here than it usually would: this tool
gates security alerting, and every pip install is a supply chain attached to that.

Deliberately small. It supports headings, paragraphs with bold/colour/size, simple
tables, and page breaks - enough for a timeline report and nothing more. If you ever
need images, footnotes or a TOC, switch to python-docx rather than growing this.

The timeline is REGENERATED IN FULL from history.json on every run, never edited in
place. Surgically appending to an existing .docx means parsing and re-emitting
someone else's XML and getting the run-splitting right; regenerating from structured
data is simpler and cannot drift from the source of truth.
"""

from __future__ import annotations

import zipfile
from xml.sax.saxutils import escape

NS = (
    'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'
)

CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
</Types>"""

ROOT_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""

DOC_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"""


def _style(sid: str, name: str, size: int, bold: bool, color: str,
           outline: int | None = None, space_before: int = 240) -> str:
    """A heading/paragraph style. outlineLevel is what makes headings appear in
    Word's navigation pane and in a generated table of contents."""
    ol = f'<w:outlineLvl w:val="{outline}"/>' if outline is not None else ""
    return (
        f'<w:style w:type="paragraph" w:styleId="{sid}">'
        f'<w:name w:val="{name}"/><w:basedOn w:val="Normal"/><w:qFormat/>'
        f'<w:pPr><w:spacing w:before="{space_before}" w:after="120"/>{ol}</w:pPr>'
        f'<w:rPr><w:b w:val="{"1" if bold else "0"}"/>'
        f'<w:color w:val="{color}"/><w:sz w:val="{size}"/></w:rPr></w:style>'
    )


STYLES = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles {NS}>
<w:docDefaults><w:rPrDefault><w:rPr>
<w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/><w:sz w:val="20"/>
</w:rPr></w:rPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal">
<w:name w:val="Normal"/><w:qFormat/>
<w:pPr><w:spacing w:after="100" w:line="264" w:lineRule="auto"/></w:pPr>
</w:style>
{_style("Title", "Title", 56, True, "1a1a1a", space_before=0)}
{_style("Heading1", "heading 1", 32, True, "1a1a1a", outline=0, space_before=360)}
{_style("Heading2", "heading 2", 26, True, "2b2b2b", outline=1)}
{_style("Heading3", "heading 3", 22, True, "444444", outline=2)}
<w:style w:type="paragraph" w:styleId="Meta">
<w:name w:val="Meta"/><w:basedOn w:val="Normal"/>
<w:rPr><w:color w:val="666666"/><w:sz w:val="18"/></w:rPr></w:style>
<w:style w:type="character" w:styleId="Code">
<w:name w:val="Code"/>
<w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/><w:sz w:val="18"/></w:rPr></w:style>
</w:styles>"""


def esc(text) -> str:
    return escape(str(text if text is not None else ""))


def run(text: str, *, bold=False, italic=False, color=None, size=None,
        mono=False) -> str:
    props = []
    if bold:
        props.append("<w:b/>")
    if italic:
        props.append("<w:i/>")
    if mono:
        props.append('<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/>')
    if color:
        props.append(f'<w:color w:val="{color}"/>')
    if size:
        props.append(f'<w:sz w:val="{size}"/>')
    rpr = f"<w:rPr>{''.join(props)}</w:rPr>" if props else ""
    # xml:space="preserve" keeps leading/trailing spaces, which Word strips otherwise.
    return f'<w:r>{rpr}<w:t xml:space="preserve">{esc(text)}</w:t></w:r>'


def para(runs: str | list[str] = "", *, style: str | None = None,
         align: str | None = None, border_bottom: bool = False) -> str:
    if isinstance(runs, str):
        runs = [run(runs)] if runs else []
    props = []
    if style:
        props.append(f'<w:pStyle w:val="{style}"/>')
    if align:
        props.append(f'<w:jc w:val="{align}"/>')
    if border_bottom:
        # A paragraph bottom border, not a one-row table - tables used as rules
        # render badly and confuse screen readers.
        props.append('<w:pBdr><w:bottom w:val="single" w:sz="6" w:space="2" '
                     'w:color="d0d0d0"/></w:pBdr>')
    ppr = f"<w:pPr>{''.join(props)}</w:pPr>" if props else ""
    return f"<w:p>{ppr}{''.join(runs)}</w:p>"


def page_break() -> str:
    return '<w:p><w:r><w:br w:type="page"/></w:r></w:p>'


def table(rows: list[list[str]], widths: list[int], *,
          header: bool = True, shading: list[list[str | None]] | None = None) -> str:
    """rows contains pre-built run XML per cell. widths are DXA and must sum to
    the table width; cell widths must be set too or Google Docs mis-renders."""
    total = sum(widths)
    grid = "".join(f'<w:gridCol w:w="{w}"/>' for w in widths)
    out = [
        f'<w:tbl><w:tblPr><w:tblW w:w="{total}" w:type="dxa"/>'
        f'<w:tblBorders>'
        f'<w:top w:val="single" w:sz="4" w:color="dddddd"/>'
        f'<w:left w:val="none" w:sz="0" w:color="auto"/>'
        f'<w:bottom w:val="single" w:sz="4" w:color="dddddd"/>'
        f'<w:right w:val="none" w:sz="0" w:color="auto"/>'
        f'<w:insideH w:val="single" w:sz="4" w:color="eeeeee"/>'
        f'<w:insideV w:val="none" w:sz="0" w:color="auto"/>'
        f'</w:tblBorders></w:tblPr><w:tblGrid>{grid}</w:tblGrid>'
    ]
    for r, cells in enumerate(rows):
        out.append("<w:tr>")
        # cantSplit keeps a row whole across a page break. Without it a CVE row can
        # split so that its "EXPLOITED" flag lands alone at the top of the next page,
        # detached from the CVE id - which reads as a separate, empty finding.
        # tblHeader repeats the header row on every page the table spans.
        trpr = "<w:cantSplit/>" + ("<w:tblHeader/>" if header and r == 0 else "")
        out.append(f"<w:trPr>{trpr}</w:trPr>")
        for c, cell in enumerate(cells):
            fill = None
            if shading and r < len(shading) and c < len(shading[r]):
                fill = shading[r][c]
            elif header and r == 0:
                fill = "f2f2f2"
            # ShadingType clear, never solid - solid renders as a black block.
            shd = f'<w:shd w:val="clear" w:color="auto" w:fill="{fill}"/>' if fill else ""
            out.append(
                f'<w:tc><w:tcPr><w:tcW w:w="{widths[c]}" w:type="dxa"/>{shd}'
                f'<w:vAlign w:val="center"/></w:tcPr>'
                f'<w:p><w:pPr><w:spacing w:before="40" w:after="40"/></w:pPr>{cell}</w:p></w:tc>'
            )
        out.append("</w:tr>")
    out.append("</w:tbl>")
    # Word needs a paragraph after a table or adjacent tables merge.
    out.append('<w:p><w:pPr><w:spacing w:after="0"/></w:pPr></w:p>')
    return "".join(out)


def write_docx(path: str, body_xml: str, *, letter: bool = True) -> None:
    """A4 is the docx default; US Letter must be set explicitly (DXA, 1440 = 1 inch)."""
    if letter:
        sect = ('<w:sectPr><w:pgSz w:w="12240" w:h="15840"/>'
                '<w:pgMar w:top="1080" w:right="1080" w:bottom="1080" w:left="1080"/></w:sectPr>')
    else:
        sect = ('<w:sectPr><w:pgSz w:w="11906" w:h="16838"/>'
                '<w:pgMar w:top="1080" w:right="1080" w:bottom="1080" w:left="1080"/></w:sectPr>')

    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f"<w:document {NS}><w:body>{body_xml}{sect}</w:body></w:document>"
    )

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", CONTENT_TYPES)
        z.writestr("_rels/.rels", ROOT_RELS)
        z.writestr("word/_rels/document.xml.rels", DOC_RELS)
        z.writestr("word/styles.xml", STYLES)
        z.writestr("word/document.xml", document)
