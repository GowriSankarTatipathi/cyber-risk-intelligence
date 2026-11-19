"""Build minimal Office files for tests (standard library only)."""

import io
import zipfile
from xml.sax.saxutils import escape

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
A = "http://schemas.openxmlformats.org/drawingml/2006/main"
P = "http://schemas.openxmlformats.org/presentationml/2006/main"
S = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"


def _core(title, created, modified):
    return (
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        f'<dc:title>{escape(title or "")}</dc:title>'
        + (f'<dcterms:created xsi:type="dcterms:W3CDTF">{created}</dcterms:created>' if created else "")
        + (f'<dcterms:modified xsi:type="dcterms:W3CDTF">{modified}</dcterms:modified>' if modified else "")
        + "</cp:coreProperties>")


def _zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        for name, body in files.items():
            z.writestr(name, body)
    return buf.getvalue()


def make_docx(paragraphs: list[tuple[str | None, str]], title=None, created=None, modified=None) -> bytes:
    """paragraphs: (style or None, text), e.g. ("Heading1", "Data protection")."""
    body = ""
    for style, text in paragraphs:
        ppr = f'<w:pPr><w:pStyle w:val="{style}"/></w:pPr>' if style else ""
        body += f"<w:p>{ppr}<w:r><w:t>{escape(text)}</w:t></w:r></w:p>"
    return _zip({"word/document.xml": f'<w:document xmlns:w="{W}"><w:body>{body}</w:body></w:document>',
                 "docProps/core.xml": _core(title, created, modified)})


def make_pptx(slides: list[list[str]]) -> bytes:
    files = {}
    for i, lines in enumerate(slides, start=1):
        paras = "".join(f"<a:p><a:r><a:t>{escape(t)}</a:t></a:r></a:p>" for t in lines)
        files[f"ppt/slides/slide{i}.xml"] = (f'<p:sld xmlns:p="{P}" xmlns:a="{A}"><p:cSld><p:spTree><p:sp><p:txBody>'
                                             f"{paras}</p:txBody></p:sp></p:spTree></p:cSld></p:sld>")
    return _zip(files)


def make_xlsx(rows: list[list[str]], sheet_name: str = "Questionnaire") -> bytes:
    strings: list[str] = []
    xml_rows = ""
    for r, row in enumerate(rows, start=1):
        cells = ""
        for value in row:
            strings.append(value)
            cells += f'<c t="s"><v>{len(strings) - 1}</v></c>'
        xml_rows += f'<row r="{r}">{cells}</row>'
    shared = "".join(f"<si><t>{escape(v)}</t></si>" for v in strings)
    return _zip({
        "xl/workbook.xml": f'<workbook xmlns="{S}"><sheets><sheet name="{sheet_name}" sheetId="1"/></sheets></workbook>',
        "xl/sharedStrings.xml": f'<sst xmlns="{S}">{shared}</sst>',
        "xl/worksheets/sheet1.xml": f'<worksheet xmlns="{S}"><sheetData>{xml_rows}</sheetData></worksheet>',
    })
