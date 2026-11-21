"""Write a single, text-safe XLSX worksheet using the standard library."""

from io import BytesIO
import re
from xml.etree import ElementTree as ET
from zipfile import ZIP_DEFLATED, ZipFile


SHEET_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
DOC_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
TYPES = "http://schemas.openxmlformats.org/package/2006/content-types"
INVALID_XML = re.compile(r"[^\x09\x0a\x0d\x20-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]")
XLSX_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def _text(value):
    text = INVALID_XML.sub("\ufffd", str(value)[:32767])
    units = text.encode("utf-16-le")
    return units[:65534].decode("utf-16-le", errors="ignore") if len(units) > 65534 else text


def _column(index):
    letters = ""
    while index:
        index, digit = divmod(index - 1, 26)
        letters = chr(65 + digit) + letters
    return letters


def workbook(name, headers, rows):
    data = [headers, *rows]
    sheet = ET.Element("worksheet", xmlns=SHEET_NS)
    columns = ET.SubElement(sheet, "cols")
    for index, values in enumerate(zip(*data), start=1):
        width = max((len(line) for value in values if value is not None for line in str(value).splitlines()), default=0)
        ET.SubElement(columns, "col", min=str(index), max=str(index), width=str(min(62, max(9, width + 3))), customWidth="1")
    body = ET.SubElement(sheet, "sheetData")
    for index, row in enumerate(data, start=1):
        record = ET.SubElement(body, "row", r=str(index))
        for number, value in enumerate(row, start=1):
            if value is None:
                continue
            cell = ET.SubElement(record, "c", r=f"{_column(number)}{index}", s="1" if index == 1 else "0")
            if isinstance(value, bool):
                cell.set("t", "b")
                ET.SubElement(cell, "v").text = str(int(value))
            elif isinstance(value, int):
                ET.SubElement(cell, "v").text = str(value)
            else:
                cell.set("t", "inlineStr")
                content = ET.SubElement(cell, "is")
                ET.SubElement(content, "t", {"xml:space": "preserve"}).text = _text(value)

    styles = f"""<styleSheet xmlns="{SHEET_NS}">
      <fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts>
      <fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>
      <borders count="1"><border/></borders>
      <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
      <cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1">
        <alignment vertical="top" wrapText="1"/></xf><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1" applyAlignment="1">
        <alignment vertical="top" wrapText="1"/></xf></cellXfs>
      <cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
    </styleSheet>"""
    book = ET.Element("workbook", {"xmlns": SHEET_NS, "xmlns:r": DOC_REL})
    ET.SubElement(ET.SubElement(book, "sheets"), "sheet", {"name": name, "sheetId": "1", "r:id": "rId1"})
    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", f"""<Types xmlns="{TYPES}">
          <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
          <Default Extension="xml" ContentType="application/xml"/>
          <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
          <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
          <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
        </Types>""")
        archive.writestr("_rels/.rels", f'<Relationships xmlns="{PKG_REL}"><Relationship Id="rId1" Type="{DOC_REL}/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        archive.writestr("xl/workbook.xml", ET.tostring(book, encoding="utf-8"))
        archive.writestr("xl/_rels/workbook.xml.rels", f"""<Relationships xmlns="{PKG_REL}">
          <Relationship Id="rId1" Type="{DOC_REL}/worksheet" Target="worksheets/sheet1.xml"/>
          <Relationship Id="rId2" Type="{DOC_REL}/styles" Target="styles.xml"/>
        </Relationships>""")
        archive.writestr("xl/styles.xml", styles)
        archive.writestr("xl/worksheets/sheet1.xml", ET.tostring(sheet, encoding="utf-8"))
    return buffer.getvalue()
