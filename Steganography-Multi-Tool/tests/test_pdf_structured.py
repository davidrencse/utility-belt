from pypdf import PdfWriter

from stegkit import pdf


def test_pdf_metadata_and_invisible_round_trip(tmp_path):
    source = tmp_path / "source.pdf"
    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    with source.open("wb") as stream:
        writer.write(stream)
    for technique in ("metadata", "invisible"):
        output = tmp_path / f"{technique}.pdf"
        pdf.encode(source, output, b"structured", "key", technique)
        assert pdf.decode(output, "key") == b"structured"
