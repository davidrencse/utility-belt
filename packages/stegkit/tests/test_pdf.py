from stegkit import pdf


def test_pdf_whitespace_round_trip(tmp_path):
    source, output = tmp_path / "source.pdf", tmp_path / "output.pdf"
    source.write_bytes(b"%PDF-1.4\n%%EOF\n")
    pdf.encode(source, output, b"pdf secret", "key", "whitespace")
    assert pdf.decode(output, "key") == b"pdf secret"

