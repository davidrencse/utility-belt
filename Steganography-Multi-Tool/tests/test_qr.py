from stegkit import qr


def test_qr_public_scan_and_secret_round_trip(tmp_path):
    output = tmp_path / "qr.png"
    qr.encode("https://example.org", output, b"qr", "key", version=25)
    public, hidden = qr.decode(output, "key")
    assert public == "https://example.org"
    assert hidden == b"qr"
