from stegkit import text


def test_zero_width_round_trip():
    cover = ("This is an ordinary sentence with enough visible cover text. " * 30)
    stego = text.encode(cover, b"hidden message", "key")
    assert text.strip(stego) == cover
    assert text.decode(stego, "key") == b"hidden message"

