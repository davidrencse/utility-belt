from PIL import Image, ImageChops

from stegkit import image


def test_png_round_trip_and_pixel_delta(tmp_path):
    source, output = tmp_path / "source.png", tmp_path / "output.png"
    Image.new("RGB", (100, 100), (120, 121, 122)).save(source)
    image.encode(source, output, b"image secret", "key")
    assert image.decode(output, "key") == b"image secret"
    diff = ImageChops.difference(Image.open(source), Image.open(output))
    assert max(channel[1] for channel in diff.getextrema()) <= 1

