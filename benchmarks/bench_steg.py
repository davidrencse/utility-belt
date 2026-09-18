"""StegKit encode/decode timings for one tree. usage: bench_steg.py <stegkit_root> <workdir>
Unencrypted frames are deterministic, so output hashes are comparable across trees."""
import hashlib
import json
import os
import sys
import time

sys.path.insert(0, sys.argv[1])
work = sys.argv[2]
os.makedirs(work, exist_ok=True)
import numpy as np  # noqa: E402
import soundfile as sf  # noqa: E402
from PIL import Image  # noqa: E402
from stegkit import audio, image, pdf, text  # noqa: E402

rng = np.random.default_rng(1)
img_src = os.path.join(work, "cover.png")
Image.fromarray(rng.integers(0, 256, (1200, 1600, 3), dtype=np.uint8)).save(img_src)
wav_src = os.path.join(work, "cover.wav")
sf.write(wav_src, rng.integers(-20000, 20000, (44100 * 20, 2)).astype(np.int16), 44100, subtype="PCM_16")
pdf_src = os.path.join(work, "cover.pdf")
with open(pdf_src, "wb") as f:
    f.write(b"%PDF-1.4\n%%EOF\n")
payload = rng.integers(0, 256, 200_000, dtype=np.uint8).tobytes()
small = payload[:20_000]
cover_text = "lorem ipsum dolor sit amet " * 7000


def h(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()[:16]


def best(fn, n=3):
    t = 1e9
    for _ in range(n):
        s = time.perf_counter()
        r = fn()
        t = min(t, time.perf_counter() - s)
    return round(t * 1000, 1), r


res = {}
out = os.path.join(work, "img.png")
res["image_encode_ms"], _ = best(lambda: image.encode(img_src, out, payload))
res["image_decode_ms"], d = best(lambda: image.decode(out))
assert d == payload
res["image_hash"] = h(out)
out = os.path.join(work, "a.wav")
res["audio_encode_ms"], _ = best(lambda: audio.encode(wav_src, out, payload))
res["audio_decode_ms"], d = best(lambda: audio.decode(out))
assert d == payload
res["audio_hash"] = h(out)
res["text_encode_ms"], st = best(lambda: text.encode(cover_text, small))
res["text_decode_ms"], d = best(lambda: text.decode(st))
assert d == small
res["text_hash"] = hashlib.sha256(st.encode()).hexdigest()[:16]
out = os.path.join(work, "p.pdf")
res["pdf_ws_encode_ms"], _ = best(lambda: pdf.encode(pdf_src, out, small, None, "whitespace"))
res["pdf_ws_decode_ms"], d = best(lambda: pdf.decode(out))
assert d == small
res["pdf_hash"] = h(out)
print(json.dumps(res))
