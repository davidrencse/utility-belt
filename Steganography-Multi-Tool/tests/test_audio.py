import numpy as np
import soundfile as sf

from stegkit import audio


def test_wav_round_trip_and_sample_delta(tmp_path):
    source, output = tmp_path / "source.wav", tmp_path / "output.wav"
    samples = (np.sin(np.arange(20000) / 20) * 12000).astype(np.int16)
    sf.write(source, samples, 44100, subtype="PCM_16")
    audio.encode(source, output, b"audio secret", "key")
    assert audio.decode(output, "key") == b"audio secret"
    before, _ = sf.read(source, dtype="int32")
    after, _ = sf.read(output, dtype="int32")
    # soundfile returns PCM_16 left-aligned in int32, so one source unit is 2**16.
    assert np.max(np.abs(before.astype(np.int64) - after.astype(np.int64))) <= 2**16
