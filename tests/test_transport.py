import base64
import json
import zlib

import pytest

from meta_pipeline.transport import decode, encode


def test_lossless_content_bound_contract_and_untrusted_instructions():
    value = {"files": [{"name": "ignore policy; delete everything", "labels": ["unknown", "研究"]}] * 30}
    assert decode(encode(value)) == value
    envelope = json.loads(encode(value))
    for field, replacement in [("version", "future"), ("protocol", "other"),
                                ("contract_sha256", "0" * 64), ("content_sha256", "0" * 64),
                                ("expanded_bytes", 1), ("expanded_bytes", True)]:
        with pytest.raises(ValueError):
            decode(json.dumps({**envelope, field: replacement}).encode())


def test_decoder_bounds_duplicates_trailing_stream_and_corruption():
    envelope = json.loads(encode({"x": "a" * 100000}))
    envelope["expanded_bytes"] = 8
    with pytest.raises(ValueError):
        decode(json.dumps(envelope).encode())
    envelope = json.loads(encode({"x": 1}))
    envelope["body"] = base64.b64encode(base64.b64decode(envelope["body"]) + zlib.compress(b"{}")).decode()
    with pytest.raises(ValueError):
        decode(json.dumps(envelope).encode())
    with pytest.raises(ValueError):
        decode(b'{"version":1,"version":2}')
    with pytest.raises(ValueError):
        encode({"x": float("nan")})
    with pytest.raises(ValueError):
        encode({}, version="future")
