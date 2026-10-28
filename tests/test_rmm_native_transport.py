import hashlib
import json
import time

import httpx
import pytest

from meta_pipeline.rmm_native import NativeRMMTransport, RMMReadGrant, _require_response_url

ENDPOINT = "https://192.0.2.60:9444"
TOKEN = "t" * 64
NOW = 1_798_000_000.0


def grant(endpoint=ENDPOINT, host="192.0.2.60", scopes=frozenset({"wall.snapshot.read"})):
    return RMMReadGrant(endpoint=endpoint, host=host, scopes=scopes)


def envelope(snapshot=None):
    snapshot = snapshot if snapshot is not None else {
        "utc": NOW, "resources": [{"id": "datastore", "status": "online"}],
        "guests": [], "metals": [], "allowed_actions": [], "allowed_guests": [],
    }
    canonical = json.dumps(snapshot, separators=(",", ":"), allow_nan=False).encode()
    cursor = '"' + hashlib.sha256(canonical).hexdigest() + '"'
    return {"snapshot": snapshot, "cursor": cursor}


def make_transport(handler):
    return NativeRMMTransport(grant(), TOKEN, ca_file="/unused/test-ca.pem",
                              transport=httpx.MockTransport(handler))


def test_native_get_projects_existing_rmm_snapshot_with_bound_auth():
    requests = []

    def handler(request):
        requests.append(request)
        body = envelope()
        return httpx.Response(200, headers={"content-type": "application/json", "etag": body["cursor"]},
                              content=json.dumps(body).encode())

    with make_transport(handler) as client:
        rows = client.observe(now=NOW)
    assert requests[0].method == "GET"
    assert requests[0].url == ENDPOINT + "/api/wall/snapshot"
    assert requests[0].headers["authorization"] == "Bearer " + TOKEN
    assert requests[0].content == b""
    assert rows[0].asset_id == "datastore"
    assert rows[0].source_ref == ENDPOINT
    assert rows[0].health == "up"


@pytest.mark.parametrize("status", [301, 302, 307, 308, 401, 403, 503])
def test_non_200_and_redirect_responses_fail_closed(status):
    def handler(_):
        return httpx.Response(status, headers={"location": "https://elsewhere.invalid/"},
                              content=b"{}")
    with make_transport(handler) as client, pytest.raises(ValueError):
        client.observe(now=NOW)


def test_stale_future_malformed_and_execution_grants_are_rejected():
    cases = [
        {"utc": NOW - 61, "resources": [], "guests": [], "metals": [],
         "allowed_actions": [], "allowed_guests": []},
        {"utc": NOW + 6, "resources": [], "guests": [], "metals": [],
         "allowed_actions": [], "allowed_guests": []},
        {"utc": NOW, "resources": [], "guests": [], "metals": [],
         "allowed_actions": ["restart"], "allowed_guests": []},
        {"utc": NOW, "resources": [], "guests": [], "metals": [],
         "allowed_actions": [], "allowed_guests": {}},
    ]
    for snapshot in cases:
        body = json.dumps(envelope(snapshot)).encode()
        with make_transport(lambda _: httpx.Response(200, headers={"content-type": "application/json"},
                                                       content=body)) as client:
            with pytest.raises(ValueError):
                client.observe(now=NOW)


def test_oversized_and_duplicate_json_fail_closed():
    over = b" " * (262144 + 1)
    dup = b'{"snapshot":{},"cursor":"\"' + b"a" * 64 + b'\","cursor":"x"}'
    for body in (over, dup):
        with make_transport(lambda _, body=body: httpx.Response(
                200, headers={"content-type": "application/json"}, content=body)) as client:
            with pytest.raises(ValueError):
                client.observe(now=NOW)


def test_missing_auth_malformed_grants_and_host_mismatch_rejected():
    with pytest.raises(ValueError):
        NativeRMMTransport(grant(), "", ca_file="/unused/test-ca.pem",
                           transport=httpx.MockTransport(lambda _: httpx.Response(200)))
    for args in [
        {"endpoint": "http://192.0.2.60:9444", "host": "192.0.2.60"},
        {"endpoint": ENDPOINT + "/api", "host": "192.0.2.60"},
        {"endpoint": "https://192.0.2.60:9445", "host": "192.0.2.60"},
        {"endpoint": ENDPOINT, "host": "elsewhere.invalid"},
        {"endpoint": ENDPOINT, "host": "192.0.2.60", "scopes": frozenset({"wall.snapshot.read", "actions.execute"})},
    ]:
        with pytest.raises(ValueError):
            grant(**args)


def test_forged_cursor_and_mismatched_etag_rejected():
    good = envelope()
    forged = {**good, "cursor": '"' + "0" * 64 + '"'}
    cases = [
        (forged, {}),
        (good, {"etag": '"' + "0" * 64 + '"'}),
    ]
    for body, extra_headers in cases:
        headers = {"content-type": "application/json", **extra_headers}
        with make_transport(lambda _, body=body, headers=headers: httpx.Response(
                200, headers=headers, content=json.dumps(body).encode())) as client:
            with pytest.raises(ValueError):
                client.observe(now=NOW)


def test_content_encoding_length_and_response_url_are_checked_before_parse():
    body = json.dumps(envelope()).encode()
    invalid_responses = [
        httpx.Response(200, headers={"content-type": "application/json", "content-encoding": "gzip"}, stream=httpx.ByteStream(body)),
        httpx.Response(200, headers={"content-type": "application/json", "content-length": "-1"}, content=body),
        httpx.Response(200, headers={"content-type": "application/json", "content-length": "262145"}, content=body),
        httpx.Response(200, headers={"content-type": "application/json", "content-length": "2"}, content=body),
    ]
    for invalid in invalid_responses:
        with make_transport(lambda _, response=invalid: response) as client:
            with pytest.raises(ValueError):
                client.observe(now=NOW)

    mismatch = httpx.Response(200, request=httpx.Request(
        "GET", "https://elsewhere.invalid/api/wall/snapshot"))
    with pytest.raises(ValueError):
        _require_response_url(mismatch, httpx.URL(ENDPOINT + "/api/wall/snapshot"))
