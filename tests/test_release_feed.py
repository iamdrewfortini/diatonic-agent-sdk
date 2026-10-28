import hashlib
import io
import os
import ssl
import zipfile

import httpx
import pytest
from pydantic import SecretStr
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from meta_pipeline.release_feed import CoordinatorProfile, SignedReleaseDownloader
import meta_pipeline.release_feed as release_feed
from meta_pipeline.release_manager import ReleaseManifest, UpdateBlocked, WheelArtifact, sign_manifest

BASE = "https://updates.example/releases/stable/"


def artifact(name, data):
    return WheelArtifact(filename=name, sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data))


def wheel():
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        archive.writestr("fixture/record.txt", "signed fixture")
    return out.getvalue()


@pytest.fixture
def feed(tmp_path):
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    key = tmp_path / "release.pub"
    key.write_bytes(public)
    app, dep = wheel(), wheel()
    manifest = ReleaseManifest(version="0.3.1", expected_incumbent_sha256="a" * 64,
        wheel=artifact("diatonic_meta_pipeline-0.3.1-py3-none-any.whl", app),
        dependencies=(artifact("dependency-1.0.0-py3-none-any.whl", dep),))
    private_pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    envelope = sign_manifest(manifest, private_pem)
    return tmp_path, key, envelope, {manifest.wheel.filename: app, manifest.dependencies[0].filename: dep}


def downloader(tmp_path, key, handler, *, spool=None, profile=BASE, **kwargs):
    spool = spool or tmp_path / "spool"
    spool.mkdir(exist_ok=True)
    transport = httpx.MockTransport(handler)
    kwargs.setdefault("capacity_reader", lambda path: 128 * 1024 ** 3)
    return SignedReleaseDownloader(CoordinatorProfile(profile), key, spool,
        trusted_uid=os.getuid(), transport=transport, **kwargs), spool


def test_valid_signature_hashes_and_wheels_are_staged(feed):
    tmp_path, key, envelope, artifacts = feed
    def handler(request):
        name = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, content=envelope if name == "update.json" else artifacts[name], request=request)
    client, spool = downloader(tmp_path, key, handler)
    assert client.stage() == {"status": "staged", "version": "0.3.1", "artifacts": 2}
    assert (spool / "update.json").read_bytes() == envelope
    for name, data in artifacts.items():
        assert (spool / name).read_bytes() == data
    assert client.stage()["status"] == "already_staged"


@pytest.mark.parametrize("attack", ["redirect", "signature", "hash", "oversize", "conflict", "artifact_conflict"])
def test_feed_attacks_fail_closed_without_overwriting(feed, attack):
    tmp_path, key, envelope, artifacts = feed
    spool = tmp_path / "spool"
    spool.mkdir()
    if attack == "conflict":
        (spool / "update.json").write_bytes(b"operator data")
    if attack == "artifact_conflict":
        filename = "diatonic_meta_pipeline-0.3.1-py3-none-any.whl"
        (spool / filename).write_bytes(b"operator wheel")
    def handler(request):
        name = request.url.path.rsplit("/", 1)[-1]
        if attack == "redirect" and name == "update.json":
            return httpx.Response(302, headers={"location": "https://evil.invalid/update.json"}, request=request)
        if attack == "signature" and name == "update.json":
            return httpx.Response(200, content=envelope[:-1] + bytes([envelope[-1] ^ 1]), request=request)
        if attack == "hash" and name.endswith(".whl"):
            return httpx.Response(200, content=b"wrong bytes", request=request)
        if attack == "oversize" and name == "update.json":
            return httpx.Response(200, content=b"x" * (128 * 1024 + 1), request=request)
        return httpx.Response(200, content=envelope if name == "update.json" else artifacts[name], request=request)
    client, _ = downloader(tmp_path, key, handler, spool=spool)
    with pytest.raises(UpdateBlocked):
        client.stage()
    if attack == "conflict":
        assert (spool / "update.json").read_bytes() == b"operator data"
    if attack == "artifact_conflict":
        assert (spool / "diatonic_meta_pipeline-0.3.1-py3-none-any.whl").read_bytes() == b"operator wheel"
        assert not (spool / "update.json").exists()


def test_profile_requires_explicit_https_directory():
    for value in ("http://updates.example/releases/stable/", "https://user@updates.example/releases/stable/",
                  "https://updates.example/releases/stable", "https://updates.example/releases/stable/?channel=x"):
        with pytest.raises(UpdateBlocked):
            CoordinatorProfile(value)


def test_injected_management_token_is_loaded_once_and_sent_only_as_configured_header(feed):
    tmp_path, key, envelope, artifacts = feed
    observed = []
    def handler(request):
        observed.append(request.headers.get("PRIVATE-TOKEN"))
        name = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, content=envelope if name == "update.json" else artifacts[name], request=request)
    class Source:
        calls = 0
        def load(self):
            self.calls += 1
            return SecretStr("private-management-fixture")
        def __repr__(self):
            return "Source()"
    source = Source()
    client, _ = downloader(tmp_path, key, handler, token_source=source, token_header="PRIVATE-TOKEN")
    assert "private-management-fixture" not in repr(client)
    assert client.stage()["status"] == "staged"
    assert source.calls == 1
    assert observed == ["private-management-fixture"] * 3


def test_credentials_require_allowlisted_fixed_header_and_secretstr(feed):
    tmp_path, key, _, _ = feed
    spool = tmp_path / "spool"
    spool.mkdir()
    with pytest.raises(UpdateBlocked):
        SignedReleaseDownloader(CoordinatorProfile(BASE), key, spool, trusted_uid=os.getuid(),
            management_token=SecretStr("secret"))
    with pytest.raises(UpdateBlocked):
        SignedReleaseDownloader(CoordinatorProfile(BASE), key, spool, trusted_uid=os.getuid(),
            management_token="secret", token_header="PRIVATE-TOKEN")
    with pytest.raises(UpdateBlocked):
        SignedReleaseDownloader(CoordinatorProfile(BASE), key, spool, trusted_uid=os.getuid(),
            management_token=SecretStr("secret"), token_header="X-Anything")
    with pytest.raises(UpdateBlocked):
        SignedReleaseDownloader(CoordinatorProfile(BASE), key, spool, trusted_uid=os.getuid(),
            management_token=SecretStr("secret"), token_header="PRIVATE-TOKEN", timeout=60.1)


def test_staging_budget_and_ssd_reserve_are_enforced_before_wheel_download(feed):
    tmp_path, key, envelope, artifacts = feed
    fetched = []
    def handler(request):
        name = request.url.path.rsplit("/", 1)[-1]
        fetched.append(name)
        return httpx.Response(200, content=envelope if name == "update.json" else artifacts[name], request=request)
    client, spool = downloader(tmp_path, key, handler, total_staged_bytes=1)
    with pytest.raises(UpdateBlocked, match="staged_release_budget"):
        client.stage()
    assert fetched == ["update.json"] and not (spool / "update.json").exists()
    fetched.clear()
    client, spool = downloader(tmp_path, key, handler, capacity_reader=lambda path: 64 * 1024 ** 3)
    with pytest.raises(UpdateBlocked, match="ssd_reserve"):
        client.stage()
    assert fetched == ["update.json"] and not (spool / "update.json").exists()


def test_each_no_clobber_link_is_directory_synced_with_envelope_last(feed, monkeypatch):
    tmp_path, key, envelope, artifacts = feed
    linked = []
    def handler(request):
        name = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, content=envelope if name == "update.json" else artifacts[name], request=request)
    monkeypatch.setattr(release_feed, "_sync_directory", lambda path: linked.append(path))
    client, spool = downloader(tmp_path, key, handler)
    client.stage()
    assert linked == [spool, spool, spool]


def test_os_trust_tls_default_and_unverified_context_rejection(feed):
    tmp_path, key, _, _ = feed
    spool = tmp_path / "spool"
    spool.mkdir()
    client = SignedReleaseDownloader(CoordinatorProfile(BASE), key, spool,
        trusted_uid=os.getuid(), capacity_reader=lambda path: 128 * 1024 ** 3)
    assert client.ssl_context.verify_mode == ssl.CERT_REQUIRED
    assert client.ssl_context.check_hostname is True
    insecure = ssl.create_default_context()
    insecure.check_hostname = False
    insecure.verify_mode = ssl.CERT_NONE
    with pytest.raises(UpdateBlocked, match="verified_tls_context"):
        SignedReleaseDownloader(CoordinatorProfile(BASE), key, spool,
            trusted_uid=os.getuid(), ssl_context=insecure)


def test_custom_verified_tls_context_is_accepted(feed):
    tmp_path, key, _, _ = feed
    spool = tmp_path / "spool"
    spool.mkdir()
    context = ssl.create_default_context()
    client = SignedReleaseDownloader(CoordinatorProfile(BASE), key, spool,
        trusted_uid=os.getuid(), ssl_context=context)
    assert client.ssl_context is context


@pytest.mark.parametrize("bad_value", [" token", "token ", "line\nbreak", "tab\tvalue", "nonascii-£", "del-\x7f"])
def test_management_header_values_reject_control_and_non_ascii_before_request(feed, bad_value):
    tmp_path, key, _, _ = feed
    requested = []
    def handler(request):
        requested.append(request)
        raise AssertionError("invalid credential must fail before request")
    client, _ = downloader(tmp_path, key, handler,
        management_token=SecretStr(bad_value), token_header="Authorization")
    with pytest.raises(UpdateBlocked, match="invalid_management_credential"):
        client.stage()
    assert requested == []


def test_httpx_transport_errors_are_stable_and_do_not_echo_sensitive_text(feed):
    tmp_path, key, _, _ = feed
    def handler(request):
        raise httpx.ConnectError("fixture-private-management-token", request=request)
    client, _ = downloader(tmp_path, key, handler)
    with pytest.raises(UpdateBlocked, match="^coordinator_transport_failed$") as error:
        client.stage()
    assert "fixture-private-management-token" not in str(error.value)
