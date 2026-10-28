import os
from types import SimpleNamespace

import pytest

from meta_pipeline import systemd_credentials
from meta_pipeline.gateway import resolve_secret
from meta_pipeline.secret_broker import InjectedCredentialFile, SystemdCredentialToken, SecretUnavailable


def test_protected_native_0440_port_keeps_ordinary_file_rule(tmp_path,monkeypatch):
    path=tmp_path/"monitor-key"
    path.write_text("fixture-key-never-output\n");path.chmod(0o440)
    with pytest.raises(ValueError):resolve_secret("file:"+str(path))
    with pytest.raises(SecretUnavailable):InjectedCredentialFile(path).load()
    monkeypatch.setenv("CREDENTIALS_DIRECTORY",str(tmp_path))
    assert not systemd_credentials.available("monitor-key")
    # Explicit simulated manager namespace and read-only mount, matching the
    # independently observed actual Alma systemd0440 metadata. No gate removed.
    monkeypatch.setattr(systemd_credentials,"_manager_path",lambda p:p==str(tmp_path))
    monkeypatch.setattr(os,"fstatvfs",lambda fd:SimpleNamespace(f_flag=os.ST_RDONLY))
    assert systemd_credentials.available("monitor-key")
    assert resolve_secret("systemd:monitor-key")=="fixture-key-never-output"
    source=SystemdCredentialToken("monitor-key")
    assert source.available() and source.load().get_secret_value()=="fixture-key-never-output"
    assert "fixture-key" not in repr(systemd_credentials.read("monitor-key"))
    path.chmod(0o444)
    assert not systemd_credentials.available("monitor-key")


def test_native_credential_refuses_writable_mount_symlink_and_paths(tmp_path,monkeypatch):
    p=tmp_path/"key";p.write_text("fixture");p.chmod(0o440)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY",str(tmp_path))
    monkeypatch.setattr(systemd_credentials,"_manager_path",lambda p:True)
    monkeypatch.setattr(os,"fstatvfs",lambda fd:SimpleNamespace(f_flag=0))
    assert not systemd_credentials.available("key")
    monkeypatch.setattr(os,"fstatvfs",lambda fd:SimpleNamespace(f_flag=os.ST_RDONLY))
    (tmp_path/"link").symlink_to(p)
    assert not systemd_credentials.available("link")
    for name in ["../key","key/other",".",".."]:
        assert not systemd_credentials.available(name)
