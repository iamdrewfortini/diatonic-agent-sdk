import copy
import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

from meta_pipeline.package_integration import (ADAPTER_VERSION, LEGACY_VERSION, TWIN_VERSION,
    adapt_record, inspect_package, iter_context_records, negotiate_version)
from meta_pipeline.protocol import CODONS, canonical


def source():
    return {'id': 'rid_fixture', 'version_sha256': 'a' * 64,
            'coordinate': {'linear_rank': 0}, 'category': 'search'}


def context():
    s = source()
    return {'id': 'D12:rid_fixture', 'source': s, 'ordinal': 0, 'track': 12,
            'domain': {'track': 12, 'codon': CODONS[11], 'name': 'ANTICIPATORY_PHASE'},
            'twin_output': {'status': 'prediction_not_observation'},
            'evidence': 'finite simulation'}


def test_legacy_preservation_and_explicit_version_negotiation():
    s = source(); before = canonical(s)
    result = adapt_record(s, from_version=LEGACY_VERSION, source_records={s['id']: s})
    assert canonical(result['source']) == before and canonical(s) == before
    assert result['schema_version'] == ADAPTER_VERSION and not result['execution_verified']
    assert 'context' not in result
    assert negotiate_version([LEGACY_VERSION, TWIN_VERSION]) == TWIN_VERSION
    assert negotiate_version([LEGACY_VERSION]) == LEGACY_VERSION
    for versions in [[], ['future-v99'], 'terminal-axiom-recipe-v1', [1]]:
        with pytest.raises(ValueError): negotiate_version(versions)
    with pytest.raises(ValueError): adapt_record(s, from_version='future-v99', source_records={})


def test_context_does_not_change_source_or_conflate_protocol_channel():
    r = context(); s = source()
    out = adapt_record(r, from_version=TWIN_VERSION, source_records={s['id']: s})
    assert out['protocol'] == 'diatonic-13-v1'
    assert out['context']['namespace'] == 'axiom-twin-domain'
    assert out['source_version'] == 'a'*64 and not out['execution_verified']
    out['source']['id'] = 'changed'
    assert r['source']['id'] == s['id']
    for patch in [{'track': True}, {'track': 14}, {'id': 'D13:rid_fixture'}, {'ordinal': 1},
                  {'domain': {'track': 12, 'codon': 'MMM'}}]:
        with pytest.raises(ValueError):
            adapt_record({**r, **patch}, from_version=TWIN_VERSION, source_records={s['id']: s})
    r['source']['version_sha256'] = 'b'*64
    with pytest.raises(ValueError):
        adapt_record(r, from_version=TWIN_VERSION, source_records={s['id']: s})


def archive(tmp_path, entries):
    p = tmp_path/'package.tar.gz'
    with tarfile.open(p, 'w:gz') as t:
        for name, raw, kind in entries:
            info = tarfile.TarInfo(name); info.type = kind
            info.size = len(raw) if kind == tarfile.REGTYPE else 0
            t.addfile(info, io.BytesIO(raw) if kind == tarfile.REGTYPE else None)
    return p


@pytest.mark.parametrize('name,kind', [('../escape', tarfile.REGTYPE),
    ('/absolute', tarfile.REGTYPE), ('axiom-twin-13d/link', tarfile.SYMTYPE),
    ('axiom-twin-13d/hard', tarfile.LNKTYPE), ('axiom-twin-13d/pipe', tarfile.FIFOTYPE),
    ('axiom-twin-13d/a/../b', tarfile.REGTYPE), ('axiom-twin-13d/a\\b', tarfile.REGTYPE)])
def test_hostile_archive_members_rejected(tmp_path, name, kind):
    p = archive(tmp_path, [(name, b'{}', kind)])
    with pytest.raises(ValueError): inspect_package(p)


def test_duplicate_member_manifest_tamper_and_duplicate_json_rejected(tmp_path):
    name = 'axiom-twin-13d/manifest.json'
    for entries in [[(name, b'{}', tarfile.REGTYPE)]*2,
                    [(name, b'{"a":{},"a":{}}', tarfile.REGTYPE)],
                    [(name, b'{}', tarfile.REGTYPE), ('axiom-twin-13d/payload', b'x', tarfile.REGTYPE)]]:
        with pytest.raises(ValueError): inspect_package(archive(tmp_path, entries))


def test_real_update_manifest_and_nested_export_bounds():
    # Required checked-in environment artifact; absence is a failure, not a skip.
    p = Path(__file__).resolve().parents[1]/'vendor/axiom-twin-13d-update.tar.gz'
    proof = inspect_package(p)
    assert proof['archive_sha256'] == '43856bd315d45f6e74b989c688135a46f991aeae4ec5e2233712999a423e47b8'
    assert proof['source_recipe_count'] == 8100 and proof['new_recipe_count'] == 0
    assert proof['contextual_record_count'] == 105300
    records = iter_context_records(p, max_expanded_bytes=1)
    with pytest.raises(ValueError): next(records)
