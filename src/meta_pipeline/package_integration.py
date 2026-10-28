"""Inert, bounded import and explicit contextual-data adapters for Axiom Twin.

Twin domain numbers are not executable SDK routes or protocol channels. The
existing nine recipe partitions and thirteen-channel control contract stay intact.
"""
from __future__ import annotations

import copy
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile

from .protocol import CODONS, PROTOCOL_ID, canonical, digest

TWIN_VERSION = 'axiom-twin-context-v1'
LEGACY_VERSION = 'terminal-axiom-recipe-v1'
ADAPTER_VERSION = 'diatonic-twin-adapter-v1'
ARCHIVE_ROOT = 'axiom-twin-13d'
MAX_COMPRESSED = 64 * 1024**2
MAX_MEMBER = 128 * 1024**2
MAX_EXPANDED = 256 * 1024**2


def _json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))


def inspect_package(path: Path):
    """Hash every member, enforce manifest, return bounded inert metadata only.

    Never extracts files, opens SQLite, imports Python, or expands nested gzip.
    Hashes establish consistency relative to this source, not authorship.
    """
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_COMPRESSED:
        raise ValueError('Expected bounded regular archive')
    observed, metadata, total, members = {}, {}, 0, 0
    selected = {'manifest.json', 'provenance.json', 'domains.json', 'axiom-table.json',
                'codons.json', 'predictor-config.json', 'performance-report.json'}
    archive_hash = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(1024**2):
            archive_hash.update(chunk)
    with tarfile.open(path, 'r|gz') as archive:
        for member in archive:
            members += 1
            parts = PurePosixPath(member.name).parts
            if (members > 128 or not parts or parts[0] != ARCHIVE_ROOT or
                    member.name.startswith('/') or '..' in parts or '\\' in member.name or
                    any(p in ('', '.') for p in member.name.split('/'))):
                raise ValueError('Unsafe or excessive archive members')
            if member.isdir():
                continue
            name = '/'.join(parts[1:])
            if not member.isfile() or not name or name in observed:
                raise ValueError('Links, special files and duplicate names forbidden')
            total += member.size
            if member.size > MAX_MEMBER or total > MAX_EXPANDED:
                raise ValueError('Expanded archive exceeds bounds')
            if name in selected and member.size > 1024**2:
                raise ValueError('Metadata exceeds bounds')
            h = hashlib.sha256(); chunks = []
            with archive.extractfile(member) as stream:
                while chunk := stream.read(1024**2):
                    h.update(chunk)
                    if name in selected:
                        chunks.append(chunk)
            observed[name] = {'bytes': member.size, 'sha256': h.hexdigest()}
            if name in selected:
                metadata[name] = _json(b''.join(chunks))
    manifest = metadata.get('manifest.json')
    if not isinstance(manifest, dict) or manifest != {k: v for k, v in observed.items() if k != 'manifest.json'}:
        raise ValueError('Manifest membership, sizes or hashes mismatch')
    provenance = metadata['provenance.json']
    if provenance['source_records'] != 8100 or provenance['domain_records'] != 105300:
        raise ValueError('Unsupported source/context coverage')
    domains = metadata['domains.json']; table = metadata['axiom-table.json']
    if [e['id'] for e in table['elements']] != [f'A{i:02d}' for i in range(16)]:
        raise ValueError('Engineering axiom identities changed')
    if (len(domains) != 13 or [d['track'] for d in domains] != list(range(1, 14)) or
            tuple(d['codon'] for d in domains) != CODONS or
            any(d['record_count'] != 8100 or d['axiom_periodic_table'] != table for d in domains)):
        raise ValueError('Unsupported twin domain bindings')
    return {'archive_sha256': archive_hash.hexdigest(), 'archive_bytes': path.stat().st_size,
            'expanded_bytes': total, 'members': observed, 'metadata': metadata,
            'adapter_version': ADAPTER_VERSION, 'protocol': PROTOCOL_ID,
            'contract_sha256': digest(), 'source_recipe_count': 8100,
            'contextual_record_count': 105300, 'new_recipe_count': 0,
            'source_consistency': 'manifest checked; authorship not established',
            'execution': 'none; database unopened; supplied Python inert'}


def negotiate_version(offered):
    if not isinstance(offered, (list, tuple)) or any(not isinstance(v, str) for v in offered):
        raise ValueError('Expected explicit supported version list')
    for version in (TWIN_VERSION, LEGACY_VERSION):
        if version in offered:
            return version
    raise ValueError('Unsupported package schema version')


def adapt_record(record, *, from_version, source_records):
    """Bind contextual data to canonical sources without granting tools or authority.

    source_records is coordinator-supplied independently validated corpus data,
    indexed by canonical source ID. Existing legacy payloads remain byte-equivalent
    under canonical serialization; contextual outputs stay unverified observations.
    """
    if not isinstance(record, dict) or not isinstance(source_records, dict):
        raise ValueError('Expected record and canonical source index objects')
    if from_version not in (LEGACY_VERSION, TWIN_VERSION):
        raise ValueError('Unsupported package schema version')
    source = record if from_version == LEGACY_VERSION else record.get('source')
    if not isinstance(source, dict) or source.get('id') not in source_records:
        raise ValueError('Unknown canonical source')
    trusted = source_records[source['id']]
    if canonical(source) != canonical(trusted):
        raise ValueError('Source differs from bound canonical recipe')
    result = {'schema_version': ADAPTER_VERSION, 'source_schema_version': from_version,
              'protocol': PROTOCOL_ID, 'contract_sha256': digest(),
              'source_id': source['id'], 'source_version': source['version_sha256'],
              'source_sha256': hashlib.sha256(canonical(source)).hexdigest(),
              'source': copy.deepcopy(source), 'execution_verified': False}
    if from_version == TWIN_VERSION:
        track = record.get('track')
        if type(track) is not int or not 1 <= track <= 13:
            raise ValueError('Invalid twin context track')
        if (record.get('id') != f'D{track:02d}:{source["id"]}' or
                record.get('ordinal') != source['coordinate']['linear_rank']):
            raise ValueError('Context identity mismatch')
        domain = record.get('domain')
        if not isinstance(domain, dict) or domain.get('track') != track or domain.get('codon') != CODONS[track-1]:
            raise ValueError('Context domain mismatch')
        # Preserve context semantics; never map MACRO_X to executable terminal track 1.
        result['context'] = {'namespace': 'axiom-twin-domain', 'track': track,
                             'domain': copy.deepcopy(domain),
                             'output': copy.deepcopy(record.get('twin_output')),
                             'evidence': record.get('evidence'),
                             'verification': 'supplied finite simulation; not independently verified effect'}
    return result


def iter_context_records(path, *, max_expanded_bytes=2 * 1024**3, max_records=105300):
    """Stream nested export with line, expansion and count bounds; never use DB."""
    # Validate complete tar before exposing records to a caller.
    inspect_package(path)
    total = count = 0
    with tarfile.open(path, 'r|gz') as archive:
        for member in archive:
            if member.name != ARCHIVE_ROOT + '/all-domains.jsonl.gz':
                continue
            with archive.extractfile(member) as packed, gzip.GzipFile(fileobj=packed) as stream:
                while line := stream.readline(1024**2 + 1):
                    total += len(line); count += 1
                    if len(line) > 1024**2 or total > max_expanded_bytes or count > max_records:
                        raise ValueError('Context export exceeds bounds')
                    value = _json(line)
                    if not isinstance(value, dict):
                        raise ValueError('Expected contextual object')
                    yield value
            if count != 105300:
                raise ValueError('Incomplete context export')
            return
    raise ValueError('Missing context export')
