"""Read the supplied corpus as bounded data, never as executable Python or SQLite."""
import collections
import hashlib
import json
from pathlib import PurePosixPath
import tarfile

from jsonschema import Draft202012Validator


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def load_corpus(path):
    if path.stat().st_size > 32 * 1024**2:
        raise ValueError('Compressed corpus exceeds limit')
    files, observed, total = {}, {}, 0
    # Streaming bounds apply before allocation; no extract(), import, or bundled DB.
    with tarfile.open(path, 'r|gz') as archive:
        for member in archive:
            parts = PurePosixPath(member.name).parts
            if not parts or member.name.startswith('/') or '..' in parts or '\\' in member.name:
                raise ValueError('Unsafe archive path')
            if len(parts) < 2 or parts[0] != 'terminal-axiom-corpus-8100':
                raise ValueError('Unexpected archive root')
            name = '/'.join(parts[1:])
            if member.isdir():
                continue
            if not member.isfile() or name in observed:
                raise ValueError('Archive links, special files, or duplicate names forbidden')
            total += member.size
            if member.size > 110 * 1024**2 or total > 256 * 1024**2 or len(observed) >= 100:
                raise ValueError('Expanded corpus exceeds limits')
            keep = name in {'manifest.json', 'recipe-schema.json', 'axiom-spec.json', 'atoms.jsonl'} or (
                name.startswith('datasets/') and name.endswith('.jsonl') and '/.' not in name)
            digest = hashlib.sha256()
            chunks = []
            with archive.extractfile(member) as stream:
                while chunk := stream.read(1024**2):
                    digest.update(chunk)
                    if keep:
                        chunks.append(chunk)
            observed[name] = {'bytes': member.size, 'sha256': digest.hexdigest()}
            if keep:
                files[name] = b''.join(chunks)
    manifest = json.loads(files['manifest.json'])
    expected = {}
    for row in manifest['files']:
        name = row['path']
        if name in expected:
            raise ValueError('Duplicate manifest entry')
        expected[name] = {'bytes': row['bytes'], 'sha256': row['sha256']}
    actual = {k: v for k, v in observed.items() if k != 'manifest.json'}
    if expected != actual:
        raise ValueError('Manifest membership, size, or hash mismatch')
    spec = json.loads(files['axiom-spec.json'])
    count = spec['record_count']
    if not isinstance(count, int) or not 1 <= count <= 10000:
        raise ValueError('Unbounded recipe count')
    schema = json.loads(files['recipe-schema.json'])
    # The supplied schema is self-contained. Refuse remote/local reference fetches.
    def no_refs(value):
        if isinstance(value, dict):
            if '$ref' in value or '$dynamicRef' in value:
                raise ValueError('External or recursive schema references forbidden')
            for item in value.values():
                no_refs(item)
        elif isinstance(value, list):
            for item in value:
                no_refs(item)
    no_refs(schema)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    atoms = {}
    for line in files['atoms.jsonl'].splitlines():
        atom = json.loads(line)
        digest = hashlib.sha256(canonical({'role': atom['role'], 'value': atom['definition']})).hexdigest()
        if atom['sha256'] != digest or atom['id'] != 'atom_' + digest or atom['id'] in atoms:
            raise ValueError('Atom identity mismatch')
        atoms[atom['id']] = atom
    entries, ids, addresses, ranks, semantic_keys = [], set(), set(), set(), set()
    for name in sorted(files):
        if not name.startswith('datasets/'):
            continue
        for line in files[name].splitlines():
            entry = json.loads(line)
            validator.validate(entry)
            if len(entries) >= count:
                raise ValueError('More recipes than declared')
            version = {k: v for k, v in entry.items() if k != 'version_sha256'}
            if hashlib.sha256(canonical(version)).hexdigest() != entry['version_sha256']:
                raise ValueError('Recipe version mismatch')
            semantic = entry['semantic_key']
            if entry['id'] != 'rid_' + hashlib.sha256(semantic.encode()).hexdigest()[:24]:
                raise ValueError('Recipe semantic identity mismatch')
            c = entry['coordinate']
            rank = 900*c['category_index'] + 30*c['row'] + c['column']
            if c['ordinal'] != 30*c['row'] + c['column'] or c['linear_rank'] != rank:
                raise ValueError('Coordinate mismatch')
            if entry['address'] != entry['category'].upper() + '_' + str(c['ordinal']+1).zfill(4):
                raise ValueError('Address mismatch')
            for value, seen in [(entry['id'], ids), (entry['address'], addresses), (rank, ranks), (semantic, semantic_keys)]:
                if value in seen:
                    raise ValueError('Duplicate recipe identity or coordinate')
                seen.add(value)
            for gene in entry['dna']['ordered_genes']:
                if gene['atom_id'] not in atoms or atoms[gene['atom_id']]['role'] != gene['role']:
                    raise ValueError('Unresolved or mismatched semantic atom')
            entries.append(entry)
    counts = dict(collections.Counter(e['category'] for e in entries))
    if len(entries) != count or len(counts) != spec['family_count']:
        raise ValueError('Corpus counts disagree')
    if count == 8100 and (len(counts) != 9 or set(counts.values()) != {900} or ranks != set(range(8100))):
        raise ValueError('Incomplete 9 by 900 corpus partition')
    return entries, {'format': 'terminal-axiom-corpus', 'expanded_bytes_checked': total,
        'manifest_files_checked': len(expected), 'schema_instances_checked': len(entries),
        'semantic_atoms_checked': len(atoms), 'category_counts': counts,
        'independent_checks': ['manifest hashes', 'JSON Schema Draft 2020-12', 'canonical version hashes',
                               'semantic IDs', 'coordinate uniqueness', 'atom hashes and references'],
        'runtime_evidence': 'supplied claims only; no recipe executed',
        'proof_scope': 'finite data integrity and shape; no command correctness, safety, speed or formal proof'}
