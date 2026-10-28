import hashlib
import io
import json
import tarfile

import pytest

from meta_pipeline.corpus import canonical
from meta_pipeline.references import ReferenceCatalog


def bundle(tmp_path, mutate=None, extra=None):
    marker = tmp_path/'must-not-execute'
    atom_value = {'role': 'family', 'value': 'search'}
    atom_hash = hashlib.sha256(canonical(atom_value)).hexdigest()
    atom = {'id': 'atom_'+atom_hash, 'role': 'family', 'definition': 'search', 'sha256': atom_hash}
    semantic = 'search:test'
    entry = {'id': 'rid_'+hashlib.sha256(semantic.encode()).hexdigest()[:24], 'semantic_key': semantic,
             'address': 'SEARCH_0001', 'title': 'Search names', 'category': 'search',
             'command': 'touch '+str(marker), 'use_when': 'Search names',
             'shell': 'Bash', 'risk': 'read_only', 'verification': {'runtime': 'claimed'},
             'interface': {'input': 'DirectoryPath', 'output': 'SearchResult'},
             'coordinate': {'category_index': 1, 'row': 0, 'column': 0, 'ordinal': 0, 'linear_rank': 900},
             'dna': {'ordered_genes': [{'role': 'family', 'atom_id': atom['id']}]}}
    entry['version_sha256'] = hashlib.sha256(canonical(entry)).hexdigest()
    files = {'axiom-spec.json': canonical({'record_count': 1, 'family_count': 1}),
             'recipe-schema.json': canonical({'type': 'object', 'required': ['id', 'command']}),
             'atoms.jsonl': canonical(atom)+b'\n', 'datasets/search.jsonl': canonical(entry)+b'\n',
             'index.sqlite': b'Not a SQLite database; must never be opened',
             'build.py': ('raise AssertionError("never import")').encode()}
    if mutate:
        mutate(files)
    files['manifest.json'] = canonical({'files': [{'path': k, 'bytes': len(v), 'sha256': hashlib.sha256(v).hexdigest()} for k,v in files.items()]})
    path = tmp_path/'fixture.tar.gz'
    with tarfile.open(path, 'w:gz') as archive:
        for name, data in files.items():
            member = tarfile.TarInfo('terminal-axiom-corpus-8100/'+name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        if extra:
            archive.addfile(extra)
    return path, marker


def test_corpus_is_reference_only_and_does_not_load_bundled_code_or_database(tmp_path):
    path, marker = bundle(tmp_path)
    catalog = ReferenceCatalog(path)
    try:
        result = catalog.search('Search names')[0]
        assert result['execution_permission'] == 'none' and 'command' not in result
        assert result['verification_claim'] == {'runtime': 'claimed'}
        assert catalog.summary()['validation']['schema_instances_checked'] == 1
        assert catalog.search('SEARCH_0001') == [result]
        assert catalog.search(result['id']) == [result]
        assert not marker.exists()
    finally:
        catalog.close()


@pytest.mark.parametrize('kind', ['link', 'traversal', 'duplicate'])
def test_reject_unsafe_archive_members(tmp_path, kind):
    member = tarfile.TarInfo('terminal-axiom-corpus-8100/evil')
    if kind == 'link':
        member.type = tarfile.SYMTYPE
        member.linkname = '/etc/passwd'
    elif kind == 'traversal':
        member.name = 'terminal-axiom-corpus-8100/../../evil'
    else:
        member.name = 'terminal-axiom-corpus-8100/build.py'
    path,_ = bundle(tmp_path, extra=member)
    with pytest.raises(ValueError):
        ReferenceCatalog(path)


@pytest.mark.parametrize('kind', ['version', 'atom', 'schema-reference'])
def test_manifest_rehash_cannot_hide_semantic_corruption(tmp_path, kind):
    def mutate(files):
        if kind == 'schema-reference':
            files['recipe-schema.json'] = canonical({'$ref': 'https://example.invalid/schema'})
        elif kind == 'version':
            entry = json.loads(files['datasets/search.jsonl'])
            entry['command'] = 'changed'
            files['datasets/search.jsonl'] = canonical(entry)
        else:
            atom = json.loads(files['atoms.jsonl'])
            atom['definition'] = 'changed'
            files['atoms.jsonl'] = canonical(atom)
    path,_ = bundle(tmp_path, mutate)
    with pytest.raises(ValueError):
        ReferenceCatalog(path)
