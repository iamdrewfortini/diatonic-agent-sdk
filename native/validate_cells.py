"""Validate registered first-party cell sources; optionally enforce built sizes.

No Rust/Python compilation or supplied hooks run here. Compilation and benchmarks
remain separate mandatory gates before registering an optional native artifact.
"""
import argparse,hashlib,json,re,tomllib
from pathlib import Path


def validate(root, *, require_artifacts=False):
    root=Path(root).resolve(strict=True)
    policy=json.loads((root/'build-policy.json').read_text())
    hard={'maximum_nonblank_lines_per_cell':400,'maximum_public_operations_per_cell':6,
          'maximum_direct_dependencies_per_cell':8,'maximum_stripped_library_bytes':2*1024**2}
    if any(type(policy[k])is not int or not 0<=policy[k]<=v for k,v in hard.items()):raise ValueError('Native hard ceiling widened')
    if (policy['arbitrary_build_hooks_permitted'] is not False or
            policy.get('require_exact_host_independent_benchmark') is not True or
            policy.get('require_equal_correctness_coverage_and_verification') is not True or
            policy.get('default_implementation')!='python'):
        raise ValueError('Native activation/coverage/default policy cannot be weakened')
    workspace=tomllib.loads((root/'Cargo.toml').read_text())['workspace']['members']
    observed={str(p.parent.relative_to(root)) for p in root.rglob('Cargo.toml') if p.parent!=root and 'target' not in p.parts}
    if set(workspace)!=observed or len(workspace)>32:raise ValueError('Every first-party crate must be one registered cell')
    results=[]
    for member in workspace:
        cell=(root/member).resolve(strict=True)
        if not cell.is_relative_to(root) or (cell/'build.rs').exists():raise ValueError('External crate or build hook forbidden')
        if any(p.is_symlink() for p in cell.rglob('*')):raise ValueError('Cell source symlinks forbidden')
        meta=json.loads((cell/'cell.json').read_text());manifest=tomllib.loads((cell/'Cargo.toml').read_text())
        src=cell/'src/lib.rs';text=src.read_text();lines=sum(bool(line.strip()) for line in text.splitlines())
        if len(list(cell.rglob('*.rs')))!=1 or re.search(r'\b(?:include|include_str|include_bytes)!|\bmacro_rules!|#\[path|\bpub\s+use\b|\bmod\s+\w+\s*;',text):
            raise ValueError('A cell must keep its declared first-party implementation in one source file')
        if '#![forbid(unsafe_code)]' not in text:raise ValueError('Safe Rust required for this cell profile')
        if re.search(r'\bpub\b(?!\s+fn\b)',text):raise ValueError('Unsupported public export; every operation must be explicit pub fn')
        if meta.get('schema_version')!='native-cell-v1' or meta.get('version')!=manifest['package']['version'] or not meta.get('responsibility'):
            raise ValueError('Versioned single responsibility declaration required')
        operations=re.findall(r'\bpub\s+fn\s+(\w+)',text)
        if any(manifest.get(key) for key in ('target','workspace','dev-dependencies','features','patch','replace')):
            raise ValueError('Alternate dependency scopes and build variants unsupported in this profile')
        if manifest.get('lib',{}).get('path')!='src/lib.rs':raise ValueError('Only the registered single library source is supported')
        deps=manifest.get('dependencies',{})
        if manifest.get('build-dependencies') or manifest['package'].get('build') or manifest['package'].get('links'):
            raise ValueError('Build scripts and native link hooks forbidden')
        for dep in deps.values():
            if not isinstance(dep,str) or not re.fullmatch(r'=\d+\.\d+\.\d+',dep):raise ValueError('Direct dependency versions must be exact registry pins')
        if (lines>policy['maximum_nonblank_lines_per_cell'] or len(operations)>policy['maximum_public_operations_per_cell'] or
                len(deps)>policy['maximum_direct_dependencies_per_cell'] or operations!=meta['public_operations']):raise ValueError('Native cell size/operation ceiling exceeded')
        schema=(root/meta['schema']).resolve(strict=True)
        if not schema.is_relative_to(root) or hashlib.sha256(schema.read_bytes()).hexdigest()!=meta['schema_sha256'] or hashlib.sha256(src.read_bytes()).hexdigest()!=meta['source_sha256']:
            raise ValueError('Cell/schema source lock differs')
        library=root/'target/release'/('lib'+manifest['package']['name'].replace('-','_')+'.so')
        status='pending_compile_and_exact_host_benchmark'
        if library.exists():
            if library.is_symlink() or library.stat().st_size>policy['maximum_stripped_library_bytes']:raise ValueError('Native library exceeds hard ceiling')
            status='size_checked_benchmark_still_required'
        elif require_artifacts:raise ValueError('Required compiled native artifact missing')
        results.append({'id':meta['id'],'responsibility':meta['responsibility'],'nonblank_lines':lines,
            'public_operations':operations,'direct_dependencies':len(deps),'source_sha256':meta['source_sha256'],
            'schema_sha256':meta['schema_sha256'],'status':status,'speedup_claim':None})
    return {'version':policy['version'],'cells':results,'source_validation':'passed','native_activation':'pending independent exact-host same-coverage benchmark'}


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--root',default=str(Path(__file__).parent));parser.add_argument('--require-artifacts',action='store_true');args=parser.parse_args()
    print(json.dumps(validate(args.root,require_artifacts=args.require_artifacts),indent=2))
