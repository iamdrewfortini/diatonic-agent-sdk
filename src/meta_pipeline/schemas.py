"""Import exact vendor JSON/YAML schemas without executing code or remote refs."""
import hashlib
import json
import re
from pathlib import Path
import yaml

def inspect(directory: str) -> dict:
    root = Path(directory).resolve(strict=True)
    files = sorted(p for p in root.rglob("*") if p.suffix.lower() in (".json",".yaml",".yml",".txt"))
    if len(files)>100:
        raise ValueError("Schema bundle too large")
    result = []
    for p in files:
        if p.is_symlink() or not p.resolve().is_relative_to(root) or p.stat().st_size>8000000:
            raise ValueError("Schema file must be a bounded regular file")
        raw = p.read_bytes()
        if p.suffix.lower()==".txt":
            text=raw.decode("utf-8-sig")
            fields=sorted(set(re.findall(r"^([A-Za-z_][\w.\[\]]*)\t",text,re.M)))
            result.append({"file":str(p.relative_to(root)),"sha256":hashlib.sha256(raw).hexdigest(),
                "format":"schema-reference-text","title":text.splitlines()[0],"field_names":fields,
                "explicit_paths":re.findall(r"^(GET|POST|DELETE|PATCH|PUT) (/\S+)",text,re.M)})
            continue
        data = json.loads(raw) if p.suffix==".json" else yaml.safe_load(raw)
        if not isinstance(data,dict):
            raise ValueError("Expected a schema object")
        refs = []
        def walk(value):
            if isinstance(value,dict):
                if "$ref" in value and not str(value["$ref"]).startswith("#"):
                    refs.append(value["$ref"])
                for v in value.values():walk(v)
            elif isinstance(value,list):
                for v in value:walk(v)
        walk(data)
        operations = [{"method":method.upper(),"path":path,"operationId":op.get("operationId")}
            for path,methods in data.get("paths",{}).items() for method,op in methods.items()
            if method.lower() in ("get","post","put","patch","delete") and isinstance(op,dict)]
        result.append({"file":str(p.relative_to(root)),"sha256":hashlib.sha256(raw).hexdigest(),
            "openapi":data.get("openapi"),"operations":operations,"external_refs_blocked":refs})
    return {"directory":str(root),"schemas":result,"status":"schema inventory; curated request subsets tested separately"}
