import argparse
import asyncio
import json
import sys
from pathlib import Path
from .models import catalog, Workload, forecast
from .evidence import load_manifest, assess
from .gateway import GatewayConfig, MetaGateway
from .ledger import Ledger
from .manager import ValidationManager

def main():
    p=argparse.ArgumentParser(description="Provider-neutral Bifrost agents with bounded admission and independent evidence verification")
    p.add_argument("--config", default="gateway.json")
    p.add_argument("--ledger",default="state/usage.sqlite3")
    sub=p.add_subparsers(dest="command",required=True)
    sub.add_parser("models")
    f=sub.add_parser("forecast");f.add_argument("workload")
    f=sub.add_parser("forecast-storage");f.add_argument("workload")
    s=sub.add_parser("schemas");s.add_argument("directory")
    q=sub.add_parser("references");q.add_argument("catalog");q.add_argument("--search");q.add_argument("--check-syntax",action="store_true")
    sub.add_parser("matrix")
    sub.add_parser("protocol")
    q=sub.add_parser("inspect-package");q.add_argument("archive")
    q=sub.add_parser("estate-scan");q.add_argument("source",help="Explicit SourceSpec JSON; metadata only")
    q.add_argument("--database",required=True);q.add_argument("--max-entries",type=int,default=1000);q.add_argument("--reconcile",action="store_true")
    q=sub.add_parser("estate-query");q.add_argument("--database",required=True);q.add_argument("--name");q.add_argument("--label")
    q=sub.add_parser("local-file-operation");q.add_argument("operation",help="Explicit FileOperation JSON")
    q.add_argument("--authorized-root",required=True);q.add_argument("--journal",required=True)
    q.add_argument("--allow",choices=["copy","create"],action="append",required=True)
    q=sub.add_parser("broker-plan");q.add_argument("bindings");q.add_argument("request");q.add_argument("--gateway-id",default="bifrost")
    q.add_argument("--remaining-nusd",type=int,default=0)
    q=sub.add_parser("broker-run");q.add_argument("bindings");q.add_argument("request");q.add_argument("--broker-config",required=True)
    q.add_argument("--audit",default="state/activity.sqlite3")
    q=sub.add_parser("broker-preflight");q.add_argument("bindings");q.add_argument("--broker-config",required=True)
    q.add_argument("--request");q.add_argument("--remaining-nusd",type=int,default=0)
    q=sub.add_parser("host-observe");q.add_argument("--host-id",required=True);q.add_argument("--observer-id",required=True)
    q=sub.add_parser("host-plan");q.add_argument("measurement");q.add_argument("catalog");q.add_argument("request")
    q.add_argument("--public-key",required=True);q.add_argument("--key-id",required=True);q.add_argument("--policy")
    q.add_argument("--catalog-lock",default="/etc/diatonic-meta/artifact-catalog.sha256")
    q=sub.add_parser('replay-regression');q.add_argument('fixtures');q.add_argument('baseline');q.add_argument('candidate')
    q=sub.add_parser("watch");q.add_argument("--after",type=int,default=0)
    q=sub.add_parser("serve-monitor");q.add_argument("--port",type=int,default=9189);q.add_argument("--key-ref",default="file:credentials/monitor-key")
    q=sub.add_parser("assemble");q.add_argument("manifest");q.add_argument("--prompt",required=True);q.add_argument("--run-id",required=True);q.add_argument("--reference-catalog")
    for command in ("check","forecast-batch","run"):
        q=sub.add_parser(command);q.add_argument("manifest")
        if command!="check":
            q.add_argument("--model");q.add_argument("--allow-contributor",action="store_true")
        if command=="run":q.add_argument("--run-id",required=True)
    sub.add_parser("usage");sub.add_parser("doctor")
    args=p.parse_args()
    try:
        if args.command=="models":result=catalog()
        elif args.command=="forecast":result=forecast(Workload.model_validate_json(Path(args.workload).read_text()))
        elif args.command=="forecast-storage":
            from .storage import StageWorkload, forecast_stages
            result=forecast_stages(StageWorkload.model_validate_json(Path(args.workload).read_text()))
        elif args.command=="schemas":
            from .schemas import inspect
            result=inspect(args.directory)
        elif args.command=="references":
            from .references import ReferenceCatalog
            catalog_ref=ReferenceCatalog(args.catalog)
            try:result=catalog_ref.check_syntax()if args.check_syntax else catalog_ref.search(args.search)if args.search else catalog_ref.summary()
            finally:catalog_ref.close()
        elif args.command=="check":result=assess(load_manifest(args.manifest))
        elif args.command=="matrix":
            from importlib.resources import files
            result=json.loads(files('meta_pipeline').joinpath('data/execution-matrix.json').read_text())
        elif args.command=="protocol":
            from .protocol import schemas
            result=schemas()
        elif args.command=="inspect-package":
            from .package_integration import inspect_package
            result=inspect_package(args.archive)
        elif args.command=="estate-scan":
            from .estate import SourceSpec,EstateProjection
            source=SourceSpec.model_validate_json(Path(args.source).read_bytes())
            estate=EstateProjection(args.database)
            estate.register(source)
            if args.reconcile:estate.reconcile(source.source_id)
            result=estate.scan(source.source_id,max_entries=args.max_entries)
        elif args.command=="estate-query":
            from .estate import EstateProjection
            estate=EstateProjection(args.database)
            result=estate.query(name=args.name,label=args.label)
        elif args.command=="local-file-operation":
            from .filesystem import FileOperation,LocalFileAdapter
            operation=FileOperation.model_validate_json(Path(args.operation).read_bytes())
            adapter=LocalFileAdapter(args.authorized_root,authorized_operations=args.allow,journal=args.journal)
            result=adapter.execute(operation)
        elif args.command in ("broker-plan","broker-run"):
            from .broker_runtime import load_bindings,read_bounded,BrokerConfig,run_broker
            from .provider_contracts import BrokerRequest
            from .model_routing import RouteSelector
            registry=load_bindings(args.bindings)
            request=BrokerRequest.model_validate_json(read_bounded(args.request))
            cfg=GatewayConfig.model_validate_json(read_bounded(args.config))
            if args.command=="broker-plan":
                result=RouteSelector(registry,gateway_id=args.gateway_id,gateway_attempts=cfg.gateway_attempts).select(request,args.remaining_nusd).model_dump(mode="json")
                result["spend_admission"]=False
            else:
                result=asyncio.run(run_broker(gateway_config=cfg,
                    broker_config=BrokerConfig.model_validate_json(read_bounded(args.broker_config)),
                    registry=registry,request=request,ledger_path=args.ledger,audit_path=args.audit)).model_dump(mode="json")
        elif args.command=="broker-preflight":
            from .broker_runtime import BrokerConfig,load_bindings,read_bounded
            from .broker_preflight import inspect_broker
            from .provider_contracts import BrokerRequest
            result=inspect_broker(gateway_config=GatewayConfig.model_validate_json(read_bounded(args.config)),
                broker_config=BrokerConfig.model_validate_json(read_bounded(args.broker_config)),
                registry=load_bindings(args.bindings),
                request=BrokerRequest.model_validate_json(read_bounded(args.request)) if args.request else None,
                remaining_nusd=args.remaining_nusd)
        elif args.command=="host-observe":
            from .host_packaging import collect_local_measurement
            result={"measurement":collect_local_measurement(host_id=args.host_id,observer_id=args.observer_id).model_dump(mode="json"),
                "signature_status":"unsigned; authenticated observation/signature admission required"}
        elif args.command=="host-plan":
            from datetime import datetime,timezone
            from .broker_runtime import read_bounded
            from .host_packaging import SignedHostMeasurement,ArtifactCatalog,PackageRequest,HostPackagingPolicy,TrustedHostKey,derive_package_plan
            request=PackageRequest.model_validate_json(read_bounded(args.request))
            public=Path(args.public_key)
            if public.is_symlink() or not public.is_file() or public.stat().st_size>16384:raise ValueError("Bounded trust key required")
            import os,stat
            pins=()
            try:
                fd=os.open(args.catalog_lock,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                with os.fdopen(fd,"rb") as source:
                    info=os.fstat(source.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or info.st_size>128:raise ValueError("Unsafe catalog trust lock")
                    pin=source.read(129).decode().strip()
                    if len(pin)!=64 or any(c not in "0123456789abcdef" for c in pin):raise ValueError("Invalid catalog trust lock")
                    pins=(pin,)
            except FileNotFoundError:pass
            result=derive_package_plan(SignedHostMeasurement.model_validate_json(read_bounded(args.measurement)),
                ArtifactCatalog.model_validate_json(read_bounded(args.catalog)),request,
                HostPackagingPolicy.model_validate_json(read_bounded(args.policy))if args.policy else HostPackagingPolicy(),
                trusted_keys=(TrustedHostKey(host_id=request.host_id,key_id=args.key_id,public_key_pem=public.read_bytes()),),
                now=datetime.now(timezone.utc),trusted_catalog_digests=pins).model_dump(mode="json")
        elif args.command=='replay-regression':
            from .regression import FixtureSet,ReplaySet,compare_replays
            def read(path,model):
                p=Path(path)
                if p.stat().st_size>8*1024**2:raise ValueError('Replay input exceeds bound')
                return model.model_validate_json(p.read_bytes())
            result=compare_replays(read(args.fixtures,FixtureSet),read(args.baseline,ReplaySet),read(args.candidate,ReplaySet)).model_dump(mode='json')
        elif args.command in ("watch","serve-monitor"):
            from .audit import Audit
            audit=Audit("state/activity.sqlite3")
            if args.command=="watch":
                result={"events":audit.events(args.after),"snapshot":audit.snapshot(),"integrity":audit.verify()}
            else:
                import uvicorn
                from .monitor import create_app
                from .gateway import resolve_secret
                cfg=GatewayConfig.model_validate_json(Path(args.config).read_text())
                ledger=Ledger(args.ledger,cfg.daily_nusd,cfg.run_nusd)
                uvicorn.run(create_app(audit,ledger,resolve_secret(args.key_ref)),host="127.0.0.1",port=args.port,access_log=False)
                return 0
        else:
            config=GatewayConfig.model_validate_json(Path(args.config).read_text())
            ledger=Ledger(args.ledger,config.daily_nusd,config.run_nusd)
            if args.command=="usage":result=ledger.summary()
            elif args.command=="forecast-batch":
                from types import SimpleNamespace
                manager=ValidationManager(SimpleNamespace(config=config))
                result=manager.forecast(load_manifest(args.manifest),model=args.model,allow_contributor=args.allow_contributor)
            elif args.command=="assemble":
                from .framework import Assembly
                from .audit import Audit
                from .workflows import WorkflowRegistry
                async def assembly():
                    from .references import ReferenceCatalog
                    audit=Audit("state/activity.sqlite3")
                    registry=WorkflowRegistry("state/workflows",audit)
                    references=ReferenceCatalog(args.reference_catalog)if args.reference_catalog else None
                    runtime=Assembly(config,ledger,audit,registry,run=args.run_id,records=load_manifest(args.manifest),references=references)
                    try:return {"model_assessment":(await runtime.execute(args.prompt)).model_dump(),
                        "verification_status":"requires independent verifier; model assessment is not proof of an external effect"}
                    finally:
                        await runtime.close()
                        if references:references.close()
                result=asyncio.run(assembly())
            else:
                async def run():
                    gateway=MetaGateway(config,ledger)
                    try:
                        if args.command=="doctor":return await gateway.readiness()
                        return await ValidationManager(gateway).run(load_manifest(args.manifest),run=args.run_id,
                            model=args.model,allow_contributor=args.allow_contributor)
                    finally:await gateway.close()
                result=asyncio.run(run())
        print(json.dumps(result,indent=2,sort_keys=True))
        if args.command=="run" and any(b["status"]!="validated" for b in result["ai_batches"]):return 2
        if args.command=='replay-regression' and not result['regression_gate_passed']:return 2
        if args.command=="broker-preflight" and result["status"]=="blocked":return 2
        return 0
    except Exception as exc:
        # Never echo exception bodies that may carry provider credentials or user metadata.
        print(json.dumps({"error_type":type(exc).__name__,"status":"failed"}),file=sys.stderr)
        return 1

if __name__=="__main__":sys.exit(main())
