import argparse,json,os,sys,tempfile,shutil,datetime,time
from pathlib import Path
import yaml
from .discovery import discover
from .security import safe_path,run,redact
from .scanners import scan
from .models import review
from .cache import investigate_cached
from .findings import deduplicate,revalidate
from .reporting import write_reports
from .environment import inventory,model_info
from .configuration import load_config

def parser():
    p=argparse.ArgumentParser(description='Read-only local mobile source security audit. No uploads, cloud fallback, builds, or automatic updates.')
    p.add_argument('source',nargs='?');g=p.add_mutually_exclusive_group();g.add_argument('--quick',action='store_true');g.add_argument('--deep',action='store_true')
    p.add_argument('--offline',action='store_true',help='Require OS network isolation (also enforced for all normal scanner/model runs)')
    p.add_argument('--no-llm',action='store_true');p.add_argument('--output',type=Path,default=Path.home()/'SecurityReports');p.add_argument('--config',type=Path);p.add_argument('--doctor',action='store_true');p.add_argument('--models',action='store_true')
    return p

def main(argv=None):
    os.umask(0o077);args=parser().parse_args(argv)
    try:
        config=load_config(args.config)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print('Configuration error: '+redact(str(exc)),file=sys.stderr)
        return 2
    if args.doctor or args.models:
        print(json.dumps(inventory(config) if args.doctor else model_info(config),indent=2));return 0
    if not args.source:parser().error('source directory required')
    root=Path(args.source).expanduser().resolve()
    if not root.is_dir():print('Source directory does not exist',file=sys.stderr);return 2
    base=args.output.expanduser().resolve()
    if base.is_relative_to(root):print('Reports must be outside audited repository',file=sys.stderr);return 2
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S-%f');out=base/(root.name+'-'+stamp);out.mkdir(parents=True,mode=0o700)
    events=[];audit_started=time.monotonic();audit_deadline=audit_started+config.get('audit_timeout',1800)
    def log(phase,**fields):
        event=dict(time=datetime.datetime.now(datetime.timezone.utc).isoformat(),phase=phase,**fields);events.append(event)
        with (out/'execution.log').open('a') as f:f.write(json.dumps(event)+'\n')
        print(f"[{phase}] "+str(fields.get('status','')),file=sys.stderr)
    try:
        check=run(['/usr/bin/true'],root,10)
        if check.returncode:raise RuntimeError('OS isolation unavailable; audit stopped closed')
        index=discover(root);log('discovery',status=str(len(index['files']))+' files')
        (out/'index.json').write_text(json.dumps({**index,'files':[{**f,'imports':[redact(x) for x in f['imports']]} for f in index['files']]},indent=2))
        statuses=[dict(name='discovery',status='partial' if index['errors'] else 'completed',errors=index['errors'])];items=[];mode='quick' if args.quick else 'deep' if args.deep else 'standard'
        with tempfile.TemporaryDirectory(prefix='mobile-audit-') as temp:
            work=Path(temp);stage=work/'source';stage.mkdir()
            for f in index['files']:
                p=safe_path(root,f['path']);target=stage/f['path'];target.parent.mkdir(parents=True,exist_ok=True)
                # Neutralize scanner control files only in the external snapshot.
                target.write_bytes(b'' if p.name in {'.semgrepignore','.gitignore','.gitleaksignore'} else p.read_bytes())
            for scanner in ['semgrep','gitleaks','mobsfscan','osv-scanner']:
                remaining=max(1,int(audit_deadline-time.monotonic()))
                found,status=scan(scanner,root,stage,work,args.deep,min(remaining,config.get('scanner_timeout',240)));items.extend(found);statuses.append(status);log(scanner,status=status['status'],findings=len(found))
            if not args.no_llm:
                config['primary']['total_timeout']=min(config['primary'].get('total_timeout',900),max(0,int(audit_deadline-time.monotonic())))
                found,status=investigate_cached(root,index,config['primary'],work,mode,items,config.get('cache_ai',True));items.extend(found);statuses.append(status);log('primary-model',status=status['status'],findings=len(found))
                items=deduplicate(items);config['reviewer']['total_timeout']=min(config['reviewer'].get('total_timeout',900),max(0,int(audit_deadline-time.monotonic())));status=review(root,items,config['reviewer'],work,mode);statuses.append(status);log('reviewer-model',status=status['status'])
            else:statuses.append(dict(name='models',status='skipped',errors=['Explicit --no-llm']))
        after=discover(root);unchanged={f['path']:f['sha256'] for f in index['files']}=={f['path']:f['sha256'] for f in after['files']}
        items=deduplicate(items);items,rejected=revalidate(root,items)
        statuses.append(dict(name='evidence-validation',status='partial' if rejected else 'completed',rejected_finding_ids=rejected,errors=['Source evidence changed or disappeared'] if rejected else []))
        coverage=dict(files_discovered=len(index['files']),files_excluded=index['excluded'],languages=index['languages'],frameworks=index['frameworks'],subsystems=index['subsystems'],files_submitted_to_scanners=[f['path'] for f in index['files']],checks=statuses,source_unchanged=unchanged,network_isolation='macOS sandbox-exec deny network* enforced for all scanner and inference children',limitations=index['limitations']+['No dynamic testing; exploitability needs manual review.','Primary AI analyzes budgeted snippets only; uninvestigated code remains uncovered.','No incremental reuse: full deterministic scan each audit.','Excluded/unsupported/binary files are not secret-scanned.','Repository ignore configuration is neutralized in the scanner snapshot; mobsf inline suppressions may still limit matches.','Snapshot may race concurrent source edits; avoid editing during audit.'])
        metadata=dict(repository=str(root),timestamp=stamp,mode=mode,offline=args.offline,models=model_info(config,include_cache=False),version='0.1.0',duration_seconds=round(time.monotonic()-audit_started,2),rule_provenance='bundled local rules v1')
        write_reports(out,items,coverage,metadata);log('report',status='written',findings=len(items));print(out/'report.html')
        incomplete=any(s['status'] in ['failed','partial'] or (s['status']=='skipped' and s['name'] not in ['models']) for s in statuses)
        return 3 if incomplete or not unchanged else 1 if items else 0
    except Exception as e:
        log('fatal',status='failed',error=redact(type(e).__name__+': '+str(e)));print('Audit failed; diagnostics: '+str(out),file=sys.stderr);return 2
if __name__=='__main__':sys.exit(main())
