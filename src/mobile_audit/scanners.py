import json,shutil,hashlib,sys,time
from pathlib import Path
from .security import run
from .findings import finding
RULES=Path(__file__).with_name('rules.yaml')
def executable(name):
    p=Path(sys.executable).parent/name
    return str(p) if p.exists() else shutil.which(name)
def scan(name, root, stage, out, deep=False, timeout=180):
    exe=executable(name)
    status=dict(name=name,status='skipped',findings=0,errors=[],version=None,files=[],ruleset=None)
    items=[]
    if not exe: status['errors']=['Not installed']; return items,status
    try:
        v=run([exe,'--version' if name!='mobsfscan' else '-v'],root,20)
        status['version']=(v.stdout+v.stderr).strip()[:200]
        target=out/(name+'.json')
        if name=='semgrep':
            cmd=[exe,'scan','--config',RULES,'--json','--metrics=off','--disable-version-check','--disable-nosem','--no-git-ignore','--no-rewrite-rule-ids','--jobs','2','--max-memory','2000','--timeout','20',stage]
            status['ruleset']=dict(provenance='mobile-audit local rules v1',sha256=hashlib.sha256(RULES.read_bytes()).hexdigest())
        elif name=='gitleaks':
            cmd=[exe,'dir',stage,'--redact=100','--config',RULES.with_name('gitleaks.toml'),'--ignore-gitleaks-allow','--report-format','json','--report-path',target,'--exit-code','0','--no-banner']
            status['ruleset']='Gitleaks embedded defaults '+status['version']
        elif name=='mobsfscan':
            cmd=[exe,'--json','--no-fail','-c',RULES.with_name('mobsf.yaml'),'-o',target,stage]
            status['ruleset']='MobSF bundled rules '+status['version']
        else:
            cache=Path.home()/'Library/Caches/osv-scalibr'
            databases=list(cache.glob('*/all.zip')) if cache.exists() else []
            ecosystems={'package-lock.json':'npm','yarn.lock':'npm','pnpm-lock.yaml':'npm','pubspec.lock':'Pub','Podfile.lock':'CocoaPods','Cargo.lock':'crates.io','poetry.lock':'PyPI','uv.lock':'PyPI','requirements.txt':'PyPI','Gemfile.lock':'RubyGems','composer.lock':'Packagist','go.sum':'Go','Package.resolved':'SwiftURL'}
            manifests=[(p,ecosystems[p.name]) for p in stage.rglob('*') if p.is_file() and p.name in ecosystems]
            status['dependency_manifests']=[dict(file=str(p.relative_to(stage)),ecosystem=eco) for p,eco in manifests]
            cached={p.parent.name.lower() for p in databases}
            status['coverage_gaps']=['No cached advisory ecosystem: '+eco for eco in sorted({eco for _,eco in manifests}) if eco.lower() not in cached]
            if not manifests:status['errors']=['No supported lockfiles/pinned requirements found; manifest-only dependency versions are not inferred'];return items,status
            status['database']=[dict(ecosystem=p.parent.name,updated=p.stat().st_mtime,age_days=round((time.time()-p.stat().st_mtime)/86400,2)) for p in databases]
            if not databases:status['errors']=['No cached OSV vulnerability databases; skipped offline'];return items,status
            status['ruleset']='OSV local cached advisory databases; cache timestamp is download time, not guarantee of currency'
            cmd=[exe,'scan','source','--offline','--offline-vulnerabilities','--no-resolve','--no-call-analysis=go,rust','--x-no-default-plugins','--x-plugins=lockfile','--format','json','--all-packages','--recursive',stage]

        p=run(cmd,root,timeout,cwd=out)
        if p.returncode not in ([0,1] if name=='osv-scanner' else [0]):
            categories=[label for label in ['permission denied','not found','unrecognized','invalid','network','timeout','configuration'] if label in (p.stderr+p.stdout).lower()]
            raise RuntimeError('Scanner exit '+str(p.returncode)+'; diagnostic categories: '+','.join(categories))
        data=json.loads(p.stdout if name in ['semgrep','osv-scanner'] else target.read_text())
        if target.exists(): target.unlink()
        def add(path,line,rule,title,sev,cwe=None,end=None):
            path=Path(path)
            if path.is_absolute(): path=path.resolve().relative_to(stage.resolve())
            try:
                item=finding(root,str(path),line,rule,title,name,sev,cwe,end)
                if name=='gitleaks':item['evidence']='[REDACTED secret-bearing source lines]'
                items.append(item)
            except (ValueError,OSError,UnicodeError):status['errors'].append('Rejected invalid evidence location')
        if name=='semgrep':
            status['files']=[str(Path(x).relative_to(stage)) if Path(x).is_absolute() else x for x in data.get('paths',{}).get('scanned',[])]
            for x in data.get('results',[]):add(x['path'],x['start']['line'],x['check_id'],x['extra']['message'],x['extra']['severity'],x['extra'].get('metadata',{}).get('cwe'),x['end']['line'])
            status['errors'] += ['Semgrep error: '+str(x.get('type','unknown')) for x in data.get('errors',[])]
        elif name=='gitleaks':
            for x in data or []:add(x['File'],x['StartLine'],x['RuleID'],x['Description'],'high','CWE-798',x['EndLine'])
        elif name=='osv-scanner':
            for result in data.get('results',[]):
                manifest=Path(result['source']['path']).resolve().relative_to(stage.resolve())
                for package in result.get('packages',[]):
                    pkg=package['package']
                    status.setdefault('dependencies',[]).append(dict(manifest=str(manifest),**pkg))
                    for vuln in package.get('vulnerabilities',[]):
                        lines=(root/manifest).read_text().splitlines();lineno=next((i+1 for i,l in enumerate(lines) if pkg['version'] in l),1)
                        add(manifest,lineno,vuln['id'],pkg['name']+' '+pkg['version']+': '+vuln.get('summary',vuln['id']),{'CRITICAL':'critical','HIGH':'high','MODERATE':'medium','LOW':'low'}.get(vuln.get('database_specific',{}).get('severity'),'medium'),vuln.get('database_specific',{}).get('cwe_ids'))
                        items[-1].update(dependency=pkg,version_status='Confirmed lockfile version; installed/reachable usage not established',advisory_ids=[vuln['id']]+vuln.get('aliases',[]),remediation='Upgrade to a fixed release after checking advisory affected ranges and application compatibility.')
        else:
            status['errors'] += ['mobsfscan reported internal error' for e in data.get('errors',[])]
            status['informational_concerns']=[{'rule':r,'description':x.get('metadata',{}).get('description','')} for r,x in data.get('results',{}).items() if not x.get('files')]
            for rule,x in data.get('results',{}).items():
                m=x.get('metadata',{})
                for f in x.get('files',[]):
                    pos=f.get('match_lines',[1,1]);add(f['file_path'],pos[0],rule,m.get('description',rule),m.get('severity','WARNING'),m.get('cwe'),pos[-1])
        status['status']='partial' if status['errors'] or status.get('coverage_gaps') else 'completed'
        if name=='osv-scanner' and any(p['age_days']>7 for p in status.get('database',[])):status['errors'].append('Cached advisory database older than 7 days');status['status']='partial'
    except Exception as e:status['status']='failed';status['errors'].append(type(e).__name__+': '+str(e)[:200])
    status['findings']=len(items)
    if deep and name=='gitleaks':status['errors'].append('Git history scan not implemented; current files only')
    return items,status
