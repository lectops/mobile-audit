import json,subprocess,sys,shutil
from pathlib import Path
import pytest,jsonschema
from mobile_audit.discovery import discover,evidence
from mobile_audit.findings import finding,deduplicate
from mobile_audit.security import safe_path,redact,run
from mobile_audit.models import investigate,infer
from mobile_audit.reporting import write_reports
from mobile_audit.cli import main,parser
from mobile_audit.scanners import scan

@pytest.fixture
def repo(tmp_path):
    p=tmp_path/'repo';p.mkdir();(p/'auth.kt').write_text('class Auth {\n val password = "fake-test-value"\n}\n');return p

def test_discovery(repo):
    (repo/'build').mkdir();(repo/'build'/'a.kt').write_text('generated');(repo/'external.kt').symlink_to('/etc/passwd')
    d=discover(repo);assert len(d['files'])==1;assert d['files'][0]['sensitive'];assert d['files'][0]['symbols'][0]['name']=='Auth'

def test_evidence(repo):
    assert 'password' in evidence(repo,'auth.kt',2,quote='password')
    with pytest.raises(ValueError):evidence(repo,'auth.kt',99)
    with pytest.raises(ValueError):evidence(repo,'auth.kt',2,quote='invented')
    with pytest.raises(ValueError):safe_path(repo,'../../etc/passwd')

def test_normalization_dedup(repo):
    f=finding(repo,'auth.kt',2,'rule','Test','semgrep','ERROR','CWE-798')
    assert f['severity']=='high';assert 'fake-test-value' not in f['evidence'];assert len(deduplicate([f,f]))==1

def test_missing_model(repo,tmp_path):
    _,s=investigate(repo,discover(repo),{'enabled':True,'path':'/no/model'},tmp_path,'quick',[]);assert s['status']=='failed'

def test_mock_investigation(repo,tmp_path,monkeypatch):
    import mobile_audit.models as models
    monkeypatch.setattr(models,'infer',lambda *a:({'findings':[{'file':'auth.kt','line':2,'quote':'password','title':'Credential','cwe':'CWE-798'}]}, {'seconds':0}))
    f,s=investigate(repo,discover(repo),{'enabled':True},tmp_path,'quick',[]);assert len(f)==1;assert s['status']=='completed'

def test_reject_invented_model_evidence(repo,tmp_path,monkeypatch):
    import mobile_audit.models as models
    monkeypatch.setattr(models,'infer',lambda *a:({'findings':[{'file':'auth.kt','line':2,'quote':'invented','title':'bad'}]},{}))
    f,s=investigate(repo,discover(repo),{},tmp_path,'quick',[]);assert not f;assert s['rejected_candidates']

def test_scanner_failure_visible(repo,tmp_path,monkeypatch):
    import mobile_audit.scanners as scanners
    monkeypatch.setattr(scanners,'executable',lambda n:None)
    f,s=scan('semgrep',repo,repo,tmp_path);assert s['status']=='skipped';assert s['errors']

def test_reports(repo,tmp_path):
    out=tmp_path/'reports';out.mkdir();f=finding(repo,'auth.kt',2,'rule','<script>','semgrep')
    write_reports(out,[f],{}, {'repository':str(repo),'timestamp':'test'})
    sarif=json.loads((out/'findings.sarif').read_text());jsonschema.validate(sarif,json.loads(Path('tests/sarif-schema.json').read_text()))
    assert '<script>' not in (out/'report.html').read_text();assert json.loads((out/'findings.json').read_text())

def test_cli_arguments(repo):
    assert parser().parse_args([str(repo),'--quick','--no-llm']).quick
    with pytest.raises(SystemExit):parser().parse_args([str(repo),'--quick','--deep'])
    assert main([str(repo),'--output',str(repo/'report')])==2

def test_isolation(repo):
    if not shutil.which('sandbox-exec'):pytest.skip('macOS required')
    r=run(['/usr/bin/touch',repo/'forbidden'],repo);assert r.returncode!=0;assert not (repo/'forbidden').exists()
    code='import socket; s=socket.socket(); s.bind(("127.0.0.1",0))'
    r=run([sys.executable,'-c',code],repo);assert r.returncode!=0

def test_no_llm_integration(repo,tmp_path):
    before=(repo/'auth.kt').read_bytes();out=tmp_path/'output'
    result=main([str(repo),'--no-llm','--offline','--output',str(out)])
    assert result in [1,3];report=next(out.iterdir());assert (report/'report.html').exists();assert (repo/'auth.kt').read_bytes()==before
    coverage=json.loads((report/'coverage.json').read_text());assert coverage['source_unchanged'];assert any(c['name']=='semgrep' and c['status']=='completed' for c in coverage['checks'])


def test_model_timeout(repo,tmp_path,monkeypatch):
    import mobile_audit.models as models
    monkeypatch.setattr(models,'run',lambda *a,**kw: (_ for _ in ()).throw(subprocess.TimeoutExpired('local-model',1)))
    model=tmp_path/'m.gguf';model.write_text('fixture')
    _,s=investigate(repo,discover(repo),{'enabled':True,'path':str(model)},tmp_path,'quick',[])
    assert s['status']=='failed';assert 'TimeoutExpired' in s['errors'][0]

def test_cwe_allowlist(repo):
    assert finding(repo,'auth.kt',1,'rule','x','primary-model',cwe='CWE-999999')['cwe'] is None

def test_symlink_parent(repo,tmp_path):
    (repo/'outside').symlink_to(tmp_path,target_is_directory=True)
    with pytest.raises(ValueError):safe_path(repo,'outside/anything')

def test_config_disable_models(repo,tmp_path):
    f,s=investigate(repo,discover(repo),{'enabled':False},tmp_path,'quick',[])
    assert not f and s['status']=='skipped'


def test_cache_requires_whole_repository(repo):
    from mobile_audit.cache import cache_key
    a=cache_key(repo,discover(repo),{},'quick')
    (repo/'other.java').write_text('class Other {}')
    assert cache_key(repo,discover(repo),{},'quick')!=a

def test_model_retry_bounded(repo,tmp_path,monkeypatch):
    import mobile_audit.models as models
    calls=[]
    def fail(*args):calls.append(1);raise RuntimeError('failure')
    monkeypatch.setattr(models,'_infer_once',fail)
    with pytest.raises(RuntimeError):models.infer({'retries':99},repo,'prompt',tmp_path)
    assert len(calls)==3

def test_neutralized_ignores_and_sarif(repo,tmp_path):
    (repo/'.semgrepignore').write_text('*')
    (repo/'auth.kt').write_text('val password = "fake-not-a-real-password" // nosemgrep\n')
    out=tmp_path/'out';main([str(repo),'--no-llm','--output',str(out)])
    report=next(out.iterdir());items=json.loads((report/'findings.json').read_text())
    assert any('semgrep' in f['detection_source'] for f in items)
    jsonschema.validate(json.loads((report/'findings.sarif').read_text()),json.loads(Path('tests/sarif-schema.json').read_text()))


def test_offline_fail_closed(repo,tmp_path,monkeypatch):
    import mobile_audit.security as security
    monkeypatch.setattr(security.shutil,'which',lambda n:None)
    with pytest.raises(RuntimeError):run(['/usr/bin/true'],repo)
    assert main([str(repo),'--offline','--output',str(tmp_path/'reports')])==2

def test_adapter_bad_json(repo,tmp_path,monkeypatch):
    import mobile_audit.scanners as scanners
    monkeypatch.setattr(scanners,'executable',lambda n:'/fake/tool')
    monkeypatch.setattr(scanners,'run',lambda *a,**kw:subprocess.CompletedProcess([],0,'not JSON',''))
    f,s=scanners.scan('semgrep',repo,repo,tmp_path);assert not f and s['status']=='failed'

def test_adapter_normalizes_semgrep(repo,tmp_path,monkeypatch):
    import mobile_audit.scanners as scanners
    output={'results':[{'path':str(repo/'auth.kt'),'start':{'line':2},'end':{'line':2},'check_id':'local.rule','extra':{'message':'Credential','severity':'ERROR','metadata':{'cwe':['CWE-798']}}}],'errors':[],'paths':{'scanned':[str(repo/'auth.kt')]}}
    monkeypatch.setattr(scanners,'executable',lambda n:'/fake/tool')
    monkeypatch.setattr(scanners,'run',lambda *a,**kw:subprocess.CompletedProcess([],0,json.dumps(output),''))
    f,s=scanners.scan('semgrep',repo,repo,tmp_path);assert len(f)==1 and f[0]['cwe']=='CWE-798' and s['status']=='completed'

def test_cache_hit(repo,tmp_path,monkeypatch):
    import mobile_audit.models as models
    from mobile_audit.cache import investigate_cached
    monkeypatch.setattr(Path,'home',classmethod(lambda cls:tmp_path))
    calls=[]
    def fake(*args,**kwargs):calls.append(1);return [],{'status':'completed'}
    monkeypatch.setattr(models,'investigate',fake)
    first=investigate_cached(repo,discover(repo),{'enabled':True},tmp_path,'quick',[])
    second=investigate_cached(repo,discover(repo),{'enabled':True},tmp_path,'quick',[])
    assert len(calls)==1 and second[1]['cache_hit']

def test_osv_advisories_not_deduplicated_by_cwe(repo):
    a=finding(repo,'auth.kt',1,'GHSA-a','advisory A','osv-scanner',cwe='CWE-1321')
    b=finding(repo,'auth.kt',1,'GHSA-b','advisory B','osv-scanner',cwe='CWE-1321')
    assert len(deduplicate([a,b]))==2


def test_final_revalidation_rejects_changed_code(repo):
    from mobile_audit.findings import revalidate
    f=finding(repo,'auth.kt',1,'rule','x','primary-model')
    (repo/'auth.kt').write_text('class Different {}')
    valid,rejected=revalidate(repo,[f]);assert not valid and rejected==[f['id']]


def test_loopback_connect_is_denied(repo):
    import socket
    with socket.socket() as server:
        server.bind(('127.0.0.1',0));server.listen(2)
        port=server.getsockname()[1]
        with socket.create_connection(('127.0.0.1',port),timeout=1):pass
        command='import socket;socket.create_connection(("127.0.0.1",'+str(port)+'),timeout=1)'
        child=run([sys.executable,'-c',command],repo)
        assert child.returncode!=0 and ('not permitted' in child.stderr or 'Permission' in child.stderr)


def test_reasoning_parser_uses_final_answer(repo,tmp_path,monkeypatch):
    import mobile_audit.models as models
    model=tmp_path/'model.gguf';model.write_text('mock')
    output='<think>{"review":{"credible":false}}</think>{"review":{"credible":true}}'
    monkeypatch.setattr(models,'run',lambda *a,**kw:subprocess.CompletedProcess([],0,output,'MTL0'))
    result,usage=models._infer_once({'path':str(model)},repo,'mock',tmp_path)
    assert result['review']['credible'] is True and usage['metal_detected']


def test_reviewer_continues_after_candidate_failure(repo,tmp_path,monkeypatch):
    import mobile_audit.models as models
    items=[finding(repo,'auth.kt',1,'one','One','semgrep'),finding(repo,'auth.kt',2,'two','Two','semgrep')]
    calls=[]
    def respond(*args):
        calls.append(1)
        if len(calls)==1:raise ValueError('invalid JSON')
        return {'review':{'credible':False,'confidence':'low','disagreement':'Preconditions not established'}},{'seconds':0}
    monkeypatch.setattr(models,'infer',respond)
    status=models.review(repo,items,{'enabled':True},tmp_path,'quick')
    assert status['status']=='partial' and len(status['reviewed'])==1 and len(items)==2
    assert any(f.get('independent_review',{}).get('credible') is False for f in items)


def test_portable_config_precedence_and_relative_paths(tmp_path):
    from mobile_audit.configuration import load_config
    user=tmp_path/'private.yaml';user.write_text('primary:\n  path: weights/local.gguf\n  context: 8192\nreviewer:\n  enabled: false\n')
    override=tmp_path/'override.yaml';override.write_text('primary:\n  context: 4096\n')
    config=load_config(override,user_path=user)
    assert config['primary']['context']==4096
    assert config['primary']['path']==str(tmp_path/'weights/local.gguf')
    assert config['primary']['max_tokens']==1536
    assert config['reviewer']['enabled'] is False


def test_packaged_defaults_have_no_machine_paths(tmp_path,monkeypatch):
    from mobile_audit.configuration import load_config
    config=load_config(user_path=tmp_path/'absent.yaml')
    assert config['primary']['path']=='' and config['reviewer']['path']==''
    monkeypatch.chdir(tmp_path)
    (tmp_path/'config.yaml').write_text('primary: {path: malicious.gguf}')
    assert load_config(user_path=tmp_path/'absent.yaml')['primary']['path']==''


def test_config_environment_path_and_invalid_mapping(tmp_path,monkeypatch):
    from mobile_audit.configuration import load_config
    monkeypatch.setenv('AUDIT_TEST_WEIGHTS',str(tmp_path/'weights'))
    override=tmp_path/'settings.yaml';override.write_text('primary:\n  path: $AUDIT_TEST_WEIGHTS/model.gguf\n')
    assert load_config(override,user_path=tmp_path/'none')['primary']['path']==str(tmp_path/'weights/model.gguf')
    override.write_text('- invalid\n')
    with pytest.raises(ValueError):load_config(override,user_path=tmp_path/'none')
