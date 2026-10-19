import hashlib
import json

from mobile_audit.discovery import discover
from mobile_audit.models import investigate
from mobile_audit.prompting import build_prompt


def large_index(count=25659):
    symbols=[{'name':'SecuritySubsystemClass'+str(n)*20,'line':n+1} for n in range(20)]
    imports=['import '+('module_'+str(n))*20 for n in range(10)]
    return [dict(path=f'generated/module_{n:05d}.ts',lines=10,sha256='f'*64,
                 sensitive=False,entrypoint=False,subsystems=[],symbols=symbols,imports=imports)
            for n in range(count)]


def test_large_navigation_index_fits_character_budget():
    files=large_index()
    assert len(json.dumps(files[:200]))>24000
    contexts=[{'file':'auth.kt','start':1,'source':[{'line':1,'text':'class Auth {}'}]}]
    prompt,stats,provided=build_prompt(files,contexts,24000)
    assert len(prompt)<=24000
    data=json.loads(prompt)
    assert data['untrusted_source'][0]['source'][0]['text']=='class Auth {}'
    assert stats['index_files_omitted']>25000
    assert provided==[{'file':'auth.kt','start':1,'end':1}]


def test_long_source_lines_are_omitted_without_invalid_json():
    contexts=[{'file':'client.ts','start':1,'source':[
        {'line':1,'text':'x'*40000}, {'line':2,'text':'const enabled = true;'}]}]
    prompt,stats,provided=build_prompt([],contexts,2048)
    assert len(prompt)<=2048 and json.loads(prompt)
    assert stats['source_lines_omitted']==1
    assert provided==[{'file':'client.ts','start':2,'end':2}]


def test_oversized_whole_source_fails_explicitly():
    import pytest
    with pytest.raises(ValueError,match='No complete source line'):
        build_prompt([], [{'file':'minified.js','start':1,'source':[{'line':1,'text':'x'*10000}]}],2048)


def test_investigation_handles_25659_file_index(tmp_path,monkeypatch):
    import mobile_audit.models as models
    source=tmp_path/'auth.kt';source.write_text('class Auth {\n fun login() {}\n}\n')
    index=discover(tmp_path)
    index['files'].extend(large_index(25658))
    calls=[];progress=[]
    def infer(config,root,prompt,work):
        assert len(prompt)<=24000
        assert json.loads(prompt)['untrusted_source']
        calls.append(prompt)
        return {'findings':[],'requests':[]},{'seconds':0}
    monkeypatch.setattr(models,'infer',infer)
    _,status=investigate(tmp_path,index,{'enabled':True},tmp_path,'quick',[],progress=lambda **p:progress.append(p))
    assert status['status']=='completed' and len(calls)==1
    assert status['prompt_budgets'][0]['index_files_omitted']>25000
    assert progress[0]['current']==1 and status['provided']


def test_empty_files_do_not_consume_investigation_budget(tmp_path,monkeypatch):
    import mobile_audit.models as models
    (tmp_path/'App.tsx').write_text('')
    (tmp_path/'auth.kt').write_text('class Auth {}')
    monkeypatch.setattr(models,'infer',lambda *a:({'findings':[],'requests':[]},{}))
    _,status=investigate(tmp_path,discover(tmp_path),{'enabled':True},tmp_path,'quick',[])
    assert status['status']=='completed' and status['empty_files_skipped']==1
    assert status['investigated']==['auth.kt']


def test_fast_verification_preserves_raw_hashes_and_skips_generated(tmp_path):
    raw=b'class Example {\r\n fun login() {}\r\n}\r\n'
    (tmp_path/'auth.kt').write_bytes(raw)
    (tmp_path/'.next').mkdir();(tmp_path/'.next'/'generated.ts').write_text('generated')
    (tmp_path/'binary.dat').write_bytes(b'hello\x00world')
    full=discover(tmp_path);fast=discover(tmp_path,index_code=False)
    assert [(f['path'],f['sha256']) for f in full['files']]==[(f['path'],f['sha256']) for f in fast['files']]
    assert full['files'][0]['sha256']==hashlib.sha256(raw).hexdigest()
    assert full['files'][0]['symbols'][1]['line']==2
    assert 'symbols' not in fast['files'][0]
    assert '.next/' in full['excluded'] and 'binary.dat' in full['excluded']
