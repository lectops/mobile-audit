"""Conservative AI reuse: require unchanged entire indexed repository and model config."""
import hashlib,json,os
from pathlib import Path

def cache_key(root,index,config,mode):
    model=Path(config.get('path','')).expanduser()
    stat=model.stat() if model.exists() else None
    implementation=hashlib.sha256(b''.join(Path(__file__).with_name(name).read_bytes() for name in ['models.py','security.py','discovery.py','findings.py','prompting.py'])).hexdigest()
    data={'implementation_hash':implementation,'root':str(root),'files':[(f['path'],f['sha256']) for f in index['files']],'config':config,'mode':mode,'model_size':stat.st_size if stat else None,'model_mtime':stat.st_mtime_ns if stat else None,'implementation':'0.1.0-v3'}
    return hashlib.sha256(json.dumps(data,sort_keys=True).encode()).hexdigest()

def investigate_cached(root,index,config,work,mode,existing,enabled=True,progress=None):
    from .models import investigate
    # Scanner findings influence secret redaction. Include their IDs and locations.
    key=hashlib.sha256((cache_key(root,index,config,mode)+json.dumps([(f['id'],f['file'],f['line']) for f in existing],sort_keys=True)).encode()).hexdigest()
    cache=Path.home()/'Library/Caches/mobile-audit';path=cache/(key+'.json')
    if enabled and config.get('enabled',True) and path.is_file() and not path.is_symlink():
        try:
            data=json.loads(path.read_text());data[1]['cache_hit']=True;data[1]['usage_is_historical']=True
            return data
        except (ValueError,IndexError,TypeError):pass
    result=investigate(root,index,config,work,mode,existing,progress=progress)
    if enabled and result[1]['status']=='completed':
        cache.mkdir(parents=True,exist_ok=True,mode=0o700)
        if cache.is_symlink():return result
        temp=cache/(key+'.'+str(os.getpid())+'.tmp');temp.write_text(json.dumps(result));temp.chmod(0o600);temp.replace(path)
    return result
