import json,platform,shutil,subprocess,sys
from pathlib import Path
from .scanners import executable
from .security import run

def inventory(config):
    components=[]
    for name in ['python','uv','ollama','mlx_lm.generate','llama-cli','semgrep','mobsfscan','gitleaks','codeql','osv-scanner','aider','sandbox-exec']:
        path=sys.executable if name=='python' else executable(name)
        version='not installed'
        if path and name in ['sandbox-exec','mlx_lm.generate']:
            version='macOS bundled' if name=='sandbox-exec' else 'Homebrew mlx-lm (see environment inventory)'
        elif path:
            try:
                r=run([path,'-v' if name=='mobsfscan' else '--version'],Path('/var/empty'),10)
                version=(r.stdout+r.stderr)[:300].strip()
            except Exception:version='version check unavailable'
        components.append(dict(component=name,location=path,version=version,status='installed' if path else 'missing',recommended_action='reuse' if path else 'optional install'))
    return dict(platform=platform.platform(),architecture=platform.machine(),components=components,models=model_info(config),isolation='sandbox-exec required; audited processes deny all networking and source writes')
def gguf_metadata(path):
    import struct
    wanted={}
    with Path(path).open('rb') as f:
        if f.read(4)!=b'GGUF':return {'error':'Not a GGUF file'}
        version,tensors,count=struct.unpack('<IQQ',f.read(20))
        if version not in [2,3] or count>10000:raise ValueError('Unsupported GGUF header')
        def string(keep=True):
            n=struct.unpack('<Q',f.read(8))[0]
            if n>100_000_000:raise ValueError('Invalid GGUF string length')
            if keep:return f.read(n).decode(errors='replace')
            f.seek(n,1)
        def value(t,keep):
            fmt={0:'B',1:'b',2:'H',3:'h',4:'I',5:'i',6:'f',7:'?',10:'Q',11:'q',12:'d'}
            if t==8:return string(keep)
            if t==9:
                k,n=struct.unpack('<IQ',f.read(12))
                if n>1_000_000:raise ValueError('Invalid GGUF array')
                for _ in range(n):value(k,False)
                return None
            code='<'+fmt[t];v=struct.unpack(code,f.read(struct.calcsize(code)))[0]
            return v if keep else None
        for _ in range(count):
            key=string();keep=key in ['general.name','general.architecture','general.file_type','general.license'] or key.endswith('.context_length')
            v=value(struct.unpack('<I',f.read(4))[0],keep)
            if keep:wanted[key]=v
    wanted['quantization']={14:'Q4_K_S',15:'Q4_K_M',8:'Q8_0',1:'F16',0:'F32'}.get(wanted.get('general.file_type'),'Other GGUF quantization')
    return wanted

def model_info(config,include_cache=True):
    selected={}
    for name in ['primary','reviewer']:
        c=config[name];path=Path(c.get('path','')).expanduser();exists=path.is_file()
        metadata={}
        if exists:
            try:metadata=gguf_metadata(path)
            except Exception as e:metadata={'error':type(e).__name__}
        selected[name]=dict(runtime='llama.cpp / Metal / network denied subprocess',path=str(path),enabled=c.get('enabled'),runtime_available=bool(shutil.which('llama-completion')),available=exists,context=c.get('context'),metadata=metadata,readiness='Local weights available; inference is validated during audit' if exists else 'missing weights')
    cached=[]
    if not include_cache:return {'selected':selected}
    roots=[Path.home()/'.lmstudio/models',Path.home()/'.cache/huggingface/hub',Path.home()/'.ollama/models/manifests']
    for root in roots:
        if not root.is_dir():continue
        for directory,dirs,files in __import__('os').walk(root,followlinks=False):
            depth=len(Path(directory).relative_to(root).parts)
            if depth>=5:dirs[:]=[]
            for filename in files:
                p=Path(directory)/filename
                if filename.endswith('.gguf') or filename=='config.json' or root.name=='manifests':
                    cached.append(dict(path=str(p),format='GGUF' if filename.endswith('.gguf') else 'Model configuration/manifest',bytes=p.stat().st_size))
    return {'selected':selected,'detected_local_cache_entries':cached}
