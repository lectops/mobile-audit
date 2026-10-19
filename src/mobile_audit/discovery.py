import os, re, hashlib
from pathlib import Path
from .security import safe_path
EXCLUDE = {'.git','node_modules','Pods','build','dist','.dart_tool','.gradle','.venv','vendor','DerivedData','.idea','coverage','__pycache__'}
LANG = {'.kt':'Kotlin','.java':'Java','.swift':'Swift','.m':'Objective-C','.h':'Objective-C','.dart':'Dart','.js':'JavaScript','.jsx':'JavaScript','.ts':'TypeScript','.tsx':'TypeScript','.py':'Python','.xml':'XML','.plist':'Plist','.json':'JSON','.yaml':'YAML','.yml':'YAML','.gradle':'Gradle','.properties':'Properties','.lock':'Lockfile','.toml':'TOML'}
SUBSYSTEMS={'authentication':r'auth|login|session|password','authorization':r'permission|role|authorize|access.?control','networking':r'http|api|request|certificate|tls|ssl','cryptography':r'crypto|cipher|encrypt|decrypt|keychain','storage':r'storage|preferences|userdefaults|keychain|sqlite','webview':r'webview|javascriptinterface','deep_links':r'deeplink|deep.link|urlscheme|intent|openurl','platform_config':r'AndroidManifest|Info.plist|entitlements|network_security_config','dependencies':r'package-lock|yarn.lock|pubspec|Podfile|gradle|Package.resolved|requirements|poetry.lock'}
SENSITIVE = re.compile(r'auth|session|token|password|crypto|keychain|storage|webview|network|http|intent|deeplink|permission|exported|certificate|login|api',re.I)
def discover(root):
    files, excluded, errors = [], [], []
    for directory, dirs, names in os.walk(root, followlinks=False,onerror=lambda e:errors.append({'type':type(e).__name__,'path':str(e.filename)})):
        for d in list(dirs):
            p=Path(directory)/d
            if d in EXCLUDE or p.is_symlink(): dirs.remove(d); excluded.append(str(p.relative_to(root))+'/')
        for name in sorted(names):
            p=Path(directory)/name; rel=str(p.relative_to(root))
            if p.is_symlink() or p.stat().st_size>1_000_000:
                excluded.append(rel); continue
            try: text=safe_path(root,rel).read_text()
            except (UnicodeError,OSError,ValueError): excluded.append(rel); continue
            files.append(dict(path=rel,language=LANG.get(p.suffix,'Text'),sha256=hashlib.sha256(text.encode()).hexdigest(),lines=len(text.splitlines()),sensitive=bool(SENSITIVE.search(rel+' '+text)),subsystems=[name for name,pattern in SUBSYSTEMS.items() if re.search(pattern,rel+' '+text,re.I)],manifest=bool(re.search(SUBSYSTEMS['dependencies'],rel)),entrypoint=bool(re.search(r'MainActivity|AppDelegate|SceneDelegate|main\.dart|index\.[jt]sx?|App\.[jt]sx?',rel)),symbols=[dict(name=m.group(1),line=text[:m.start()].count('\n')+1) for m in re.finditer(r'(?:class|func|fun|function|def)\s+(\w+)',text)],imports=re.findall(r'(?:import|require)\s*[(]?[^\n;]+',text)[:80]))
    frameworks=[]
    paths=' '.join(f['path'] for f in files)
    for framework,pattern in {'Android':r'AndroidManifest|build.gradle','iOS':r'Info.plist|AppDelegate|\.xcodeproj','Flutter':r'pubspec|\.dart','React Native':r'App\.[jt]sx?|metro.config|react-native'}.items():
        if re.search(pattern,paths):frameworks.append(framework)
    return dict(files=files,excluded=excluded,errors=errors,frameworks=frameworks,subsystems={s:[f['path'] for f in files if s in f['subsystems']] for s in SUBSYSTEMS},languages=sorted({f['language'] for f in files}),limitations=['Symbol/import index is heuristic; no compiler-resolved call graph.','Generated/vendor directories excluded, including manifests within them.'])
def evidence(root, path, start, end=None, quote=None):
    p=safe_path(root,path); lines=p.read_text().splitlines(); end=end or start
    if not 1<=start<=end<=len(lines) or end-start>100: raise ValueError('Invalid evidence lines')
    snippet='\n'.join(lines[start-1:end])
    if quote is not None and quote.strip() not in snippet: raise ValueError('Quoted evidence does not match source')
    return snippet
