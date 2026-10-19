"""Process isolation, redaction, and read-only source access."""
import os, re, subprocess, shutil, signal, sys, math
from collections import Counter
from pathlib import Path

PROFILE = '(version 1)(allow default)(deny network*)(deny file-write* (subpath "{root}"))'

def redact(s):
    def opaque(m):
        token=m.group()
        entropy=-sum((n/len(token))*math.log2(n/len(token)) for n in Counter(token).values())
        return '[REDACTED opaque value]' if entropy>4.0 and not token.startswith(('http','CWE-','GHSA-','CVE-')) else token
    s=re.sub(r'[A-Za-z0-9_+/=-]{28,}',opaque,str(s))
    s = re.sub(r"(?i)((?:password|secret|token|api[_-]?key|credential)\s*[=:]\s*)[\"\']?[^\s;<>]+", r"\1[REDACTED]", str(s))
    s = re.sub(r"(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)", "[REDACTED]", s)
    return s

def safe_path(root, name):
    root = Path(root).resolve()
    p = root / name
    if p.is_symlink() or not p.resolve().is_relative_to(root):
        raise ValueError('Source path escapes repository')
    if any(x.is_symlink() for x in p.parents if x != root and x.is_relative_to(root)):
        raise ValueError('Symlink source forbidden')
    return p

def run(cmd, root, timeout=180, cwd=None):
    if not shutil.which('sandbox-exec'):
        raise RuntimeError('Network isolation unavailable: check skipped closed')
    escaped = str(Path(root).resolve()).replace('\\', '\\\\').replace('"', '\\"')
    env = {k:v for k,v in os.environ.items() if not any(x in k.upper() for x in ['TOKEN','SECRET','PASSWORD','PROXY','SEMGREP_APP'])}
    env['PATH']=str(Path(sys.executable).parent)+os.pathsep+env.get('PATH','/usr/bin:/bin')
    env.update(SEMGREP_SEND_METRICS='off', SEMGREP_ENABLE_VERSION_CHECK='0', HF_HUB_OFFLINE='1', DO_NOT_TRACK='1', OTEL_SDK_DISABLED='true', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_TERMINAL_PROMPT='0')
    process=subprocess.Popen(['sandbox-exec','-p',PROFILE.format(root=escaped),*map(str,cmd)],cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
    try:
        stdout,stderr=process.communicate(timeout=timeout)
    except BaseException:
        try:os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        process.communicate()
        raise
    return subprocess.CompletedProcess(cmd,process.returncode,stdout,stderr)


def redact_source(source):
    # Report evidence preserves code structure while withholding quoted literal values.
    # This is intentionally more conservative than context redaction for local inference.
    pattern = r'("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`)'
    def mask(match):
        value=match.group()
        if value[1:-1] in {'true','false','0','1',''}:return value
        return value[0]+'[REDACTED literal]'+value[-1]
    return re.sub(pattern,mask,redact(source))
