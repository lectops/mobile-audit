import hashlib,re
from .discovery import evidence
from .security import redact,redact_source
SEVERITY={'ERROR':'high','WARNING':'medium','INFO':'low','CRITICAL':'critical','HIGH':'high','MEDIUM':'medium','LOW':'low'}
def finding(root, path, line, rule, title, source, severity='medium', cwe=None, end=None, quote=None, **extra):
    snippet=evidence(root,path,int(line),int(end or line),quote)
    cwe=re.search(r'CWE-\d+',str(cwe or ''))
    item=dict(id='MA-'+hashlib.sha256(f'{path}:{line}:{rule}'.encode()).hexdigest()[:14],title=redact(title),severity=SEVERITY.get(severity.upper(),'medium'),cwe=cwe.group() if cwe and cwe.group() in {'CWE-20','CWE-22','CWE-78','CWE-79','CWE-89','CWE-94','CWE-95','CWE-200','CWE-201','CWE-209','CWE-250','CWE-259','CWE-269','CWE-276','CWE-284','CWE-285','CWE-287','CWE-295','CWE-297','CWE-306','CWE-307','CWE-311','CWE-312','CWE-319','CWE-321','CWE-326','CWE-327','CWE-330','CWE-338','CWE-347','CWE-352','CWE-359','CWE-377','CWE-400','CWE-434','CWE-489','CWE-502','CWE-522','CWE-532','CWE-601','CWE-613','CWE-614','CWE-639','CWE-640','CWE-749','CWE-757','CWE-770','CWE-798','CWE-862','CWE-863','CWE-918','CWE-922','CWE-926','CWE-942','CWE-1104','CWE-1321'} else None,file=path,line=int(line),end_line=int(end or line),evidence=redact_source(snippet),rule=rule,detection_source=[source],classification='Scanner-detected' if source!='primary-model' else 'Potential vulnerability requiring manual verification',confidence='medium',validation_status='Code evidence verified; exploitability requires review',explanation=redact(title),attack_prerequisites='Review reachable code paths and attacker control.',impact='Depends on application use and trust boundaries.',remediation='Review the matched implementation; enforce secure platform APIs and explicit trust checks.')
    fixes={'CWE-295':'Use platform certificate and hostname validation; cancel on SSL errors. Do not accept arbitrary certificates.', 'CWE-532':'Remove sensitive logging and redact tokens before diagnostic logging, including release builds.', 'CWE-798':'Remove embedded credentials, rotate exposed values, and obtain short-lived scoped credentials through a trusted backend.', 'CWE-926':'Disable unnecessary exports; validate caller identity and enforce appropriate component permissions.', 'CWE-319':'Require HTTPS with valid certificates and disable broad cleartext/ATS exceptions.', 'CWE-327':'Use maintained platform cryptography with authenticated encryption and secure key management; avoid obsolete primitives and ECB.', 'CWE-922':'Use Android Keystore-backed protection or iOS Keychain with suitable accessibility; avoid plaintext token preferences.', 'CWE-200':'Restrict WebView file access and untrusted content; minimize accessible sensitive data.', 'CWE-489':'Disable debug capabilities for distributed release configurations.'}
    if item['cwe'] in fixes:item['remediation']=fixes[item['cwe']]
    if source=='primary-model':item['classification']='AI-identified with verified code evidence'
    item.update({k:redact(v) for k,v in extra.items() if k in ['explanation','attack_prerequisites','impact','remediation','confidence']})
    return item

def deduplicate(items):
    result={}
    for f in items:
        key=(f['file'],f['line'],f['rule'] if 'osv-scanner' in f['detection_source'] else (f['cwe'] or f['rule']))
        if key in result:
            result[key]['detection_source']=sorted(set(result[key]['detection_source']+f['detection_source']))
            observation={k:f[k] for k in ['id','title','rule','evidence','classification','confidence','detection_source']}
            if observation not in result[key].setdefault('additional_observations',[]):result[key]['additional_observations'].append(observation)
        else: result[key]=f
    return list(result.values())


def revalidate(root,items):
    valid=[];rejected=[]
    for item in items:
        try:
            current=evidence(root,item['file'],item['line'],item['end_line'])
            if item['evidence']!='[REDACTED secret-bearing source lines]' and redact_source(current)!=item['evidence']:
                raise ValueError('Evidence changed')
            valid.append(item)
        except (ValueError,OSError,KeyError,UnicodeError):rejected.append(item.get('id','unknown'))
    return valid,rejected
