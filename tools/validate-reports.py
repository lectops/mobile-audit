"""Validate saved audit artifacts without network access or inference."""
import json,sys,hashlib
from pathlib import Path
import jsonschema
from mobile_audit.discovery import evidence
from mobile_audit.security import redact
out=Path(sys.argv[1]);source=Path(sys.argv[2])
findings=json.loads((out/'findings.json').read_text())
coverage=json.loads((out/'coverage.json').read_text())
jsonschema.validate(json.loads((out/'findings.sarif').read_text()),json.loads(Path(__file__).resolve().parents[1].joinpath('tests/sarif-schema.json').read_text()))
for finding in findings:
    evidence(source,finding['file'],finding['line'],finding['end_line'])
assert coverage['source_unchanged']
assert (out/'report.html').stat().st_size>1000
assert out.stat().st_mode&0o077==0
# Never print the fake token; ensure it is absent from every report artifact.
for line in (source/'client.ts').read_text().splitlines():
    if 'github_token' in line:
        token=line.split('"')[1]
        for artifact in out.iterdir():
            if artifact.is_file():assert token not in artifact.read_text(errors='replace'),artifact.name
print(json.dumps({'report':str(out),'findings':len(findings),'sarif_schema':'valid','all_locations':'valid','source_unchanged':True,'private_permissions':True,'fake_secret_absent':True,'checks':[{k:c[k] for k in ['name','status']} for c in coverage['checks']]},indent=2))
