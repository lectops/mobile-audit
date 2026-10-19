"""Local conversion after approved official model download; no network access."""
from pathlib import Path
import os,subprocess,time,json,hashlib
root=Path(__file__).resolve().parent.parent
source=root/'models/foundation-official'
expected=json.loads((source/'model.safetensors.index.json').read_text())['weight_map']
files=set(expected.values())
while not all((source/name).is_file() for name in files):
    time.sleep(15)
env=dict(os.environ,HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1',DO_NOT_TRACK='1')
f16=root/'models/foundation-sec-f16.gguf';quant=root/'models/foundation-sec-q4_k_m.gguf'
with (root/'models/conversion.log').open('w') as log:
    if not f16.is_file():subprocess.run([str(root/'.conversion-venv/bin/python'),str(root/'tools/llama.cpp/convert_hf_to_gguf.py'),str(source),'--outfile',str(f16),'--outtype','f16','--model-name','Cisco Foundation-Sec-8B-Reasoning'],check=True,env=env,stdout=log,stderr=log)
    subprocess.run(['llama-quantize',str(f16),str(quant),'Q4_K_M'],check=True,env=env,stdout=log,stderr=log)
provenance={'repository':'https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning','revision':'63c930c82d7646226d33502bec5870019738400e','quantization':'Q4_K_M','format':'GGUF','converter_revision':subprocess.check_output(['git','-C',str(root/'tools/llama.cpp'),'rev-parse','HEAD'],text=True).strip(),'weights':{}}
for p in [*(source/name for name in sorted(files)),quant]:
    digest=hashlib.sha256()
    with p.open('rb') as f:
        for chunk in iter(lambda:f.read(16*1024*1024),b''):digest.update(chunk)
    provenance['weights'][p.name]={'bytes':p.stat().st_size,'sha256':digest.hexdigest()}
expected_hashes=json.loads((root/'models/official-sha256.json').read_text())
for name,details in expected_hashes.items():
    if provenance['weights'][name]['sha256']!=details['sha256']:raise RuntimeError('Official weight SHA256 mismatch: '+name)
provenance['official_hashes_verified']=True
(root/'models/provenance.json').write_text(json.dumps(provenance,indent=2))
print('Foundation-Sec converted and hashed:',quant,flush=True)
