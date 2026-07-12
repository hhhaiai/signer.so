import json, os, pathlib, re, subprocess
root=pathlib.Path.cwd()
fixture=root/'device-reference/references/pixel8-api36'
base=json.load(open(fixture/'signer-job.json'))
base.pop('expectedResultFile',None)
base['device']['baseApk']=str(fixture/'adjust-reference.apk')
base['device']['certificateFile']=str(fixture/'reference-certificate.der')
for v in base['device']['filesystem']['files'].values():
    if isinstance(v,dict) and 'file' in v: v['file']=str(fixture/pathlib.Path(v['file']).name)
full=dict(base['device']['systemProperties'])
sparse=dict(json.load(open(root/'examples/signer-job.json'))['device']['systemProperties'])
cp='unidbg-adjust-runner/target/classes:'+open('unidbg-adjust-runner/target/runtime-classpath.txt').read().strip()
cache={}
counter=0

def has3c(keys):
    global counter
    key=tuple(sorted(keys))
    if key in cache: return cache[key]
    counter+=1
    j=json.loads(json.dumps(base)); props=dict(sparse)
    props.update({k:full[k] for k in keys})
    j['device']['systemProperties']=props
    p=root/'.omx'/f'3c-min-{counter:02d}.json'; p.write_text(json.dumps(j))
    env=dict(os.environ); env['ADJUST_NATIVE_CONTEXT_WORD_WATCH_OFFSET']='0x50'
    q=subprocess.run(['java','-XX:TieredStopAtLevel=1','-Dorg.slf4j.simpleLogger.defaultLogLevel=error','-cp',cp,'local.SignerOneClick',str(p),str(root)],text=True,capture_output=True,env=env)
    if q.returncode: raise SystemExit(q.stderr[-2000:])
    value='w1=0x3c ' in q.stderr
    cache[key]=value
    print(f'test={counter} keys={len(keys)} has3c={value}',flush=True)
    return value

current=[k for k in full if k not in sparse or sparse.get(k)!=full[k]]
assert not has3c(current)
assert has3c([])
# Greedy chunk removal: retain only properties necessary for no-0x3c.
granularity=2
while len(current)>1:
    chunk=max(1,(len(current)+granularity-1)//granularity)
    removed=False
    for start in range(0,len(current),chunk):
        trial=current[:start]+current[start+chunk:]
        if not has3c(trial):
            current=trial; granularity=max(2,granularity-1); removed=True; break
    if not removed:
        if granularity>=len(current): break
        granularity=min(len(current),granularity*2)
print('MINIMAL_COUNT',len(current))
for k in current: print(json.dumps({'key':k,'value':full[k]},ensure_ascii=False))
(root/'.omx/3c-minimal-properties.json').write_text(json.dumps({k:full[k] for k in current},indent=2,ensure_ascii=False))
