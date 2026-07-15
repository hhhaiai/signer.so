import json, os, pathlib, subprocess, sys
root=pathlib.Path.cwd()
fixture=root/'device-reference/references/pixel8-api36'
base=json.loads((fixture/'signer-job.json').read_text())
base.pop('expectedResultFile',None)
base['device']['baseApk']=str(fixture/'adjust-reference.apk')
base['device']['certificateFile']=str(fixture/'reference-certificate.der')
for v in base['device']['filesystem']['files'].values():
    if isinstance(v,dict) and 'file' in v:
        v['file']=str(fixture/pathlib.Path(v['file']).name)
cp='unidbg-adjust-runner/target/classes:'+open('unidbg-adjust-runner/target/runtime-classpath.txt').read().strip()
cases=[
 ('api36_prop36',36,'36'),
 ('api36_missing',36,None),
 ('api36_prop35',36,'35'),
 ('api36_prop036',36,'036'),
 ('api35_prop36',35,'36'),
 ('api35_prop35',35,'35'),
]
rows=[]
for name,api,value in cases:
    j=json.loads(json.dumps(base))
    j['device']['androidApi']=api
    if value is None: j['device']['systemProperties'].pop('ro.build.version.sdk',None)
    else: j['device']['systemProperties']['ro.build.version.sdk']=value
    p=root/'.omx'/f'3c-property-{name}.json'; p.write_text(json.dumps(j))
    env=dict(os.environ); env['ADJUST_NATIVE_CONTEXT_WORD_WATCH_OFFSET']='0x50'
    q=subprocess.run(['java','-XX:TieredStopAtLevel=1','-Dorg.slf4j.simpleLogger.defaultLogLevel=error','-cp',cp,'local.SignerOneClick',str(p),str(root)],text=True,capture_output=True,env=env)
    (root/'.omx'/f'3c-property-{name}.stdout').write_text(q.stdout)
    (root/'.omx'/f'3c-property-{name}.stderr').write_text(q.stderr)
    corrections=[]
    for line in q.stderr.splitlines():
        marker='native-context-correction '
        if marker in line and ' w1=0x' in line:
            corrections.append(line.split(' w1=0x',1)[1].split(' ',1)[0])
    row={'case':name,'api':api,'property':value,'exit':q.returncode,'corrections':corrections,'has3c':'3c' in corrections}
    rows.append(row); print(json.dumps(row),flush=True)
    if q.returncode:
        print(q.stderr[-3000:],file=sys.stderr); sys.exit(q.returncode)
(root/'.omx/3c-sdk-property-matrix.json').write_text(json.dumps(rows,indent=2))
