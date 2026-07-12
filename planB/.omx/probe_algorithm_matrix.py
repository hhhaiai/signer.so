import copy, json, os, subprocess, pathlib
root=pathlib.Path.cwd()
base=json.load(open('examples/signer-job.json'))
base['device']['baseApk']=str((root/'adjust-android-signature-3.67.0.aar').resolve())
cp='unidbg-adjust-runner/target/classes:'+open('unidbg-adjust-runner/target/runtime-classpath.txt').read().strip()
cases=[]
def add(name, fn):
    j=copy.deepcopy(base); fn(j); cases.append((name,j))
add('baseline', lambda j: None)
for api in (18,22,23,28,35,36,40): add(f'api{api}', lambda j,a=api: j['device'].__setitem__('androidApi',a))
for env in ('production','sandbox','unknown',''):
    add('environment_'+(env or 'empty'), lambda j,v=env: j['sign']['parameters'].__setitem__('environment',v))
for kind in ('session','event','install','reattribution',''):
    add('activity_'+(kind or 'empty'), lambda j,v=kind: j['sign'].__setitem__('activityKind',v))
for sdk in ('android4.38.5','android5.0.0','ios5.0.0',''):
    add('clientSdk_'+(sdk or 'empty'), lambda j,v=sdk: j['sign'].__setitem__('clientSdk',v))
for ver in ('v4','V4',''):
    add('signVersion_'+(ver or 'empty'), lambda j,v=ver: j['sign'].__setitem__('version',v))
def v5(j):
    j['sign']['version']='v5'
    j['sign']['request']={'activity_kind':'session','client_sdk':'android4.38.5'}
add('signVersion_v5', v5)
add('minimal_params', lambda j: j['sign'].__setitem__('parameters',{'environment':'sandbox'}))
add('many_params', lambda j: j['sign']['parameters'].update({f'x{i}':'y'*64 for i in range(64)}))
jobdir=root/'.omx/algorithm-matrix/jobs'; jobdir.mkdir(parents=True,exist_ok=True)
rows=[]
for name,j in cases:
    p=jobdir/(name+'.json'); p.write_text(json.dumps(j),encoding='utf-8')
    q=subprocess.run(['java','-XX:TieredStopAtLevel=1','-Dorg.slf4j.simpleLogger.defaultLogLevel=error','-cp',cp,'local.SignerOneClick',str(p),str(root)],text=True,capture_output=True)
    result=None
    for line in q.stdout.splitlines():
        if line.startswith('SIGNER_RESULT_JSON='):
            result=json.loads(line.split('=',1)[1])
    if result:
        m=result.get('metadata',{})
        rows.append({'case':name,'status':'ok','algorithm':m.get('algorithm'),'length':len(bytes.fromhex(result['rawSignatureHex'])),'adj_signing_id':m.get('adj_signing_id'),'headers_id':m.get('headers_id'),'native_version':m.get('native_version')})
    else:
        tail=(q.stderr+'\n'+q.stdout).strip().splitlines()[-1:]
        rows.append({'case':name,'status':'error','error':tail[0] if tail else f'exit {q.returncode}'})
out=root/'.omx/algorithm-matrix/results.json'; out.write_text(json.dumps(rows,indent=2),encoding='utf-8')
for x in rows: print(json.dumps(x,ensure_ascii=False))
