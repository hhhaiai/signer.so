import re
import struct
from pathlib import Path
T=open('.omx/static-audit-20260713/disasm-143e8-14e10.txt').read();ins={}
for l in T.splitlines():
 m=re.match(r'\s*([0-9a-f]+):\s+[0-9a-f]+\s+([a-z.]+)\s*(.*?)(?:\s+//.*)?$',l)
 if m:ins[int(m.group(1),16)]=(m.group(2),m.group(3).strip())
MASK=(1<<64)-1

def ops(s):
 out=[];st=0;d=0
 for i,c in enumerate(s):
  if c=='[':d+=1
  elif c==']':d-=1
  elif c==',' and d==0:out.append(s[st:i].strip());st=i+1
 if s[st:].strip():out.append(s[st:].strip())
 return out
class VM:
 def __init__(self,res=None,status=None):
  self.r=[0]*31;self.vr={};self.sp=0x800000;self.r[0]=0x100000;self.mem={};self.pc=0x143e8;self.N=self.Z=self.C=self.V=0;self.steps=0;self.calls=[];self.corrections=[];self.res=res or {};self.status=status or {}
  self.tpidr=0x900000;self.store(self.tpidr+0x28,0x1122334455667788,8)
  self.store(0x100000+0xe0,0,8)
  # one-time decoded flags
  self.store(0x14619a,1,1);self.store(0x14619b,1,1)
 def reg(self,n):
  if n in ('xzr','wzr'):return 0
  if n=='sp':return self.sp
  if re.fullmatch(r'[dq]\d+',n):return self.vr.get(n,0)
  m=re.fullmatch(r'([xw])(\d+)',n);assert m,n
  v=self.r[int(m.group(2))];return v if m.group(1)=='x' else v&0xffffffff
 def set(self,n,v):
  if n in ('xzr','wzr'):return
  if n=='sp':self.sp=v&MASK;return
  if re.fullmatch(r'[dq]\d+',n):self.vr[n]=v&((1<<(128 if n[0]=='q' else 64))-1);return
  m=re.fullmatch(r'([xw])(\d+)',n);assert m,n
  self.r[int(m.group(2))]=v&MASK if m.group(1)=='x' else v&0xffffffff
 def val(self,o):
  if o.startswith('#'):return int(o[1:],0)
  if o.startswith('0x'):return int(o.split()[0],0)
  return self.reg(o)
 def addr(self,o):
  m=re.fullmatch(r'\[(.*)\](!)?',o);assert m,o
  p=[x.strip() for x in m.group(1).split(',')];b=p[0];off=0
  if len(p)>1:
   off=self.val(p[1]);
   if len(p)>2 and p[2].startswith('lsl '):off<<=int(p[2].split('#')[1],0)
  a=(self.reg(b)+off)&MASK
  if m.group(2):self.set(b,a)
  return a,b
 def load(self,a,n):return sum(self.mem.get(a+i,0)<<(8*i) for i in range(n))
 def store(self,a,v,n):
  for i in range(n):self.mem[a+i]=(v>>(8*i))&255
 def flags_sub(self,a,b,bits):
  m=(1<<bits)-1;s=1<<(bits-1);a&=m;b&=m;r=(a-b)&m
  self.N=bool(r&s);self.Z=r==0;self.C=a>=b;self.V=bool(((a^b)&(a^r)&s)!=0)
 def cond(self,c):return {'eq':self.Z,'ne':not self.Z,'lt':self.N!=self.V,'ge':self.N==self.V,'lo':not self.C,'hs':self.C,'hi':self.C and not self.Z,'ls':not self.C or self.Z}[c]
 def call(self,t):
  self.calls.append((t,self.reg('x0'),self.reg('x1')))
  if t==0x139800:self.set('w0',0);return
  if t==0x13548c:self.corrections.append(self.reg('w1'));return
  fixed={0x14e10:0x35,0x14e44:0x36,0x14e78:0x3a,0x14eac:0x3a}
  if t in fixed:
   self.corrections.append(fixed[t]);self.store(0x100000+0xe0,self.load(0x100000+0xe0,8)|1,8);return
  if t in (0x1309cc,0x1311f0,0xdb410,0xd78b8):
   self.store(self.reg('x0'),self.status.get(t,0),4)
  self.set('w0',self.res.get(t,0))
 def run(self):
  while self.steps<500000:
   self.steps+=1;op,a=ins[self.pc];p=ops(a);nxt=self.pc+4
   if op=='ret':return self.calls,self.corrections,self.load(0x100000+0xe0,8)
   if op=='b':self.pc=int(re.search(r'0x([0-9a-f]+)',a).group(1),16);continue
   if op.startswith('b.'):
    if self.cond(op[2:]):self.pc=int(re.search(r'0x([0-9a-f]+)',a).group(1),16);continue
   elif op=='bl':
    t=int(re.search(r'0x([0-9a-f]+)',a).group(1),16)
    if t==0x139df0:raise Exception('stackfail')
    self.call(t)
   elif op=='mrs':self.set(p[0],self.tpidr)
   elif op in ('adrp','adr'):self.set(p[0],self.val(p[1]))
   elif op=='mov':self.set(p[0],self.val(p[1]))
   elif op=='movk':
    sh=int(p[2].split('#')[1]) if len(p)>2 else 0;mask=0xffff<<sh;self.set(p[0],(self.reg(p[0])&~mask)|(self.val(p[1])<<sh))
   elif op in ('add','sub'):
    rv=self.val(p[2]);
    if len(p)>3 and p[3].startswith('lsl '):rv<<=int(p[3].split('#')[1],0)
    self.set(p[0],self.val(p[1])+rv if op=='add' else self.val(p[1])-rv)
   elif op=='orr':self.set(p[0],self.val(p[1])|self.val(p[2]))
   elif op=='cmp':self.flags_sub(self.val(p[0]),self.val(p[1]),32 if p[0].startswith('w') else 64)
   elif op=='tst':
    v=self.val(p[0])&self.val(p[1]);self.N=bool(v&(1<<(31 if p[0].startswith('w') else 63)));self.Z=v==0;self.C=self.V=0
   elif op=='ccmp':
    if self.cond(p[3]):self.flags_sub(self.val(p[0]),self.val(p[1]),32 if p[0].startswith('w') else 64)
    else:
     z=self.val(p[2]);self.N=(z>>3)&1;self.Z=(z>>2)&1;self.C=(z>>1)&1;self.V=z&1
   elif op=='csel':self.set(p[0],self.val(p[1]) if self.cond(p[3]) else self.val(p[2]))
   elif op=='movi':self.set(('q' if '.16b' in p[0] else 'd')+re.search(r'\d+',p[0]).group(),0)
   elif op=='eor':
    # skipped in initialized paths
    if p[0].startswith('v'):raise Exception('unexpected vector eor')
    self.set(p[0],self.val(p[1])^self.val(p[2]))
   elif op in ('str','stur','ldr','ldur'):
    a0,b=self.addr(p[1]);rn=p[0];sz=4 if rn.startswith('w') else 16 if rn.startswith('q') else 8
    if op in ('str','stur'):self.store(a0,self.reg(rn),sz)
    else:self.set(rn,self.load(a0,sz))
    if len(p)>2:self.set(b,self.reg(b)+self.val(p[2]))
   elif op in ('strb','stlrb','ldrb'):
    a0,b=self.addr(p[1])
    if op in ('strb','stlrb'):self.store(a0,self.reg(p[0]),1)
    else:self.set(p[0],self.load(a0,1))
    if len(p)>2:self.set(b,self.reg(b)+self.val(p[2]))
   elif op in ('stp','ldp'):
    a0,b=self.addr(p[2]);sz=4 if p[0].startswith('w') else 8
    for i,n in enumerate(p[:2]):
     if op=='stp':self.store(a0+i*sz,self.reg(n),sz)
     else:self.set(n,self.load(a0+i*sz,sz))
    if len(p)>3:self.set(b,self.reg(b)+self.val(p[3]))
   else:raise Exception(hex(self.pc),op,a)
   self.pc=nxt
  raise Exception('limit')


ROOT = Path(__file__).resolve().parents[2]
SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text()

def virtual_bytes(address, size):
 data=SO.read_bytes(); shoff=struct.unpack_from('<Q',data,0x28)[0]
 entsize=struct.unpack_from('<H',data,0x3a)[0]; count=struct.unpack_from('<H',data,0x3c)[0]
 for index in range(count):
  section=struct.unpack_from('<IIQQQQIIQQ',data,shoff+index*entsize)
  base,offset,length=section[3:6]
  if base<=address<base+length:
   start=offset+address-base
   return data[start:start+size]
 raise AssertionError(hex(address))

assert bytes(value ^ 0x44 for value in virtual_bytes(0x143050,16)) == b'/proc/self/maps\0'
assert bytes(value ^ 0x28 for value in virtual_bytes(0x143060,14)) == b'/proc/self/fd\0'

targets=[0xd78b8,0xdb410,0x13063c,0x1309cc,0x1311f0]
def run_case(results=None,statuses=None):
 calls,corrections,flags=VM(results or {},statuses or {}).run()
 call_order=[target for target,_,_ in calls if target in targets]
 return call_order,corrections,flags

mask=0x0460603c00000000
assert run_case() == (targets,[],mask)
matrices = [
 (0xd78b8,0x22,0x35),
 (0xdb410,0x23,0x36),
 (0x13063c,0x25,None),
 (0x1309cc,0x2d,0x3a),
 (0x1311f0,0x2e,0x3a),
]
for target,result_code,status_code in matrices:
 assert run_case({target:1}) == (targets,[result_code],mask|1)
 if status_code is not None:
  assert run_case({}, {target:9}) == (targets,[status_code],mask|1)
  assert run_case({target:1},{target:9}) == (
      targets,[result_code,status_code],mask|1)
assert run_case(
 {target:1 for target in targets},
 {0xd78b8:7,0xdb410:8,0x1309cc:9,0x1311f0:10},
) == (targets,[0x22,0x35,0x23,0x36,0x25,0x2d,0x3a,0x2e],mask|1)

for needle in (
 'struct RecoveredEnvironmentDispatcher143e8Operations',
 'void runRecoveredEnvironmentDispatcher143e8(',
 'operations.stageD78b8(&status, "/proc/self/maps")',
 'operations.stageDb410(&status, "/proc/self/fd")',
 'operations.stage13063c()',
 'operations.stage1309cc(&status)',
 'operations.stage1311f0(&status)',
 'if (fridaServerStatus == 0 && status != 0)',
 'applyProtectedContextMask0460603c00000000(context);',
 'recoveredEnvironmentDispatcher143e8Regression()',
):
 assert needle in CPP, needle

print('arm64 environment dispatcher 0x143e8 evidence: PASS')
