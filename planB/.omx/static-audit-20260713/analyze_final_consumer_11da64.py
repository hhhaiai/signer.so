import re
from pathlib import Path
T=open('.omx/static-audit-20260713/disasm-11da64-11ea78.txt').read();ins={}
for l in T.splitlines():
 m=re.match(r'\s*([0-9a-f]+):\s+[0-9a-f]+\s+([a-z.]+)\s*(.*?)(?:\s+//.*)?$',l)
 if m:ins[int(m.group(1),16)]=(m.group(2),m.group(3).strip())
M=(1<<64)-1
def ops(s):
 out=[];st=d=0
 for i,c in enumerate(s):
  if c=='[':d+=1
  elif c==']':d-=1
  elif c==',' and d==0:out.append(s[st:i].strip());st=i+1
 if s[st:].strip():out.append(s[st:].strip())
 return out
class VM:
 def __init__(self,fail=None):
  self.r=[0]*31;self.sp=0x800000;self.mem={};self.pc=0x11da64;self.N=self.Z=self.C=self.V=0;self.steps=0;self.calls=[];self.count={};self.fail=fail
  for i,v in enumerate([0x1000,0x200000,0x300000,0x400000,0x500000,0x600000]):self.r[i]=v
  self.tpidr=0x900000;self.store(self.tpidr+0x28,0x1122334455667788,8)
  self.store(0x200000,0,4)
  # context observed regions, count/pointer at 118/120 left zero
  for i in range(0x128):self.mem[0x300000+i]=(i*3)&255
  self.store(0x300000+0x118,0,4);self.store(0x300000+0x120,0,8)
  self.nextptr=0xa00000
 def reg(self,n):
  if n in ('xzr','wzr'):return 0
  if n=='sp':return self.sp
  m=re.fullmatch(r'([xw])(\d+)',n);assert m,n
  v=self.r[int(m.group(2))];return v if m.group(1)=='x' else v&0xffffffff
 def set(self,n,v):
  if n in ('xzr','wzr'):return
  if n=='sp':self.sp=v&M;return
  m=re.fullmatch(r'([xw])(\d+)',n);assert m,n
  self.r[int(m.group(2))]=v&M if m.group(1)=='x' else v&0xffffffff
 def val(self,o):
  if o.startswith('#'):return int(o[1:],0)
  if o.startswith('0x'):return int(o.split()[0],0)
  return self.reg(o)
 def addr(self,o):
  m=re.fullmatch(r'\[(.*)\](!)?',o);assert m,o
  p=[x.strip() for x in m.group(1).split(',')];b=p[0];off=0
  if len(p)>1:off=self.val(p[1])
  a=(self.reg(b)+off)&M
  if m.group(2):self.set(b,a)
  return a,b
 def load(self,a,n):return sum(self.mem.get(a+i,0)<<(8*i) for i in range(n))
 def store(self,a,v,n):
  for i in range(n):self.mem[a+i]=(v>>(8*i))&255
 def cmp(self,a,b,bits):
  m=(1<<bits)-1;s=1<<(bits-1);a&=m;b&=m;r=(a-b)&m
  self.N=bool(r&s);self.Z=r==0;self.C=a>=b;self.V=bool(((a^b)&(a^r)&s)!=0)
 def cond(self,c):return {'eq':self.Z,'ne':not self.Z,'lt':self.N!=self.V,'ge':self.N==self.V,'lo':not self.C,'hs':self.C,'hi':self.C and not self.Z,'ls':not self.C or self.Z}[c]
 def alloc(self,n=0x100):
  p=self.nextptr;self.nextptr+=0x1000
  for i in range(n):self.mem[p+i]=0
  return p
 def call(self,t):
  i=self.count.get(t,0);self.count[t]=i+1
  args=tuple(self.reg('x'+str(k)) for k in range(8));self.calls.append((t,i,args))
  fail=self.fail==(t,i)
  if t==0x13a030:self.set('x0',1760000000);return
  if t==0x13a040:return
  if t==0x13917c:
   if fail:self.store(self.reg('x0'),2,4);self.set('x0',0)
   else:
    p=self.alloc(0x20);self.store(p,self.reg('w1'),8);self.store(p+8,self.reg('x2'),8);self.set('x0',p)
   return
  if t==0x1393cc:
   if fail:self.store(self.reg('x0'),2,4);self.set('x0',0)
   else:self.set('x0',self.alloc(0xa0))
   return
  if t==0xf1ec8:
   if fail:self.store(self.reg('x0'),9,4)
   return
  if t==0x11d798:
   if fail:self.store(self.reg('x0'),9,4)
   else:
    p=self.alloc(16);self.store(self.reg('x3'),p,8);self.store(self.reg('x4'),7,8)
   return
  if t==0x139270:self.set('w0',32);return
  if t==0x139e50:
   self.set('x0',0 if fail else self.alloc(max(1,self.reg('x0')*self.reg('x1'))));return
  if t in (0x13927c,0xaf3c,0xa334):
   if fail:self.store(self.reg('x0'),9,4)
   return
  # cleanup calls/free no changes
 def run(self):
  while self.steps<1000000:
   self.steps+=1;op,a=ins[self.pc];p=ops(a);n=self.pc+4
   if op=='ret':return self.reg('w0')&1,self.calls,self.load(0x200000,4)
   if op=='b':self.pc=int(re.search(r'0x([0-9a-f]+)',a).group(1),16);continue
   if op.startswith('b.'):
    if self.cond(op[2:]):self.pc=int(re.search(r'0x([0-9a-f]+)',a).group(1),16);continue
   elif op=='bl':
    t=int(re.search(r'0x([0-9a-f]+)',a).group(1),16)
    if t==0x139df0:raise Exception('stackfail')
    self.call(t)
   elif op=='mrs':self.set(p[0],self.tpidr)
   elif op=='mov':self.set(p[0],self.val(p[1]))
   elif op=='movk':
    sh=int(p[2].split('#')[1]) if len(p)>2 else 0;mask=0xffff<<sh;self.set(p[0],(self.reg(p[0])&~mask)|(self.val(p[1])<<sh))
   elif op in ('add','sub'):self.set(p[0],self.val(p[1])+self.val(p[2]) if op=='add' else self.val(p[1])-self.val(p[2]))
   elif op=='cmp':self.cmp(self.val(p[0]),self.val(p[1]),32 if p[0].startswith('w') else 64)
   elif op=='csel':self.set(p[0],self.val(p[1]) if self.cond(p[3]) else self.val(p[2]))
   elif op=='cset':self.set(p[0],int(self.cond(p[1])))
   elif op=='rev':
    v=self.reg(p[1])&0xffffffff;self.set(p[0],int.from_bytes(v.to_bytes(4,'little'),'big'))
   elif op in ('str','stur','ldr','ldur'):
    a0,b=self.addr(p[1]);sz=4 if p[0].startswith('w') else 8
    if op in ('str','stur'):self.store(a0,self.reg(p[0]),sz)
    else:self.set(p[0],self.load(a0,sz))
    if len(p)>2:self.set(b,self.reg(b)+self.val(p[2]))
   elif op in ('stp','ldp'):
    a0,b=self.addr(p[2]);sz=4 if p[0].startswith('w') else 8
    for j,nm in enumerate(p[:2]):
     if op=='stp':self.store(a0+j*sz,self.reg(nm),sz)
     else:self.set(nm,self.load(a0+j*sz,sz))
    if len(p)>3:self.set(b,self.reg(b)+self.val(p[3]))
   else:raise Exception(hex(self.pc),op,a)
   self.pc=n
  raise Exception('limit')


ROOT=Path(__file__).resolve().parents[2]
CPP=(ROOT/'native-reimplementation/recovered_primitives.cpp').read_text()

def summary(failure=None):
 result,calls,status=VM(failure).run()
 targets=[target for target,_,_ in calls]
 return result,status,targets,calls

result,status,targets,calls=summary()
expected_targets=[
 0x13a030,0x13a040,
 0x13917c,0x13917c,0x11d798,
 0x13917c,0x13917c,0x13917c,0x13917c,0x13917c,0x13917c,0x13917c,
 0x1393cc,0xf1ec8,0x139270,0x139e50,0x13927c,0xaf3c,
 0x1392c4,
 0x13926c,0x13926c,0x13926c,0x13926c,0x13926c,
 0x13926c,0x13926c,0x13926c,0x13926c,
 0x139de0,0x139de0,
]
assert (result,status,targets)==(1,0,expected_targets)
descriptor_calls=[args for target,_,args in calls if target==0x13917c]
assert [args[1] for args in descriptor_calls] == [128,20,16,32,4,4,7,4,0]
assert [args[2] for args in descriptor_calls[:5]] == [
 0x300050,0x3000f0,0x3000e0,0x300030,0x300020]

failure_expectations=[]
for index in range(9): failure_expectations.append(((0x13917c,index),4))
failure_expectations += [
 ((0x11d798,0),9),((0x1393cc,0),4),((0xf1ec8,0),4),
 ((0x139e50,0),2),((0x13927c,0),4),((0xaf3c,0),9),
]
for failure,expected_status in failure_expectations:
 result,status,targets,_=summary(failure)
 assert result==0 and status==expected_status, (failure,result,status)
 assert 0xa334 in targets
 assert targets.count(0x1392c4)==1
 assert targets.count(0x13926c)==9
 assert targets.count(0x139de0)==2

for needle in (
 'struct RecoveredFinalConsumer11da64Operations',
 'bool runRecoveredFinalConsumer11da64(',
 'std::array<std::uint64_t, 9> descriptors{};',
 'kDescriptorCleanupOrder = {\n        2, 1, 6, 5, 0, 3, 4, 8, 7',
 'operations.cleanupMetadata(',
 'return *status == 0;',
 'recoveredFinalConsumer11da64Regression()',
):
 assert needle in CPP, needle

print('arm64 final consumer 0x11da64 evidence: PASS')
