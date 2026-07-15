import re
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
T = (Path(__file__).resolve().parent / 'disasm-12a30-13000.txt').read_text()
CPP = (ROOT / 'native-reimplementation/recovered_primitives.cpp').read_text()
ins={}
for l in T.splitlines():
 m=re.match(r'\s*([0-9a-f]+):\s+[0-9a-f]+\s+([a-z.]+)\s*(.*?)(?:\s+//.*)?$',l)
 if m: ins[int(m.group(1),16)]=(m.group(2),m.group(3).strip())
MASK=(1<<64)-1

def ops(s):
 out=[]; st=0; d=0
 for i,c in enumerate(s):
  if c=='[':d+=1
  elif c==']':d-=1
  elif c==',' and d==0:out.append(s[st:i].strip());st=i+1
 if s[st:].strip():out.append(s[st:].strip())
 return out
class VM:
 def __init__(self,true_target=None):
  self.r=[0]*31;self.sp=0x800000;self.r[0]=0x100000;self.r[1]=0x200000
  self.mem={};self.pc=0x12a30;self.N=self.Z=self.C=self.V=0;self.calls=[];self.true=true_target;self.steps=0
  self.store(0x200000+0xe0,0,8)
 def reg(self,n):
  if n in ('xzr','wzr'):return 0
  if n=='sp':return self.sp
  m=re.fullmatch(r'([xw])(\d+)',n); assert m,n
  v=self.r[int(m.group(2))];return v if m.group(1)=='x' else v&0xffffffff
 def set(self,n,v):
  if n in ('xzr','wzr'):return
  if n=='sp':self.sp=v&MASK;return
  m=re.fullmatch(r'([xw])(\d+)',n);assert m,n
  self.r[int(m.group(2))]=v&MASK if m.group(1)=='x' else v&0xffffffff
 def val(self,o):return int(o.lstrip('#'),0) if o.startswith('#') else self.reg(o)
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
 def run(self):
  while self.steps<200000:
   self.steps+=1;op,a=ins[self.pc];p=ops(a);nxt=self.pc+4
   if op=='ret':return self.calls,self.load(0x200000+0xe0,8)
   if op=='b':self.pc=int(re.search(r'0x([0-9a-f]+)',a).group(1),16);continue
   if op.startswith('b.'):
    if self.cond(op[2:]):self.pc=int(re.search(r'0x([0-9a-f]+)',a).group(1),16);continue
   elif op=='bl':
    t=int(re.search(r'0x([0-9a-f]+)',a).group(1),16);self.calls.append((self.pc,t,self.reg('x0'),self.reg('x1')))
    self.set('w0',1 if t==self.true else 0)
   elif op=='mov':self.set(p[0],self.val(p[1]))
   elif op=='movk':
    sh=int(p[2].split('#')[1]) if len(p)>2 else 0;mask=0xffff<<sh;self.set(p[0],(self.reg(p[0])&~mask)|(self.val(p[1])<<sh))
   elif op in ('add','sub'):
    self.set(p[0],self.val(p[1])+self.val(p[2]) if op=='add' else self.val(p[1])-self.val(p[2]))
   elif op=='orr':self.set(p[0],self.val(p[1])|self.val(p[2]))
   elif op=='cmp':self.flags_sub(self.val(p[0]),self.val(p[1]),32 if p[0].startswith('w') else 64)
   elif op=='tst':
    r=self.val(p[0])&self.val(p[1]);self.N=bool(r&(1<<(31 if p[0].startswith('w') else 63)));self.Z=r==0;self.C=self.V=0
   elif op=='ccmp':
    if self.cond(p[3]):self.flags_sub(self.val(p[0]),self.val(p[1]),32 if p[0].startswith('w') else 64)
    else:
     z=self.val(p[2]);self.N=(z>>3)&1;self.Z=(z>>2)&1;self.C=(z>>1)&1;self.V=z&1
   elif op=='csel':self.set(p[0],self.val(p[1]) if self.cond(p[3]) else self.val(p[2]))
   elif op in ('str','stur','ldr','ldur'):
    a0,b=self.addr(p[1]);sz=4 if p[0].startswith('w') else 8
    if op in ('str','stur'):self.store(a0,self.reg(p[0]),sz)
    else:self.set(p[0],self.load(a0,sz))
   elif op in ('stp','ldp'):
    a0,b=self.addr(p[2]);sz=4 if p[0].startswith('w') else 8
    for i,n in enumerate(p[:2]):
     if op=='stp':self.store(a0+i*sz,self.reg(n),sz)
     else:self.set(n,self.load(a0+i*sz,sz))
    if len(p)>3:self.set(b,self.reg(b)+self.val(p[3]))
   else:raise Exception(hex(self.pc),op,a)
   self.pc=nxt
  raise Exception('limit')
expected_targets = [
 0x4d9bc, 0x59658, 0x5a8e0, 0x5c6d8, 0x5f900, 0x615d8,
 0x6a4e0, 0x6c590, 0x6dbbc, 0x6f758, 0x76f2c, 0x77f7c,
 0x78f68,
]
vm=VM();calls,flags=vm.run()
assert [target for _,target,_,_ in calls] == expected_targets
assert flags == 0x0000000200000000
assert all(argument0 == 0x100000 for _,_,argument0,_ in calls)
for index, target in enumerate(expected_targets):
 v=VM(target);cs,f=v.run()
 assert [callee for _,callee,_,_ in cs] == (
     expected_targets[:index + 1] + [0x13548c])
 assert cs[-1][3] == 0x21
 assert f == 0x0000000200000001

for needle in (
 'kRecoveredPostDetectorStage12a30Arm64Predicates = {{',
 'recoveredPostDetectorStage12a30DirectOperations()',
 'void runRecoveredPostDetectorStage12a30(',
 'void runRecoveredPostDetectorStage12a30Direct(',
 'applyProtectedCorrectionAndFlagBit0(context, 0x21);',
 'applyProtectedContextBit33(context);',
 'recoveredPostDetectorStage12a30Regression()',
 'recoveredPostDetectorStage12a30DirectRegression()',
):
 assert needle in CPP, needle
source = CPP[
 CPP.index('kRecoveredPostDetectorStage12a30Arm64Predicates = {{'):
 CPP.index('// Complete libsigner.so+0x7ba5c')]
position = -1
for target in expected_targets:
 position = source.index(hex(target), position + 1)

direct_names = [
 'runRecoveredGreatFruitSensorPredicate4d9bc',
 'runRecoveredMicrovirtPairPredicate59658',
 'runRecoveredTiantianSensorPredicate5a8e0',
 'runRecoveredPhysicalSensorPredicate5c6d8',
 'runRecoveredGoldfishTripletPredicate5f900',
 'runRecoveredMpuOrientationPredicate615d8',
 'runRecoveredGoldfishSubsetPredicate6a4e0',
 'runRecoveredGenymotionSensorPredicate6c590',
 'runRecoveredLeapdroidPredicate6dbbc',
 'runRecoveredOpenSourceSensorPredicate6f758',
 'runRecoveredHaimaPredicate76f2c',
 'runRecoveredVmosPredicate77f7c',
 'runRecoveredDeviceBuildPairPredicate78f68',
]
direct_source = CPP[
 CPP.index('recoveredPostDetectorStage12a30DirectOperations()'):
 CPP.index('// Complete orchestration in libsigner.so+0x12a30')]
position = -1
for name in direct_names:
 position = direct_source.index(name, position + 1)

print('arm64 post-detector stage 0x12a30 orchestration/direct evidence: PASS')
