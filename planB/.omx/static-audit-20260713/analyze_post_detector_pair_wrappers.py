import re,struct
from pathlib import Path
ROOT=Path('/Users/sanbo/Desktop/api/qbdi');AUDIT=ROOT/'.omx/static-audit-20260713';SO=ROOT/'adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so';IMG=SO.read_bytes();MASK=(1<<64)-1
ph=struct.unpack_from('<Q',IMG,32)[0];es=struct.unpack_from('<H',IMG,54)[0];n=struct.unpack_from('<H',IMG,56)[0];segs=[]
for i in range(n):
 f=struct.unpack_from('<IIQQQQQQ',IMG,ph+i*es)
 if f[0]==1:segs.append((f[2],f[3],f[5]))
def load_image():
 m={}
 for o,v,s in segs:
  for i,b in enumerate(IMG[o:o+s]):m[v+i]=b
 return m
def raw(a,n=64):
 for o,v,s in segs:
  if v<=a and a+n<=v+s:return IMG[o+a-v:o+a-v+n]
 return b''
def decode(a):
 out=[]
 for key in range(1,256):
  x=[]
  for z in raw(a):
   c=z^key
   if c==0:
    if 1<=len(x)<=60 and all(32<=q<127 for q in x):out.append((key,bytes(x).decode()))
    break
   if not 32<=c<127:break
   x.append(c)
 # sort plausible exact candidates: alpha-heavy, fewer repeated prefix chars, longer
 return sorted(out,key=lambda q:(sum(c.isalpha() or c in ' ._-' for c in q[1])/max(1,len(q[1])),sum(c.isalpha() for c in q[1]),-len(q[1])),reverse=True)
def parse(path):
 ins={}
 for l in path.read_text().splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+[0-9a-f]+\s+([a-z.]+)\s*(.*?)(?:\s+//.*)?$',l)
  if m:ins[int(m.group(1),16)]=(m.group(2),m.group(3).strip())
 return ins
def ops(s):
 out=[];st=0;d=0
 for i,c in enumerate(s):
  if c=='[':d+=1
  elif c==']':d-=1
  elif c==',' and d==0:out.append(s[st:i].strip());st=i+1
 if s[st:].strip():out.append(s[st:].strip())
 return out
class VM:
 def __init__(self,path,start,helper_result):
  self.ins=parse(path);self.r=[0]*31;self.sp=0x800000;self.mem=load_image();self.N=self.Z=self.C=self.V=0;self.pc=start;self.steps=0
  self.scratch=0x1000000;self.r[0]=self.scratch;self.helper_result=helper_result;self.record=None
  # All one-time decoder state bytes are published. Keep raw marker storage;
  # it is not consumed before the helper call and is decoded from ELF later.
  for a in range(0x146000,0x147000):self.mem[a]=1
  self.thread=0x900000;self.store(self.thread+0x28,0x1122334455667788,8)
  self.store(self.scratch+0x870,0,8)
 def reg(self,n):
  if n in ('xzr','wzr'):return 0
  if n=='sp':return self.sp
  m=re.fullmatch(r'([xw])(\d+)',n);assert m,n
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
   off=self.val(p[1])
   if len(p)>2 and p[2].startswith('lsl '):off<<=int(p[2].split('#')[1],0)
  a=(self.reg(b)+off)&MASK
  if m.group(2):self.set(b,a)
  return a,b
 def load(self,a,n):return sum(self.mem.get(a+i,0)<<(8*i) for i in range(n))
 def store(self,a,v,n):
  for i in range(n):self.mem[a+i]=(v>>(8*i))&255
 def subflags(self,a,b,bits):
  m=(1<<bits)-1;s=1<<(bits-1);a&=m;b&=m;r=(a-b)&m
  self.N=bool(r&s);self.Z=r==0;self.C=a>=b;self.V=bool(((a^b)&(a^r)&s)!=0)
 def addflags(self,a,b,bits):
  m=(1<<bits)-1;s=1<<(bits-1);a&=m;b&=m;full=a+b;r=full&m
  self.N=bool(r&s);self.Z=r==0;self.C=full>m;self.V=bool((~(a^b)&(a^r)&s)!=0)
 def cond(self,c):return {'eq':self.Z,'ne':not self.Z,'lt':self.N!=self.V,'ge':self.N==self.V,'lo':not self.C,'hs':self.C,'hi':self.C and not self.Z,'ls':not self.C or self.Z,'le':self.Z or self.N!=self.V,'gt':not self.Z and self.N==self.V}[c]
 def run(self):
  while self.steps<10000000:
   self.steps+=1;op,a=self.ins[self.pc];p=ops(a);nxt=self.pc+4
   if op=='ret':return (self.reg('w0')&1,self.record,self.steps)
   if op=='b':self.pc=int(re.search(r'0x([0-9a-f]+)',a).group(1),16);continue
   if op.startswith('b.'):
    if self.cond(op[2:]):self.pc=int(re.search(r'0x([0-9a-f]+)',a).group(1),16);continue
   elif op=='bl':
    t=int(re.search(r'0x([0-9a-f]+)',a).group(1),16)
    if t==0x58498:
     count=self.reg('x2');table=self.reg('x1');ptrs=[self.load(table+i*8,8) for i in range(count*2)]
     self.record=(hex(self.pc),hex(self.reg('x0')),count,[(hex(q),decode(q)[:4]) for q in ptrs]);self.set('w0',self.helper_result);self.pc=nxt;continue
    if t==0x139df0:raise Exception('stack chk fail',hex(self.pc))
    assert t==0x139800,(hex(self.pc),hex(t));self.set('w0',0)
   elif op in ('nop','movi'):pass
   elif op=='mrs':self.set(p[0],self.thread)
   elif op=='mov':self.set(p[0],self.val(p[1]))
   elif op=='movk':
    sh=int(p[2].split('#')[1]) if len(p)>2 else 0;m=0xffff<<sh;self.set(p[0],(self.reg(p[0])&~m)|(self.val(p[1])<<sh))
   elif op in ('add','sub'):self.set(p[0],self.val(p[1])+self.val(p[2]) if op=='add' else self.val(p[1])-self.val(p[2]))
   elif op in ('orr','eor','and'):
    if p[0].startswith(('v','d','s','q')):pass
    else:self.set(p[0],{'orr':self.val(p[1])|self.val(p[2]),'eor':self.val(p[1])^self.val(p[2]),'and':self.val(p[1])&self.val(p[2])}[op])
   elif op=='cmp':self.subflags(self.val(p[0]),self.val(p[1]),32 if p[0].startswith('w') else 64)
   elif op=='cmn':self.addflags(self.val(p[0]),self.val(p[1]),32 if p[0].startswith('w') else 64)
   elif op=='tst':
    v=self.val(p[0])&self.val(p[1]);bits=32 if p[0].startswith('w') else 64;self.N=bool(v&(1<<(bits-1)));self.Z=v==0;self.C=self.V=0
   elif op=='ccmp':
    if self.cond(p[3]):self.subflags(self.val(p[0]),self.val(p[1]),32 if p[0].startswith('w') else 64)
    else:
     z=self.val(p[2]);self.N=(z>>3)&1;self.Z=(z>>2)&1;self.C=(z>>1)&1;self.V=z&1
   elif op=='csel':self.set(p[0],self.val(p[1]) if self.cond(p[3]) else self.val(p[2]))
   elif op=='cset':self.set(p[0],1 if self.cond(p[1]) else 0)
   elif op in ('adr','adrp'):self.set(p[0],int(re.search(r'0x([0-9a-f]+)',p[1]).group(1),16))
   elif op in ('str','stur','strb','stlrb','ldr','ldur','ldrb'):
    a0,b=self.addr(p[1]);fp=p[0].startswith(('d','s','v','q'));sz=1 if op in ('strb','stlrb','ldrb') else (16 if p[0].startswith('q') else 4 if p[0].startswith(('w','s')) else 8)
    if op in ('str','stur','strb','stlrb'):self.store(a0,0 if fp else self.reg(p[0]),sz)
    elif not fp:self.set(p[0],self.load(a0,sz))
    if len(p)>2:self.set(b,self.reg(b)+self.val(p[2]))
   elif op in ('stp','ldp'):
    a0,b=self.addr(p[2]);fp=p[0].startswith(('d','s','v','q'));sz=16 if p[0].startswith('q') else 4 if p[0].startswith(('w','s')) else 8
    for i,n in enumerate(p[:2]):
     if op=='stp':self.store(a0+i*sz,0 if fp else self.reg(n),sz)
     elif not fp:self.set(n,self.load(a0+i*sz,sz))
    if len(p)>3:self.set(b,self.reg(b)+self.val(p[3]))
   else:raise Exception(hex(self.pc),op,a)
   self.pc=nxt
  raise Exception('limit')


SPECS = {
    0x4D9BC: (0x58498, 8, [
        0x144400, 0x144418, 0x144428, 0x144418,
        0x144438, 0x144418, 0x144440, 0x144458,
        0x144468, 0x144458, 0x144480, 0x144458,
        0x1444A0, 0x144458, 0x1444C0, 0x144458]),
    0x5A8E0: (0x5C6D8, 1, [0x144500, 0x144520]),
    0x5C6D8: (0x5F900, 7, [
        0x144540, 0x144560, 0x1444A0, 0x144014,
        0x144428, 0x144570, 0x144590, 0x1445A4,
        0x144468, 0x1445A8, 0x144440, 0x144014,
        0x144480, 0x144014]),
    0x5F900: (0x615D8, 3, [
        0x1445C0, 0x1445E0, 0x144600, 0x1445E0,
        0x144620, 0x1445E0]),
    0x615D8: (0x6A4E0, 2, [
        0x144660, 0x144678, 0x144688, 0x1445A8]),
    0x6A4E0: (0x6C590, 2, [
        0x1445C0, 0x1445E0, 0x144620, 0x1445E0]),
    0x6F758: (0x76F2C, 2, [
        0x144400, 0x144720, 0x144750, 0x144770]),
}

for start, (end, count, addresses) in SPECS.items():
    path = AUDIT / f"disasm-{start:x}-{end:x}.txt"
    for helper_result in (0, 1):
        result, record, _ = VM(path, start, helper_result).run()
        assert result == helper_result, (hex(start), helper_result, result)
        call_pc, scratch, actual_count, pointer_records = record
        assert scratch == hex(0x1000000)
        assert actual_count == count
        assert [int(pointer, 16) for pointer, _ in pointer_records] == addresses

MARKERS = {
    0x144400: (0x2E, "Acceleration sensor"),
    0x144418: (0xF1, "GreatFruit"),
    0x144428: (0x0A, "Gyroscope"),
    0x144438: (0x04, "Compass"),
    0x144440: (0x24, "Rotation Vector Sensor"),
    0x144458: (0x16, "Google Inc."),
    0x144468: (0x49, "Gravity Sensor"),
    0x144480: (0x23, "Linear Acceleration Sensor"),
    0x1444A0: (0x44, "Orientation Sensor"),
    0x1444C0: (0xD8, "Corrected Gyroscope Sensor"),
    0x144500: (0x77, "TiantianVM Accelerometer"),
    0x144520: (0xA7, "TianTian"),
    0x144540: (0x50, "Invensense Accelerometer"),
    0x144560: (0x12, "Invensense Inc."),
    0x144014: (0x3C, "AOSP"),
    0x144570: (0x1D, "STMicroelectronics"),
    0x144590: (0x4C, "AK8963 Magnetometer"),
    0x1445A4: (0xCB, "AKM"),
    0x1445A8: (0xB5, "Qualcomm"),
    0x1445C0: (0xA7, "Goldfish 3-axis Accelerometer"),
    0x1445E0: (0x71, "The Android Open Source Project"),
    0x144600: (0x67, "Goldfish 3-axis Gyroscope"),
    0x144620: (0xDE, "Goldfish Orientation sensor"),
    0x144660: (0x5C, "MPU6515 Accelerometer"),
    0x144678: (0x23, "InvenSense"),
    0x144688: (0x15, "Orientaion"),
    0x144720: (0x9D, "The Acceleration Sensor Open Source Project"),
    0x144750: (0x94, "Compass Magnetic field sensor"),
    0x144770: (0xA8, "The Compass Sensor Open Source Project"),
}
for address, (key, plaintext) in MARKERS.items():
    encoded = raw(address, len(plaintext) + 1)
    assert bytes(value ^ key for value in encoded) == plaintext.encode() + b"\0"

CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text()
for needle in (
    "kRecoveredPostDetectorGreatFruitPairs4d9bc",
    "kRecoveredPostDetectorTiantianPairs5a8e0",
    "kRecoveredPostDetectorPhysicalSensorPairs5c6d8",
    "kRecoveredPostDetectorGoldfishTripletPairs5f900",
    "kRecoveredPostDetectorMpuOrientationPairs615d8",
    "kRecoveredPostDetectorGoldfishSubsetPairs6a4e0",
    "kRecoveredPostDetectorOpenSourceSensorPairs6f758",
    "runRecoveredGreatFruitSensorPredicate4d9bc(",
    "runRecoveredTiantianSensorPredicate5a8e0(",
    "runRecoveredPhysicalSensorPredicate5c6d8(",
    "runRecoveredGoldfishTripletPredicate5f900(",
    "runRecoveredMpuOrientationPredicate615d8(",
    "runRecoveredGoldfishSubsetPredicate6a4e0(",
    "runRecoveredOpenSourceSensorPredicate6f758(",
    "recoveredPostDetectorPairWrappersRegression()",
):
    assert needle in CPP, needle

print("arm64 post-detector pair wrappers evidence: PASS")
