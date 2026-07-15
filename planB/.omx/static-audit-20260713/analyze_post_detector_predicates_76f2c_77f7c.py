import re,struct
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
MASK=(1<<64)-1

def parse(path):
 ins={}
 for l in Path(path).read_text().splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+[0-9a-f]+\s+([a-z.]+)\s*(.*?)(?:\s+//.*)?$',l)
  if m:ins[int(m.group(1),16)]=(m.group(2),m.group(3).strip())
 return ins
def split(s):
 out=[];st=0;d=0
 for i,c in enumerate(s):
  if c=='[':d+=1
  elif c==']':d-=1
  elif c==',' and d==0:out.append(s[st:i].strip());st=i+1
 if s[st:].strip():out.append(s[st:].strip())
 return out
class VM:
 def __init__(self,path,start,offset,value,marker_addr,marker,flag):
  self.ins=parse(path);self.r=[0]*31;self.sp=0x800000;self.mem={};self.N=self.Z=self.C=self.V=0;self.pc=start;self.steps=0
  scratch=0x100000;self.r[0]=scratch
  ptr=0
  if value is not None:
   ptr=0x200000
   for i,b in enumerate(value.encode()+b'\0'):self.mem[ptr+i]=b
  self.store(scratch+offset,ptr,8)
  for i,b in enumerate(marker.encode()+b'\0'):self.mem[marker_addr+i]=b
  self.mem[flag]=0;self.mem[flag+1]=1
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
  while self.steps<2000000:
   self.steps+=1;op,a=self.ins[self.pc];p=split(a);nxt=self.pc+4
   if op=='ret':return self.reg('w0')&1,self.steps
   if op=='b':self.pc=int(re.search(r'0x([0-9a-f]+)',a).group(1),16);continue
   if op.startswith('b.'):
    if self.cond(op[2:]):self.pc=int(re.search(r'0x([0-9a-f]+)',a).group(1),16);continue
   elif op=='bl':self.set('w0',0)
   elif op=='nop':pass
   elif op=='mov':self.set(p[0],self.val(p[1]))
   elif op=='movk':
    sh=int(p[2].split('#')[1]) if len(p)>2 else 0;m=0xffff<<sh;self.set(p[0],(self.reg(p[0])&~m)|(self.val(p[1])<<sh))
   elif op in ('add','sub'):self.set(p[0],self.val(p[1])+self.val(p[2]) if op=='add' else self.val(p[1])-self.val(p[2]))
   elif op in ('orr','eor','and'):
    self.set(p[0],{'orr':self.val(p[1])|self.val(p[2]),'eor':self.val(p[1])^self.val(p[2]),'and':self.val(p[1])&self.val(p[2])}[op])
   elif op=='cmp':self.subflags(self.val(p[0]),self.val(p[1]),32 if p[0].startswith('w') else 64)
   elif op=='cmn':self.addflags(self.val(p[0]),self.val(p[1]),32 if p[0].startswith('w') else 64)
   elif op=='ccmp':
    if self.cond(p[3]):self.subflags(self.val(p[0]),self.val(p[1]),32 if p[0].startswith('w') else 64)
    else:
     z=self.val(p[2]);self.N=(z>>3)&1;self.Z=(z>>2)&1;self.C=(z>>1)&1;self.V=z&1
   elif op=='csel':self.set(p[0],self.val(p[1]) if self.cond(p[3]) else self.val(p[2]))
   elif op=='cset':self.set(p[0],1 if self.cond(p[1]) else 0)
   elif op in ('adr','adrp'):self.set(p[0],int(re.search(r'0x([0-9a-f]+)',p[1]).group(1),16))
   elif op in ('str','stur','strb','stlrb','ldr','ldur','ldrb'):
    a0,b=self.addr(p[1]);sz=1 if op in ('strb','stlrb','ldrb') else (4 if p[0].startswith('w') else 8)
    if op in ('str','stur','strb','stlrb'):self.store(a0,self.reg(p[0]),sz)
    else:self.set(p[0],self.load(a0,sz))
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

def run(spec,v):return VM(spec[0],spec[1],spec[2],v,spec[3],spec[4],spec[5]).run()[0]
specs=[(AUDIT/'disasm-76f2c-77f7c.txt',0x76f2c,0x20,0x1447b4,'haima',0x146218),(AUDIT/'disasm-77f7c-78f68.txt',0x77f7c,0x08,0x1447bc,'vmos',0x14621c)]

haima, vmos = specs
for value, expected in (
        (None, 0), ('', 0), ('haima', 1), ('HAIMA', 1),
        ('prefix-haima', 1), ('haima-tail', 1), ('xhaimax', 1),
        ('physical', 0), ('haim', 0)):
    assert run(haima, value) == expected, (value, expected)
for value, expected in (
        (None, 0), ('', 0), ('vmos', 1), ('VMOS', 1),
        ('prefix-vmos', 1), ('vmos-tail', 1), ('xvmosx', 1),
        ('physical', 0), ('vmo', 0)):
    assert run(vmos, value) == expected, (value, expected)

image = (ROOT / 'adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so').read_bytes()
program_offset = struct.unpack_from('<Q', image, 32)[0]
entry_size = struct.unpack_from('<H', image, 54)[0]
entry_count = struct.unpack_from('<H', image, 56)[0]
segments = []
for index in range(entry_count):
    fields = struct.unpack_from(
        '<IIQQQQQQ', image, program_offset + index * entry_size)
    if fields[0] == 1:
        segments.append((fields[2], fields[3], fields[5]))
def virtual_bytes(address, size):
    for offset, virtual, file_size in segments:
        if virtual <= address and address + size <= virtual + file_size:
            start = offset + address - virtual
            return image[start:start + size]
    raise AssertionError(hex(address))
assert bytes(value ^ 0x80 for value in virtual_bytes(0x1447b4, 6)) == b'haima\0'
assert bytes(value ^ 0x5b for value in virtual_bytes(0x1447bc, 5)) == b'vmos\0'

text_a = Path(haima[0]).read_text()
text_b = Path(vmos[0]).read_text()
for needle in (
        '76fd0: f9401000     \tldr\tx0, [x0, #0x20]',
        '778f0: 10667629     \tadr\tx9, 0x1447b4'):
    assert needle in text_a, needle
for needle in (
        '78024: f9400400     \tldr\tx0, [x0, #0x8]',
        '78994: 1065f149     \tadr\tx9, 0x1447bc'):
    assert needle in text_b, needle

cpp = (ROOT / 'native-reimplementation/recovered_primitives.cpp').read_text()
for needle in (
        'kRecoveredPostDetectorHaimaMarker76f2c[] = "haima"',
        'kRecoveredPostDetectorVmosMarker77f7c[] = "vmos"',
        'bool runRecoveredHaimaPredicate76f2c(',
        'scratch->fixedString20',
        'bool runRecoveredVmosPredicate77f7c(',
        'scratch->fixedString08',
        'recoveredPostDetectorPredicates76f2c77f7cRegression()'):
    assert needle in cpp, needle

print('arm64 post-detector predicates 0x76f2c/0x77f7c evidence: PASS')
