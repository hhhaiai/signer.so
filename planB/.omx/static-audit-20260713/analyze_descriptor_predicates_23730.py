#!/usr/bin/env python3
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
TEXT = (AUDIT / 'disasm-23730-24444.txt').read_text(errors='replace')
CPP = (ROOT / 'native-reimplementation/recovered_primitives.cpp').read_text(
    errors='replace')

ins = {}
for line in TEXT.splitlines():
    m = re.match(r'\s*([0-9a-f]+):\s+[0-9a-f]+\s+([a-z.]+)\s*(.*?)(?:\s+//.*)?$', line)
    if m:
        ins[int(m.group(1),16)] = (m.group(2), m.group(3).strip())

def splitops(s):
    out=[]; start=0; depth=0
    for i,c in enumerate(s):
        if c=='[': depth+=1
        elif c==']': depth-=1
        elif c==',' and depth==0:
            out.append(s[start:i].strip()); start=i+1
    if s[start:].strip(): out.append(s[start:].strip())
    return out

MASK=(1<<64)-1

class VM:
    def __init__(self, kind, left='candidate-value', right='marker',
                 start=0x23730, follow_calls=None):
        self.r=[0]*31
        self.sp=0x800000
        self.r[0]=0x100000
        self.r[1]=0x200000
        self.r[2]=kind
        self.mem={}
        for base,data in ((0x100000,left.encode()+b'\0'),
                          (0x200000,right.encode()+b'\0')):
            for i,b in enumerate(data): self.mem[base+i]=b
        self.N=self.Z=self.C=self.V=0
        self.pc=start
        self.steps=0
        self.follow_calls=set(follow_calls or ())
    def reg(self,n):
        n=n.strip()
        if re.fullmatch(r'q\d+',n): return 0
        if n in ('xzr','wzr'): return 0
        if n=='sp': return self.sp
        m=re.fullmatch(r'([xw])(\d+)',n); assert m,n
        v=self.r[int(m.group(2))]
        return v if m.group(1)=='x' else v&0xffffffff
    def setreg(self,n,v):
        n=n.strip()
        if re.fullmatch(r'q\d+',n): return
        if n in ('xzr','wzr'): return
        if n=='sp': self.sp=v&MASK; return
        m=re.fullmatch(r'([xw])(\d+)',n); assert m,n
        self.r[int(m.group(2))]=v&MASK if m.group(1)=='x' else v&0xffffffff
    def imm(self,s):
        s=s.strip().lstrip('#')
        return int(s,0)
    def val(self,s):
        return self.imm(s) if s.strip().startswith('#') else self.reg(s)
    def cond(self,c):
        return {'eq':self.Z==1,'ne':self.Z==0,'lt':self.N!=self.V,
                'ge':self.N==self.V,'lo':self.C==0,'hs':self.C==1,
                'hi':self.C==1 and self.Z==0,'ls':self.C==0 or self.Z==1,
                'le':self.Z==1 or self.N!=self.V,'gt':self.Z==0 and self.N==self.V}[c]
    def subflags(self,a,b,bits=64):
        mask=(1<<bits)-1; sign=1<<(bits-1)
        a&=mask; b&=mask; r=(a-b)&mask
        self.N=bool(r&sign); self.Z=(r==0); self.C=(a>=b)
        self.V=bool(((a^b)&(a^r)&sign)!=0)
    def addflags(self,a,b,bits=64):
        mask=(1<<bits)-1; sign=1<<(bits-1)
        a&=mask; b&=mask; full=a+b; r=full&mask
        self.N=bool(r&sign); self.Z=(r==0); self.C=full>mask
        self.V=bool((~(a^b)&(a^r)&sign)!=0)
    def addr(self,op):
        m=re.fullmatch(r'\[(.*)\](!)?',op); assert m,op
        parts=[x.strip() for x in m.group(1).split(',')]
        base=parts[0]; off=0
        if len(parts)>1:
            if parts[1].startswith('#'): off=self.imm(parts[1])
            else:
                off=self.reg(parts[1])
                if len(parts)>2:
                    if parts[2].startswith('lsl '): off <<= self.imm(parts[2].split()[1])
                    elif parts[2].startswith('uxtw '):
                        off &= 0xffffffff
                        off <<= self.imm(parts[2].split()[1])
                    else: raise AssertionError(op)
        a=(self.reg(base)+off)&MASK
        if m.group(2): self.setreg(base,a)
        return a,base
    def load(self,a,n):
        return sum(self.mem.get(a+i,0)<<(8*i) for i in range(n))
    def store(self,a,v,n):
        for i in range(n): self.mem[a+i]=(v>>(8*i))&0xff
    def run(self):
        while self.steps<200000:
            self.steps+=1
            op,args=ins[self.pc]; nxt=self.pc+4; o=splitops(args)
            if op=='bl':
                target=int(re.search(r'0x([0-9a-f]+)',args).group(1),16)
                if target in self.follow_calls:
                    self.setreg('x30',nxt); self.pc=target; continue
                return self.pc,target
            if op=='ret':
                if self.reg('x30') != 0:
                    self.pc=self.reg('x30'); continue
                return self.pc,'ret:'+str(self.reg('w0'))
            if op=='b': self.pc=int(re.search(r'0x([0-9a-f]+)',args).group(1),16); continue
            if op.startswith('b.'):
                if self.cond(op[2:]): self.pc=int(re.search(r'0x([0-9a-f]+)',args).group(1),16); continue
            elif op=='mov': self.setreg(o[0],self.val(o[1]))
            elif op=='mrs':
                assert o[1]=='TPIDR_EL0'
                self.setreg(o[0],0x900000)
            elif op=='movi':
                pass
            elif op=='mvn': self.setreg(o[0],~self.val(o[1]))
            elif op in ('lsl','lsr'):
                shift=self.imm(o[2]) if o[2].startswith('#') else self.reg(o[2])
                shift &= 31 if o[0].startswith('w') else 63
                value=self.val(o[1])
                self.setreg(o[0],value<<shift if op=='lsl' else value>>shift)
            elif op=='ubfiz':
                lsb=self.imm(o[2]); width=self.imm(o[3])
                self.setreg(o[0],(self.val(o[1])&((1<<width)-1))<<lsb)
            elif op=='bfi':
                lsb=self.imm(o[2]); width=self.imm(o[3]); mask=((1<<width)-1)<<lsb
                self.setreg(o[0],(self.reg(o[0])&~mask)|((self.val(o[1])<<lsb)&mask))
            elif op=='bfxil':
                lsb=self.imm(o[2]); width=self.imm(o[3]); mask=(1<<width)-1
                self.setreg(o[0],(self.reg(o[0])&~mask)|((self.val(o[1])>>lsb)&mask))
            elif op=='movk':
                shift=int(o[2].split('#')[1]) if len(o)>2 else 0
                cur=self.reg(o[0]); val=self.imm(o[1]); mask=0xffff<<shift
                self.setreg(o[0],(cur&~mask)|(val<<shift))
            elif op in ('add','sub'):
                v=self.val(o[1]); rhs=self.val(o[2]); self.setreg(o[0],v+rhs if op=='add' else v-rhs)
            elif op=='subs':
                v=self.val(o[1]); rhs=self.val(o[2]); bits=32 if o[0].startswith('w') else 64
                self.setreg(o[0],v-rhs); self.subflags(v,rhs,bits)
            elif op=='orr':
                rhs=self.val(o[2])
                if len(o)>3 and o[3].startswith('lsl '): rhs <<= self.imm(o[3].split()[1])
                self.setreg(o[0],self.val(o[1])|rhs)
            elif op=='eor': self.setreg(o[0],self.val(o[1])^self.val(o[2]))
            elif op=='and': self.setreg(o[0],self.val(o[1])&self.val(o[2]))
            elif op=='cmp': self.subflags(self.val(o[0]),self.val(o[1]),32 if o[0].startswith('w') else 64)
            elif op=='cmn': self.addflags(self.val(o[0]),self.val(o[1]),32 if o[0].startswith('w') else 64)
            elif op=='tst':
                v=self.val(o[0])&self.val(o[1]); bits=32 if o[0].startswith('w') else 64
                self.N=bool(v&(1<<(bits-1))); self.Z=(v==0); self.C=self.V=0
            elif op=='ccmp':
                if self.cond(o[3]): self.subflags(self.val(o[0]),self.val(o[1]),32 if o[0].startswith('w') else 64)
                else:
                    nzcv=self.imm(o[2]); self.N=(nzcv>>3)&1; self.Z=(nzcv>>2)&1; self.C=(nzcv>>1)&1; self.V=nzcv&1
            elif op=='csel': self.setreg(o[0],self.val(o[1]) if self.cond(o[3]) else self.val(o[2]))
            elif op=='cset': self.setreg(o[0],1 if self.cond(o[1]) else 0)
            elif op=='csinc': self.setreg(o[0],self.val(o[1]) if self.cond(o[3]) else self.val(o[2])+1)
            elif op in ('str','stur','strb'):
                size=1 if op=='strb' else (4 if o[0].startswith('w') else 8)
                a,_=self.addr(o[1]); self.store(a,self.reg(o[0]),size)
            elif op in ('ldr','ldur','ldrb'):
                size=1 if op=='ldrb' else (4 if o[0].startswith('w') else 8)
                a,base=self.addr(o[1]); self.setreg(o[0],self.load(a,size))
                if len(o)>2: self.setreg(base,self.reg(base)+self.imm(o[2]))
            elif op in ('stp','ldp'):
                size=16 if o[0].startswith('q') else (4 if o[0].startswith('w') else 8)
                a,base=self.addr(o[2])
                if op=='stp': self.store(a,self.reg(o[0]),size); self.store(a+size,self.reg(o[1]),size)
                else: self.setreg(o[0],self.load(a,size)); self.setreg(o[1],self.load(a+size,size))
                if len(o)>3: self.setreg(base,self.reg(base)+self.imm(o[3]))
            else: raise RuntimeError((hex(self.pc),op,args))
            self.pc=nxt
        raise RuntimeError('step limit')

def parse_disassembly(name):
    parsed = {}
    for line in (AUDIT / name).read_text(errors='replace').splitlines():
        match = re.match(
            r'\s*([0-9a-f]+):\s+[0-9a-f]+\s+([a-z.]+)\s*'
            r'(.*?)(?:\s+//.*)?$', line)
        if match:
            parsed[int(match.group(1), 16)] = (
                match.group(2), match.group(3).strip())
    return parsed


def execute(name, start, left, right, kind=0):
    global ins
    ins = parse_disassembly(name)
    return VM(kind, left, right, start).run()


# Constant propagation through the flattened dispatcher.  The call-site and
# target pairs are stable even though the state values are randomized.
ins = parse_disassembly('disasm-23730-24444.txt')
routes = {}
for kind in range(9):
    call_site, target = VM(kind).run()
    routes[kind] = (call_site, target)

assert routes == {
    0: (0x24440, 'ret:0'),
    1: (0x24384, 0x12AD00),
    2: (0x24214, 0x12B474),
    3: (0x24104, 0x12BA10),
    4: (0x24440, 'ret:0'),
    5: (0x240C4, 0x127A78),
    6: (0x24268, 0x128038),
    7: (0x24228, 0x128364),
    8: (0x24440, 'ret:1'),
}

# Inline dispatcher kinds zero and four are full-string equality with and
# without ASCII folding, respectively.
ins = parse_disassembly('disasm-23730-24444.txt')
assert VM(0, '', '').run()[1] == 'ret:1'
assert VM(0, 'MARKER', 'marker').run()[1] == 'ret:1'
assert VM(0, 'prefix-marker', 'marker').run()[1] == 'ret:0'
assert VM(4, 'marker', 'marker').run()[1] == 'ret:1'
assert VM(4, 'MARKER', 'marker').run()[1] == 'ret:0'
assert VM(4, 'marker-tail', 'marker').run()[1] == 'ret:0'

# Directly interpret the call-free helpers selected by detector kinds 1, 2,
# 3 and 6.  This is static instruction interpretation of the saved objdump,
# not execution of the target shared object.
starts_with = 'disasm-12ad00-12b474.txt'
ends_with_ci = 'disasm-12b474-12ba10.txt'
contains_ci = 'disasm-12ba10-12c12c.txt'
ends_with_cs = 'disasm-128038-128364.txt'

assert execute(starts_with, 0x12AD00, '', '')[1] == 'ret:1'
assert execute(starts_with, 0x12AD00, 'SDK_GPHONE_X86', 'sdk_gphone_')[1] == 'ret:1'
assert execute(starts_with, 0x12AD00, 'product-sdk_gphone_', 'sdk_gphone_')[1] == 'ret:0'
assert execute(ends_with_ci, 0x12B474, 'prefix-MARKER', 'marker')[1] == 'ret:1'
assert execute(ends_with_ci, 0x12B474, 'marker-tail', 'marker')[1] == 'ret:0'
assert execute(contains_ci, 0x12BA10, '', '')[1] == 'ret:0'
assert execute(contains_ci, 0x12BA10, 'x', '')[1] == 'ret:1'
assert execute(contains_ci, 0x12BA10, 'prefix-MaRkEr-tail', 'marker')[1] == 'ret:1'
assert execute(ends_with_cs, 0x128038, 'prefix-marker', 'marker')[1] == 'ret:1'
assert execute(ends_with_cs, 0x128038, 'marker-tail', 'marker')[1] == 'ret:0'
assert execute(ends_with_cs, 0x128038, 'prefix-MARKER', 'marker')[1] == 'ret:0'

# Kind seven enters the large call-free 0x128364 implementation.  Interpret it
# in-line with the caller register state: its observable result is the same
# case-sensitive substring predicate as kind five, including empty-marker
# behavior.  The optimized/protected implementation uses a byte-indexed table
# and four-byte packing, which is why shifted-register OR and UXTW addressing
# are modeled above.
ins = parse_disassembly('disasm-23730-24444.txt')
ins.update(parse_disassembly('disasm-128364-12ad00.txt'))
for left, right, expected in (
    ('', '', 'ret:1'),
    ('', 'x', 'ret:0'),
    ('marker', 'marker', 'ret:1'),
    ('prefix-marker-tail', 'marker', 'ret:1'),
    ('aaaaab', 'aaab', 'ret:1'),
    ('prefix-MARKER-tail', 'marker', 'ret:0'),
    ('physical', 'marker', 'ret:0'),
):
    result = VM(7, left, right, follow_calls={0x128364}).run()[1]
    assert result == expected, (left, right, result)

# Kind eight ignores descriptor contents and reports whether argument zero is
# a non-null, non-empty C string.
ins = parse_disassembly('disasm-23730-24444.txt')
assert VM(8, '', 'marker').run()[1] == 'ret:0'
assert VM(8, 'x', '').run()[1] == 'ret:1'
kind8_null = VM(8, 'x', 'marker')
kind8_null.r[0] = 0
assert kind8_null.run()[1] == 'ret:0'
kind8_null_descriptor = VM(8, 'x', 'marker')
kind8_null_descriptor.r[1] = 0
assert kind8_null_descriptor.run()[1] == 'ret:1'

for needle in (
    'recoveredAsciiCaseInsensitiveStartsWith12ad00(',
    'recoveredAsciiCaseInsensitiveEndsWith12b474(',
    'recoveredAsciiCaseInsensitiveContains12ba10(',
    'recoveredCaseSensitiveEndsWith128038(',
    'recoveredCaseSensitiveContains128364(',
    'runRecoveredDescriptorPredicate23730(',
    'recoveredDescriptorPredicate23730HelpersRegression()',
):
    assert needle in CPP, needle

print('arm64 descriptor dispatcher 0x23730 kinds 0..8: PASS')
