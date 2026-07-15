#!/usr/bin/env python3
import re
from pathlib import Path
P=Path(__file__).with_name('disasm-12c12c-12e95c.txt')
I=[]
for l in P.read_text().splitlines():
 m=re.match(r'\s*([0-9a-f]+):\s+[0-9a-f]+\s+(.+)',l)
 if m:I.append((int(m.group(1),16),m.group(2).split('//')[0].strip(),l))
# state->target from generated map
state_target={}
for l in Path(__file__).with_name('arm64-12c12c-state-map.csv').read_text().splitlines():
 s,t,_=l.split(',');state_target[int(s,16)]=int(t,16)
# alias state -> next state from dispatch x6 tracking
const={};pending=None;aliases={}
for a,op,l in I:
 if not 0x12c1fc<=a<0x12d7a0:continue
 m=re.fullmatch(r'mov\s+(x\d+),\s+#0x([0-9a-f]+)',op)
 if m:const[m.group(1)]=int(m.group(2),16);continue
 m=re.fullmatch(r'movk\s+(x\d+),\s+#0x([0-9a-f]+),\s+lsl\s+#(\d+)',op)
 if m:
  r,v,sh=m.group(1),int(m.group(2),16),int(m.group(3));old=const.get(r)
  if old is not None:const[r]=(old&~(0xffff<<sh))|(v<<sh)
  continue
 m=re.fullmatch(r'cmp\s+x3,\s+(x\d+)',op)
 if m:pending=const.get(m.group(1));continue
 m=re.fullmatch(r'b\.eq\s+0x([0-9a-f]+).*',op)
 if m and pending is not None:
  if int(m.group(1),16)==0x12c1fc and const.get('x6') is not None:aliases[pending]=const['x6']
  pending=None
 elif op.startswith(('cmp ','subs ','tst ','ccmp ')):pending=None

def resolve(s):
 seen=[]
 while s in aliases and s not in seen:seen.append(s);s=aliases[s]
 return s,state_target.get(s),seen
# semantic starts
starts=sorted(set(t for t in state_target.values() if t>=0x12d7a0))
idx={a:i for i,(a,_,_) in enumerate(I)}
noise=('stp ','ldp ','stur ','ldur ','str ','ldr ','mov x27','mov x26','mov x23','mov x13','mov x7','mov w12','mov x11','mov x8','mov x14','mov x16')
for start in starts:
 i=idx[start]; block=[]
 for a,op,l in I[i:]:
  block.append((a,op,l))
  if (op.startswith('b\t') or re.match(r'b\s+0x',op)) and a>start:break
 # find incoming resolved state names
 incoming=[s for s,t in state_target.items() if t==start]
 print(f'\n## 0x{start:x} states '+','.join(f'{s:016x}' for s in incoming))
 for a,op,l in block:
  if op.startswith(('movk ','mov x6, #','mov x8, #','mov x9, #')):continue
  if op.startswith(noise):continue
  print(f'{a:x}: {op}')
 # transitions from x6 direct/csel in full block
 c={}; cond=''
 for a,op,l in block:
  m=re.fullmatch(r'mov\s+(x\d+),\s+#0x([0-9a-f]+)',op)
  if m:c[m.group(1)]=int(m.group(2),16);continue
  m=re.fullmatch(r'movk\s+(x\d+),\s+#0x([0-9a-f]+),\s+lsl\s+#(\d+)',op)
  if m:
   r,v,sh=m.group(1),int(m.group(2),16),int(m.group(3));old=c.get(r)
   if old is not None:c[r]=(old&~(0xffff<<sh))|(v<<sh)
  m=re.fullmatch(r'(cmp|tst|subs|ccmp)\s+(.+)',op)
  if m:cond=op
  m=re.fullmatch(r'csel\s+x6,\s+(x\d+),\s+(x\d+),\s+(\w+)',op)
  if m:
   a1,a2,cc=m.group(1),m.group(2),m.group(3)
   print('TRANS',cond,cc, f'{c.get(a1,0):016x}->{resolve(c.get(a1,0))}', f'{c.get(a2,0):016x}->{resolve(c.get(a2,0))}')
 if 'x6' in c and not any('csel\tx6' in l or 'csel x6' in op for _,op,l in block):
  print('TRANS direct',f'{c["x6"]:016x}->{resolve(c["x6"])}')
