#!/usr/bin/env python3
import re
from pathlib import Path
P=Path(__file__).with_name('disasm-12c12c-12e95c.txt')
I=[]
for l in P.read_text().splitlines():
 m=re.match(r'\s*([0-9a-f]+):\s+[0-9a-f]+\s+(.+)',l)
 if m:I.append((int(m.group(1),16),m.group(2).split('//')[0].strip(),l))
const={}
pending=None
maps=[]
for a,op,l in I:
 if not (0x12c1fc<=a<0x12d7a0): continue
 m=re.fullmatch(r'mov\s+(x\d+),\s+#0x([0-9a-f]+)',op)
 if m:
  const[m.group(1)]=int(m.group(2),16);continue
 m=re.fullmatch(r'movk\s+(x\d+),\s+#0x([0-9a-f]+),\s+lsl\s+#(\d+)',op)
 if m:
  r,v,sh=m.group(1),int(m.group(2),16),int(m.group(3)); old=const.get(r)
  if old is not None:const[r]=(old&~(0xffff<<sh))|(v<<sh)
  continue
 m=re.fullmatch(r'cmp\s+x3,\s+(x\d+)',op)
 if m:pending=const.get(m.group(1));continue
 m=re.fullmatch(r'b\.eq\s+0x([0-9a-f]+).*',op)
 if m and pending is not None:
  maps.append((pending,int(m.group(1),16),a));pending=None
 elif op.startswith(('cmp ','subs ','tst ','ccmp ')): pending=None
for s,t,a in maps:print(f'0x{s:016x},0x{t:x},0x{a:x}')
