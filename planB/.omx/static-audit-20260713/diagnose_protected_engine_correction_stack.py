#!/usr/bin/env python3
from collections import deque
import importlib.util,sys
from pathlib import Path
p=Path(__file__).with_name('analyze_protected_engine_full.py');s=importlib.util.spec_from_file_location('corr_vm',p);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;assert s.loader;s.loader.exec_module(m)
d,_,r=m.pixel_descriptors();v=m.ProtectedEngineVm(r);v.setup(d);recent=deque(maxlen=24);hits=0
for _ in range(9_000_000):
 ins=v.instructions[v.pc];recent.append((v.pc,ins.mnemonic,ins.operands))
 if ins.mnemonic=='bl' and v.branch_target(ins.parts[0])==v.HELPER_STACK_PUSH:
  val=v.read_reg('w2'); off=v.read_reg('w2'); arena=v.read_reg('x1')
  if val in (0xa19a,0xadea,0xa19a6ae7,0xadea6ae7):
   print(f'write pc={v.pc:#x} executed={v.executed} arena={arena:#x} off={off:#x} val={val:#x}')
   for x in recent:print(f'  {x[0]:#x}: {x[1]} {x[2]}')
   hits+=1
 v.execute_one()
 if v.returned:break
print(f'done executed={v.executed} hits={hits}')
