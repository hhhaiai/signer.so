#!/usr/bin/env python3
from collections import deque
import importlib.util,sys
from pathlib import Path
p=Path(__file__).with_name('analyze_protected_engine_full.py'); s=importlib.util.spec_from_file_location('evm_large_push',p); m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;assert s.loader;s.loader.exec_module(m)
d,_,rv=m.pixel_descriptors();v=m.ProtectedEngineVm(rv);v.setup(d);recent=deque(maxlen=100)
for _ in range(200000):
 ins=v.instructions[v.pc]; recent.append((v.pc,ins.mnemonic,ins.operands))
 if ins.mnemonic=='bl' and v.branch_target(ins.parts[0]) in (v.HELPER_STACK_PUSH,v.HELPER_STACK_PUSH_ALIAS):
  val=v.read_reg('w2')
  if val>100000:
   print(f'large_stack_push pc={v.pc:#x} value={val:#x} executed={v.executed}')
   for x in recent: print(f'  {x[0]:#x}: {x[1]} {x[2]}')
   print('stack_tail_before=',v.stacks[v.read_reg('x1')].values[-32:])
   break
 v.execute_one()
else: print('not found')
