#!/usr/bin/env python3
from collections import deque
import importlib.util,sys
from pathlib import Path
p=Path(__file__).with_name('analyze_protected_engine_full.py');s=importlib.util.spec_from_file_location('last_vm',p);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;assert s.loader;s.loader.exec_module(m)
d,_,r=m.pixel_descriptors();v=m.ProtectedEngineVm(r);v.setup(d);mainaddr=v.memory.read(v.work_address,8);events=deque(maxlen=40)
while v.executed<100000:
 ins=v.instructions[v.pc]
 if ins.mnemonic=='bl':
  t=v.branch_target(ins.parts[0])
  if t in (v.HELPER_STACK_PUSH,v.HELPER_STACK_PUSH_ALIAS) and v.read_reg('x1')==mainaddr:
   events.append((v.pc,'push',v.read_reg('w2')))
  elif t in (v.HELPER_STACK_POP,v.HELPER_STACK_POP_ALIAS) and v.read_reg('x1')==mainaddr:
   events.append((v.pc,'pop_before',list(v.stacks[mainaddr].values[-5:])))
  elif t==v.HELPER_STACK_DUPLICATE and v.read_reg('x1')==mainaddr:
   events.append((v.pc,'dup',v.read_reg('w2'),list(v.stacks[mainaddr].values[-5:])))
  elif t==v.HELPER_STACK_SWAP and v.read_reg('x1')==mainaddr:
   events.append((v.pc,'swap',v.read_reg('w2'),list(v.stacks[mainaddr].values[-5:])))
 if v.pc==0xf4840:
  print('executed',v.executed,'stack',v.stacks[mainaddr].values)
  for e in events:print(e)
  break
 v.execute_one()
