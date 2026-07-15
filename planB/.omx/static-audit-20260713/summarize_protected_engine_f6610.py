#!/usr/bin/env python3
import importlib.util,sys
from pathlib import Path
p=Path(__file__).with_name('analyze_protected_engine_full.py');s=importlib.util.spec_from_file_location('sum_vm',p);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;assert s.loader;s.loader.exec_module(m)
d,_,r=m.pixel_descriptors();v=m.ProtectedEngineVm(r);v.setup(d);count=0
while not v.returned and v.executed<500000:
 pc=v.pc
 if pc==0xf6494:
  main=v.stacks[v.memory.read(v.work_address,8)].values
  print(f'iter={count} start_main={main[-12:]}')
 if pc==0xf6610:
  print(f'iter={count} result={v.read_reg("w2"):#010x}')
  count+=1
 v.execute_one()
 if count>=40:break
