#!/usr/bin/env python3
import importlib.util,sys
from pathlib import Path
p=Path(__file__).with_name('analyze_protected_engine_full.py');s=importlib.util.spec_from_file_location('lane0_vm',p);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;assert s.loader;s.loader.exec_module(m)
d,_,r=m.pixel_descriptors();v=m.ProtectedEngineVm(r);v.setup(d);lane0=v.memory.read(v.work_address+0x20,8)
while not v.returned and v.executed<100000:
 ins=v.instructions[v.pc]
 if ins.mnemonic=='bl' and v.branch_target(ins.parts[0])==v.HELPER_ARENA_WRITE and v.read_reg('x1')==lane0 and v.read_reg('w2')==2:
  print(f'pc={v.pc:#x} executed={v.executed} value={v.read_reg("w3"):#010x}')
 v.execute_one()
