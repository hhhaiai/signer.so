#!/usr/bin/env python3
import importlib.util,sys
from pathlib import Path
p=Path(__file__).with_name('analyze_protected_engine_full.py');s=importlib.util.spec_from_file_location('f4840_vm',p);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;assert s.loader;s.loader.exec_module(m)
d,_,r=m.pixel_descriptors();v=m.ProtectedEngineVm(r);v.setup(d)
while v.executed<100000:
 if 0xf4838<=v.pc<=0xf4888:
  st=v.stacks[v.memory.read(v.work_address,8)].values
  print(f'pc={v.pc:#x} {v.instructions[v.pc].mnemonic} {v.instructions[v.pc].operands} w0={v.read_reg("w0"):#x} z={v.z} c={v.c} stack={st[-16:]}')
 v.execute_one()
