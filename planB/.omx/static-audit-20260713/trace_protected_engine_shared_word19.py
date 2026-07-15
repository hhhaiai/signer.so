#!/usr/bin/env python3
import importlib.util,sys
from pathlib import Path
p=Path(__file__).with_name('analyze_protected_engine_full.py');s=importlib.util.spec_from_file_location('sh_vm',p);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;assert s.loader;s.loader.exec_module(m)
d,_,r=m.pixel_descriptors();v=m.ProtectedEngineVm(r);v.setup(d);shared=v.memory.read(v.work_address+8,8)
while v.executed<100000:
 ins=v.instructions[v.pc]
 if ins.mnemonic=='bl' and v.branch_target(ins.parts[0])==v.HELPER_ARENA_WRITE and v.read_reg('x1')==shared:
  a=v.arenas[shared];off=v.read_reg('w2');idx=(a.frame_bases[-1]+off)&0xffffffff;val=v.read_reg('w3')
  if idx==19 or val in (0x9aa1e76a,0xeaade76a):print(f'pc={v.pc:#x} executed={v.executed} base={a.frame_bases[-1]} off={off} idx={idx} val={val:#010x}')
 v.execute_one()
