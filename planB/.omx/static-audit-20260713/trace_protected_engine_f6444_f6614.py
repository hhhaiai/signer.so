#!/usr/bin/env python3
import importlib.util,sys
from pathlib import Path
p=Path(__file__).with_name('analyze_protected_engine_full.py');s=importlib.util.spec_from_file_location('trace_vm',p);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;assert s.loader;s.loader.exec_module(m)
d,_,r=m.pixel_descriptors();v=m.ProtectedEngineVm(r);v.setup(d)
start,end=0xf6444,0xf6614
while not v.returned and v.executed<100000:
 pc=v.pc;ins=v.instructions[pc]
 active=start<=pc<=end
 if active:
  main=v.stacks[v.memory.read(v.work_address,8)].values
  aux=v.stacks[v.memory.read(v.work_address+0x18,8)].values
  print(f'before {pc:#x} {ins.mnemonic} {ins.operands} w0={v.read_reg("w0"):#x} w1={v.read_reg("w1"):#x} w2={v.read_reg("w2"):#x} w21={v.read_reg("w21"):#x} main={main[-12:]} aux={aux[-8:]}')
 v.execute_one()
 if active and ins.mnemonic=='bl':
  main=v.stacks[v.memory.read(v.work_address,8)].values;aux=v.stacks[v.memory.read(v.work_address+0x18,8)].values
  print(f' after call w0={v.read_reg("w0"):#x} main={main[-12:]} aux={aux[-8:]}')
 if pc==end:break
