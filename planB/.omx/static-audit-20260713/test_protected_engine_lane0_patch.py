#!/usr/bin/env python3
import importlib.util,sys
from pathlib import Path
p=Path(__file__).with_name('analyze_protected_engine_full.py');s=importlib.util.spec_from_file_location('patch_vm',p);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;assert s.loader;s.loader.exec_module(m)
d,e,r=m.pixel_descriptors();v=m.ProtectedEngineVm(r);v.setup(d);lane0=v.memory.read(v.work_address+0x20,8)
while not v.returned:
 pc=v.pc;v.execute_one()
 if pc==0xfb55c:
  v.arenas[lane0].words[2]=0x9aa1e76a
actual=v.output();print(f'exact={actual==e} status={v.status.value} executed={v.executed}');print(actual.hex())
