#!/usr/bin/env python3
import importlib.util,sys
from pathlib import Path
p=Path(__file__).with_name('analyze_protected_engine_full.py');s=importlib.util.spec_from_file_location('skip_vm',p);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;assert s.loader;s.loader.exec_module(m)
d,e,r=m.pixel_descriptors();v=m.ProtectedEngineVm(r);v.setup(d)
while not v.returned:
 if v.pc==0xf4884:v.write_reg('w0',0)
 v.execute_one()
a=v.output();print('exact',a==e,'status',v.status.value,'executed',v.executed);print(a.hex())
