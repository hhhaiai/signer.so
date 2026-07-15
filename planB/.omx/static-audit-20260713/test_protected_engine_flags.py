#!/usr/bin/env python3
import importlib.util,struct,sys
from pathlib import Path
p=Path(__file__).with_name('analyze_protected_engine_full.py');s=importlib.util.spec_from_file_location('flags_vm',p);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;assert s.loader;s.loader.exec_module(m)
d,e,r=m.pixel_descriptors()
mask=int(sys.argv[1],0)
d[2]=struct.pack('<Q',mask)+bytes(8)
v=m.ProtectedEngineVm(r);v.setup(d);v.run();a=v.output();
print(f'mask={mask:#018x} status={v.status.value} executed={v.executed} exact={a==e}')
print(a.hex())
