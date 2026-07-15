#!/usr/bin/env python3
import importlib.util,sys
from pathlib import Path
p=Path(__file__).with_name('analyze_protected_engine_full.py');s=importlib.util.spec_from_file_location('mid_vm',p);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;assert s.loader;s.loader.exec_module(m)
d,_,r=m.pixel_descriptors();v=m.ProtectedEngineVm(r);v.setup(d);lane0=v.memory.read(v.work_address+0x20,8)
while v.executed<36500:v.execute_one()
a=v.arenas[lane0]
print('pc',hex(v.pc),'len',a.length,'frames',a.frame_bases)
for i in range(32):print(i,hex(a.words[i]),hex(int.from_bytes(d[0][i*4:i*4+4],'big')))
