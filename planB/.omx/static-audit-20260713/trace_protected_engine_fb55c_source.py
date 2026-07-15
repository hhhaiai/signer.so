#!/usr/bin/env python3
import importlib.util,sys
from pathlib import Path
p=Path(__file__).with_name('analyze_protected_engine_full.py');s=importlib.util.spec_from_file_location('fb_vm',p);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;assert s.loader;s.loader.exec_module(m)
d,_,r=m.pixel_descriptors();v=m.ProtectedEngineVm(r);v.setup(d);lane0=v.memory.read(v.work_address+0x20,8);shared=v.memory.read(v.work_address+8,8)
last_read=None
while v.executed<100000:
 pc=v.pc;ins=v.instructions[pc]
 if pc==0xfb548: print(f'before read w1={v.read_reg("w1"):#x} source_word={v.arenas[shared].read(v.read_reg("w1")):#x} w22={v.read_reg("w22")} w27={v.read_reg("w27"):#x} w23={v.read_reg("w23"):#x}')
 if pc==0xfb55c and v.read_reg('x1')==lane0 and v.read_reg('w2')==2:
  print(f'copy write value={v.read_reg("w3"):#x} source_index={v.read_reg("w1"):#x} shared_len={v.arenas[shared].length} shared_frames={v.arenas[shared].frame_bases}')
  break
 v.execute_one()
