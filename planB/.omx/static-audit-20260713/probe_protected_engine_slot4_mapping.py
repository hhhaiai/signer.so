#!/usr/bin/env python3
import importlib.util,sys,struct
from pathlib import Path
p=Path(__file__).with_name('analyze_protected_engine_full.py');s=importlib.util.spec_from_file_location('map_vm',p);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;assert s.loader;s.loader.exec_module(m)
base,_,r=m.pixel_descriptors()
for value in [0xa19a,0xadea,0,0xffff,0x19be,0xd2c3,0x1fd6,0x6c8f,0x6ae7]:
 d=list(base); raw=bytearray(d[0]);raw[8:10]=struct.pack('<H',value);d[0]=bytes(raw)
 v=m.ProtectedEngineVm(r);v.setup(d);lane0=v.memory.read(v.work_address+0x20,8)
 while v.executed<36500:v.execute_one()
 print(f'input={value:#06x} output_word2={v.arenas[lane0].words[2]:#010x}')
