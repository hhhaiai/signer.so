#!/usr/bin/env python3
import importlib.util,sys
from pathlib import Path
p=Path(__file__).with_name('analyze_protected_engine_full.py');s=importlib.util.spec_from_file_location('lane_vm',p);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;assert s.loader;s.loader.exec_module(m)
d,e,r=m.pixel_descriptors();v=m.ProtectedEngineVm(r);v.setup(d);v.run()
print(f'executed={v.executed} status={v.status.value} rand={v.rand_index}')
for i in range(16):
 a=v.memory.read(v.work_address+0x20+i*8,8); arena=v.arenas[a]
 data=b''.join(x.to_bytes(4,'big') for x in arena.words[:arena.length])
 print(f'lane{i}: len_words={arena.length} frames={arena.frame_bases} data={data[:256].hex()}')
print('stack',v.stacks[v.memory.read(v.work_address,8)].values[-64:])
print('aux',v.stacks[v.memory.read(v.work_address+0x18,8)].values[-64:])
print('counter',v.counters[v.memory.read(v.work_address+0x10,8)].values)
