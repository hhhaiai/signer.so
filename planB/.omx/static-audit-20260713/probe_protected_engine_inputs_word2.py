#!/usr/bin/env python3
import importlib.util,sys,struct
from pathlib import Path
p=Path(__file__).with_name('analyze_protected_engine_full.py');s=importlib.util.spec_from_file_location('inp_vm',p);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;assert s.loader;s.loader.exec_module(m)
base,_,r=m.pixel_descriptors()
cases={
'base':{},
'cert_zero':{1:bytes(20)},
'flags_zero':{2:bytes(16)},
'flags_ones':{2:bytes([0xff])*16},
'basis_zero':{3:bytes(32)},
'basis_be':{3:b''.join(struct.pack('>H',x) for x in m.CODEWORD_BASIS)},
'field2_rev':{4:base[4][::-1]},
'length_113':{5:(113).to_bytes(4,'big')},
'plain_empty':{5:bytes(4),6:b''},
'dynamic4':{7:(4).to_bytes(4,'big'),8:b'abcd'},
}
for name,mods in cases.items():
 d=list(base)
 for i,x in mods.items():d[i]=x
 v=m.ProtectedEngineVm(r);v.setup(d);lane0=v.memory.read(v.work_address+0x20,8)
 try:
  while v.executed<36500 and not v.returned:v.execute_one()
  print(f'{name}: status={v.status.value} returned={v.returned} pc={v.pc:#x} word2={v.arenas[lane0].words[2]:#010x}')
 except Exception as e:print(f'{name}: ERROR {e!r} pc={v.pc:#x} status={v.status.value}')
