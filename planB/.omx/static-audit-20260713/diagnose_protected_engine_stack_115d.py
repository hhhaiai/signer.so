#!/usr/bin/env python3
import importlib.util, sys
from pathlib import Path
path=Path(__file__).with_name('analyze_protected_engine_full.py')
spec=importlib.util.spec_from_file_location('engine_vm_stack', path)
module=importlib.util.module_from_spec(spec); sys.modules[spec.name]=module
assert spec.loader is not None; spec.loader.exec_module(module)
descriptors,_,rand_values=module.pixel_descriptors(); vm=module.ProtectedEngineVm(rand_values); vm.setup(descriptors)
watch={0x115da8,0x115db0,0x115db4,0x115dc0,0x115dc8,0x115dcc,0x115dd8,0x115de0,0x115de4,0x115dec,0x115dfc}
while vm.executed < 200000 and not vm.returned:
 if vm.pc in watch:
  stack=vm.stacks.get(vm.read_reg('x1'))
  print(f'before pc={vm.pc:#x} executed={vm.executed} x1={vm.read_reg("x1"):#x} w0={vm.read_reg("w0"):#x} w2={vm.read_reg("w2"):#x} stack_tail={None if stack is None else stack.values[-12:]}')
 vm.execute_one()
 if vm.pc==0x115e00:
  break
