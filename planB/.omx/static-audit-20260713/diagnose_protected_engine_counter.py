#!/usr/bin/env python3
from collections import deque
import importlib.util
import sys
from pathlib import Path
path = Path(__file__).with_name('analyze_protected_engine_full.py')
spec = importlib.util.spec_from_file_location('engine_vm_counter', path)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = module
spec.loader.exec_module(module)
descriptors, _, rand_values = module.pixel_descriptors()
vm = module.ProtectedEngineVm(rand_values)
vm.setup(descriptors)
recent = deque(maxlen=64)
for _ in range(5_000_000):
    ins = vm.instructions[vm.pc]
    recent.append((vm.pc, ins.mnemonic, ins.operands))
    if ins.mnemonic == 'bl' and vm.branch_target(ins.parts[0]) == vm.HELPER_COUNTER_PUSH:
        value = vm.read_reg('w2')
        print(f'counter_push pc={vm.pc:#x} value={value:#x} ({value}) executed={vm.executed}')
        if value > 100000:
            print('recent=')
            for item in recent:
                print(f'  {item[0]:#x}: {item[1]} {item[2]}')
            print('regs=' + ' '.join(f'x{i}={vm.regs[i]:#x}' for i in range(31)))
            break
    vm.execute_one()
else:
    print('no large counter push')
