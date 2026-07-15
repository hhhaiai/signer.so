#!/usr/bin/env python3
from collections import Counter, deque
import importlib.util
import sys
from pathlib import Path

path = Path(__file__).with_name('analyze_protected_engine_full.py')
spec = importlib.util.spec_from_file_location('engine_vm', path)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = module
spec.loader.exec_module(module)

descriptors, _, rand_values = module.pixel_descriptors()
vm = module.ProtectedEngineVm(rand_values)
vm.setup(descriptors)
visits = Counter()
edges = Counter()
recent = deque(maxlen=32)
previous = None
limit = 3_000_000
for _ in range(limit):
    if vm.returned:
        break
    pc = vm.pc
    visits[pc] += 1
    if previous is not None:
        edges[(previous, pc)] += 1
    recent.append(pc)
    previous = pc
    vm.execute_one()
print(f'executed={vm.executed} returned={vm.returned} pc={vm.pc:#x} status={vm.status.value}')
print('top_visits=')
for pc, count in visits.most_common(30):
    print(f'  {pc:#x}:{count}')
print('top_edges=')
for (source, target), count in edges.most_common(30):
    print(f'  {source:#x}->{target:#x}:{count}')
print('recent=' + ','.join(hex(pc) for pc in recent))
print('stacks=')
for address, stack in vm.stacks.items():
    print(f'  {address:#x}:count={len(stack.values)} tail={stack.values[-8:]}')
print('counters=')
for address, chain in vm.counters.items():
    print(f'  {address:#x}:{chain.values[:16]}')
print('arenas=')
for address, arena in vm.arenas.items():
    if arena.length or len(arena.frame_bases) != 1:
        print(f'  {address:#x}:length={arena.length} frames={arena.frame_bases[-8:]}')
