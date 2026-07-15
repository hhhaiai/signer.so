// Optional read-only addendum for fixed-runtime.js.
//
// IMPORTANT: only hook real helper-function entries.  Do not attach to the
// middle of protected ARM64 basic blocks: Frida's inline trampoline may cover
// neighbouring instructions and change the value being measured.

function protectedHex32(value) {
    return '0x' + ('00000000' + (value >>> 0).toString(16)).slice(-8);
}

function protectedReadStatus(status) {
    if (status === null || status.isNull()) return null;
    try {
        return status.readS32();
    } catch (error) {
        return '<unreadable:' + error + '>';
    }
}

function protectedReadWordStack(stack, limit) {
    if (stack === null || stack.isNull()) return {pointer: '<null>'};
    const count = stack.readU32();
    let node = stack.add(8).readPointer();
    const values = [];
    for (let i = 0; i < Math.min(count, limit) && !node.isNull(); i++) {
        values.push(protectedHex32(node.readU32()));
        node = node.add(8).readPointer();
    }
    return {pointer: stack.toString(), count: count, top: values};
}

function protectedReadCounterChain(owner, limit) {
    if (owner === null || owner.isNull()) return {pointer: '<null>'};
    let node = owner.readPointer();
    const values = [];
    for (let i = 0; i < limit && !node.isNull(); i++) {
        values.push(protectedHex32(node.readU32()));
        node = node.add(8).readPointer();
    }
    return {pointer: owner.toString(), head: values};
}

function protectedReadArenaMeta(arena) {
    if (arena === null || arena.isNull()) return {pointer: '<null>'};
    const capacity = arena.readU32();
    const words = arena.add(8).readPointer();
    const length = arena.add(0x10).readU32();
    const depth = arena.add(0x14).readU32();
    const frameBases = arena.add(0x18).readPointer();
    let base = 0;
    if (depth > 0 && depth < 0x10000 && !frameBases.isNull()) {
        base = frameBases.add((depth - 1) * 4).readU32();
    }
    return {
        pointer: arena.toString(),
        capacity: capacity,
        wordsPointer: words.toString(),
        length: length,
        depth: depth,
        base: base,
        frameLength: length >= base ? length - base : 0
    };
}

function protectedReadArenaAbsolute(arena, absoluteOffset) {
    const meta = protectedReadArenaMeta(arena);
    if (meta.pointer === '<null>' || meta.wordsPointer === '0x0') return null;
    if (absoluteOffset >= meta.capacity) return '<out-of-capacity>';
    return arena.add(8).readPointer().add(absoluteOffset * 4).readU32();
}

function protectedReadWork(work) {
    if (work === null || work.isNull()) return {pointer: '<null>'};
    try {
        return {
            pointer: work.toString(),
            evaluation: protectedReadWordStack(work.readPointer(), 24),
            shared: protectedReadArenaMeta(work.add(8).readPointer()),
            counters: protectedReadCounterChain(work.add(0x10).readPointer(), 24),
            auxiliary: protectedReadWordStack(work.add(0x18).readPointer(), 24)
        };
    } catch (error) {
        return {pointer: work.toString(), error: error.toString()};
    }
}

let protectedTraceInstalled = false;
const protectedTracePoll = setInterval(function () {
    if (protectedTraceInstalled) return;
    const signer = Process.findModuleByName('libsigner.so');
    if (signer === null) return;

    protectedTraceInstalled = true;
    clearInterval(protectedTracePoll);

    function relativeAddress(pointer) {
        return pointer.sub(signer.base).toUInt32();
    }

    const namedWriterCallers = {
        0x0f5118: 'f5114-writer',
        0x0f5d34: 'f5d30-writer',
        0x0f58c8: 'f58c4-writer'
    };

    // ABI at 0x138318:
    //   x0 = status*, x1 = arena*, w2 = frame-relative offset, w3 = value
    Interceptor.attach(signer.base.add(0x138318), {
        onEnter(args) {
            try {
                this.status = args[0];
                this.arena = args[1];
                this.offset = args[2].toUInt32();
                this.value = args[3].toUInt32();
                this.caller = relativeAddress(this.returnAddress);
                this.metaBefore = protectedReadArenaMeta(this.arena);
                this.absoluteOffset = (this.metaBefore.base + this.offset) >>> 0;

                const namedCaller = namedWriterCallers[this.caller];
                const touchesTarget = this.absoluteOffset >= 0x40 && this.absoluteOffset <= 0x43;
                this.shouldTrace = namedCaller !== undefined || touchesTarget;
                if (!this.shouldTrace) return;

                trace('protected arena-writer enter=' + JSON.stringify({
                    caller: protectedHex32(this.caller),
                    callerName: namedCaller || 'other-target-writer',
                    status: protectedReadStatus(this.status),
                    arena: this.metaBefore,
                    relativeOffset: protectedHex32(this.offset),
                    absoluteOffset: protectedHex32(this.absoluteOffset),
                    value: protectedHex32(this.value),
                    existingValue: (() => {
                        try {
                            const value = protectedReadArenaAbsolute(this.arena, this.absoluteOffset);
                            return typeof value === 'number' ? protectedHex32(value) : value;
                        } catch (error) {
                            return '<unreadable:' + error + '>';
                        }
                    })(),
                    work: protectedReadWork(this.context.x20)
                }));
            } catch (error) {
                this.shouldTrace = false;
                trace('protected arena-writer enter failed=' + error);
            }
        },
        onLeave() {
            if (!this.shouldTrace) return;
            try {
                const stored = protectedReadArenaAbsolute(this.arena, this.absoluteOffset);
                trace('protected arena-writer leave=' + JSON.stringify({
                    caller: protectedHex32(this.caller),
                    status: protectedReadStatus(this.status),
                    arena: protectedReadArenaMeta(this.arena),
                    absoluteOffset: protectedHex32(this.absoluteOffset),
                    storedValue: typeof stored === 'number' ? protectedHex32(stored) : stored
                }));
            } catch (error) {
                trace('protected arena-writer leave failed=' + error);
            }
        }
    });

    // ABI at 0x138744:
    //   x0 = arena*, w1 = frame-relative offset, return w0 = value
    // Observe both the earlier arena-to-shared copy and the later
    // shared-to-lane copy.  The former is the first currently known point
    // where the static VM and the real device disagree.
    const namedReaderCallers = {
        0x0f5d20: 'f5d1c-source-read',
        0x0f58b4: 'f58b0-lane-copy-read'
    };
    Interceptor.attach(signer.base.add(0x138744), {
        onEnter(args) {
            try {
                this.caller = relativeAddress(this.returnAddress);
                this.callerName = namedReaderCallers[this.caller];
                this.shouldTrace = this.callerName !== undefined;
                if (!this.shouldTrace) return;
                this.arena = args[0];
                this.offset = args[1].toUInt32();
                this.meta = protectedReadArenaMeta(this.arena);
                this.absoluteOffset = (this.meta.base + this.offset) >>> 0;
            } catch (error) {
                this.shouldTrace = false;
                trace('protected arena-reader enter failed=' + error);
            }
        },
        onLeave(retval) {
            if (!this.shouldTrace) return;
            try {
                trace('protected arena-reader leave=' + JSON.stringify({
                    caller: protectedHex32(this.caller),
                    callerName: this.callerName,
                    arena: this.meta,
                    relativeOffset: protectedHex32(this.offset),
                    absoluteOffset: protectedHex32(this.absoluteOffset),
                    value: protectedHex32(retval.toUInt32())
                }));
            } catch (error) {
                trace('protected arena-reader leave failed=' + error);
            }
        }
    });

    trace('protected-engine helper-entry hooks installed');
}, 10);
