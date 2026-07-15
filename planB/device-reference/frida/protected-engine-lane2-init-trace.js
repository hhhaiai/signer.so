// Minimal read-only probe for the protected-engine descriptor-3 import.
// Only one real helper entry is hooked, and only the four calls returning to
// 0xf1fbc are logged.  No register, memory or control-flow mutation occurs.

let protectedLane2TraceInstalled = false;
const protectedLane2TracePoll = setInterval(function () {
    if (protectedLane2TraceInstalled) return;
    const signer = Process.findModuleByName('libsigner.so');
    if (signer === null) return;
    protectedLane2TraceInstalled = true;
    clearInterval(protectedLane2TracePoll);

    Interceptor.attach(signer.base.add(0x138318), {
        onEnter(args) {
            const caller = this.returnAddress.sub(signer.base).toUInt32();
            if (caller !== 0x0f1fbc) return;
            const hex32 = value => '0x' +
                    ('00000000' + value.toUInt32().toString(16)).slice(-8);
            trace('protected lane2-init=' + JSON.stringify({
                caller: '0x000f1fbc',
                status: args[0].readS32(),
                arena: args[1].toString(),
                offset: hex32(args[2]),
                valueAfterRev32: hex32(args[3])
            }));
        }
    });
    trace('protected-engine minimal lane2-init hook installed');
}, 10);
