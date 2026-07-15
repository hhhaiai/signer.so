'use strict';

const FIXED_PID = 4242;
const FIXED_SECONDS = 1760000000;
const FIXED_MICROSECONDS = 123000;
const FIXED_NANOSECONDS = 123000000;
const FIXED_URANDOM = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
const randomFileDescriptors = {};
let activeThreadId = -1;
let activeDepth = 0;
let armPlaintextCapture = null;

function callerIsSigner(address) {
    try {
        const module = Process.findModuleByAddress(address);
        return module !== null && module.name === 'libsigner.so';
    } catch (_) {
        return false;
    }
}

function exported(module, name) {
    try {
        return module.getExportByName(name);
    } catch (_) {
        return null;
    }
}

function trace(message) {
    console.log('[qbdi-reference] ' + message);
}

function isControlledCall(returnAddress) {
    return callerIsSigner(returnAddress) ||
        (activeDepth > 0 && Process.getCurrentThreadId() === activeThreadId);
}

const libc = Process.getModuleByName('libc.so');

const getpid = exported(libc, 'getpid');
if (getpid !== null) {
    Interceptor.attach(getpid, {
        onEnter() { this.hit = isControlledCall(this.returnAddress); },
        onLeave(retval) {
            if (!this.hit) return;
            trace('getpid actual=' + retval.toInt32() + ' fixed=' + FIXED_PID);
            retval.replace(FIXED_PID);
        }
    });
}

['getuid', 'geteuid', 'getgid', 'getegid', 'getppid'].forEach(function (name) {
    const address = exported(libc, name);
    if (address === null) return;
    Interceptor.attach(address, {
        onEnter() { this.hit = isControlledCall(this.returnAddress); },
        onLeave(retval) {
            if (this.hit) trace(name + '=' + retval.toInt32());
        }
    });
});

['timer_create', 'timer_settime'].forEach(function (name) {
    const address = exported(libc, name);
    if (address === null) return;
    Interceptor.attach(address, {
        onEnter(args) {
            this.hit = isControlledCall(this.returnAddress);
            this.a0 = args[0];
            this.a1 = args[1];
            this.a2 = args[2];
            this.a3 = args[3];
        },
        onLeave(retval) {
            if (this.hit) trace(name + ' args=' + this.a0 + ',' + this.a1 + ',' + this.a2 + ',' + this.a3 +
                ' result=' + retval.toInt32());
        }
    });
});

const time = exported(libc, 'time');
if (time !== null) {
    Interceptor.attach(time, {
        onEnter(args) {
            this.hit = isControlledCall(this.returnAddress);
            this.out = args[0];
        },
        onLeave(retval) {
            if (!this.hit) return;
            if (!this.out.isNull()) this.out.writeS64(FIXED_SECONDS);
            trace('time actual=' + retval.toString() + ' fixed=' + FIXED_SECONDS);
            retval.replace(FIXED_SECONDS);
        }
    });
}

const gettimeofday = exported(libc, 'gettimeofday');
if (gettimeofday !== null) {
    Interceptor.attach(gettimeofday, {
        onEnter(args) {
            this.hit = isControlledCall(this.returnAddress);
            this.out = args[0];
        },
        onLeave(retval) {
            if (!this.hit || this.out.isNull()) return;
            this.out.writeS64(FIXED_SECONDS);
            this.out.add(8).writeS64(FIXED_MICROSECONDS);
            trace('gettimeofday fixed=' + FIXED_SECONDS + '.' + FIXED_MICROSECONDS);
            retval.replace(0);
        }
    });
}

const clockGettime = exported(libc, 'clock_gettime');
if (clockGettime !== null) {
    Interceptor.attach(clockGettime, {
        onEnter(args) {
            this.hit = isControlledCall(this.returnAddress);
            this.clockId = args[0].toInt32();
            this.out = args[1];
        },
        onLeave(retval) {
            if (!this.hit || this.out.isNull()) return;
            this.out.writeS64(FIXED_SECONDS);
            this.out.add(8).writeS64(FIXED_NANOSECONDS);
            trace('clock_gettime clock=' + this.clockId + ' fixed=' + FIXED_SECONDS + '.' + FIXED_NANOSECONDS);
            retval.replace(0);
        }
    });
}

const srand = exported(libc, 'srand');
if (srand !== null) {
    Interceptor.attach(srand, {
        onEnter(args) {
            if (!isControlledCall(this.returnAddress)) return;
            if (armPlaintextCapture !== null) {
                const install = armPlaintextCapture;
                armPlaintextCapture = null;
                install();
            }
            trace('srand actual=' + args[0].toUInt32() + ' fixed=' + FIXED_SECONDS);
            args[0] = ptr(FIXED_SECONDS);
        }
    });
}

const rand = exported(libc, 'rand');
if (rand !== null) {
    Interceptor.attach(rand, {
        onEnter() { this.hit = isControlledCall(this.returnAddress); },
        onLeave(retval) {
            if (this.hit) trace('rand=' + retval.toInt32());
        }
    });
}

const propertyGet = exported(libc, '__system_property_get');
if (propertyGet !== null) {
    Interceptor.attach(propertyGet, {
        onEnter(args) {
            this.hit = isControlledCall(this.returnAddress);
            this.name = this.hit ? args[0].readCString() : null;
            this.value = args[1];
        },
        onLeave() {
            if (this.hit) trace('__system_property_get ' + this.name + '=' + this.value.readCString());
        }
    });
}

const getauxval = exported(libc, 'getauxval');
if (getauxval !== null) {
    Interceptor.attach(getauxval, {
        onEnter(args) {
            this.hit = isControlledCall(this.returnAddress);
            this.type = args[0].toUInt32();
        },
        onLeave(retval) {
            if (!this.hit) return;
            let extra = '';
            if (this.type === 25 && !retval.isNull()) {
                try { extra = ' bytes=' + hexBytes(retval, 16); } catch (_) {}
            }
            trace('getauxval type=' + this.type + ' result=' + retval + extra);
        }
    });
}

function hexBytes(pointer, length) {
    if (length <= 0 || pointer.isNull()) return '';
    const bytes = new Uint8Array(pointer.readByteArray(Math.min(length, 64)));
    let value = '';
    for (let i = 0; i < bytes.length; i++) value += ('0' + bytes[i].toString(16)).slice(-2);
    return value;
}

function hexBytesFull(pointer, length) {
    if (length <= 0 || pointer.isNull()) return '';
    const bytes = new Uint8Array(pointer.readByteArray(Math.min(length, 4096)));
    let value = '';
    for (let i = 0; i < bytes.length; i++) value += ('0' + bytes[i].toString(16)).slice(-2);
    return value;
}

const read = exported(libc, 'read');
if (read !== null) {
    Interceptor.attach(read, {
        onEnter(args) {
            this.hit = isControlledCall(this.returnAddress);
            this.fd = args[0].toInt32();
            this.buffer = args[1];
            this.count = args[2].toUInt32();
        },
        onLeave(retval) {
            if (!this.hit) return;
            const length = retval.toInt32();
            if (length > 0 && randomFileDescriptors[this.fd] === true) {
                const replacement = [];
                for (let i = 0; i < length; i++) replacement.push(FIXED_URANDOM[i % FIXED_URANDOM.length]);
                this.buffer.writeByteArray(replacement);
                trace('read fd=' + this.fd + ' /dev/urandom fixed=' + hexBytes(this.buffer, length));
                return;
            }
            if (this.count <= 64) {
                trace('read fd=' + this.fd + ' requested=' + this.count + ' result=' + length +
                    ' bytes=' + (length > 0 ? hexBytes(this.buffer, length) : ''));
            }
        }
    });
}

function socketAddress(pointer, length) {
    if (pointer.isNull() || length < 2) return '<null>';
    const family = pointer.readU16();
    if (family === 2 && length >= 8) {
        const port = (pointer.add(2).readU8() << 8) | pointer.add(3).readU8();
        const parts = [];
        for (let i = 0; i < 4; i++) parts.push(pointer.add(4 + i).readU8());
        return 'inet:' + parts.join('.') + ':' + port;
    }
    if (family === 10 && length >= 28) {
        const port = (pointer.add(2).readU8() << 8) | pointer.add(3).readU8();
        return 'inet6:port=' + port + ' raw=' + hexBytes(pointer, Math.min(length, 28));
    }
    if (family === 1) {
        let path = '';
        try { path = pointer.add(2).readCString(); } catch (_) {}
        return 'unix:' + path;
    }
    return 'family=' + family + ' raw=' + hexBytes(pointer, Math.min(length, 32));
}

const socket = exported(libc, 'socket');
if (socket !== null) {
    Interceptor.attach(socket, {
        onEnter(args) {
            this.hit = isControlledCall(this.returnAddress);
            this.domain = args[0].toInt32();
            this.type = args[1].toInt32();
            this.protocol = args[2].toInt32();
        },
        onLeave(retval) {
            if (this.hit) trace('socket domain=' + this.domain + ' type=' + this.type +
                ' protocol=' + this.protocol + ' result=' + retval.toInt32());
        }
    });
}

const connect = exported(libc, 'connect');
if (connect !== null) {
    Interceptor.attach(connect, {
        onEnter(args) {
            this.hit = isControlledCall(this.returnAddress);
            this.fd = args[0].toInt32();
            this.address = this.hit ? socketAddress(args[1], args[2].toUInt32()) : '';
            this.blockFridaProbe = this.hit && this.address === 'inet:127.0.0.1:27042';
        },
        onLeave(retval) {
            if (!this.hit) return;
            if (this.blockFridaProbe) {
                if (errnoPointer !== null) errnoPointer().writeS32(111);
                retval.replace(-1);
                trace('connect fd=' + this.fd + ' address=' + this.address + ' forced=ECONNREFUSED');
            } else {
                trace('connect fd=' + this.fd + ' address=' + this.address +
                    ' result=' + retval.toInt32());
            }
        }
    });
}

const sendto = exported(libc, 'sendto');
if (sendto !== null) {
    Interceptor.attach(sendto, {
        onEnter(args) {
            this.hit = isControlledCall(this.returnAddress);
            this.fd = args[0].toInt32();
            this.buffer = args[1];
            this.length = args[2].toUInt32();
            this.address = this.hit ? socketAddress(args[4], args[5].toUInt32()) : '';
        },
        onLeave(retval) {
            if (this.hit) trace('sendto fd=' + this.fd + ' address=' + this.address +
                ' length=' + this.length + ' result=' + retval.toInt32() +
                ' bytes=' + hexBytes(this.buffer, this.length));
        }
    });
}

const recvfrom = exported(libc, 'recvfrom');
if (recvfrom !== null) {
    Interceptor.attach(recvfrom, {
        onEnter(args) {
            this.hit = isControlledCall(this.returnAddress);
            this.fd = args[0].toInt32();
            this.buffer = args[1];
            this.length = args[2].toUInt32();
        },
        onLeave(retval) {
            if (!this.hit) return;
            const length = retval.toInt32();
            trace('recvfrom fd=' + this.fd + ' requested=' + this.length + ' result=' + length +
                ' bytes=' + (length > 0 ? hexBytes(this.buffer, length) : ''));
        }
    });
}

const fread = exported(libc, 'fread');
if (fread !== null) {
    Interceptor.attach(fread, {
        onEnter(args) {
            this.hit = isControlledCall(this.returnAddress);
            this.buffer = args[0];
            this.size = args[1].toUInt32();
            this.count = args[2].toUInt32();
        },
        onLeave(retval) {
            if (!this.hit) return;
            const items = retval.toUInt32();
            const length = items * this.size;
            trace('fread size=' + this.size + ' requested=' + this.count + ' result=' + items +
                ' bytes=' + (length > 0 ? hexBytes(this.buffer, length) : ''));
        }
    });
}

function tracePath(name, argumentIndex) {
    const address = exported(libc, name);
    if (address === null) return;
    Interceptor.attach(address, {
        onEnter(args) {
            this.hit = callerIsSigner(this.returnAddress);
            if (!this.hit) return;
            try {
                this.path = args[argumentIndex].readCString();
            } catch (_) {
                this.path = '<unreadable>';
            }
        },
        onLeave(retval) {
            if (this.hit) trace(name + ' path=' + this.path + ' result=' + retval.toString());
        }
    });
}

tracePath('access', 0);
tracePath('fopen', 0);
tracePath('open', 0);
tracePath('open64', 0);
tracePath('openat', 1);
tracePath('readlink', 0);
tracePath('stat', 0);

const errnoAddress = exported(libc, '__errno');
const errnoPointer = errnoAddress === null ? null : new NativeFunction(errnoAddress, 'pointer', []);
const opendir = exported(libc, 'opendir');
if (opendir !== null) {
    Interceptor.attach(opendir, {
        onEnter(args) {
            this.hit = isControlledCall(this.returnAddress);
            this.path = this.hit ? args[0].readCString() : null;
            this.forceMissing = this.hit && this.path === '/proc/self/fd';
        },
        onLeave(retval) {
            if (!this.hit) return;
            if (this.forceMissing) {
                if (errnoPointer !== null) errnoPointer().writeS32(2);
                retval.replace(ptr(0));
                trace('opendir path=' + this.path + ' forced=ENOENT');
            } else {
                trace('opendir path=' + this.path + ' result=' + retval.toString());
            }
        }
    });
}

const syscall = exported(libc, 'syscall');
if (syscall !== null) {
    Interceptor.attach(syscall, {
        onEnter(args) {
            this.hit = isControlledCall(this.returnAddress);
            if (!this.hit) return;
            this.number = args[0].toInt32();
            this.out = args[1];
            if (this.number === 56) {
                this.openPath = null;
                try { this.openPath = args[2].readCString(); } catch (_) {}
            } else if (this.number === 57) {
                this.closeFd = args[1].toInt32();
            }
        },
        onLeave(retval) {
            if (!this.hit) return;
            if (this.number === 56 && this.openPath === '/dev/urandom') {
                const fd = retval.toInt32();
                if (fd >= 0) randomFileDescriptors[fd] = true;
                trace('syscall openat /dev/urandom fd=' + fd);
            } else if (this.number === 57) {
                delete randomFileDescriptors[this.closeFd];
            } else if (this.number === 172) {
                trace('syscall getpid fixed=' + FIXED_PID);
                retval.replace(FIXED_PID);
            } else if (this.number === 169 && !this.out.isNull()) {
                this.out.writeS64(FIXED_SECONDS);
                this.out.add(8).writeS64(FIXED_MICROSECONDS);
                trace('syscall gettimeofday fixed=' + FIXED_SECONDS + '.' + FIXED_MICROSECONDS);
                retval.replace(0);
            } else {
                trace('syscall number=' + this.number + ' result=' + retval);
            }
        }
    });
}

let signerHooked = false;
const signerPoll = setInterval(function () {
    if (signerHooked) return;
    const module = Process.findModuleByName('libsigner.so');
    if (module === null) return;
    signerHooked = true;
    clearInterval(signerPoll);
    trace('libsigner.so loaded base=' + module.base + ' size=' + module.size);
    let plaintextBuffer = NULL;
    let plaintextLength = 0;
    armPlaintextCapture = function () {
        const callocAddress = exported(libc, 'calloc');
        const freeAddress = exported(libc, 'free');
        if (callocAddress === null) return;
        let callocHook = null;
        callocHook = Interceptor.attach(callocAddress, {
            onEnter(args) {
                this.caller = callerIsSigner(this.returnAddress)
                    ? this.returnAddress.sub(module.base) : ptr(0);
                this.count = args[0].toUInt32();
                this.size = args[1].toUInt32();
            },
            onLeave(retval) {
                if (!this.caller.equals(ptr(0x11d9e0)) || retval.isNull()) return;
                plaintextBuffer = retval;
                plaintextLength = this.count * this.size;
                trace('plaintext-allocation pointer=' + retval + ' length=' + plaintextLength);
                callocHook.detach();
            }
        });
        if (freeAddress !== null) {
            let freeHook = null;
            freeHook = Interceptor.attach(freeAddress, {
                onEnter(args) {
                    if (plaintextBuffer.isNull() || !args[0].equals(plaintextBuffer)) return;
                    trace('plaintext-before-free hex=' + hexBytesFull(plaintextBuffer, plaintextLength));
                    freeHook.detach();
                }
            });
        }
    };
    Interceptor.attach(module.base.add(0x95680), {
        onEnter(args) {
            try {
                const length = args[4].toInt32();
                const buffer = args[5];
                trace('set-byte-array-region caller=libsigner.so+0x' +
                    this.returnAddress.sub(module.base).toString(16) +
                    ' length=' + length + ' pointer=' + buffer +
                    ' bytes=' + hexBytesFull(buffer, length));
            } catch (error) {
                trace('set-byte-array-region failed=' + error);
            }
        }
    });
    try {
        module.enumerateImports().forEach(function (entry) {
            if (['getpid', 'gettimeofday', 'clock_gettime', 'time', 'srand', 'rand', 'getauxval', 'read', 'syscall'].indexOf(entry.name) !== -1) {
                trace('import ' + entry.name + ' module=' + entry.module + ' address=' + entry.address + ' slot=' + entry.slot);
            }
        });
    } catch (error) {
        trace('enumerateImports failed: ' + error);
    }
    function markNativeCall(name) {
        const address = exported(module, name);
        if (address === null) return;
        Interceptor.attach(address, {
            onEnter() {
                if (activeDepth === 0) activeThreadId = Process.getCurrentThreadId();
                activeDepth++;
                trace(name + ' enter thread=' + activeThreadId);
            },
            onLeave(retval) {
                trace(name + ' leave result=' + retval);
                activeDepth--;
                if (activeDepth === 0) activeThreadId = -1;
            }
        });
    }
    markNativeCall('Java_com_adjust_sdk_sig_NativeLibHelper_nOnResume');
    const nSign = exported(module, 'Java_com_adjust_sdk_sig_NativeLibHelper_nSign');
    if (nSign !== null) {
        Interceptor.attach(nSign, {
            onEnter(args) {
                if (activeDepth === 0) activeThreadId = Process.getCurrentThreadId();
                activeDepth++;
                trace('NativeLibHelper.nSign enter thread=' + activeThreadId);
                try {
                    const env = Java.vm.tryGetEnv();
                    const length = env.getArrayLength(args[4]);
                    const elements = env.getByteArrayElements(args[4], NULL);
                    trace('nSign-input-native bytes=' + hexBytesFull(elements, length));
                    env.releaseByteArrayElements(args[4], elements, 2);
                } catch (error) {
                    trace('nSign-input-native failed=' + error);
                }
            },
            onLeave(retval) {
                trace('environment-flags hex=' + hexBytesFull(module.base.add(0x146840), 64));
                trace('plaintext-at-sign-return hex=' +
                    (plaintextBuffer.isNull() ? '<missing>' : hexBytesFull(plaintextBuffer, plaintextLength)));
                trace('NativeLibHelper.nSign leave jobject=' + retval);
                activeDepth--;
                if (activeDepth === 0) activeThreadId = -1;
            }
        });
    }
}, 10);

trace('hooks installed');
