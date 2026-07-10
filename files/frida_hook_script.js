// Frida脚本 - 用于Hook和分析libspringIns.so

console.log("[*] Frida脚本已加载");

// 工具函数: 打印字节数组
function bytesToHex(bytes) {
    var result = '';
    for (var i = 0; i < bytes.length; i++) {
        var hex = bytes[i].toString(16);
        result += (hex.length === 1 ? '0' + hex : hex) + ' ';
        if ((i + 1) % 16 === 0) result += '\n';
    }
    return result;
}

// 工具函数: 读取jbyteArray
function readJByteArray(env, byteArray) {
    if (byteArray.isNull()) {
        return null;
    }
    
    var getByteArrayElements = env.handle.readPointer().add(Process.pointerSize * 183).readPointer();
    var releaseByteArrayElements = env.handle.readPointer().add(Process.pointerSize * 184).readPointer();
    var getArrayLength = env.handle.readPointer().add(Process.pointerSize * 171).readPointer();
    
    var isCopy = Memory.alloc(1);
    var getArrayLengthFn = new NativeFunction(getArrayLength, 'int32', ['pointer', 'pointer']);
    var length = getArrayLengthFn(env.handle, byteArray);
    
    var getByteArrayElementsFn = new NativeFunction(getByteArrayElements, 'pointer', ['pointer', 'pointer', 'pointer']);
    var elements = getByteArrayElementsFn(env.handle, byteArray, isCopy);
    
    var bytes = Memory.readByteArray(elements, length);
    
    var releaseByteArrayElementsFn = new NativeFunction(releaseByteArrayElements, 'void', ['pointer', 'pointer', 'pointer', 'int32']);
    releaseByteArrayElementsFn(env.handle, byteArray, elements, 2); // JNI_ABORT
    
    return bytes;
}

// 工具函数: 读取jstring
function readJString(env, jstr) {
    if (jstr.isNull()) {
        return null;
    }
    
    var getStringUTFChars = env.handle.readPointer().add(Process.pointerSize * 169).readPointer();
    var releaseStringUTFChars = env.handle.readPointer().add(Process.pointerSize * 170).readPointer();
    
    var isCopy = Memory.alloc(1);
    var getStringUTFCharsFn = new NativeFunction(getStringUTFChars, 'pointer', ['pointer', 'pointer', 'pointer']);
    var chars = getStringUTFCharsFn(env.handle, jstr, isCopy);
    
    var result = Memory.readCString(chars);
    
    var releaseStringUTFCharsFn = new NativeFunction(releaseStringUTFChars, 'void', ['pointer', 'pointer', 'pointer']);
    releaseStringUTFCharsFn(env.handle, jstr, chars);
    
    return result;
}

// ===== Hook Java层 =====
Java.perform(function() {
    console.log("[*] Java.perform() 开始");
    
    try {
        // Hook SpringUtil.getMyInstaData
        var SpringUtil = Java.use("a.backwebview.SpringUtil");
        
        SpringUtil.getMyInstaData.implementation = function(bArr) {
            console.log("\n[Java] SpringUtil.getMyInstaData 被调用");
            console.log("[Java] 输入字节数组长度:", bArr.length);
            
            // 打印前64字节
            if (bArr.length > 0) {
                var hexStr = "";
                for (var i = 0; i < Math.min(64, bArr.length); i++) {
                    hexStr += ("0" + (bArr[i] & 0xFF).toString(16)).slice(-2) + " ";
                }
                console.log("[Java] 输入数据(hex前64字节):\n" + hexStr);
            }
            
            // 调用原始方法
            var result = this.getMyInstaData(bArr);
            
            console.log("[Java] 返回值:", result);
            console.log("[Java] 返回值长度:", result ? result.length : 0);
            
            return result;
        };
        
        console.log("[+] SpringUtil.getMyInstaData Hook成功");
        
    } catch(e) {
        console.log("[-] Hook SpringUtil 失败:", e);
    }
    
    try {
        // Hook SpringUtil.getWeijuData
        var SpringUtil2 = Java.use("a.backwebview.SpringUtil");
        
        SpringUtil2.getWeijuData.implementation = function(bArr) {
            console.log("\n[Java] SpringUtil.getWeijuData 被调用");
            console.log("[Java] 输入字节数组长度:", bArr.length);
            
            var result = this.getWeijuData(bArr);
            console.log("[Java] 返回值:", result);
            
            return result;
        };
        
        console.log("[+] SpringUtil.getWeijuData Hook成功");
        
    } catch(e) {
        console.log("[-] Hook getWeijuData 失败:", e);
    }
    
    try {
        // Hook Utils.rL
        var Utils = Java.use("com.netease.nis.sdkwrapper.Utils");
        
        Utils.rL.implementation = function(objArr) {
            console.log("\n[Java] Utils.rL 被调用");
            console.log("[Java] 输入对象数组长度:", objArr ? objArr.length : 0);
            
            if (objArr) {
                for (var i = 0; i < objArr.length; i++) {
                    console.log("[Java] 参数[" + i + "]:", objArr[i]);
                }
            }
            
            var result = this.rL(objArr);
            console.log("[Java] 返回值:", result);
            
            return result;
        };
        
        console.log("[+] Utils.rL Hook成功");
        
    } catch(e) {
        console.log("[-] Hook Utils.rL 失败:", e);
    }
});

// ===== Hook Native层 =====
setTimeout(function() {
    console.log("\n[*] 开始Hook Native函数");
    
    var moduleName = "libspringIns.so";
    var module = Process.findModuleByName(moduleName);
    
    if (!module) {
        console.log("[-] 未找到模块:", moduleName);
        return;
    }
    
    console.log("[+] 找到模块:", module.name);
    console.log("[+] 基地址:", module.base);
    console.log("[+] 大小:", module.size);
    
    // Hook getMyInstaData
    try {
        var getMyInstaData = Module.findExportByName(moduleName, "_Z14getMyInstaDataP7_JNIEnvP8_jobjectP11_jbyteArray");
        
        if (getMyInstaData) {
            console.log("[+] 找到 getMyInstaData:", getMyInstaData);
            
            Interceptor.attach(getMyInstaData, {
                onEnter: function(args) {
                    console.log("\n[Native] getMyInstaData 被调用");
                    console.log("[Native] JNIEnv*:", args[0]);
                    console.log("[Native] jobject:", args[1]);
                    console.log("[Native] jbyteArray:", args[2]);
                    
                    // 尝试读取字节数组
                    try {
                        var bytes = readJByteArray(args[0], args[2]);
                        if (bytes) {
                            console.log("[Native] 输入数据长度:", bytes.byteLength);
                            console.log("[Native] 输入数据(hex前64字节):");
                            var view = new Uint8Array(bytes.slice(0, 64));
                            console.log(bytesToHex(view));
                            
                            // 保存用于onLeave
                            this.inputBytes = bytes;
                        }
                    } catch(e) {
                        console.log("[Native] 读取输入数据失败:", e);
                    }
                    
                    // 打印调用栈
                    console.log("[Native] 调用栈:");
                    console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).join('\n'));
                },
                onLeave: function(retval) {
                    console.log("[Native] getMyInstaData 返回");
                    console.log("[Native] 返回值(jstring):", retval);
                    
                    // 尝试读取返回的字符串
                    try {
                        var env = this.context.x0; // 第一个参数通常是JNIEnv*
                        var resultStr = readJString(env, retval);
                        console.log("[Native] 返回字符串:", resultStr);
                    } catch(e) {
                        console.log("[Native] 读取返回值失败:", e);
                    }
                }
            });
            
            console.log("[+] getMyInstaData Hook成功");
        } else {
            console.log("[-] 未找到 getMyInstaData 导出函数");
        }
    } catch(e) {
        console.log("[-] Hook getMyInstaData 失败:", e);
    }
    
    // Hook getWeijuData
    try {
        var getWeijuData = Module.findExportByName(moduleName, "_Z12getWeijuDataP7_JNIEnvP8_jobjectP11_jbyteArray");
        
        if (getWeijuData) {
            console.log("[+] 找到 getWeijuData:", getWeijuData);
            
            Interceptor.attach(getWeijuData, {
                onEnter: function(args) {
                    console.log("\n[Native] getWeijuData 被调用");
                    console.log("[Native] JNIEnv*:", args[0]);
                    console.log("[Native] jobject:", args[1]);
                    console.log("[Native] jbyteArray:", args[2]);
                    
                    try {
                        var bytes = readJByteArray(args[0], args[2]);
                        if (bytes) {
                            console.log("[Native] 输入数据长度:", bytes.byteLength);
                        }
                    } catch(e) {
                        console.log("[Native] 读取输入数据失败:", e);
                    }
                },
                onLeave: function(retval) {
                    console.log("[Native] getWeijuData 返回:", retval);
                }
            });
            
            console.log("[+] getWeijuData Hook成功");
        }
    } catch(e) {
        console.log("[-] Hook getWeijuData 失败:", e);
    }
    
    // Hook processData
    try {
        var processData = Module.findExportByName(moduleName, "_Z11processDataP7_JNIEnvP8_jobjectP11_jbyteArrayP8_jstring");
        
        if (processData) {
            console.log("[+] 找到 processData:", processData);
            
            Interceptor.attach(processData, {
                onEnter: function(args) {
                    console.log("\n[Native] processData 被调用");
                    console.log("[Native] JNIEnv*:", args[0]);
                    console.log("[Native] jobject:", args[1]);
                    console.log("[Native] jbyteArray:", args[2]);
                    console.log("[Native] jstring:", args[3]);
                    
                    // 读取字符串参数
                    try {
                        var str = readJString(args[0], args[3]);
                        console.log("[Native] 字符串参数:", str);
                    } catch(e) {
                        console.log("[Native] 读取字符串失败:", e);
                    }
                },
                onLeave: function(retval) {
                    console.log("[Native] processData 返回:", retval);
                }
            });
            
            console.log("[+] processData Hook成功");
        }
    } catch(e) {
        console.log("[-] Hook processData 失败:", e);
    }
    
    // Hook JNI_OnLoad
    try {
        var jniOnLoad = Module.findExportByName(moduleName, "JNI_OnLoad");
        
        if (jniOnLoad) {
            console.log("[+] 找到 JNI_OnLoad:", jniOnLoad);
            
            Interceptor.attach(jniOnLoad, {
                onEnter: function(args) {
                    console.log("\n[Native] JNI_OnLoad 被调用");
                    console.log("[Native] JavaVM*:", args[0]);
                },
                onLeave: function(retval) {
                    console.log("[Native] JNI_OnLoad 返回 JNI版本:", retval);
                }
            });
        }
    } catch(e) {
        console.log("[-] Hook JNI_OnLoad 失败:", e);
    }
    
}, 1000);

// ===== 内存搜索和Dump =====
function dumpMemory(moduleName, offset, size) {
    var module = Process.findModuleByName(moduleName);
    if (!module) {
        console.log("[-] 未找到模块");
        return;
    }
    
    var addr = module.base.add(offset);
    console.log("[*] Dumping从地址:", addr, "大小:", size);
    
    try {
        var data = Memory.readByteArray(addr, size);
        console.log("[+] Dump成功");
        // 可以通过send()发送到Python脚本保存
        send({
            type: 'memory_dump',
            address: addr.toString(),
            data: data
        });
    } catch(e) {
        console.log("[-] Dump失败:", e);
    }
}

// ===== 搜索特定字符串 =====
function searchString(moduleName, searchStr) {
    var module = Process.findModuleByName(moduleName);
    if (!module) {
        console.log("[-] 未找到模块");
        return;
    }
    
    console.log("[*] 在", moduleName, "中搜索字符串:", searchStr);
    
    Memory.scan(module.base, module.size, searchStr, {
        onMatch: function(address, size) {
            console.log("[+] 找到匹配:", address);
            console.log("    上下文:", Memory.readCString(address, 100));
        },
        onComplete: function() {
            console.log("[*] 搜索完成");
        }
    });
}

console.log("\n[*] Frida脚本初始化完成");
console.log("[*] 可用命令:");
console.log("    dumpMemory('libspringIns.so', 0x1000, 4096)");
console.log("    searchString('libspringIns.so', 'AES')");
