原创 二手的程序员 2026-07-08 21:19:50

精确发文时间由壹伴提供

手机阅读

> https://github.com/QBDI/QBDI

> https://bbs.kanxue.com/thread-289884.htm

QBDI是一个动态二进制插桩框架，可以用于trace真机so。相比于 Unidbg，就是不用补各种环境，虽然对于AI来说，这都是小问题。但是它还有几个巨大的缺点：

1. Unidbg太慢了，有一些so会在app运行5-10分钟后才会触发一些逻辑，Unidbg模拟起来会进入空转状态。
2. 有时候还会与网络等进行交互，弄起来很糟心，一些特征也需要伪造。
3. 生命周期问题，有些so的一些方法是有调用顺序的，还会涉及到消息队列等，这些模拟起来就得先摸清楚整套so的java与native交互，不然会在奇葩的地方卡住，或者走不全逻辑。

真机的trace，之前是尝试过 Frida 的 Stalker，但是不稳定，挂上去就crash，后来尝试了 GumTrace，说是提升了稳定性，有一个 so 确实可以 trace 了，但是依然无法 trace 另一个 so。

QBDI 与 stalker 的实现方式不一样，听说优点是稳定，先来看看其实现原理。

## 基本原理

QBDI 是一个"代码翻译执行器"——它不直接运行你的程序，而是把程序一小块一小块地"抄"到自己的工作区，插入监控代码后再执行，从而实现对每条指令的监控和控制。

这里会涉及到比较多的东西，比如：

- 如何介入程序的运行
- 在翻译程序时如何保证正确
- 运行程序时如何保存程序状态以便在监控代码与程序代码中切换

我们后续慢慢介绍，先看整体架构：

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                   │
│                        QBDI 整体架构                              │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │                    你的代码 (Guest)                        │    │
│  │                                                            │    │
│  │    func:                                                   │    │
│  │      add x0, x1, x2      ← 原始指令                      │    │
│  │      ldr x3, [x0, #8]                                     │    │
│  │      cmp x3, #0                                            │    │
│  │      b.eq label                                            │    │
│  │      ...                                                   │    │
│  └──────────────────────────────────────────────────────────┘    │
│                          │                                        │
│                          │ 读取 & 反汇编                         │
│                          ▼                                        │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │                   VM Engine (大脑)                         │    │
│  │                                                            │    │
│  │  • 读取原始代码                                            │    │
│  │  • 划分基本块 (Basic Block)                                │    │
│  │  • 生成插桩后的代码 (CodeBlock)                            │    │
│  │  • 管理执行流程                                            │    │
│  │  • 调用用户注册的回调                                      │    │
│  └──────────────────────────────────────────────────────────┘    │
│                          │                                        │
│                          │ 生成                                   │
│                          ▼                                        │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │                CodeBlock (副本+监控)                       │    │
│  │                                                            │    │
│  │    [回调setup] → [原始指令0] → [回调setup] → [原始指令1]  │    │
│  │    → ... → [BB终结器: 回到 VM Engine]                     │    │
│  │                                                            │    │
│  │    ← 实际被 CPU 执行的是这里                              │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

基本块 = 一段"没有分叉"的连续指令。为什么按 BB 处理？粒度适中：比单条指令高效，比整个函数灵活。

qbdi本质上是一个VM，所以VM Engine部分就是一个循环，会不断的对 BB 进行处理，然后执行，同时也会触发我们设置的回调。

## 上下文切换

需要先说清楚一个概念，就是 Host 与 Guest。我们称 QBDI 为 Host，称需要监控的程序为 Guest。

QBDI是让目标程序运行在自己内部，通过给目标程序进行插桩来实现监控的目的。这里就需要上下文切换与指令处理技术。

QBDI必然要做到对目标程序透明，也就是 Guest 有自己的 context，QBDI 自己也需要运行，它也有自己的 context，当程序控制流在 guest 与 host 之间互相切换的时候（CPU 只有一套物理寄存器 ），就需要先保存自己的 context，恢复别人的 context。

GPRState和FPRState，一个保存通用寄存器，一个保存浮点寄存器。

寄存器的保存也需要好好设计，设想有一个需要trace的代码片段，它使用了所有的通用寄存器进行某种计算，在里边添加的instrument指令是某种函数调用，调用到qbdi提供的指令跟踪函数(处于qbdi上下文)，那么这些instrument指令如何实现?

如果是近端可以使用pc相对寻址，如果是远端则需要借助于ADRP/LDR这样的指令，这样就引入了对某个guest寄存器的修改，就需要保存该寄存器，执行完指令以后再恢复。

那么保存到哪里又成了问题，像普通的函数调用是有调用约定，caller保存一些可能被callee修改的寄存器在栈上，调用完之后从栈中恢复。

但对qbdi来说它不能保存在guest的栈上(会破坏原代码环境)，那么就需要保存到qbdi上下文的内存中，这段内存需要事先配置好让guest上下文中的代码可以相对寻址访问到，qbdi对应的则为ExecBlock。

![图片](data:image/svg+xml,%3C%3Fxml version='1.0' encoding='UTF-8'%3F%3E%3Csvg width='1px' height='1px' viewBox='0 0 1 1' version='1.1' xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink'%3E%3Ctitle%3E%3C/title%3E%3Cg stroke='none' stroke-width='1' fill='none' fill-rule='evenodd' fill-opacity='0'%3E%3Cg transform='translate(-249.000000, -126.000000)' fill='%23FFFFFF'%3E%3Crect x='249' y='126' width='1' height='1'%3E%3C/rect%3E%3C/g%3E%3C/g%3E%3C/svg%3E)

两个核心概念，一个是 DataBlock，一个是 CodeBlock。这两个构成了 ExecBlock。

CodeBlock 里面装的就是插桩后的 BB。在执行 CodeBlock 内的指令时，一些数据访问会被导向 DataBlock 里面去。

这样设计的目的是为了让修改之后的指令可以使用相对寻址方式访问到dataBlock中的数据。

## PatchDSL

qbdi使用LLVM的MC功能来反汇编、分析以及生成目标指令。

![图片](data:image/svg+xml,%3C%3Fxml version='1.0' encoding='UTF-8'%3F%3E%3Csvg width='1px' height='1px' viewBox='0 0 1 1' version='1.1' xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink'%3E%3Ctitle%3E%3C/title%3E%3Cg stroke='none' stroke-width='1' fill='none' fill-rule='evenodd' fill-opacity='0'%3E%3Cg transform='translate(-249.000000, -126.000000)' fill='%23FFFFFF'%3E%3Crect x='249' y='126' width='1' height='1'%3E%3C/rect%3E%3C/g%3E%3C/g%3E%3C/svg%3E)

可以看到，出现了两次 Patch，一次是需要将原始指令拷贝到 CodeBlock，比如会对一些 pc 相关的指令处理，避免地址错误。第二次是添加指令监控，也是我们设置的回调，就需要在指令执行前和执行后都插入回调函数调用指令，以及 context 恢复等等指令。

举个例子：原始指令位于地址 `0x1000` ，但实际执行时在 ExecBlock 中（比如地址 `0x7F000000` ）。所有 **依赖当前PC值** 的指令都会产生错误结果。

```
原始指令（在 Guest 原始位置 0x1000）:
    ldr x8, [pc, #0x14]     ; 从 PC+0x14 = 0x1014 处加载一个 64-bit 值到 x8

Patched（在 ExecBlock 中，PC 已经变了，不能直接用 PC 相对寻址了）:
    ldr x28, [x27, #1248]   ; 从 DataBlock 中的 shadow slot 加载预计算好的地址
    ldr x8, [x28]           ; 用该地址做间接加载，结果放入 x8
```

这里，我们需要先计算出 PC + 0x14 的值，写入 DataBlock 中，然后将这个地址写入 patch 后的指令中。

x27 寄存器（ScratchRegister）被当成了类似基址寄存器一样的东西，用途是指向dataBlock让PatchDSL中的寄存器可以访问dataBlock。

**可以看到 patch 的指令中经常出现 x28, 为什么选 x28？**

x28 在这里更多是一个临时寄存器。QBDI 会分析当前 guest 指令使用了哪些寄存器，如果 x28 没有冲突，就优先借用它；如果 x28 被目标指令使用，TempManager 会换其他通用寄存器作为 Temp，或者插入保存/恢复逻辑。

x28 寄存器靠后，被 guest 使用的概率相对小一些，有助于减少额外保存/恢复的成本。但重点不是 x28 天然安全，而是 QBDI 会保证借用临时寄存器时不破坏 guest 的真实语义。

看一个当 x27 被使用到的patch例子：

```
long sum_all_gprs() {
  long sum;
  // 内联汇编：读取所有通用寄存器并相加
    __asm__ volatile(
      "mov x0, #0\\n"
      "add x0, x0, x1\\n"
      ...
      "add x0, x0, x28\\n"
      "mov %[sum], x0\\n"
      : [sum] "=r"(sum)
      :
      : "memory", "cc"
  );
  return sum;
}
```

下面的代码所对应的patch后的指令，主要关注add x0,x0, x27 这条指令：

```
--> 发现从此条指令开始x27 ScratchRegister寄存器被使用
--> 从当前指令开始调用initScratchRegisterForPatch计算出新的ScratchRegister为x26
--> 然后执行函数changeScratchRegister
ldr    x28, [x27]               --> 原先hostState.scratchRegisterValue的值赋值给temp Reg X28
str    x26, [x27]               --> 新的ScratchRegister x26存入hostState.scratchRegisterValue
mov    x26, x27                 --> 更换ScratchRegister,从旧的x27到新的x26,x26就指向了datablock地址
mov    x27, x28                 --> 恢复x27的值
mov    x28, #26                 --> #26为x26的下标值
str    x28, [x26, #8]           --> 下标值存入到hostState.currentSROffset中
------------------------------>下面就是instrum逻辑
ldr    x28, [x26, #1344]
str    x28, [x26, #32]
mov    x28, #0
str    x28, [x26, #40]
mov    x28, #28
str    x28, [x26, #48]
ldr    x28, [x26, #1352]
str    x28, [x26, #336]
adr    x28, #12
str    x28, [x26, #24]
b    #2396
add    x0, x0, x27           --> 原始指令
```

可以看到逻辑比较绕，但是总的来说，就是换了一个寄存器来储存而已：

```
┌────────────────────────────────────────────────────────────────┐
│  执行前:                                                        │
│    x27 = DataBlock 基址 (Scratch)                              │
│    x26 = Guest 的真实 x26 值                                   │
│    DataBlock.scratchRegisterValue = Guest 的真实 x27 值        │
│    DataBlock.currentSROffset = 27                              │
│                                                                │
│  执行后:                                                        │
│    x26 = DataBlock 基址 (新 Scratch)                           │
│    x27 = Guest 的真实 x27 值 (已恢复！)                        │
│    DataBlock.scratchRegisterValue = Guest 的真实 x26 值        │
│    DataBlock.currentSROffset = 26                              │
└────────────────────────────────────────────────────────────────┘
```

当 guest 指令使用到了当前的 ScratchRegister 时，QBDI 会重新选择一个 ScratchRegister。核心目的就是保证始终有一个寄存器能指向 DataBlock，同时又不影响 guest 原本要使用的寄存器。

## 序言和尾声

qbdi执行函数前，需要先给 guest 准备好 SP、参数和返回地址。常见用法是通过 `allocateVirtualStack` 分配一块虚拟栈，再将 guest 的 SP 指向栈顶；栈大小不是固定的 1M，而是由调用者传入。

qbdi会准备好函数调用所需的参数，对于arm64来说就是将前8个参数放在 x0-x7 中，其余参数入栈，并且将Context中的lr寄存器设置为虚拟返回地址42，这样qbdi就可以监控函数的返回。

设置好环境以后qbdi就开始了patch，instrument的操作生成各个ExecBlock，每一块ExecBlock都有序言和尾声片段，序言位于codeBlock起始处，尾声则占据着codeBlock末尾。

序言和尾声部分涉及到存储和保存qbdi和guest上下文，qbdi上下文位于Context.hostState结构中，guest上下文位于Context.gprState和Context.fprState结构中。

一个例子：

```
hint 0x22   -->  是BTI指令的另一种编码形式, 功能上HINT 0x22完全等价于BTI C --> 允许通过 BR 或 BLR 跳转至此。这一步是为了避开开启了BTI安全扩展机制的机器上跳转的限制。这一点可以通过执行echo "BTI C " | llvm-mc --assemble -triple=aarch64 --show-inst得到验证
adrp    x28, #4096             -->X28 is used to address the DataBlock(此时仍然处于host上下文，用x28保存datablock基址)
str    x30, [sp, #-16]!       --> Save return address
mov    x0, sp                     --> Save Host SP
str    x0, [x28, #16]   --> 保存到Context.hostState.sp
add    x0, x28, #368      --> Restore SIMD

ld1    { v0.2d, v1.2d, v2.2d, v3.2d }, [x0], #64   --> 加载完成后，X0寄存器的值会自动增加64字节（这是后变址寻址模式）。
ld1    { v4.2d, v5.2d, v6.2d, v7.2d }, [x0], #64
ld1    { v8.2d, v9.2d, v10.2d, v11.2d }, [x0], #64
ld1    { v12.2d, v13.2d, v14.2d, v15.2d }, [x0], #64
ld1    { v16.2d, v17.2d, v18.2d, v19.2d }, [x0], #64
ld1    { v20.2d, v21.2d, v22.2d, v23.2d }, [x0], #64
ld1    { v24.2d, v25.2d, v26.2d, v27.2d }, [x0], #64
ld1    { v28.2d, v29.2d, v30.2d, v31.2d }, [x0], #64
ldp    x1, x2, [x0], #16   --> Restore FPCR and FPSR

msr    FPCR, x1
msr    FPSR, x2
add    x0, x28, #72
ldp    x1, x2, [x0, #248]     --> Restore Stack and NZCV
msr    NZCV, x2
mov    sp, x1

ldp    x29, x30, [x0, #232]    --> Restore LR and X29
ldp    x26, x27, [x0, #208]    --> Load other registers
ldp    x24, x25, [x0, #192]
ldp    x22, x23, [x0, #176]
ldp    x20, x21, [x0, #160]
ldp    x18, x19, [x0, #144]
ldp    x16, x17, [x0, #128]
ldp    x14, x15, [x0, #112]
ldp    x12, x13, [x0, #96]
ldp    x10, x11, [x0, #80]
ldp    x8, x9, [x0, #64]
ldp    x6, x7, [x0, #48]
ldp    x4, x5, [x0, #32]
ldp    x2, x3, [x0, #16]
ldp    x0, x1, [x0]
ldr    x28, [x28, #24]        -->  Context.hostState.selector -->  Jump selector , 在ExecBlock::selectSeq的函数中赋值

br    x28   --> 跳转到对应的selector即基本块运行
```

总结就是：x28设置为datablock起始块，恢复上下文，跳转到 selector 去执行。

尾声Epilogue就是反过来了：

```
adrp    x28, #4096    -->利用adrp将x28设置为datablock的起始地址

stp    x0, x1, [x28, #72]  --> Save GPR from the guest
stp    x2, x3, [x28, #88]
stp    x4, x5, [x28, #104]
stp    x6, x7, [x28, #120]
stp    x8, x9, [x28, #136]
stp    x10, x11, [x28, #152]
stp    x12, x13, [x28, #168]
stp    x14, x15, [x28, #184]
stp    x16, x17, [x28, #200]
stp    x18, x19, [x28, #216]
stp    x20, x21, [x28, #232]
stp    x22, x23, [x28, #248]
stp    x24, x25, [x28, #264]
stp    x26, x27, [x28, #280]
stp    x29, x30, [x28, #304]    --> Save X29 and LR

mrs    x1, NZCV                      --> Save stack and NZCV
mov    x0, sp
stp    x0, x1, [x28, #320]
add    x0, x28, #368             --> set X0 at the beginning of the FPRState
mrs    x1, FPCR                   --> Get FPCR and FPSR
mrs    x2, FPSR

st1    { v0.2d, v1.2d, v2.2d, v3.2d }, [x0], #64     --> Save FPR
st1    { v4.2d, v5.2d, v6.2d, v7.2d }, [x0], #64
st1    { v8.2d, v9.2d, v10.2d, v11.2d }, [x0], #64
st1    { v12.2d, v13.2d, v14.2d, v15.2d }, [x0], #64
st1    { v16.2d, v17.2d, v18.2d, v19.2d }, [x0], #64
st1    { v20.2d, v21.2d, v22.2d, v23.2d }, [x0], #64
st1    { v24.2d, v25.2d, v26.2d, v27.2d }, [x0], #64
st1    { v28.2d, v29.2d, v30.2d, v31.2d }, [x0], #64
stp    x1, x2, [x0]          --> Set FPCR and FPSR

ldr    x0, [x28, #16]      --> Restore Host SP
mov    sp, x0
ldr    x30, [sp], #16    --> Return to host

ret
```

总结：x28设置为datablock起始块，保存 guest context 并恢复 host context，最后跳转到保存的host lr(x30)寄存器。

Engine会一直执行直到currentPC是虚构地址42。

执行序言代码以后会跳转到已经生成好的 patch 代码执行。patch 生成发生在执行前，不是在序言里临时生成。生成 patch 的时候遇到了修改 pc 的指令会特殊处理（不然就失去控制了）：

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                       │
│  原始 Guest BB：                                                      │
│                                                                       │
│    0x1000:  mov x8, x3                                               │
│    0x1004:  add x0, x1, x2                                           │
│    0x1008:  blr x8          ← 修改 PC 的指令（间接调用）            │
│                                                                       │
│  QBDI 翻译时识别 blr x8 是"终结指令"（修改 PC 的指令）              │
│  它不能直接执行 blr x8，因为那会真的跳走，失去控制                   │
│    blr x8 被拆解为：                                                 │
│      ① 设置 Guest LR = 返回地址（blr 的语义）                      │
│      ② 设置 Guest PC = x8（目标地址）                               │
│      ③ 跳回 VM Engine                                               │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

此时，vm循环会得到这个地址，循环中会判断这个地址是否在trace的范围内，如果不在则交由ExecBroker，如果在那么需要处理目标地址指令，接着跳转至该地址执行。

## Instrument

instrument是因为我们添加了trace回调，就是我们的监控代码了。

instrument代码也是由PatchDSL生成，我们先看一下经过instrument以后指令是什么样：

```
ldr x28, [x27, #896]  --> 将指令跟踪InstCallback函数的地址写入Context的Shadow区域并且赋值给x28
str x28, [x27, #32]   -->将InstCallback函数的地址写入Context.hostState.callback
mov x28, #0   --> 将调用addCodeCB时的data指针值写入Constant区域并且赋值给x28，由于data为nullptr，因此优化为mov x28, #0
str x28, [x27, #40] --> 将data指针值写入Context.hostState.data
mov x28, #0 --> 将InstID值赋值给x28
str x28, [x27, #48]  --> 将InstID值写入Context.hostState.origin用于上层回调获取正在执行指令id
ldr x28, [x27, #904] --> 将目标指令地址加载至x28寄存器
str x28, [x27, #336] --> 将目标指令地址写入Context.gprState.pc
adr x28, #12           --> 将回调结束后继续执行的 CodeBlock 地址存入x28
str x28, [x27, #24] --> 将x28存入Context.hostState.selector
b #3764    --> 跳转至尾声部分切换回qbdi上下文

sub sp, sp, #32 ----> 这一条为原始指令
```

总的来说，就是将回调函数的地址写入了 datablock 中保存起来了，data作为回调参数也保存了，将目标指令的运行时地址也保存起来了，同时保存回调结束后继续执行的位置。

重新回到 qbdi 后，会判断是否设置了 callback：

```
VMAction ExecBlock::execute() {
    do {
      ...
      run(); //执行dataBlock序言代码，该代码实现为汇编函数__qbdi_runCodeBlock
      if (context->hostState.callback != 0) {
          //执行代码跟踪回调
          VMAction r =
          (reinterpret_cast<InstCallback>(context->hostState.callback))(
              vminstance, &context->gprState, &context->fprState,
              (void *)context->hostState.data);
      }
      ...
    }while (context->hostState.callback != 0);
}
```

执行完代码跟踪回调以后重新进入run()函数，从而进入到序言部分，跳转至Context.hostState.selector 处执行，即原始指令sub sp, sp, #32处。

## ExecBroker

如果遇到不在trace范围内的指令，会交由ExecBroker并将控制权递交出去，这样我们就不用trace已知或者不感兴趣的逻辑，提升效率。

例子：

```
long test() {
 int i = 10;
 // qbdi遇到printf会将控制权转交出去
 int ret = printf("Hello test\\n");
 return i + ret;
}
```

我们不想trace printf，它不在范围内，此时会生成下面的代码。

**transfertLR:**

```
// Sequence Broker with LR
//生成的指令列表:
ldr    x30, [x27, #32]  // hostState.brokerAddr加载至x30 LR,运行前此地址会设置为目标printf地址
mrs    x28, TPIDR_EL0   // 保存TPIDR_EL0寄存器: 先加载至x28
str    x28, [x27, #56]  // TPIDR_EL0保存至hostState.tpidr
ldr    x28, [x27, #296] // 恢复x28寄存器: 内存datablock当中的x28偏移处值加载到x28寄存器
ldr    x27, [x27]       // 恢复x27寄存器: [x27]为HostState的scratchRegisterValue
//所有使用到的寄存器已恢复，可以跳转到目标执行了
blr    x30              // 跳转至hostState.brokerAddr
// 从控制流返回以后要接管程序，此时需要做的是重置scratchRegister
// 保存x27原先的值并且设置x27为datablock地址
msr    TPIDR_EL0, x27   // 保存x27至TPIDR_EL0
adrp    x27, #4096       // x27设置为datablock地址
str    x28, [x27, #296] // 保存x28
mrs    x28, TPIDR_EL0   // 读取原先的x27的值
str    x28, [x27]       // 保存scratchRegister至Context.hostState.scratchRegisterValue
ldr    x28, [x27, #56]  // 将保存的hostState.tpidr赋值给x28
msr    TPIDR_EL0, x28   // 恢复TPIDR_EL0
b    #3752              // 跳转回Epilogue
```

这段指令是会在序言后面的，整体逻辑非常清晰，就是在 blr x30 之前，将 x27/x28 恢复为 guest 的真实值，这样外部函数看到的寄存器状态是干净的。 `blr` 会把下一条指令地址写入 LR，所以外部函数执行完 `ret` 之后，会回到 `blr` 后面的 hook 逻辑。

`bl` 或 `blr` （带 link 的跳转），因为这类指令会把下一条指令地址写入 LR。

qbdi选择了线程指针寄存器TPIDR_EL0做为中转寄存器。这里要注意，不是说转移过去执行的函数完全不会用到 TPIDR_EL0，而是 QBDI 在跳到目标函数前会恢复原本的 TPIDR_EL0；等目标函数返回到 hook 后，才短暂借用 TPIDR_EL0 保存 x27，并在进入 Epilogue 前恢复。

**TPIDR_EL0 是线程指针寄存器** ，由 OS/runtime 在线程创建时设置。

很多用户态函数（包括 libc 里的 TLS 相关逻辑）可能会 **读取** 它来定位 TLS block，所以目标函数执行期间不能破坏它。

**transfertX28:**

```
// Sequence Broker with X28生成的指令列表:
ldr    x28, [x27, #32] // hostState.brokerAddr加载至x28,运行前此地址会设置为目标printf地址
ldr    x27, [x27] //恢复x27
br    x28  // 跳转到目标执行
// 保存x27原先的值并且设置x27为datablock地址
mov    x28, x27
adrp    x27, #4096
str    x28, [x27] //保存scratchRegister至Context.hostState.scratchRegisterValue
b    #3724  // 跳转回Epilogue
```

当明确不需要恢复x28寄存器时将会使用上面的指令，x28就代替了TPIDR_EL0做为中转寄存器，所以指令会简单很多。

`b` 或 `br` （不带 link 的跳转，即尾调用/tail call），这类指令不修改 LR。

看汇编，这里 br 指令完之后，会接着执行 mov 下面的汇编，但是 br 指令并没有返回的功能，是如何做到的呢？关键是 QBDI 在跳出去之前，把原本指向 trace 内的返回地址临时替换成了自己的 hook 地址。外部函数 `ret` 时先回到 hook，再由 QBDI 恢复原来的返回地址。

执行的是transfertLR还是transfertX28，首先看 `Context.gprState->lr` 是否在 trace 范围内。如果 LR 指向 trace 内，就使用 transfertLR；如果 LR 不在 trace 内，QBDI 会再扫描 SP 附近，看栈上是否保存了指向 trace 内的返回地址，找到了才会使用 transfertX28。

这里的栈上判断是启发式的：QBDI 不能严格证明这个 trace 内地址一定是返回地址，只是基于 AArch64 常见函数序言和返回地址保存习惯进行判断。

## 原子指令LDXR、STXR死循环的问题

在没有LSE功能的时候，原子操作必须由LL/SC指令来实现。也就是ldaxr/stlxr，LL/SC缩写为load-linked/store-conditional，它是很多平台用于实现原子性和锁的基础。

我们可以用以下伪代码来理解LL/SC操作：

```
int LoadLinked(int *ptr) {
        return *ptr;
    }
    int StoreConditional(int *ptr, int value) {
        if (no one has updated *ptr since the LoadLinked to this address) {
            *ptr = value;
            return 0; // success!
        } else {
           return 1; // failed to update
       }
   }
```

LL的加载指令和典型加载指令类似，都是从内存中取出值存入一个寄存器。关键区别来自条件式存储（store-conditional）指令，只有上一次加载的地址在期间都没有更新时，才会成功，（同时更新刚才链接的加载的地址的值）。成功时，条件存储返回0，并将ptr指的值更新为value。失败时，返回1，并且不会更新值。

利用LL/SC实现自旋锁的代码如下：

```
void lock(lock_t *lock) {
      while (LoadLinked(&lock->flag)||!StoreConditional(&lock->flag, 1))
        ; // spin
    }
```

利用LL/SC实现原子操作就是我们这里程序的汇编代码：

```
LDAXR           W0, [X1]             -->将X1(a2变量)地址处的值存储到w0，并设置本地监视器表示对x1地址处的独占访问

ADD             W17, W0, W16     --> 将读取到的值和a1变量相加，设置给W17

STLXR           W15, W17, [X1]  --> 试图将W17写入到X1地址，这个操作会检查本地监视器是否还拥有对x1地址处的独占访问，如果在STLXR执行前另外一个线程修改了X1地址处的内容(包括当前线程自己)则会清除独占访问标记那么会将W15置为1表示出错，否则将会写入成功并将W15置为0表示成功

CBNZ            W15, loc_188C --> 如果出错那么自旋重试
```

为什么qbdi在trace包含有LL/SC片段的时候会死循环?

这是因为qbdi在LL/SC中间插入了很多trace相关代码，会导致独占访问标志被清除，即使没有往上面的X1地址处写值也会导致独占访问标志被清除从而导致自旋自循环。

qbdi应对策略是针对单线程程序(像上面的LL/SC用于原子操作时)，用软件实现一个本地监视器，在执行SC之前再插入一条LL指令重新设置独占访问标志，但是这种方式对多线程明显是不行的。

需要多线程使用的话，就要自行处理：https://github.com/QBDI/QBDI/issues/232

看一个例子：

```
static inline int atomic_increment_ll_sc(int32_t* ptr) {
    uint32_t status;
    __asm__ volatile (
    "1:                     \\n\\t"
    "ldaxr   w0, [%1]       \\n\\t"   // 加载当前值到w0
    "add     w0, w0, #1     \\n\\t"   // w0 = w0 + 1
    "stlxr   %w0, w0, [%1]  \\n\\t"   // 尝试存储，结果在status
    "cbnz    %w0, 1b        \\n\\t"   // 失败则重试
    : "=&r" (status)                // 输出: status
    : "r" (ptr)                     // 输入: ptr
    : "w0", "memory"                // 破坏: w0寄存器，内存
    );
    return (status == 0) ? 0 : 1;      // 成功返回0，失败返回1
}
```

生成patch如下：

```
这一条是ldaxr w0, [x9]的patch:
mov x28, #1
str x28, [x27, #352]  // 将1写入gprState.localMonitor.enable表示需要设置独占访问标志
str x9, [x27, #344]    //将存储地址写入gprState.localMonitor.addr
ldaxr w0, [x9]   //原始指令

这一条是没做更改的add w0, w0, #1

下面是stlxr w8, w0, [x9]的patch
ldr x28, [x27, #352]  //读取gprState.localMonitor.enable
cbz x28, #12                    //如果为0跳转到第5条指令原样执行
ldr x28, [x27, #344]         //如果为1表示上面有ldaxr指令存在需要确保独占访问标志不被清除，首先读取需要访问的地址
ldxrb w28, [x28]              //多执行一步ldxrb确保独占访问标志被设置
stlxr w8, w0, [x9]             //原始指令
mov x28, #0
str x28, [x27, #352]         //清除gprState.localMonitor.enable软件独占访问标志
```

## 死锁问题

```
时间线 ─────────────────────────────────────────────────▶

Guest 代码执行:
    │
    ▼
┌─────────────────────────────────────────┐
│ Guest 调用 malloc(64)                    │
│                                         │
│   malloc 内部:                           │
│     1. pthread_mutex_lock(&malloc_lock) │  ← 获取锁 ✓
│     2. 开始操作 heap 数据结构            │
│     3. ... 正在执行中 ...               │
│                                         │
└─────────────────────┬───────────────────┘
                      │
                      │  ← QBDI 在这里触发了 instrument 回调
                      │     (比如 PREINST callback on 某条指令)
                      ▼
┌─────────────────────────────────────────┐
│ 用户的 Callback 函数执行:                │
│                                         │
│   void my_callback(...) {               │
│       // 用户想记录日志                  │
│       char *buf = malloc(256);  ←─────────── 再次调用 malloc!
│       sprintf(buf, "inst at %p", addr); │
│       ...                               │
│   }                                     │
└─────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────┐
│ malloc(256) 内部:                        │
│                                         │
│   pthread_mutex_lock(&malloc_lock)      │  ← 尝试获取锁
│                                         │
│   💀 死锁！锁已经被同一线程持有          │
│      (非递归锁 / 或即使是递归锁,         │
│       heap 数据结构处于不一致状态)        │
│                                         │
└─────────────────────────────────────────┘
```

## 栈溢出问题

> https://github.com/QBDI/QBDI/issues/243

安卓运行时会对栈指针进行动态检查，当栈指针低于预期栈限制时，生成StackOverflowError异常。

第一种方案，用户可以自行操作。它需要检查当前进程中当前分配的区域，找到一个地址比当前SP更大的合适范围，并用mmap（固定地址）分配。

## 动态代码块问题

> https://github.com/QBDI/QBDI/issues/297

QBDI 拥有一个缓存，会在某个地址首次执行后保存其插桩信息，以便提升性能，比如，循环。

QBDI **没有** 内置机制来监控每一次内存写操作，并在"写入地址恰好命中已缓存的插桩代码"时清除该缓存。

会影响性能，而且，动态代码的方式很多，无法覆盖全面，自行处理。

## 限制

host和guest共享同一个进程，因此也共享相同的资源。这意味着它们使用同一个堆和相同的库，这会导致任何非可重入代码出现问题。

例如，追踪堆内存分配器会导致死锁，因为它不具备可重入性。虽然还有其他问题场景，但大多仅限于标准 C 库和操作系统加载器。为避免此类问题，我们设计了一个执行代理系统，允许将特定代码片段加入白名单或黑名单。

此外，宿主程序依赖于加载器来加载并初始化其库依赖项，这意味着在加载器完成其工作之前，无法启动插桩过程。因此，加载器本身无法被插桩。

**微信扫一扫赞赏作者**

作者提示: 个人观点，仅供参考

![](chrome-extension://ibefaeehajgcpooopoegkifhgecigeeg/assets/imgs/data-enhance/isok.svg) 订阅成功
