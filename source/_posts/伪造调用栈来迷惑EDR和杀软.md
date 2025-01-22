---
title: 伪造调用栈来迷惑EDR和杀软
date: 2024-12-02 17:17:02
categories: "EDR"
tags: 
 - "EDR"
 - "主机安全"
---

### 调用栈

调用栈是EDR产品一个被低估但通常重要的遥测数据源。它们可以为事件提供重要的上下文，并在确定误报和真正阳性（尤其是在凭证盗窃事件，例如对lsass的句柄访问）方面成为一个极其强大的工具。已经有一些公开的研究关于伪造调用栈（最著名的是[ThreadStackSpoofer](https://github.com/mgeeky/ThreadStackSpoofer)和[Ekko](https://github.com/Cracked5pider/Ekko)），但这些研究似乎主要集中在从AV/EDR检测中隐藏睡眠线程的调用栈（例如，用于Cobalt Strike的睡眠掩码）。

这与另一种场景形成对比 - 主动欺骗EDR（或ETW AGENT）使其从内核驱动程序记录伪造的调用栈，特别是在执行特定TTP时，例如为了获取凭证而打开lsass进程句柄。本文将展示一个概念验证技术，使NtOpenProcess能够携带任意伪造的调用栈被调用。

### 技术详解

Windows内核为AV/EDR驱动程序提供了多种回调机制，使其能够订阅并接收系统事件通知。这些回调包括进程创建/删除事件（PsSetCreateProcessNotifyRoutineEx）、线程创建/删除事件（PsSetCreateThreadNotifyRoutine）以及对象访问（ObRegisterCallbacks）等。

这些回调大多在触发事件的线程上下文中执行。具体来说，当内核驱动程序的进程通知例程被调用时，它会在触发回调的进程上下文中运行（例如通过调用CreateProcess），并能解析该用户进程上下文中的用户模式虚拟地址。这些回调是内联执行的，也就是说操作系统会等待目标操作（如创建进程或新线程）完成后才返回。

以下是通过windbg内核调试获得的一个内核调用栈示例。它展示了在自定义ObRegisterCallback例程上设置的断点（这里是进程句柄操作），该断点由Outflank的dumpert工具触发：

```nasm
1: kd> k
00 ffff9387`368011f0 fffff806`2e0a78cc exampleAVDriver!ObjectCallback+0x50
01 ffff9387`36801b70 fffff806`2e0a7a3a nt!ObpCallPreOperationCallbacks+0x10c
02 ffff9387`36801bf0 fffff806`2e015e13 nt!ObpPreInterceptHandleCreate+0xaa
03 ffff9387`36801c60 fffff806`2e086ca9 nt!ObpCreateHandle+0xce3
04 ffff9387`36801e70 fffff806`2e09a60f nt!ObOpenObjectByPointer+0x1b9
05 ffff9387`368020f0 fffff806`2e0f27b3 nt!PsOpenProcess+0x3af
06 ffff9387`36802480 fffff806`2de272b5 nt!NtOpenProcess+0x23
07 ffff9387`368024c0 00007ff7`ef821d42 nt!KiSystemServiceCopyEnd+0x25
08 0000000f`f4aff1e8 00007ff7`ef8219b2 Outflank_Dumpert+0x1d42
09 0000000f`f4aff1f0 00007ff7`ef821fb0 Outflank_Dumpert+0x19b2
0a 0000000f`f4aff890 00007ffd`6c317034 Outflank_Dumpert+0x1fb0
0b 0000000f`f4aff8d0 00007ffd`6d862651 KERNEL32!BaseThreadInitThunk+0x14
0c 0000000f`f4aff900 00000000`00000000 ntdll!RtlUserThreadStart+0x21

```

从这个回调中，AV/EDR驱动程序可以检查对象访问请求并采取直接行动，比如在必要时从请求的句柄中移除权限位。同样，对于进程或线程回调，AV/EDR可以检查新进程/线程，并根据检测逻辑或启发式规则（如线程是否指向可疑内存等）采取预防措施，包括阻止执行。

此外，上述示例有力地证明了调用栈收集的重要性，因为它清楚地显示了直接系统调用的使用——在nt!KiSystemServiceCopyEnd之前的调用栈中并未出现ntdll。

需要注意的是，ObjectCallback并不一定在触发操作的线程上下文中运行，而是在所谓的任意线程上下文中运行（这意味着当前上下文可能不是实际触发回调的进程）。不过，在大多数情况下可以认为它确实在触发线程的上下文中运行。

从上述示例可以明确看出，AV/EDR可以在内核回调中内联执行调用栈遍历。这正是SysMon在处理进程访问事件（事件ID 10）时所做的。

在下面的截图中，我们可以看到SysMon记录的进程访问事件，显示svchost获取了lsass的句柄：

![](https://labs.withsecure.com/adobe/dynamicmedia/deliver/dm-aid--8a131c9e-aced-4776-9530-ca766ff25779/sysmon-generic-lsass-access.png?quality=82&preferwebp=true)

图1：一个SysMon事件示例，显示进程访问事件，其中lsass是目标映像。

我们可以看到事件包含一个"CallTrace"字段，它显示了用户模式调用栈，揭示了导致句柄请求的进程内事件链（虽然没有完整的符号解析）。这个特定事件是在安装SysMon后几分钟生成的，之后会定期出现。由于调用栈中不包含任何异常内存区域，这明显是一个误报。

通过将SysMon驱动程序（SysmonDrv.sys）加载到IDA中，我们可以了解SysMon如何收集调用栈。关键是找到RtlWalkFrameChain函数并追踪其引用。SysMonDrv为进程句柄操作注册了一个回调（ObjectHandleCallback），每次调用时都会通过StackWalkWrapper函数调用RtlWalkFrameChain来收集用户模式调用栈：

![](https://labs.withsecure.com/adobe/dynamicmedia/deliver/dm-aid--1510fbeb-5890-4759-a451-aebdece007d2/object-callback-sysmondrv--resizedimagewzewnjgsota3xq.png?quality=82&preferwebp=true)

图2：由IDA生成的SysMonDrv的反编译对象回调。

需要注意的是，SysMon在调用RtlWalkFrameChain时使用标志1（'mov r8d, 1'），这表明它只收集用户模式调用栈。

RtlWalkFrameChain由ntoskrnl导出，其工作原理（高层次概述）如下：

- 调用RtlCaptureContext来捕获当前线程的ContextRecord/CONTEXT结构
- 调用RtlpxVirtualUnwind，根据CONTEXT结构（如Rip/Rsp等）中记录的当前执行状态开始展开堆栈

RtlVirtualUnwind的实现示例可以在这些位置找到：[unicorn_pe](https://github.com/hzqst/unicorn_pe/blob/master/unicorn_pe/except.cpp#L773)和[ReactOS](https://doxygen.reactos.org/d8/d2f/unwind_8c.html#a03c91b6c437066272ebc2c2fff051a4c)。

此外，ETW也可以配置为收集堆栈跟踪（参见：[krabsetw](https://github.com/microsoft/krabsetw/pull/191)）。这对于识别许多AGENT的异常活动非常有用，比如在应用Microsoft TI feed或查找未备份的wininet调用时。值得注意的是，ETW收集调用栈的方式与典型的内联内核回调方法略有不同——它先向目标线程排队一个APC，然后调用RtlWalkFrameChain。这可能是因为某些ETW AGENT在任意线程上下文中执行。

快速查看RtlVirtualUnwind的实现可以发现它需要解析（相当复杂的）X64展开代码。因此，要理解通过RtlVirtualUnwind遍历调用栈，首先需要了解X64上的代码生成和执行机制。完整的介绍超出了本文范围，但这篇优秀的CodeMachine博客文章包含了所需的所有信息：[CodeMachine](https://codemachine.com/articles/x64_deep_dive.html)。

简要回顾一下，CPU本身并没有函数的概念，这是高级语言的抽象。在x86上，函数是通过框架指针寄存器（Ebp）在CPU层面实现的。Ebp作为参考点，用于访问堆栈上的局部变量和传递的参数。通过跟踪这个Ebp指针链（即函数框架），可以找到下一个堆栈框架，从而遍历x86堆栈。

在X64上，情况变得更复杂了，因为Rbp不再用作框架指针。需要理解的关键区别是X64可执行文件包含一个名为".pdata"的新节区。这个节区本质上是一个数据库，包含了可执行文件中每个函数的指令（称为UNWIND_CODE），说明如何在异常发生时"展开"该函数。在X64上，函数一旦完成其序言（即堆栈修改），就不会再修改堆栈指针，直到其尾声恢复这些修改，因此Rsp在整个函数体中保持静态。

一些典型的UNWIND_CODEs包括：

- ALLOC_SMALL/LARGE（为局部参数分配小型/大型内存，如sub rsp, 80h）
- PUSH_NONVOL（将非易失性寄存器压入堆栈，如push rdi）

在windbg中，'.fnent'命令可以解析指定函数的这些信息并显示其展开信息，下面是kernelbase!OpenProcess的示例：

```nasm
0:000> .fnent kernelbase!OpenProcess
Debugger function entry 000001e2`92241720 for:
(00007ff8`7a3bc0f0) KERNELBASE!OpenProcess | (00007ff8`7a3bc170) KERNELBASE!SetWaitableTimer
Exact matches:
BeginAddress = 00000000`0002c0f0
EndAddress = 00000000`0002c160
UnwindInfoAddress = 00000000`00266838

Unwind info at 00007ff8`7a5f6838, 6 bytes
version 1, flags 0, prolog 7, codes 1
00: offs 7, unwind op 2, op info c UWOP_ALLOC_SMALL.

```

这显示OpenProcess只有一个展开代码—在堆栈上分配一个小型内存区域。"UWOP_ALLOC_SMALL"的实际大小是通过将op info值乘以8再加8计算得出（0xc × 8 + 8 = 0x68）。通过反汇编kernelbase!OpenProcess的前几个字节可以验证这一点（sub rsp, 68h）：

```
0:000> uf kernelbase!OpenProcess
KERNELBASE!OpenProcess:
00007ff8`7a3bc0f0 4c8bdc mov r11,rsp
00007ff8`7a3bc0f3 4883ec68 sub rsp,68h

```

- 局部变量的空间
- 基于堆栈的参数空间
- 返回地址（8字节）
- 定位空间
- 保存非易失性寄存器的堆栈空间

让我们以OpenProcess的调用为例：

```nasm
0:000> knf
# Memory Child-SP RetAddr Call Site
00 000000df`7d8fef88 00007ffd`b1bdc13e ntdll!NtOpenProcess
01 8 000000df`7d8fef90 00007ff7`f10c087d KERNELBASE!OpenProcess+0x4e
02 70 000000df`7d8ff000 00007ff7`f10c24b9 VulcanRaven!main+0x5d [C:\\Users\\wb\\source\\repos\\VulcanRaven\\VulcanRaven\\VulcanRaven.cpp @ 641]
03 9e0 000000df`7d8ff9e0 00007ff7`f10c239e VulcanRaven!invoke_main+0x39 [d:\\a01\\_work\\43\\s\\src\\vctools\\crt\\vcstartup\\src\\startup\\exe_common.inl @ 79]
04 50 000000df`7d8ffa30 00007ff7`f10c225e VulcanRaven!__scrt_common_main_seh+0x12e [d:\\a01\\_work\\43\\s\\src\\vctools\\crt\\vcstartup\\src\\startup\\exe_common.inl @ 288]
05 70 000000df`7d8ffaa0 00007ff7`f10c254e VulcanRaven!__scrt_common_main+0xe [d:\\a01\\_work\\43\\s\\src\\vctools\\crt\\vcstartup\\src\\startup\\exe_common.inl @ 331]
06 30 000000df`7d8ffad0 00007ffd`b2237034 VulcanRaven!mainCRTStartup+0xe [d:\\a01\\_work\\43\\s\\src\\vctools\\crt\\vcstartup\\src\\startup\\exe_main.cpp @ 17]
07 30 000000df`7d8ffb00 00007ffd`b3e82651 KERNEL32!BaseThreadInitThunk+0x14
08 30 000000df`7d8ffb30 00000000`00000000 ntdll!RtlUserThreadStart+0x21

```

顶部条目ntdll!NtOpenProcess（#00）是当前堆栈框架。Child-SP值000000df`7d8fef88表示NtOpenProcess完成函数序言后的Rsp值（即完成所有必要的堆栈修改后的堆栈指针值）。"Memory"列中的值8代表NtOpenProcess使用的总堆栈大小。因此，要计算下一个框架的Child-SP，只需将当前框架的总堆栈大小（8）加到当前Child-SP上：

```
0:000> ? 000000df`7d8fef88 + 8
Evaluate expression: 959884291984 = 000000df`7d8fef90

```

需要注意的是，NtOpenProcess没有展开操作代码（因为它不修改堆栈），所以下一个Child-SP只需跳过前一个调用者（KERNELBASE!OpenProcess）推送的返回地址。这就解释了为什么它的总堆栈大小是8字节（即仅包含返回地址）。

新的Child-SP（000000df`7d8fef90）代表KERNELBASE!OpenProcess完成其函数序言后的Rsp值。当KERNELBASE!OpenProcess调用ntdll!NtOpenProcess时，它会将返回地址推送到堆栈上。这个返回地址会位于Child-SP指向的位置之后，如图3中的Child-SP 01所示。

这个过程在下一个框架中继续进行。Kernelbase!OpenProcess的Child-SP是000000df`7d8fef90，总堆栈使用量为0x70字节。将这两个值相加，我们就能得到VulcanRaven!main的下一个Child-SP：

```
0:000&gt; ? 000000df`7d8fef90 + 70
Evaluate expression: 959884292096 = 000000df`7d8ff000
```

这个遍历过程会一直持续，直到调试器完整地走完整个堆栈。因此，堆栈遍历过程可以概括如下：

![](https://labs.withsecure.com/adobe/dynamicmedia/deliver/dm-aid--c1d5a3c5-3137-477d-8def-bc9ae7dac4f1/call-stack-walking-example--resizedimagewzgwmcw0ntzd.png?quality=82&preferwebp=true)

图3：显示X64堆栈遍历过程的图表。

这篇博客文章的关键点在于，只要知道函数的总堆栈大小，就能够在不需要符号的情况下跟踪子堆栈指针链并遍历调用栈。在伪造调用栈时，我们将反向运用这一过程。

在讨论了调用栈遥测的用途，并简要介绍了x64上调用栈展开的工作原理后，我们现在来探讨这篇博客文章的核心问题：我们能否伪造一个调用栈，使其在内联收集（例如从内核驱动程序回调例程内）时被记录下来？

### PoC设计

这篇博客文章中的PoC采取了以下方法：

1. 确定要伪造的目标调用栈。在此示例中，我们使用SysMon，从中选取了一个事件类型10的条目（涉及打开lsass句柄），如下所示：

```
CallTrace:
C:\\Windows\\SYSTEM32\\ntdll.dll + 9d204 (ntdll!NtOpenProcess)
C:\\Windows\\System32\\KERNELBASE.dll + 32ea6 (KERNELBASE!OpenProcess)
C:\\Windows\\System32\\lsm.dll + e959
C:\\Windows\\System32\\RPCRT4.dll + 79633
C:\\Windows\\System32\\RPCRT4.dll + 13711
C:\\Windows\\System32\\RPCRT4.dll + dd77b
C:\\Windows\\System32\\RPCRT4.dll + 5d2ac
C:\\Windows\\System32\\RPCRT4.dll + 5a408
C:\\Windows\\System32\\RPCRT4.dll + 3a266
C:\\Windows\\System32\\RPCRT4.dll + 39bb8
C:\\Windows\\System32\\RPCRT4.dll + 48a0f
C:\\Windows\\System32\\RPCRT4.dll + 47e18
C:\\Windows\\System32\\RPCRT4.dll + 47401
C:\\Windows\\System32\\RPCRT4.dll + 46e6e
C:\\Windows\\System32\\RPCRT4.dll + 4b542
C:\\Windows\\SYSTEM32\\ntdll.dll + 20330
C:\\Windows\\SYSTEM32\\ntdll.dll + 52f26
C:\\Windows\\System32\\KERNEL32.DLL + 17034
C:\\Windows\\SYSTEM32\\ntdll.dll + 52651

```

1. 对于目标调用栈中的每个返回地址，分析其展开代码并计算所需的总堆栈空间，以便定位下一个childSP框架。
2. 创建一个挂起的线程，并修改CONTEXT结构，使堆栈/rsp完全匹配要伪造的目标调用栈的**精确**轮廓（无实际数据）。通过推送伪造的返回地址并减去正确的子SP偏移量（即反向展开堆栈），我们初始化线程状态以"模拟"目标线程的"轮廓"。需要注意的是，在处理某些展开代码（如UWOP_SET_FPREG）时要格外小心，因为这会导致rsp == rbp的重置。
3. 修改CONTEXT结构，将Rip指向目标函数（ntdll!NtOpenProcess），并按x64调用约定设置必要的参数（通过配置Rcx/Rdx/R8/R9）。
4. 恢复线程执行。由于使用了伪造的调用栈，系统调用返回时必然会产生错误，此时通过向量化异常处理程序进行处理。在异常处理程序中，我们可以通过重设Rip将线程重定向至RtlExitUserThread，从而实现优雅退出。

针对上述方法的局限性，我们可以采用一个更优的解决方案：使用向量化异常处理和硬件或软件断点，这类似于这个无补丁AMSI绕过技术：[patchless AMSI bypass](https://www.notion.so/fe3b63d80890fafeca982f76c8a3efdf?pvs=21)。

通过这种方法，我们可以在NtOpenProcess系统调用（00007ff8`7ca6d204）返回时精确设置断点：

```
ntdll!NtOpenProcess:
00007ff8`7ca6d1f0 4c8bd1 mov r10,rcx
00007ff8`7ca6d1f3 b826000000 mov eax,26h
00007ff8`7ca6d1f8 f604250803fe7f01 test byte ptr [SharedUserData+0x308 (00000000`7ffe0308)],1
00007ff8`7ca6d200 7503 jne ntdll!NtOpenProcess+0x15 (00007ff8`7ca6d205) Branch
ntdll!NtOpenProcess+0x12:
00007ff8`7ca6d202 0f05 syscall
00007ff8`7ca6d204 c3 ret```

```

一旦生成了断点异常（在线程返回并崩溃之前），我们可以像以前讨论的那样处理错误。此外，恢复伪造线程的状态并能够重用它将是一个改进，并停止需要反复创建“牺牲线程”。

此外，这种方法还可能被应用于睡眠混淆问题；一个具有合法调用栈的伪造线程可以被初始化为调用ntdll!NtDelayExecution（或WaitForSingleObject等），并使用向量化异常处理程序在睡眠时间返回时将流程重定向到主信标函数。

### PoC

概念验证（PoC）代码可在此获取：[CallStackSpoofer](https://github.com/countercept/CallStackSpoofer)

该PoC包含三个示例调用栈（wmi/rpc/svchost），这些都是通过观察对lsass进程句柄访问从SysMon日志中精选的。可以通过'--wmi'、'--rpc'和'--svchost'参数选择这些调用栈配置。

![](https://labs.withsecure.com/adobe/dynamicmedia/deliver/dm-aid--89414471-f36d-4079-ac09-c2a7771027e4/vulcan-raven-example.png?quality=82&preferwebp=true)

图4：展示了VulcanRaven获取lsass句柄时伪造调用栈以模拟RPC活动的过程。

上述截图展示了被SysMon记录的伪造调用栈（对比正常使用OpenProcess时的调用栈应为：VulcanRaven.exe -> kernelbase!OpenProcess -> ntdll!NtOpenProcess）。值得注意的是，虽然这个PoC中的示例是模仿SysMon发现的真实事件，但调用栈可以是任意构造的，如下图所示：

![](https://labs.withsecure.com/adobe/dynamicmedia/deliver/dm-aid--dbb0da97-ac3b-4877-a6dc-acf5f03813f7/nonsense-call-stack-example.png?quality=82&preferwebp=true)

图5：WinDbg截图展示了在调用NtOpenProcess时使用的完全任意的伪造调用栈。

这项技术之所以引起攻击者的兴趣，主要是因为大多数远程访问木马（如信标）仍在使用浮动或无后备内存操作。因此，当攻击者将mimikatz直接注入内存时，来自这些注入代码的句柄访问会产生明显异常的调用栈。

下面是一个来自未备份内存调用OpenProcess的SysMon事件示例：

![](https://labs.withsecure.com/adobe/dynamicmedia/deliver/dm-aid--8745809b-c509-4b54-a820-e864b0a074dc/sysmon-unbacked-lsass-access.png?quality=82&preferwebp=true)

图6：展示了来自未备份内存的lsass句柄访问SysMon事件。

这是使用Stephen Fewer的ReflectiveDLLInjection代码库修改版本生成的示例。

在此示例中，一个反射式DLL被注入到cmd.exe中，随后获取了对lsass的PROCESS_ALL_ACCESS访问权限。由于调用源自未备份内存，SysMon将调用栈中的最后一个条目标记为"UNKNOWN"（即堆栈回溯中最后一个返回地址属于浮动或未备份代码，而非合法加载的模块），这显然很可疑。

但是，当我们将上述VulcanRaven PoC修改为反射式DLL运行时，生成了如下事件：

图7：展示了作为反射式DLL运行的Vulcan Raven。尽管代码来自未备份内存，但访问lsass句柄的调用栈被成功伪装成合法操作。

"CallTrace"被伪造成了符合SysMon预期的值。从调用栈上看不出NtOpenProcess/OpenProcess的调用实际来自未备份内存中的代码，线程表面上完全合法（虽然使用cmd.exe本身就很可疑）。此外还要注意图1中不同的GrantedAccess值，这里使用了PROCESS_ALL_ACCESS/0x1FFFFF。

显然，攻击者可以根据注入目标进程（如wmi、procexp、svchost等常见的lsass句柄访问者）来定制相应的调用栈。

以下是我建议的优化版本，使内容更加清晰易懂：