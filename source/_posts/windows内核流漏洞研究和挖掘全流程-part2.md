---
title: windows内核流漏洞研究和挖掘全流程(part2)
date: 2024-10-22 18:17:02
categories: "漏洞分析与挖掘"
tags: 
 - "内核漏洞"
 - "主机安全"
---

# 《Windows 内核中的流漏洞——代理到内核——第二部分



在之前的一篇研究中，我们在内核流中发现了多个漏洞以及一个被忽视的漏洞类别。我们在 2024 年温哥华 Pwn2Own 大赛中成功利用漏洞 CVE-2024-35250 和 CVE-2024-30084 攻陷了 Windows 11。 在本文中，我们将继续探索这个攻击面和漏洞类别，揭示另一个漏洞和利用技术，该技术也在 [HEXACON 2024](https://www.hexacon.fr/)上进行了展示。 经过一段时间后，我们在 KS 对象的属性操作中没有发现其他可利用的点。因此，我们将注意力转移到另一个功能——KS 事件（KS Event）上。 



### [KS 事件](https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/ks-events) 

与上一篇文章中提到的[KS 属性](https://devco.re/blog/2024/08/23/streaming-vulnerabilities-from-windows-kernel-proxying-to-kernel-part1-en/#ks-property)类似，KS 对象不仅有自己的属性集，还提供了设置 KS 事件的功能。例如，你可以设置一个事件，在设备状态改变时或在固定时间间隔触发，这对于播放软件的开发者来说很方便，可以定义后续的行为。每个 KS 事件，就像一个属性一样，需要 KS 对象支持才能使用。我们可以通过[IOCTL\_KS\_ENABLE\_EVENT](https://learn.microsoft.com/zh-tw/windows-hardware/drivers/ddi/ks/ni-ks-ioctl_ks_enable_event)和[IOCTL\_KS\_DISABLE\_EVENT](https://learn.microsoft.com/zh-tw/windows-hardware/drivers/ddi/ks/ni-ks-ioctl_ks_disable_event)来注册或禁用这些事件。 

### KSEVENTDATA 

在注册 KS 事件时，你可以通过提供[KSEVENTDATA](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ks/ns-ks-kseventdata)来注册所需的事件。你可以在注册中包含诸如 EVENT\_HANDLE（事件句柄）和 SEMAPHORE\_HANDLE（信号量句柄）等句柄。当 KS 触发这个事件时，它将使用提供的句柄通知你。 

### IOCTL\_KS\_ENABLE\_EVENT 的工作流程 

整个工作流程与 IOCTL\_KS\_PROPERTY 类似。当调用 DeviceIoControl 时，如下图所示，用户的请求依次传递给相应的驱动程序进行处理。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1021/1.png) 同样，在步骤 3 中，32 位请求将被转换为 64 位请求。到步骤 6 时，ks.sys 将根据你的请求的事件确定哪个驱动程序和[addhandler](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ks/nc-ks-pfnksaddevent)来处理你的请求。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1021/2.png) 最后，将其转发到相应的驱动程序。如上图所示，最终它被转发到 ks 中的“KsiDefaultClockAddMarkEvent”以设置[定时器](https://learn.microsoft.com/zh-tw/windows-hardware/drivers/ddi/wdm/nf-wdm-kesettimerex)。 在掌握了 KS 事件的功能和流程后，我们根据之前的[漏洞模式](https://devco.re/blog/2024/08/23/streaming-vulnerabilities-from-windows-kernel-proxying-to-kernel-part1/#the-new-bug-pattern)迅速确定了另一个可利用的漏洞[CVE-2024-30090](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2024-30090)。 再次代理到内核！ 

--------------------------

这次，问题出现在“ksthunk”将 32 位请求转换为 64 位请求的时候。 如下图所示，当“ksthunk”接收到一个“IOCTL_KS_ENABLE_EVENT”请求且请求来自一个 WoW64 进程时，它将执行从 32 位结构到 64 位结构的转换。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1021/3.png) 这个转换将调用“ksthunk!CKSAutomationThunk::ThunkEnableEventIrp”来处理它。 

```
__int64 __fastcall CKSAutomationThunk::ThunkEnableEventIrp(__int64 ioctlcode_d, PIRP irp, __int64 a3, int *a4)
{
 ...
  if ( (v25->Parameters.DeviceIoControl.Type3InputBuffer->Flags & 0xEFFFFFFF) == KSEVENT_TYPE_ENABLE
    || (v25->Parameters.DeviceIoControl.Type3InputBuffer->Flags & 0xEFFFFFFF) == KSEVENT_TYPE_ONESHOT
    || (v25->Parameters.DeviceIoControl.Type3InputBuffer->Flags & 0xEFFFFFFF) == KSEVENT_TYPE_ENABLEBUFFERED )  
  {
    // 将 32 位请求转换并直接传递下去
  }
  else if ( (v25->Parameters.DeviceIoControl.Type3InputBuffer->Flags & 0xEFFFFFFF) == KSEVENT_TYPE_QUERYBUFFER ) 
  {
   ...
    newinputbuf = (KSEVENT *)ExAllocatePoolWithTag((POOL_TYPE)0x600, (unsigned int)(inputbuflen + 8), 'bqSK');
   ...
    memcpy(newinputbuf,Type3InputBuffer,0x28);  //------------------------[1]
   ...
    v18 = KsSynchronousIoControlDevice( 
            v25->FileObject,
            0,
            IOCTL_KS_ENABLE_EVENT,
            newinputbuf,
            inputbuflen + 8,
            OutBuffer,
            outbuflen,
            &BytesReturned);  //-----------------[2]
   ...
  }
 ...
}
```



在“CKSAutomationThunk::ThunkEnableEventIrp”中，明显可以看到一个类似的漏洞模式。你可以看到，在处理过程中，原始请求首先被复制到一个新分配的缓冲区中，如[1]所示。随后，这个缓冲区被用于通过“KsSynchronousIoControlDevice”调用新的 IOCTL，如[2]所示。“newinputbuf”和“OutBuffer”都由用户控制。 调用“CKSAutomationThunk::ThunkEnableEventIrp”的流程如下所示： ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1021/4.png) 当在 WoW64 进程中调用 IOCTL 时，你可以在图中的步骤 2 中看到，I/O 管理器将“Irp->RequestorMode”设置为用户模式（UserMode(1)）。在步骤 3 中，ksthunk 将用户的请求从 32 位转换为 64 位，由“CKSAutomationThunk::ThunkEnableEventIrp”处理。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1021/5.png) 之后，在步骤 5 中，“KsSynchronousIoControlDevice”将被调用以发出 IOCTL，此时，新的“Irp->RequestorMode”已变为**内核模式（KernelMode(0)）**。后续的处理与典型的“IOCTL_KS_ENABLE_EVENT”相同，因此不再详细说明。总之，我们现在有了一个允许我们以内核模式执行任意“IOCTL_KS_ENABLE_EVENT”的原语。接下来，我们需要寻找可以实现权限提升（EoP）的地方。



## 利用方法 

----------------

按照上一篇公众号分享的方法，我们首先分析了入口点“ksthunk”。然而，经过一段时间的搜索，我们没有找到潜在的权限提升点。在“ksthunk”中，大多数“Irp->RequestMode”为“KernelMode(0)”的情况都是直接传递下去，没有进行额外的处理。因此，我们将目光转向下一层，“ks”，看看在事件处理过程中是否有任何权限提升的机会。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1021/6.png) 很快，我们找到了一个引起我们注意的地方。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1021/7.png) 在“KspEnableEvent”处理程序中，一段代码首先检查你传入的“KSEVENTDATA”中的“NotificationType”，以确定如何注册和处理你的事件。通常，它通常提供一个[EVENT\_HANDLE](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createeventa)或一个[SEMAPHORE\_HANDLE](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createsemaphorea)。然而，在“ks”中，如果从“内核模式”调用，我们可以提供一个[事件对象](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/event-objects)甚至一个[延迟过程调用（DPC）对象](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-dpc-objects)来注册你的事件，使整体处理更加高效。 

这意味着我们可以使用这个具有“内核模式”原语的“DeviceIoControl”来提供一个**内核对象**进行后续处理。如果构建得好，它可能实现“EoP”，但这取决于这个“对象”在后面是如何使用的。 然而，经过一段时间的尝试，我们发现…… 

```
__int64 __fastcall CKSAutomationThunk::ThunkEnableEventIrp(__int64 ioctlcode_d, PIRP irp, __int64 a3, int *a4)
{
 ...
  if ( (v25->Parameters.DeviceIoControl.Type3InputBuffer->Flags & 0xEFFFFFFF) == KSEVENT_TYPE_ENABLE
    || (v25->Parameters.DeviceIoControl.Type3InputBuffer->Flags & 0xEFFFFFFF) == KSEVENT_TYPE_ONESHOT
    || (v25->Parameters.DeviceIoControl.Type3InputBuffer->Flags & 0xEFFFFFFF) == KSEVENT_TYPE_ENABLEBUFFERED )  //-------[3]
  {
    // 将 32 位请求转换并直接传递下去
  }
  else if ( (v25->Parameters.DeviceIoControl.Type3InputBuffer->Flags & 0xEFFFFFFF) == KSEVENT_TYPE_QUERYBUFFER ) //-------[4]
  {
   ...
    newinputbuf = (KSEVENT *)ExAllocatePoolWithTag((POOL_TYPE)0x600, (unsigned int)(inputbuflen + 8), 'bqSK');
   ...
    memcpy(newinputbuf,Type3InputBuffer,0x28); //------[5] 
   ...
    v18 = KsSynchronousIoControlDevice( 
            v25->FileObject,
            0,
            IOCTL_KS_ENABLE_EVENT,
            newinputbuf,
            inputbuflen + 8,
            OutBuffer,
            outbuflen,
            &BytesReturned);  
   ...
  }
 ...
} 
```

 如果你想提供一个内核对象来注册一个事件，那么在 IOCTL 中为[KSEVENT](https://learn.microsoft.com/zh-tw/windows-hardware/drivers/stream/ksevent-structure)给出的标志必须在[3]处为“KSEVENT_TYPE_ENABLE”。然而，在触发漏洞的[4]处，它必须是“KSEVENT_TYPE_QUERYBUFFER”，并且不可能像我们预期的那样直接提供一个内核对象。



 幸运的是，“IOCTL_KS_ENABLE_EVENT”也使用“Neither I/O”来传输数据。它再次出现了“双重获取（Double Fetch）”问题。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1021/9.png) 如上图所示，我们可以在调用 IOCTL 之前将标志设置为“KSEVENT_TYPE_QUERYBUFFER”。

在检查时，它将以“KSEVENT_TYPE_QUERYBUFFER”进行处理。在第二次调用“KsSynchronousIoControlDevice”之前，我们可以将标志更改为“KSEVENT_TYPE_ENABLE”。 这样，我们就可以成功触发漏洞并构建一个特定的内核对象来注册事件。 

### 触发事件 

什么时候会使用你构建的内核对象呢？当一个事件被触发时，ks 将通过延迟过程调用（DPC）调用“ks!ksGenerateEvent”。此时，它将根据你指定的“NotificationType”确定如何处理你的事件。 让我们看一下 KsGenerateEvent。

 

``` 
NTSTATUS __stdcall KsGenerateEvent(PKSEVENT_ENTRY EventEntry)
{

  switch ( EventEntry->NotificationType )
  {
    case KSEVENTF_DPC:
     ...
      if (!KeInsertQueueDpc(EventEntry->EventData->Dpc.Dpc, EventEntry->EventData, 0LL) )
        _InterlockedAdd(&EventEntry->EventData->EventObject.Increment, 0xFFFFFFFF); //--------[6]
     ...
    case KSEVENTF_KSWORKITEM:
     ...
      KsIncrementCountedWorker(eventdata->KsWorkItem.KsWorkerObject); //-----------[7]

  }
} 
```

此时，有多种利用方法。最直接的方法是直接构建一个 DPC 结构并排队一个 DPC 以实现任意内核代码执行，这对应于[6]处的代码片段。然而，调用 KsGenerateEvent 时的中断请求级别（IRQL）为“DISPATCH_LEVEL”，使得在用户空间中构建 DPC 对象非常困难，并且利用过程会遇到很多问题。 

因此，我们选择另一种途径，使用[7]处的“KSEVENTF_KSWORKITEM”。这种方法涉及传入一个内核地址并进行操作，使其被识别为指向[KSWORKITEM](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ks/ns-ks-kseventdata)的指针。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1021/10.png) 它可以实现将任意内核地址的值增加一。整个过程如下图所示。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1021/11.png) 当调用“IOCTL_KS_ENABLE_EVENT”时，在构建“KSEVENTDATA”以指向一个内核内存地址后，ks 将把它作为内核对象处理并注册指定的事件。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1021/12.png) 当触发时，ks 将增加我们提供的内存地址中的内容。因此，我们在这里有一个内核任意增加的原语。 

### 从任意增加原语到EoP

从任意增加原语到权限提升，有很多方法可以利用，其中最著名的是[滥用令牌权限](https://media.blackhat.com/bh-us-12/Briefings/Cerrudo/BH_US_12_Cerrudo_Windows_Kernal_Slides.pdf)和[IoRing](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)。起初，这似乎就是结束了。 然而，这两种方法在这种情况下都有一定的局限性： 

#### 滥用令牌权限 

如果我们使用滥用令牌权限的方法进行权限提升，关键在于该技术中的覆盖“Privileges.Enable”和“Privileges.Present”。由于我们的漏洞每次只能增加一，因此两个字段都需要被写入才能获得“SeDebugPrivilege”。这两个字段的默认值分别为“0x602880000”和“0x800000”，需要更改为 0x602**9**80000 和 0x**9**00000。这意味着每个字段需要被写入 0x10 次，总共需要写入 0x20 次。每次写入都需要一个竞争条件，这需要时间并显著降低了稳定性。 

#### IoRing

使用IoRing 实现任意写入可能是一种更简单的方法。为了实现任意写入，你只需要覆盖“IoRing->RegBuffersCount”和“IoRing->RegBuffers”。然而，一个问题出现了。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1021/13.png) 当触发任意增加时，如果原始值为 0，它将调用“KsQueueWorkItem”，其中会发生一些相应的复杂处理，导致蓝屏死机（BSoD）。IoRing 的利用方法恰好遇到了这种情况…… 



 真的无法稳定地进行利用吗？ 

#### 寻找新的方法！

> 当传统的利用方法遇到障碍时，深入研究技术的核心机制可能是值得的。在这个过程中，你可能会意外地发现新的方法。 

经过几天的思考，我们决定寻找一种新的方法。然而，从头开始可能需要相当长的时间，并且可能不会有结果。因此，我们选择从两种现有方法中获得新的灵感。首先，让我们看一下“滥用令牌权限”。这里的关键是利用漏洞获得“SeDebugPrivilege”，允许我们打开高权限进程，如“winlogon”。 问题出现了：为什么拥有“SeDebugPrivilege”允许你打开高权限进程？ 我们首先需要看一下“nt!PsOpenProcess”。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1021/15.png) 从这个代码片段中，我们可以看到，当我们打开进程时，内核将使用[SeSinglePrivilegeCheck](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-sesingleprivilegecheck)来检查你是否具有 SeDebugPrivilege。如果你有它，你将被授予“PROCESS_ALL_ACCESS”权限，允许你对除了受保护进程（PPL）之外的任何进程执行任何操作。

顾名思义，它是用于调试目的的。然而，值得注意的是，“nt!SeDebugPrivilege”是“ntoskrnl.exe”中的一个全局变量。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1021/16.png) 它是一个[本地唯一标识符（LUID）](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-luid)结构，在系统启动时初始化。实际值为 0x14，表示“Privileges.Enable”和“Privileges.Present”字段中的哪个位代表“SeDebugPrivilege”。因此，当我们使用 NtOpenProcess 时，系统读取这个全局变量的值。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1021/17.png) 一旦获得“nt!SeDebugPrivilege”的值，它将用于检查令牌中的“Privileges”字段，以查看“Enable”和“Present”字段是否被设置。对于“SeDebugPrivilege”，它将检查第 0x14 位。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1021/18.png) 然而，有一个有趣的事情…… ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1021/19.png) 全局变量“nt!SeDebugPrivilege”位于一个可写的部分！ 一个新的想法诞生了。

 #### 魔改滥用令牌权限

默认情况下，普通用户将只有有限数量的“特权（Privileges）”，如下图所示。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1021/20.png) 我们可以注意到，在大多数情况下，“SeChangeNotifyPrivilege”是启用的。此时，我们可以查看初始化部分，发现“SeChangeNotifyPrivilege”代表值 0x17。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1021/21.png) 如果我们使用漏洞将“nt!SeDebugPrivilege”从 0x14 更改为 0x17 会发生什么？ ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1021/22.png) 如图所示，在“NtOpenProcess”流程中，它将首先获取“nt!SeDebugPrivilege”的值，此时获得的值是 0x17（SeChangeNotifyPrivilege）。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1021/23.png) 下一个检查将使用 0x17 检查当前进程令牌，看它是否具有此“特权”。然而，普通用户通常具有“SeChangeNotifyPrivilege”，所以即使你没有“SeDebugPrivilege”，你仍然会通过检查并获得“PROCESS_ALL_ACCESS”。换句话说，任何具有“SeChangeNotifyPrivilege”的人都可以打开除 PPL 之外的高权限进程。 

此外，通过使用上述漏洞，我们可以将“nt!SeDebugPrivilege”从**0x14 更改为 0x17**。由于原始值不为 0，它将不受“KsQueueWorkItem”的影响，非常适合我们的目的。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1021/24.png) 一旦我们可以打开高权限进程，权限提升的方法与“滥用令牌权限”方法相同，因此我们在这里不再详细说明。最终，我们通过再次利用代理到内核在 Windows 11 23H2 上成功实现了权限提升（EoP）。 



#### 备注

实际上，这种技术也适用于其他 “特权”。

- SeTcbPrivilege = 0x7
- SeTakeOwnershipPrivilege = 0x9
- SeLoadDriverPrivilege = 0xa
- …

下一步和总结

------

这两篇文章的重点主要是我们如何分析过去的漏洞以发现新的漏洞，我们如何从以前的研究中获得新的想法，找到新的利用方法、新的漏洞和新的攻击面。

这个漏洞类别可能仍然存在许多安全问题，并且它们可能不仅限于内核流和[IoBuildDeviceIoControlRequest](https://learn.microsoft.com/zh-tw/windows-hardware/drivers/ddi/wdm/nf-wdm-iobuilddeviceiocontrolrequest)。我相信这是 Windows 中的一个设计缺陷，如果我们仔细搜索，我们可能会发现更多的漏洞。

对于这种类型的漏洞，你需要注意设置 “Irp->RequestorMode” 的时机。如果它被设置为 “内核模式”，然后使用用户输入，可能会出现问题。此外，这种类型的漏洞通常非常容易被利用。

在内核流中，我相信有相当多的潜在安全漏洞。也有许多组件，如 “Hdaudio.sys” 或 “Usbvideo.sys”，可能值得检查，并且是模糊测试的合适地方。如果你是一个内核驱动程序开发人员，最好不要只检查 “Irp->RequestorMode”。在 Windows 架构中可能仍然存在问题。最后，我强烈建议每个人尽快将 Windows 更新到最新版本。

### 参考

------

- [Easy Local Windows Kernel Exploitation](https://media.blackhat.com/bh-us-12/Briefings/Cerrudo/BH_US_12_Cerrudo_Windows_Kernal_Slides.pdf)
- [One I/O Ring to Rule Them All: A Full Read/Write Exploit Primitive on Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
