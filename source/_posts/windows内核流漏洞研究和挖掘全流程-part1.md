---
title: windows内核流漏洞研究和挖掘全流程(part1)
date: 2024-10-21 17:32:02
categories: "漏洞分析与挖掘"
tags: 
 - "内核漏洞"
 - "主机安全"
---



## 前言



在过去的几十年中，Windows内核的漏洞层出不穷，热门的攻击面逐渐从Win32k慢慢转移到CLFS（通用日志文件系统）上。微软也持续且积极地修补这些漏洞，使得这些组件越来越安全。那么下一个热门的目标会是哪个组件呢？从去年开始，MSKSSRV（Microsoft内核流服务）成为黑客喜爱的目标之一。这个驱动程序小到可以在几天内完成分析。这是否意味着可能不太会有新的漏洞了呢？ 

在这篇文章基于devco的研究和分享的博文修改，将讲述一个长期被忽视的攻击面，让研究团队在两个月内就找出了超过10个漏洞。此外，我们还将深入探讨一种基于代理的逻辑漏洞类型，使我们可以忽略掉大多数的检查，最终成功在Pwn2Own Vancouver 2024中，攻下Windows 11的项目。 这份研究将分成数个部分来撰写，分别讲述不同的漏洞类型及漏洞形态，亦发表于[HITCON CMT 2024](https://hitcon.org/2024/CMT/agenda/)中。 



## 从MSKSSRV开始 

>  对于一项漏洞研究来说，从历史的漏洞看起，是不可或缺的。 

起初，为了挑战Pwn2Own Vancouver 2024中Windows 11的项目，我们开始从过去的Pwn2Own以及近期在野的漏洞中开始审视，寻找可能的攻击面。沿着历史轨迹可以得知，过去主要负责GDI相关操作的Win32K一直是个很热门的目标，从2018年以来，CLFS（通用日志文件系统）也渐渐成为了热门目标之一。这两个组件都非常复杂，并且直到现在仍然有不少新漏洞出现，但要熟悉这两个组件需要花不少时间，同时也有许多研究员在关注这两个组件，所以最终我们没有先选择分析它们。 去年[Synacktiv](https://www.synacktiv.com/en)在Pwn2Own 2023中，使用MSKSSRV的[漏洞](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29360)成功攻下Windows 11后，便有不少人往这个组件开始看起，短时间内就又出现了[第二个漏洞CVE-2023-36802](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36802)，这时[chompie](https://x.com/chompie1337)也发表了一篇[非常详细的文章](https://securityintelligence.com/x-force/critically-close-to-zero-day-exploiting-microsoft-kernel-streaming-service/)，讲述这个漏洞成因及其利用细节。由于这个组件非常小，只看文件大小约略只有72KB，可能认真看个几天就可以全部看完，因此我们便挑了MSKSSRV来做历史漏洞分析，看看是否有机会抓出其他漏洞。 接下来我们会提一下这两个漏洞，但不会着墨过多。 



### CVE-2023-29360 - 逻辑漏洞 

第一个是Synacktiv在Pwn2Own 2023中所使用的漏洞： ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/1.png) 这是一个逻辑上的漏洞。当MSKSSRV使用[MmProbeAndLockPages](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmprobeandlockpages)锁定用户给的内存位置作为帧缓冲区时，并没有设置正确的访问模式，导致没有检查用户指定的位置是否属于用户空间。如果用户给的是内核空间中的位置，它就会把指定的内核位置映射到用户空间给用户用，最终导致用户可以对内核中的任意位置写入，利用上简单且非常稳定，成为了受欢迎的[漏洞之一](https://www.cisa.gov/news-events/alerts/2024/02/29/cisa-adds-one-known-exploited-vulnerability-catalog)。 更多细节可以参考Synacktiv在HITB 2023 HKT的[演讲](https://conference.hitb.org/hitbsecconf2023hkt/materials/D2T1%20-%20Windows%20Kernel%20Security%20-%20A%20Deep%20Dive%20into%20Two%20Exploits%20Demonstrated%20at%20Pwn2Own%20-%20Thomas%20Imbert.pdf)及[Nicolas Zilio(@Big5\_sec)](https://x.com/Big5_sec)的[博客文章](https://big5-sec.github.io/posts/CVE-2023-29360-analysis/)。 

### CVE-2023-36802 - 类型混淆 

这个漏洞则是在CVE-2023-29360出来后没多久被许多人发现，并且在微软发布更新时，就已经侦测到利用，是个非常容易被发现的漏洞。MSKSSRV会先将内部使用的对象（FSContextReg、FSStreamReg）存放在[FILE\_OBJECT](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_object)的FsContext2中，然而后续使用时并没有对FsContext2的**类型**做检查，导致类型混淆，详细内容可参考[IBM X-Force的博客](https://securityintelligence.com/x-force/critically-close-to-zero-day-exploiting-microsoft-kernel-streaming-service/)。 至此之后，就很少有关于MSKSSRV的相关漏洞了。 

### 但这就是结束了吗？

 然而是否这样就没洞了呢？ **而我要更准确地回答，不！** 实际上整个内核流就像下面这张图这样： ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/2.png) MSKSSRV只是冰山一角而已，实际上还有不少潜在的组件，上图中所写的都是属于内核流的一部分。实际往这方向挖掘之后，最终也在这个攻击面上取得不少漏洞，就如同流水般的流出漏洞来。![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/cover.png) 顺便一提，我在写这篇博客时，chompie也发表了有关他在今年Pwn2Own Vancouver 2024中所使用的漏洞[CVE-2024-30089](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-30089)。这个漏洞也在MSKSSRV中，该漏洞发生在引用计数的处理，其成因也很有趣，不过这边就不多谈，详细内容可参考她[发表的文章](https://securityintelligence.com/x-force/little-bug-that-could/)。 

## 内核流概述  





那么，什么是内核流呢？事实上，我们正常使用电脑情况下就会用到： ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/4.png) 在Windows系统上，当我们打开摄像头、开启音效以及麦克风等音频设备时，系统需要从这些设备读取你的声音、影像等相关资料到RAM中。为了更高效地完成这些资料的传输，微软提供了一个名为[内核流](https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/kernel-streaming)的框架，用来处理这些资料。**这个框架主要在内核模式下运行**，具有低延迟、良好的扩展性和统一接口等特性，使你能更方便、更高效地处理流（Stream）资料。 内核流中，提供了三种多媒体驱动模型：端口类、AVStream和流类。这里将主要介绍端口类和AVStream，而流类因为较为罕见且过时，不会多加讨论。 

### [端口类](https://learn.microsoft.com/en-us/windows-hardware/drivers/audio/introduction-to-port-class) 

大多数用于PCI和DMA型音频设备的硬件驱动程序，它处理与音频相关的数据传输，例如音量控制、麦克风输入等等，主要会使用到的组件函数库会是portcls.sys。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/5.png) 

### [AVStream](https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/avstream-overview) 

AVStream则是由微软提供的多媒体类驱动程序，主要支持仅限影片的流和整合音频/影片流，目前跟影像有关的处理多数都跟这类别有关，例如你的视频摄像头、采集卡等等。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/6.png) 

实际上内核流的使用很复杂，因此这里只会简单的叙述一下，更多详细内容可以参考[微软官方文档](https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/)。 

## 与设备交互 

在我们想要与音频设备或是视频摄像头等设备互动时该怎么做呢？其实就跟一般设备互动一样，可以透过CreateFile函数来开启一个设备。那么这类设备的名称又会是什么呢？其实这边不太会像是`\Devcie\NamedPipe`这类型的名称，而是会像下面这样的路径： ``` \\?\hdaudio#subfunc_01&ven_8086&dev_2812&nid_0001&subsys_00000000&rev_1000#6&2f1f346a&0&0002&0000001d#{6994ad04-93ef-11d0-a3cc-00a0c9223196}\ehdmiouttopo  ``` 

### 枚举设备 

每台电脑都可能不一样，必须使用[SetupDiGetClassDevs](https://learn.microsoft.com/zh-tw/windows/win32/api/setupapi/nf-setupapi-setupdigetclassdevsw)等API去列举设备，一般来说KS系列的设备都会注册在`KSCATEGORY*`底下，像是音频设备就会注册在[KSCATEGORY\_AUDIO](https://learn.microsoft.com/zh-tw/windows-hardware/drivers/install/kscategory-audio)中。 你也可以使用KS所提供的[KsOpenDefaultDevice](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ksproxy/nf-ksproxy-ksopendefaultdevice)获得该类别中第一个符合的PnP装置的句柄，实际上来说也只是SetupDiGetClassDevs和CreateFile的封装而已。 ``` hr = KsOpenDefaultDevice(KSCATEGORY_VIDEO_CAMERA,GENERIC_READ|GENERIC_WRITE, &g_hDevice)  ``` 

### 内核流对象 

我们在开启这些设备之后，内核流会在内核中建立一些相关的实例，其中最为重要的就是[KS过滤器](https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/ks-filters)及[KS引脚](https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/ks-pins)。在内核流的使用过程中，这些实例会被频繁使用，它们主要用来封装设备的硬件功能，方便开发者透过统一的接口进行流的处理。 这边先以[音频过滤器](https://learn.microsoft.com/en-us/windows-hardware/drivers/audio/audio-filters)作为例子，其他多数大同小异，我们也只会简单介绍，其他细节请自行参考微软官方文档。 

#### KS过滤器 

每个KS过滤器通常代表一个设备或设备的特定功能，在我们打开一个音频设备后，大部分情况下会对应到一个内核过滤器，当我们从音频设备读取资料时，这些资料就会先通过这个KS过滤器进行处理。 概念上如下所示，中间的大框表示一个代表音频设备的KS过滤器。而我们想要从音频设备中读取资料时，会从左边读入过滤器，经过几个节点进行处理后，从右边输出。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/7.png) (From: https://learn.microsoft.com/en-us/windows-hardware/drivers/audio/audio-filters) 

#### KS引脚 

上图中，读取及输出资料的点称为引脚，内核也有相对应的KS引脚对象，用于描述这些引脚的行为，例如引脚是输入端还是输出端、支持的格式有哪些等。我们使用时必须在过滤器上，[开启一个引脚](https://learn.microsoft.com/zh-tw/windows-hardware/drivers/ddi/ks/nf-ks-kscreatepin)来建立实例，才能从设备读取或输出资料。 

### KS属性 

这些KS对象都有自己的属性，每个属性都有相对应的功能，前面所提到的引脚中的资料格式、音量大小及设备的状态等等，这些都是一个属性，通常会对应到一组GUID，我们可以透过[IOCTL\_KS\_PROPERTY](https://learn.microsoft.com/zh-tw/windows-hardware/drivers/ddi/ks/ni-ks-ioctl_ks_property)来读取或设定这些属性。 这大大简化了多媒体驱动程序的开发，并确保了不同设备之间的一致性和可扩展性。 

### 从网络摄像头读取流 

这边就用个简单的范例来介绍一下应用程序如何从视频摄像头读取资料 其最简单的流程大概如这张图所示： ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/8.png) 

1.  开启设备后获得设备句柄 

2.  使用这个句柄在这个过滤器上建立引脚的实例并获得引脚句柄 
3.  使用IOCTL\_KS\_PROPERTY设置引脚的状态到RUN 
4.  最后就可以使用[IOCTL\_KS\_READ\_STREAM](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ks/ni-ks-ioctl_ks_read_stream)从这个引脚中读资料进来 

## 内核流架构 

对漏洞研究而言，我们必须先了解其架构，思考有哪些可能的攻击面 在初步了解内核流有哪些功能和操作后，为了找寻漏洞必须先了解一下架构，了解Windows是怎么实现这些功能、分别有哪些组件等等，才知道应该要分析哪些系统文件，从哪下手会比较好。 经过我们分析后，整个架构约略会像这张图所示： ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/9.png) 在内核流组件中，最为核心的就是ksthunk.sys及ks.sys，几乎所有功能都会与它们有关。 r

### ksthunk（内核流WOW转换服务驱动程序）

 应用程序调用DeviceIoControl后，在内核流中的**入口点**，但它功能很简单，负责将WoW64进程中32位的请求转换成64位的请求，使得下层的驱动程序就可以不必为32位的结构另外处理。 

### ks（内核连接和流架构库） 

内核流的**核心组件**之一，它是内核流的函数库，负责及转发IOCTL\_KS\_PROPERTY等请求到对应设备的驱动程序中，同时也会负责处理AVStream的相关功能。 

### IOCTL\_KS\_\*的工作流程 

而在呼叫DeviceIoControl时，就会像下所示，将使用者的请求依序给相对应的驱动程序来处理 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/10.png) 而到第6步时ks.sys就会根据你请求的[属性](https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/ksproperty-structure)来决定要交给哪个驱动程序及处理程序来处理你的请求。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/11.png) 最终再转发给相对应的驱动程序，如上中最后转发给portcls中的处理程序来操作音频设备。 到这边应该对内核流的架构及流程有初步概念了，接下来就是找洞的时刻。依照现有的元素来看，哪些是值得一看的攻击面呢？ 

### 从攻击者的角度 

>在挖掘漏洞前，如果能仔细思考怎样的情况下容易有洞，可以达到事半功倍的效果 

从一个漏洞研究员的角度来说，大概会有下列这几个点 

1. 每个设备中的属性处理程序每个设备中的KS对象都有各自的属性，而且每个属性都有各自的实现，有些属性处理起来容易出问题。 
2. ks及ksthunk ks及ksthunk已经有很长一段时间没有漏洞，但却是个最容易接触到的入口点，也许是一个好目标，上一次出现的漏洞是在2020年[@nghiadt1098](https://x.com/nghiadt1098)所找到的两个漏洞[CVE-2020-16889](https://msrc.microsoft.com/update-guide/en-us/vulnerability/CVE-2020-16889)及[CVE-2020-17045](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-17045)。 
3. 每个驱动程序都各自处理一部分的内容在内核流的部分功能中，有些驱动程序会各自先处理部分的内容，

可能会造成一些不一致性的问题。 我们针对上面几个角度去对整个内核流做代码审查后，很快的就发现了几个比较容易发现的漏洞： 

* portcls.sys    
  * CVE-2024-38055（设置引脚数据格式时的越界读取）    
  * CVE-2024-38056 
* ksthunk    
  * CVE-2024-38054（越界写入）    
  * CVE-2024-38057 

不过我们这一篇不会一一讲解这些漏洞，这几个多数都是没有检查长度或是索引之类的越界存取等等明显的漏洞，也许会在后续的部分慢慢来讲解，[@Fr0st1706](https://x.com/Fr0st1706)也在前阵子写出了 CVE-2024-38054 的[利用](https://github.com/Black-Frost/windows-learning/tree/main/CVE-2024-38054)，这边就暂时留给读者研究了。 这篇要提的是，我们在审查过程中发现了一些有趣的事情。 你觉得下面这段代码是否安全呢？ 

```
__int64 __fastcall CKSThunkDevice::CheckIrpForStackAdjustmentNative(__int64 a1, struct _IRP *irp, __int64 a3, int *a4)
{

    if ( irp->RequestorMode )
    {
        v14 = 0xC0000010;
    }
    else
    {
        UserBuffer = (unsigned int *)irp->UserBuffer;
       ...
        v14 = (*(__int64 (__fastcall **)(_QWORD, _QWORD, __int64 *))    (Type3InputBuffer + 0x38))(// call Type3InputBuffer+0x38
                *UserBuffer,
                0LL,
               v19);
    }
} 
```



看到这段代码让我想起了[CVE-2024-21338](https://decoded.avast.io/janvojtesek/lazarus-and-the-fudmodule-rootkit-beyond-byovd-with-an-admin-to-kernel-zero-day/)，该漏洞原先并没有任何检查，而在修补后则是新增了[ExGetPreviousMode](https://learn.microsoft.com/zh-tw/windows-hardware/drivers/ddi/wdm/nf-wdm-exgetpreviousmode)，但这边检查则是使用了[IRP](https://learn.microsoft.com/zh-tw/windows-hardware/drivers/ddi/wdm/ns-wdm-_irp)中的 RequestorMode 来做检查，不过一般情况下从使用者呼叫的 IOCTL 的 RequestorMode 都会是 UserMode(1)是不会有问题的。 此时我又想起了[James Forshaw](https://x.com/tiraniddo)的[Windows Kernel Logic Bug Class: Access Mode Mismatch in IO Manager](https://googleprojectzero.blogspot.com/2019/03/windows-kernel-logic-bug-class-access.html)这篇文章。 

## 被忽视的漏洞类别 

这部分我们必须先提一下几个名词跟概念，不过如果你对 PreviousMode 及 RequestorMode 很熟悉，可以跳至[A logical bug class](#A-logical-bug-class)。 

### PreviousMode 

第一个是 PreviousMode，在应用程序中如果使用者透过 Nt*等系统服务调用对设备或文件进行操作时，进入内核后就会在[\_ETHREAD](https://learn.microsoft.com/zh-tw/windows-hardware/drivers/kernel/eprocess#ethread)中的 PreviousMode 标注 UserMode(1)表示这个系统服务调用是来自用户模式的应用程序。如果你是从内核模式中，例如设备驱动程序呼叫 Zw*系统服务调用的 API 就会标记成 KernelMode(0)。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/12.png) 

### RequestorMode 

另外一个类似的则是 IRP 中的 RequestorMode，这里就是记录你原始的请求是来自用户模式还是内核模式，在内核驱动程序中的代码是非常常用到的字段，通常会来自 PreviousMode。 

经常被用来决定是否要对来自使用者的请求做额外检查，像是内存访问检查或是安全访问检查，例如下面这个例子中，如果请求来自用户模式就会检查使用者提供的位置，如果是从内核来的，就不做额外检查以增加效率。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/13.png) 但实际上这也出现了一些问题… 

### A logical bug class 

在[James Forshaw](https://x.com/tiraniddo)的[Windows Kernel Logic Bug Class: Access Mode Mismatch in IO Manager](https://googleprojectzero.blogspot.com/2019/03/windows-kernel-logic-bug-class-access.html)中，就提到了一种漏洞类别。 这里可以先想想看，使用者呼叫 NtDeviceIoControlFile之类的系统服务调用之后，如果处理的驱动程序又去用使用者可控的资料来作为 ZwOpenFile 的参数，会发生什么事。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/14.png) 在驱动程序呼叫 ZwOpenFile 之后，PreviousMode 会转换成为`KernelMode`，并且在 NtOpenFile 处理时，就会因为 PreviousMode 是`KernelMode`的关系少掉大部分的检查，而后续的`Irp->RequestorMode`也会因此变成`KernelMode`，从而绕过安全访问检查及内存访问检查。不过这边很看后续处理的驱动程序怎么去实现这些检查，如果只依赖 RequestorMode 来决定要不要检查，就可能会有问题。这边省略了一些细节，实际上的状况会稍微再复杂一点点，也会跟 CreateFile 的标志有关，细节可参考下列几篇文章： 

* [Windows Kernel Logic Bug Class: Access Mode Mismatch in IO Manager](https://googleprojectzero.blogspot.com/2019/03/windows-kernel-logic-bug-class-access.html) 
* [Hunting for Bugs in Windows Mini-Filter Drivers](https://googleprojectzero.blogspot.com/2021/01/hunting-for-bugs-in-windows-mini-filter.html) 
* [Local privilege escalation via the Windows I/O Manager: a variant finding collaboration](https://msrc.microsoft.com/blog/2019/03/local-privilege-escalation-via-the-windows-i-o-manager-a-variant-finding-collaboration/) 



这边有这样的概念就好，原先这些研究主要是在 Zw*系列的系统服务调用上面，大家可以思考一下，有没有其他类似的情况，也可能造成这种逻辑漏洞呢？ 

#### 新的漏洞模式 

事实上来说是有的，使用[IoBuildDeviceIoControlRequest](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iobuilddeviceiocontrolrequest)这个方法去创建一个 DeviceIoControl 的 IRP 时，万一没注意到也很容易有这样的问题。这个 API 主要是内核驱动程序用来呼叫 IOCTL 的其中一种方法，它会帮你建好 IRP，而后续在去呼叫[IofCallDriver](https://learn.microsoft.com/zh-tw/windows-hardware/drivers/ddi/wdm/nf-wdm-iofcalldriver)，就可以在内核驱动程序中呼叫 IOCTL。在[Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iobuilddeviceiocontrolrequest)中，有一段话特别值得注意： ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/15.png) 也就是预设情况下，如果你没有特别去设置 RequestorMode 就会直接以 KernelMode 形式去呼叫 IOCTL。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/16.png) 

按照这个思路，我们重新回头审视一下我们的目标内核流，我们发现了一个吸引我们的地方。 

![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/17.png) 

在内核流中使用这个 IoBuildDeviceIoControlRequest 地方是在`ks!KsSynchronousIoControlDevice`，而主要内容明显就是在用刚刚提到的方法，在内核中呼叫 DeviceIoControl，不过这边看似有好好的设置`Irp->RequestorMode`，且会根据 KsSynchronousIoControlDevice 参数不同而去设置不同的数值，对于开发者来说会是一个方便的函数库。 然而… ks!CKsPin::GetState![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/18.png) ks!SerializePropertySet![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/19.png) ks!UnserializePropertySet![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/20.png) 

我们发现到在内核流中，全部有使用到`KsSynchronousIoControlDevice`的地方都是固定的使用 KernelMode(0)，到这边就可以仔细的检查看看，有用到的地方是否有安全上的问题了。因此我们将内核流中的漏洞模式转换成下列几点：

1. 有使用 KsSynchronousIoControlDevice。 
2. 有可控的：    

*   InputBuffer。   
*   OutputBuffer。 

3.  第二次处理 IOCTL 的地方有依赖 RequestorMode 做安全检查，并且有可以作为提权利用的地方。![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/21.png) 

按照这个模式我们很快地就找到了第一个漏洞。 



## 漏洞及利用

### CVE-2024-35250 

这个漏洞也是我们今年在[Pwn2Own Vancouver 2024 中所使用的漏洞](https://x.com/thezdi/status/1770517322203070674)。在内核流的 IOCTL\_KS\_PROPERTY 功能中，为了让效率增加，提供了`KSPROPERTY_TYPE_SERIALIZESET`和`KSPROPERTY_TYPE_UNSERIALIZESET`功能允许使用者透过**单一呼叫**与多个属性进行操作。当我们用这功能时，这些请求将被 KsPropertyHandler 函数分解成多个呼叫，详情可参考[这篇](https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/ksproperty-structure#remarks)。 该功能实现在 ks.sys 中。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/22.png) 上图中可以看到，在 ks 处理属性时，如果有给上述的标志就会由 UnserializePropertySet 来处理你的请求。 我们这边就先来看一下 UnserializePropertySet。 

```
unsigned __int64 __fastcall UnserializePropertySet(
    PIRP irp,
    KSIDENTIFIER* UserProvideProperty,
    KSPROPERTY_SET* propertyset_)
{
   ...
    New_KsProperty_req = ExAllocatePoolWithTag(NonPagedPoolNx, InSize, 0x7070534Bu);
   ...
    memmove(New_KsProperty_req, CurrentStackLocation->Parameters.DeviceIoControl.Type3InputBuffer, InSize); //------[1] 
   ...
    status = KsSynchronousIoControlDevice(
            CurrentStackLocation->FileObject,
            0,
            CurrentStackLocation->Parameters.DeviceIoControl.IoControlCode,
            New_KsProperty_req,
            InSize,
            OutBuffer,
            OutSize,
            &BytesReturned); //-----------[2]
   ...
} 
```



可看到在处理过程中会先将原始的请求，复制到新分配出来的缓冲区中\[1\]，而后续就会使用这个缓冲区来使用 KsSynchronousIoControlDevice 呼叫新的 IOCTL\[2\]。其中`New_KsProperty_req`及`OutBuffer`都是使用者所传入的内容。 而呼叫 UnserializePropertySet 时的流程，大概如下所示： ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/23.png) 这边呼叫 IOCTL 时可以看到图中第 2 步 I/O 管理器会将`Irp->RequestorMode`设成 UserMode(1)，直到第 6 步时，ks 会去判断使用者请求的属性是否存在于该 KS 对象中，如果该 KS 对象的属性**存在**，并且有设置`KSPROPERTY_TYPE_UNSERIALIZESET`就会用`UnserializePropertySet`来处理指定的属性。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/24.png) 而接下来第 7 步就会呼叫 KsSynchronousIoControlDevice 重新做一次 IOCTL，而此时新的`Irp->RequestorMode`就变成了 KernelMode(0)了，而后续的处理就如一般的 IOCTL\_KS\_PROPERTY 相同，就不另外详述了，总之我们到这里已经有个可以任意做 IOCTL\_KS\_PROPERTY 的基本条件了，接下来我们必须寻找看看是否有可以提权的地方。 

### 提权 

最先看到的想必就是入口点 ksthunk，我们这边可以直接来看`ksthunk!CKSThunkDevice::DispatchIoctl`。 

```
 __int64 __fastcall CKSThunkDevice::DispatchIoctl(CKernelFilterDevice *a1, IRP *irp, unsigned int a3, NTSTATUS *a4)
{
 ...
  if ( IoIs32bitProcess(irp) && irp->RequestorMode ) //------[3]
  {
   //Convert 32-bit requests to 64-bit requests
  }
  else if ( CurrentStackLocation->Parameters.DeviceIoControl.IoControlCode == IOCTL_KS_PROPERTY )
  {
    return CKSThunkDevice::CheckIrpForStackAdjustmentNative((__int64)a1, irp, v11, a4) //-----[4];
  }
} 
```



ksthunk 会先判断是否是 WoW64 的进程的请求，如果是就会将原本 32 位的请求转换成 64 位的\[3\]，如果原本就是 64 位则会呼叫`CKSThunkDevice::CheckIrpForStackAdjustmentNative`\[4\]往下传递。 

```
 __int64 __fastcall CKSThunkDevice::DispatchIoctl(CKernelFilterDevice *a1, IRP *irp, unsigned int a3, NTSTATUS *a4)
{
 ...
  if ( IoIs32bitProcess(irp) && irp->RequestorMode ) //------[3]
  {
   //Convert 32-bit requests to 64-bit requests
  }
  else if ( CurrentStackLocation->Parameters.DeviceIoControl.IoControlCode == IOCTL_KS_PROPERTY )
  {
    return CKSThunkDevice::CheckIrpForStackAdjustmentNative((__int64)a1, irp, v11, a4) //-----[4];
  }
} __int64 __fastcall CKSThunkDevice::CheckIrpForStackAdjustmentNative(__int64 a1, struct _IRP *irp, __int64 a3, int *a4)
{
 ...
    if ( *(_OWORD *)&Type3InputBuffer->Set == *(_OWORD *)&KSPROPSETID_DrmAudioStream
        &&!type3inputbuf.Id
        && (type3inputbuf.Flags & 2)!= 0 )   //-----[5] 
    {
        if ( irp->RequestorMode ) //-------[6]
        {
        v14 = 0xC0000010;
        }
        else
        {
        UserBuffer = (unsigned int *)irp->UserBuffer;
       ...
        v14 = (*(__int64 (__fastcall **)(_QWORD, _QWORD, __int64 *))(Type3InputBuffer + 0x38))(// call Type3InputBuffer+0x38
                *UserBuffer,
                0LL,
                v19); //------------[7]
        }
    } 
} 
```



我们在\[5\]看到，如果我们给定的属性集是[KSPROPSETID\_DrmAudioStream](https://learn.microsoft.com/mt-mt/windows-hardware/drivers/audio/kspropsetid-drmaudiostream)，就有特别的处理。而在\[6\]时，会先去判断 Irp->RequestorMode 是否为 KernelMode(0)，如果从 UserMode(1)呼叫的 IOCTL 就会直接返回错误，但如果我们使用前面所说的`KSPROPERTY_TYPE_UNSERIALIZESET`来呼叫 IOCTL，并指定`KSPROPSETID_DrmAudioStream`这个属性，那么这里\[6\]就会是 KerenlMode(0)。接下就会在\[7\]直接使用使用者所传入的内容作为函数呼叫，甚至第一个参数是可控的，实际写 PoC 后，验证了我们的结果。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/25.png) 这边可能会有人有疑惑，什么设备或是情况下会有`KSPROPSETID_DrmAudioStream`？实际上来说音频设备大多情况下都会有，主要是用来设置 DRM 相关内容用的。 



### 利用 

在有了任意呼叫之后，要达成提权就不是太大的问题，虽然会遇到 kCFG、kASLR、SMEP 等等保护，但在 Medium IL 下唯一比较需要处理的就只有 kCFG。 

-  **kCFG** 
-  kASLR    
   -  NtQuerySystemInformation 
-  SMEP    
   - * 重用内核代码 *   … 

#### 绕过 kCFG 

那我们目标很简单，就是从合法的函数做出任意写的基本条件，而之后就可以利用常见的方法[用系统令牌取代当前的进程令牌](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/how-kernel-exploits-abuse-tokens-for-privilege-escalation#id-1.-replacing-tokens-for-privilege-escalation)或是[滥用牌权限](https://media.blackhat.com/bh-us-12/Briefings/Cerrudo/BH_US_12_Cerrudo_Windows_Kernal_Slides.pdf)

去做到提权。 直觉地会直接去找看看，kCFG 中合法的函数名称有 set 的函数，比较可能是可以写入的。我们这里是直接拿 ntoskrnl.exe 中导出函数去寻找看看是否有合法的函数，这些大多情况下都是合法的。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/26.png) 而很快的我们就找到了[RtlSetAllBits](https://learn.microsoft.com/zh-tw/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlsetallbits)。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/27.png) 它是个非常好用的 gadget 而且是 kCFG 中合法的函数，另外也只要控制一个参数`_RTL_BITMAP`。 

```
struct _RTL_BITMAP
{
    ULONG SizeOfBitMap;                                               
    ULONG* Buffer;                                                   
}; 
```



我们可将 Buffer 指定到任意位置并指定大小，就可以将一段范围的 bits 全部设置起来，到这边就差不多结束了，只要将`Token->Privilege`全部设置起来，就可以利用 Abuse Privilege 方法来做到提权了。 然而…在 Pwn2Own 比赛前，我们在 Hyper-V 上安装一个全新 Windows 11 23H2 VM 测试 Exploit，结果失败了。而且是在开启设备阶段就失败。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/28.png) 经过调查后发现到 Hyper-V 在预设情况下并不会有音频设备，造成 exploit 会失败。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/29.png) 在 Hyper-V 中，预设情况下只会有 MSKSSRV，然而 MSKSSRV 也没有 KSPROPSETID\_DrmAudioStream 这个属性，使得我们无法成功利用这个漏洞达成提权，因此我们必须找其他方式触发或者找新的漏洞，此时我们决定重新审查一遍整个流程，看看是否还有其他可能利用的地方。 

### CVE-2024-30084 

重新审视后，发现到 IOCTL\_KS\_PROPERTY 是使用[Neither I/O](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-neither-buffered-nor-direct-i-o)来传递资料的，也就是说会直接拿使用者的输入缓冲区来做资料上的处理，一般来说不太建议使用这个方法，很常出现 Double Fetch 的问题。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/30.png) 我们可从上图中 KspPropertyHandler 看到，在使用者呼叫 IOCTL 之后，会直接将 Type3InputBuffer 复制到新分配出来的缓冲区中，其中会存有[KSPROPERTY](https://learn.microsoft.com/zh-tw/windows-hardware/drivers/stream/ksproperty-structure)结构，接下会用这结构中的 GUID 来查询属性是否有在该设备所支持的属性中，若存在才会继续往下呼叫`UnserializePropertySet`。 这边我们再回头看一眼`UnserializePropertySet`。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/31.png) 我们可以发现到，**它又再次从 Type3InputBuffer 复制使用者所提供的资料**做为新的 IOCTL 的输入，很明显的这边就存在了一个 Double Fetch 的漏洞，因此我们将整个利用流程改成下的样子。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/32.png) 我们一开始发送 IOCTL\_KS\_PROPERTY 时，就会先以 MSKSSRV 既有的属性`KSPROPSETID_Service`来做后续操作，而在图中第 6 步时，会先复制一份属性的 GUID 到内核中，而后再用这个属性 GUID 去查询是否有在该 KS 对象的支持清单中，而这边因为 MSKSSRV 有支持，就会往下呼叫`UnserializePropertySet`。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/33.png) 在呼叫 UnserializePropertySet 后，因为有 Double Fetch 的漏洞，让我们可以在检查后到使用之间，将`KSPROPSETID_Service`换成`KSPROPSETID_DrmAudioStream`，而接下就可以让 ks 使用`KSPROPSETID_DrmAudioStream`作为请求来发送 IOCTL，从而触发前述了 CVE-2024-35250 逻辑漏洞，使这个漏洞不论在什么环境下都可以使用。 最终我们成功在 Pwn2Own Vancouver 2024 中，成功攻下 Micorsoft Windows 11。 ![](https://raw.githubusercontent.com/Hipepper/allPictures/main/202410/1018/34.png) 在 Pwn2Own 结束后，经过我们调查，发现到这个漏洞从 Windows 7 就存在了，至少存在将近 20 年，而且利用上非常稳定，有着百分之百的成功率，强烈建议大家尽快更新至最新版本。    



## 参考

- [Critically Close to Zero-Day: Exploiting Microsoft Kernel Streaming Service](https://securityintelligence.com/x-force/critically-close-to-zero-day-exploiting-microsoft-kernel-streaming-service/)
- [Windows Kernel Security - A Deep Dive into Two Exploits Demonstrated at Pwn2Own](https://conference.hitb.org/hitbsecconf2023hkt/materials/D2T1 - Windows Kernel Security - A Deep Dive into Two Exploits Demonstrated at Pwn2Own - Thomas Imbert.pdf)
- [CVE-2023-29360 Analysis](https://big5-sec.github.io/posts/CVE-2023-29360-analysis/)
- [Racing Round and Round: The Little Bug That Could](https://securityintelligence.com/x-force/little-bug-that-could/)
- [Windows Kernel Logic Bug Class: Access Mode Mismatch in IO Manager](https://googleprojectzero.blogspot.com/2019/03/windows-kernel-logic-bug-class-access.html)
- [Hunting for Bugs in Windows Mini-Filter Drivers](https://googleprojectzero.blogspot.com/2021/01/hunting-for-bugs-in-windows-mini-filter.html)
- [Local Privilege Escalation via the Windows I/O Manager: A Variant Finding & Collaboration](https://msrc.microsoft.com/blog/2019/03/local-privilege-escalation-via-the-windows-i-o-manager-a-variant-finding-collaboration/)。