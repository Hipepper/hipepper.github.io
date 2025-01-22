---
title: 俄罗斯APT组织技战术情报
date: 2024-11-05 18:19:11
categories: "APT"
tags: 
 - 'APT'
 - 'RussiaAPT'
 - 'CTI'
---

# 前言

- Russian GRU: 主要情报局（俄罗斯军队）
- Russian SVR: 俄罗斯联邦外国情报局
- Russian FSB: 俄罗斯联邦安全局

# 技战术

## 远程监控和管理（RMM）工具

 提示

- RMM（远程监控和管理）工具是 IT 专业人员和托管服务提供商 （MSP） 用来远程监控、管理和维护 IT 系统、网络和设备的一种软件。
- 这些工具旨在提高 IT 运营效率，使技术人员能够从集中位置处理任务，而无需对客户端设备进行物理访问。

通过合法的 RMM 渠道进行操作，攻击者可以通过混入常规 IT 活动来逃避检测，并且由于这些工具提供的特权提升，可能会绕过安全措施。

| Tool Name                       | Threat Group Usage |
| ------------------------------- | ------------------ |
| InnoSetup                       | UAC-0020           |
| IntelliAdmin                    | Turla              |
| RemCom                          | Sandworm           |
| Remote Manipulator System (RMS) | Gamaredon          |
| RemoteUtilities                 | UAC-0050           |
| SyncThing                       | UAC-0020           |
| TeamViewer                      | BERSERK BEAR       |
| UltraVNC                        | Gamaredon          |

## 渗透工具

 提示

文件同步和管理工具旨在促进跨各种平台和云存储服务高效传输、备份和同步文件。

 重要

- 这些工具可能被滥用，将被盗数据上传到攻击者控制的云帐户或目标服务器。
- 通过利用加密数据传输，攻击者可以向网络监控系统隐藏他们的活动，将恶意行为与合法操作混合在一起。
- 这些工具的合法性通常会阻止安全系统立即检测到。



| Tool Name    | Threat Group Usage    |
| ------------ | --------------------- |
| 4Shared      | Turla                 |
| Dropbox      | COZY BEAR, Turla      |
| Firebase     | COZY BEAR             |
| Gmail        | Turla                 |
| GMX          | Turla                 |
| Google Drive | COZY BEAR             |
| Notion       | COZY BEAR             |
| MEGA         | EMBER BEAR            |
| OneDrive     | COZY BEAR, Turla      |
| Telegram     | Gamaredon             |
| Trello       | COZY BEAR             |
| Rclone       | EMBER BEAR, Gamaredon |
| VFEmail      | Turla                 |

## 凭证盗窃工具

提示

- 有许多免费的密码恢复工具可用，旨在帮助用户恢复存储在自己的系统中丢失或忘记的密码。
- 这些工具可以提取保存在网络浏览器、电子邮件客户端和其他应用程序中的密码。
- IT 专业人员可以使用这些工具来恢复系统维护或故障排除所需的凭据。

重要的

如果攻击者在未经所有者许可的情况下在计算机上运行这些工具，则它们可能会被非法利用获取密码，从而导致未经授权访问敏感信息。

| Tool Name     | Threat Group Usage                                    |
| ------------- | ----------------------------------------------------- |
| CookieEditor  | COZY BEAR                                             |
| Mimikatz      | COZY BEAR, FANCY BEAR, BERSERK BEAR, Gamaredon, Turla |
| ProcDump      | BERSERK BEAR                                          |
| SharpChromium | COZY BEAR                                             |



## 防御规避工具



提示

- 各种免费的恶意软件检测工具专门用于识别和删除像 rootkit 这样的隐秘威胁。
- 它们提供扫描隐藏进程、文件和驱动程序、分析系统内存中的恶意模块以及监控系统挂钩以查找未经授权的修改等功能。
- 这些工具提供了对系统内部的详细了解，有助于发现标准防病毒程序可能错过的深层嵌入的恶意软件。

重要的

- 恶意行为者可以滥用这些 rootkit 检测工具来干扰安全工具、篡改文件和注册表以破坏工具功能以及破坏内存以阻止检测。
- 通过使用这些工具进行权限提升，对手可以禁用或改变安全软件的运行，从而消除系统用于检测或预防威胁的方法。



| Tool Name         | Threat Group Usage |
| ----------------- | ------------------ |
| EDRSandBlast      | COZY BEAR          |
| libprocesshider   | Sandworm           |
| PowerShellRunner  | Turla              |
| SDelete           | Sandworm           |
| VirtualBox Driver | Turla              |



## 网络工具



提示

- 网上有许多网络隧道工具可用于管理和与不同环境中的系统交互。
- 它们允许用户通过可以绕过网络限制和防火墙的加密通道安全地连接到远程服务器或服务。
- 这些工具还可以将本地开发服务器暴露到互联网上以进行测试和共享。
- 它们广泛用于远程管理和开发工作流程等任务，为网络管理提供灵活性。

重要的

- 网络犯罪分子可以利用网络隧道工具创建加密隧道、逃避检测并访问受限网络。
- 这些工具本质上为对手提供了指挥和控制的便利，帮助他们站稳脚跟并策划进一步的恶意活动。



| Tool Name   | Threat Group Usage                          |
| ----------- | ------------------------------------------- |
| Chisel      | Sandworm                                    |
| Cloudflared | Gamaredon                                   |
| dnscat2     | EMBER BEAR                                  |
| Dropbear    | COZY BEAR                                   |
| FortiClient | BERSERK BEAR                                |
| GOST        | EMBER BEAR                                  |
| Iodine      | EMBER BEAR                                  |
| Ngrok       | Gamaredon                                   |
| OpenSSH     | FANCY BEAR                                  |
| Pivotnacci  | Sandworm                                    |
| ProxyChains | EMBER BEAR                                  |
| ReGeorg     | COZY BEAR, FANCY BEAR, EMBER BEAR, Sandworm |
| Rsockstun   | COZY BEAR                                   |
| SSHDoor     | FANCY BEAR                                  |



## 发现和爆破工具



提示

- 网上有许多网络扫描和分析工具，旨在帮助管理员和 IT 专业人员完成诸如发现和映射网络设备、执行 IP 地址和开放端口的详细扫描以及查询 Active Directory 等网络服务等任务。

重要的

- 恶意对手利用这些网络管理工具进行侦察并收集有关目标网络的详细信息。
- 他们可以使用这些工具来识别活动设备、开放端口和漏洞，然后利用这些漏洞来获取访问权限。
- 此外，查询活动目录服务的工具可以让他们收集有关用户、群组和权限的敏感信息，从而发起有针对性的攻击或内部威胁。
- 本质上，这些工具虽然对于合法的网络管理很有价值，但却可能被滥用来规划和利用网络基础设施来达到邪恶的目的。



| Tool Name        | Threat Group Usage    |
| ---------------- | --------------------- |
| Acunetix         | EMBER BEAR            |
| Amass            | EMBER BEAR            |
| AADInternals     | COZY BEAR             |
| AdFind           | COZY BEAR             |
| Adminer          | EMBER BEAR            |
| Angry IP Scanner | BERSERK BEAR          |
| Bloodhound       | COZY BEAR, EMBER BEAR |
| Droopescan       | EMBER BEAR            |
| DSInternals      | COZY BEAR             |
| JoomScan         | EMBER BEAR            |
| LdapDomainDump   | EMBER BEAR            |
| NBTScan          | Turla                 |
| Nmap             | EMBER BEAR            |
| Masscan          | EMBER BEAR            |
| RoadTools        | COZY BEAR             |
| SScan            | Turla                 |
| WPScan           | EMBER BEAR            |



## CC工具

提示

- 攻击性安全工具由专业的道德黑客开发，用于模拟网络攻击并评估组织的防御能力。
- 这些工具为后开发活动提供了强大的功能，例如隐秘通信、横向移动以及高级指挥和控制功能。
- 一些工具专注于绕过现代安全防御的规避技术，从而实现真实的威胁模拟和有效载荷开发。

重要的

- 网络犯罪分子可以通过各种方式获取攻击性安全工具，通常利用合法渠道或采取非法手段来获取。
- 这些工具还允许攻击者自动执行部分攻击，从而使攻击更加高效、范围更加广泛。

| Tool Name         | Threat Group Usage                                        |
| ----------------- | --------------------------------------------------------- |
| Brute Ratel C4    | COZY BEAR                                                 |
| Cobalt Strike     | COZY BEAR, Sandworm                                       |
| CrackMapExec      | EMBER BEAR, BERSERK BEAR                                  |
| Empyre            | FANCY BEAR, Sandworm                                      |
| EvilGinx          | COLDRIVER                                                 |
| Evil-WinRM        | Turla                                                     |
| Hydra             | BERSERK BEAR                                              |
| Impacket          | COZY BEAR, FANCY BEAR, EMBER BEAR, Sandworm, BERSERK BEAR |
| JuicyPotatoNG     | Sandworm                                                  |
| Koadic            | FANCY BEAR                                                |
| LinPEAS           | EMBER BEAR                                                |
| NetCat            | EMBER BEAR                                                |
| Nishang           | FANCY BEAR                                                |
| Metasploit        | FANCY BEAR, EMBER BEAR, Sandworm, Turla                   |
| Meterpreter       | EMBER BEAR, Sandworm                                      |
| PAS Web Shell     | EMBER BEAR, Sandworm                                      |
| Phishery          | BERSERK BEAR                                              |
| PoshC2            | Sandworm                                                  |
| PowerSploit       | COZY BEAR, Turla                                          |
| PowerShell Empire | FANCY BEAR, Sandworm, Turla                               |
| Responder         | FANCY BEAR, EMBER BEAR                                    |
| RottenPotatoNG    | Sandworm                                                  |
| Rubeus            | COZY BEAR                                                 |
| Sliver            | COZY BEAR                                                 |
| Weevely Web Shell | Sandworm                                                  |
| WinPEAS           | COZY BEAR                                                 |
| WSO Web Shell     | EMBER BEAR, Sandworm                                      |

## 持久化文件

提示

- Windows 环境配备了各种各样的命令行实用程序。
- 这些工具共同为高效的系统管理、故障排除和优化提供了强大的支持，帮助管理员维护安全、稳定和高性能的 Windows 环境。

重要的

- 网络犯罪分子经常利用合法的 Windows 管理工具执行恶意操作，同时逃避检测。
- 这些工具用于远程执行、文件传输和系统管理等任务，允许攻击者在网络中横向移动、下载和执行恶意软件、操纵日志并收集敏感信息。
- 通过利用这些内置实用程序，攻击者可以秘密地开展活动，将他们的行为与正常的管理操作混合在一起。

| Tool Name                        | Threat Group Usage                                    |
| -------------------------------- | ----------------------------------------------------- |
| BITSAdmin                        | BERSERK BEAR                                          |
| MiniDump                         | FANCY BEAR                                            |
| PsExec                           | COZY BEAR, EMBER BEAR, BERSERK BEAR, Gamaredon, Turla |
| Windows Event Utility (wevtutil) | FANCY BEAR                                            |
| WMIC                             | COZY BEAR                                             |



# 总TTPs

| Discovery        | RMM Tools                       | Defense Evasion   | Credential Theft | OffSec            | Networking  | LOLBAS                           | Exfiltration |
| ---------------- | ------------------------------- | ----------------- | ---------------- | ----------------- | ----------- | -------------------------------- | ------------ |
| Acunetix         | InnoSetup                       | EDRSandBlast      | CookieEditor     | Brute Ratel C4    | Chisel      | BITSAdmin                        | 4Shared      |
| Amass            | IntelliAdmin                    | libprocesshider   | Mimikatz         | Cobalt Strike     | dnscat2     | MiniDump                         | Dropbox      |
| AADInternals     | RemCom                          | PowerShellRunner  | ProcDump         | CrackMapExec      | Dropbear    | PsExec                           | Firebase     |
| AdFind           | Remote Manipulator System (RMS) | SDelete           | SharpChromium    | Empyre            | FortiClient | Windows Event Utility (wevtutil) | Gmail        |
| Adminer          | RemoteUtilities                 | VirtualBox Driver |                  | EvilGinx          | GOST        | WMIC                             | GMX          |
| Angry IP Scanner | SyncThing                       |                   |                  | Evil-WinRM        | Iodine      |                                  | Google Drive |
| Bloodhound       | TeamViewer                      |                   |                  | Hydra             | OpenSSH     |                                  | Notion       |
| Droopescan       | UltraVNC                        |                   |                  | Impacket          | Pivotnacci  |                                  | MEGA         |
| DSInternals      |                                 |                   |                  | JuicyPotatoNG     | ProxyChains |                                  | OneDrive     |
| JoomScan         |                                 |                   |                  | Koadic            | ReGeorg     |                                  | Trello       |
| LdapDomainDump   |                                 |                   |                  | LinPEAS           | Rsockstun   |                                  | Rclone       |
| NBTScan          |                                 |                   |                  | NetCat            | SSHDoor     |                                  | VFEmail      |
| Nmap             |                                 |                   |                  | Nishang           |             |                                  |              |
| Masscan          |                                 |                   |                  | Metasploit        |             |                                  |              |
| RoadTools        |                                 |                   |                  | Meterpreter       |             |                                  |              |
| SScan            |                                 |                   |                  | PAS Web Shell     |             |                                  |              |
| WPScan           |                                 |                   |                  | Phishery          |             |                                  |              |
|                  |                                 |                   |                  | PoshC2            |             |                                  |              |
|                  |                                 |                   |                  | PowerSploit       |             |                                  |              |
|                  |                                 |                   |                  | PowerShell Empire |             |                                  |              |
|                  |                                 |                   |                  | Responder         |             |                                  |              |
|                  |                                 |                   |                  | RottenPotatoNG    |             |                                  |              |
|                  |                                 |                   |                  | Rubeus            |             |                                  |              |
|                  |                                 |                   |                  | Sliver            |             |                                  |              |
|                  |                                 |                   |                  | Weevely Web Shell |             |                                  |              |
|                  |                                 |                   |                  | WinPEAS           |             |                                  |              |
|                  |                                 |                   |                  | WSO Web Shell     |             |                                  |              |

# 一些发现

在最近的威胁分析中，观察到不同的俄罗斯威胁组织对公共可用资源的显著依赖，尤其是在入侵活动中使用各种攻击性安全工具（OST）。以下是一些主要发现：

1. **使用扫描仪的主要对手**：隶属于 GRU 的 EMBER BEAR 组织在使用扫描仪方面最为活跃。
2. **其他 GRU 威胁组**：如 FANCY BEAR 和 Sandworm，通常依赖多种攻击性安全工具来支持其入侵活动。
3. **SVR 组织的多样化工具使用**：隶属于 SVR 的 COZY BEAR 是使用不同工具总数最多的俄罗斯威胁组。
4. **工具依赖性**：记录显示，俄罗斯威胁组织对攻击性安全工具的严重依赖，累计使用多达 27 种不同的工具。
5. **共同使用的工具**：
   - **Mimikatz**：被 COZY BEAR、FANCY BEAR、BERSERK BEAR、GAMAREDON 和 Turla 使用。
   - **Impacket**：被 COZY BEAR、FANCY BEAR、EMBER BEAR、Sandworm 和 BERSERK BEAR 使用。
   - **PsExec**：被 COZY BEAR、EMBER BEAR、BERSERK BEAR、GAMAREDON 和 Turla 使用。
   - **Metasploit**：被 FANCY BEAR、EMBER BEAR、Sandworm 和 Turla 使用。
   - **ReGeorg**：被 COZY BEAR、FANCY BEAR、EMBER BEAR 和 Sandworm 使用。
6. **入侵识别**：如果在一次入侵中观察到上述工具的组合，这可能表明该入侵是由俄罗斯国家支持的威胁组织进行的，并且可能与勒索活动有关。

这些观察为我们理解俄罗斯威胁组织的战术和工具选择提供了宝贵的洞见，有助于更好地防范潜在的网络威胁。



# 报告来源

| Date Published    | Russian APT                                                  | Report                                                       |
| ----------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| 26 September 2024 | Gamaredon                                                    | https://www.welivesecurity.com/en/eset-research/cyberespionage-gamaredon-way-analysis-toolset-used-spy-ukraine-2022-2023 |
| 5 September 2024  | EMBER BEAR                                                   | https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-249a |
| 14 August 2024    | Star Blizzard                                                | https://citizenlab.ca/2024/08/sophisticated-phishing-targets-russias-perceived-enemies-around-the-globe/ |
| 19 June 2024      | COZY BEAR                                                    | https://www.cert.ssi.gouv.fr/cti/CERTFR-2024-CTI-006/        |
| 5 June 2024       | UAC-0020                                                     | https://cert.gov.ua/article/6279600                          |
| 1 May 2024        | FANCY BEAR                                                   | https://www.trendmicro.com/en_us/research/24/e/router-roulette.html |
| 19 April 2024     | Sandworm                                                     | https://cert.gov.ua/article/6278706                          |
| 17 April 2024     | Sandworm                                                     | https://services.google.com/fh/files/misc/apt44-unearthing-sandworm.pdf |
| 21 March 2024     | Turla                                                        | https://blog.talosintelligence.com/tinyturla-full-kill-chain/ |
| 22 January 2024   | UAC-0050                                                     | https://cert.gov.ua/article/6277285                          |
| 28 December 2023  | FANCY BEAR                                                   | https://cert.gov.ua/article/6276894                          |
| 13 December 2023  | COZY BEAR                                                    | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a |
| 8 December 2023   | FANCY BEAR                                                   | https://securityintelligence.com/x-force/itg05-ops-leverage-israel-hamas-conflict-lures-to-deliver-headlace-malware/ |
| 27 January 2023   | COZY BEAR                                                    | https://go.recordedfuture.com/hubfs/reports/cta-2023-0127.pdf |
| 2 May 2022        | COZY BEAR                                                    | https://cloud.google.com/blog/topics/threat-intelligence/unc3524-eye-spy-email/ |
| 27 January 2022   | COZY BEAR                                                    | https://www.crowdstrike.com/blog/observations-from-the-stellarparticle-campaign/ |
| 4 November 2021   | Gamaredon                                                    | [https://ssu.gov.ua/uploads/files/DKIB/Technical%20report%20Armagedon.pdf](https://ssu.gov.ua/uploads/files/DKIB/Technical report Armagedon.pdf) |
| 25 October 2021   | COZY BEAR                                                    | https://www.microsoft.com/en-us/security/blog/2021/10/25/nobelium-targeting-delegated-administrative-privileges-to-facilitate-broader-attacks/ |
| 1 July 2021       | FANCY BEAR                                                   | https://media.defense.gov/2021/Jul/01/2002753896/-1/-1/1/CSA_GRU_GLOBAL_BRUTE_FORCE_CAMPAIGN_UOO158036-21.PDF |
| 27 May 2021       | COZY BEAR                                                    | https://www.microsoft.com/en-us/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/ |
| 18 December 2020  | COZY BEAR                                                    | https://www.microsoft.com/en-us/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/ |
| 2 December 2020   | Turla                                                        | https://www.welivesecurity.com/2020/12/02/turla-crutch-keeping-back-door-open/ |
| 10 September 2020 | FANCY BEAR                                                   | https://www.microsoft.com/en-us/security/blog/2020/09/10/strontium-detecting-new-patters-credential-harvesting/ |
| 15 June 2020      | Turla                                                        | https://web-assets.esetstatic.com/wls/2020/05/ESET_Turla_ComRAT.pdf |
| 24 July 2019      | BERSERK BEAR                                                 | https://www.secureworks.com/research/resurgent-iron-liberty-targeting-energy-sector |
| 20 June 2019      | Turla                                                        | https://symantec-enterprise-blogs.security.com/threat-intelligence/waterbug-espionage-governments |
| 17 August 2018    | Turla                                                        | https://web-assets.esetstatic.com/wls/2018/08/Eset-Turla-Outlook-Backdoor.pdf |
| 6 June 2018       | FANCY BEAR                                                   | https://unit42.paloaltonetworks.com/unit42-sofacy-groups-parallel-attacks/ |
| 22 May 2018       | https://www.welivesecurity.com/2018/05/22/turla-mosquito-shift-towards-generic-tools/ |                                                              |
| 18 April 2018     | FANCY BEAR                                                   | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-108 |
| 16 March 2018     | BERSERK BEAR                                                 | https://www.cisa.gov/news-events/alerts/2018/03/15/russian-government-cyber-activity-targeting-energy-and-other-critical-infrastructure-sectors |
| 20 October 2017   | BERSERK BEAR                                                 | https://symantec-enterprise-blogs.security.com/threat-intelligence/dragonfly-energy-sector-cyber-attacks |
| 11 August 2017    | FANCY BEAR                                                   | https://web.archive.org/web/20170811181009/https://www.fireeye.com/blog/threat-research/2017/08/apt28-targets-hospitality-sector.html |
| 4 December 2015   | FANCY BEAR                                                   | https://securelist.com/sofacy-apt-hits-high-profile-targets-with-updated-toolset/72924/ |
| 18 April 2015     | FANCY BEAR                                                   | https://cloud.google.com/blog/topics/threat-intelligence/probable-apt28-useo/ |