# T1068-Win-权限提升-带有Headless参数的Windows ConHost

## 来自ATT&CK的描述

攻击者可能会利用软件漏洞来尝试提升权限。当攻击者利用程序、服务或操作系统软件或内核本身中的编程错误来执行攻击者控制的代码时，就会发生软件漏洞的利用。权限级别等安全结构通常会阻碍对信息的访问和某些技术的使用，因此攻击者可能需要执行权限升级以包括使用软件漏洞来规避这些限制。

当最初获得对系统的访问权限时，攻击者可能会在特权较低的进程中运行，这将阻止他们访问系统上的某些资源。漏洞通常存在于通常以较高权限运行的操作系统组件和软件中，可利用这些漏洞获得更高级别的系统访问权限。这可能使某人能够从非特权或用户级权限转移到系统或根权限，具体取决于易受攻击的组件。这还可能使攻击者能够从虚拟化环境（例如虚拟机或容器内）转移到底层主机上。

## 测试案例

conhost.exe（命令行程序的宿主进程）
全称是Console Host Process, 即命令行程序的宿主进程。简单的说他是微软出于安全考虑，在windows 7和Windows server 2008中引进的新的控制台应用程序处理机制。

Windows控制台主机进程 (conhost.exe) 与`–headless`参数的异常使用来生成新进程。这种行为非常不寻常，表明存在可疑活动，因为`–headless`参数在合法操作中并不常用。

## 检测日志

windows 安全日志

## 测试复现

用例：使用conhost.exe作为代理二进制文件来逃避防御
所需权限： 用户
操作系统：Windows 10、Windows 11

以conhost.exe作为父进程执行calc.exe

```
conhost.exe calc.exe
```

用例：指定`--headless`参数来隐藏子进程窗口
所需权限： 用户
操作系统：Windows 10、Windows 11

以conhost.exe作为父进程执行calc.exe

```
conhost.exe --headless calc.exe
```

## 测试留痕

windows安全事件4688，sysmon日志

```yml
 EventData 

  SubjectUserSid S-1-5-21-4139220405-2433135684-1686031733-1000 
  SubjectUserName jackma 
  SubjectDomainName MAJACKD3D7 
  SubjectLogonId 0x1f9f5 
  NewProcessId 0x16b4 
  NewProcessName C:\Windows\System32\conhost.exe 
  TokenElevationType %%1938 
  ProcessId 0x670 
  CommandLine conhost.exe --headless calc.exe 
  TargetUserSid S-1-0-0 
  TargetUserName - 
  TargetDomainName - 
  TargetLogonId 0x0 
  ParentProcessName C:\Windows\System32\cmd.exe 
  MandatoryLabel S-1-16-8192 
```

## 检测规则/思路

### sigma规则

```yml
title: 带有Headless参数的Windows ConHost
author: 0x783kb
date: 2024/03/24
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Conhost/
tags:
    - attack.t1068
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4688
    NewProcessName: '*\conhost.exe'
    CommandLine: '*--headless*'
    condition: selection
level: high
```

### 建议

如果应用程序是合法使用的，则可能会出现误报，并根据需要按用户或终端进行过滤。

## 参考推荐

MITRE-ATT&CK-T1068

<https://attack.mitre.org/techniques/T1068>

Conhost

<https://lolbas-project.github.io/lolbas/Binaries/Conhost/>

Windows ConHost with Headless Argument

<https://research.splunk.com/endpoint/d5039508-998d-4cfc-8b5e-9dcd679d9a62/>
