# T1505-003-web服务关联可疑进程识别webshell行为

## 来自ATT&CK的描述

攻击者可能会通过Web Shell为web服务器创建后门，以便实现对系统的持久访问。Web Shell是攻击者放置在可公开访问的web服务器上的web脚本，以便通过web服务器进入网络。Web Shell可以提供一套待执行的函数，或是为web服务器所在系统提供命令行界面。

除服务器端脚本之外，Web Shell可能还有客户端接口程序，用于与web服务器通信，例如：[China Chopper](https://attack.mitre.org/software/S0020)（引自：Lee 2013）

## 测试案例

此检测方法将查找常见的Web服务器进程名称，并标识使用脚本语言（cmd，powershell，wscript，cscript），请注意常见的初始配置文件命令（net\net1\whoami\ping\ipconfig）或管理命令（sc）启动的任何进程。看到此活动并不意味着您的服务器立即存在可疑行为，因此您需要自己调整检测语句，以便该检测方法适应您的web应用环境。

## 检测日志

windows、sysmon日志、以及其他可记录进程、命令行参数的EDR产品

linux日志

## 测试复现

暂无

## 测试留痕

```yml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
 <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
 <EventID>4688</EventID> 
 <Version>2</Version> 
 <Level>0</Level> 
 <Task>13312</Task> 
 <Opcode>0</Opcode> 
 <Keywords>0x8020000000000000</Keywords> 
 <TimeCreated SystemTime="2015-11-12T02:24:52.377352500Z" /> 
 <EventRecordID>2814</EventRecordID> 
 <Correlation /> 
 <Execution ProcessID="4" ThreadID="400" /> 
 <Channel>Security</Channel> 
 <Computer>WIN-GG82ULGC9GO.contoso.local</Computer> 
 <Security /> 
 </System>
- <EventData>
 <Data Name="SubjectUserSid">S-1-5-18</Data> 
 <Data Name="SubjectUserName">WIN-GG82ULGC9GO$</Data> 
 <Data Name="SubjectDomainName">CONTOSO</Data> 
 <Data Name="SubjectLogonId">0x3e7</Data> 
 <Data Name="NewProcessId">0x2bc</Data> 
 <Data Name="NewProcessName">C:\\Windows\\System32\\rundll32.exe</Data> 
 <Data Name="TokenElevationType">%%1938</Data> 
 <Data Name="ProcessId">0xe74</Data> 
 <Data Name="CommandLine" /> 
 <Data Name="TargetUserSid">S-1-5-21-1377283216-344919071-3415362939-1104</Data> 
 <Data Name="TargetUserName">dadmin</Data> 
 <Data Name="TargetDomainName">CONTOSO</Data> 
 <Data Name="TargetLogonId">0x4a5af0</Data> 
 <Data Name="ParentProcessName">C:\\Windows\\explorer.exe</Data> 
 <Data Name="MandatoryLabel">S-1-16-8192</Data> 
 </EventData>
</Event>
```

## 检测规则/思路

### sigma规则

```yml
title: web服务产生的可疑进程
status: experimental #测试状态
description: Web服务器产生的可疑的shell进程，可能是成功放置Web shell或其他攻击的结果
logsource:
    category: process_creation #进程创建
    product: windows #数据源，windows
detection:
    selectio1:
        ParentImage:
            - '*\w3wp.exe'
            - '*\httpd.exe'
            - '*\nginx.exe'
            - '*\php-cgi.exe'
            - '*\tomcat.exe'
            - '*\sqlservr.exe'
        Image:
            - '*\cmd.exe'
            - '*\sh.exe'
            - '*\bash.exe'
            - '*\powershell.exe'
            - '*\bitsadmin.exe'
            - '*\cscript.exe'
            - '*\wscript.exe'
            - '*\net.exe'
            - '*\net1.exe'
            - '*\ping.exe'
            - '*\whoami.exe'
    selection2:
        User.name: #参考elastic公开规则，此处用父进程来理解更容易一些
            - 'apache'
            - 'nginx'
            - 'www'
            - 'www-data'
        process.name:
            - 'bash'
            - 'dash'
        
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.persistence
    - attack.t1505.003
    - attack.privilege_escalation       # an old one
    - attack.t1190
falsepositives:
    - 特定的web应用程序可以合法地派生shell进程，如ipconfig、whoami等进程，在部分客户侧，发现此两进程频繁被调用，其主机并无异常。
level: high
```

## 备注

整体检测思路，攻击者通过webshell执行一些信息收集的命令，如ipconfig等命令。此类行为在windows日志上的表现形式为，用户调用了常见的中间件的进程，执行了某些命令。此规则检测思路便是来源于此，可自行添加常见的用于信息收集或者其他目的的命令行参数，不断完善规则。

## 参考推荐

MITRE-ATT&CK-T1505-003

<https://attack.mitre.org/techniques/T1505/003/>

Web服务器执行可疑应用程序

<https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Execution/Webserver%20Executing%20Suspicious%20Applications.md>

persistence_shell_activity_by_web_server

<https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_shell_activity_by_web_server.toml>
