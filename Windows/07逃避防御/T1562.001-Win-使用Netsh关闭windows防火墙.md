# T1562.001-Win-使用Netsh关闭Windows防火墙

## 描述

攻击者可能通过禁用或干扰防御机制来规避检测（MITRE ATT&CK T1562.001）。这包括阻止监测软件捕获告警、阻止事件日志收集和分析，或修改安全工具配置以逃避追踪。一种常见技术是使用`netsh`命令禁用**Windows防火墙**，以允许未经授权的网络通信（如C2连接、数据外泄）。

**Windows防火墙**（由`mpssvc`服务支持）是Windows内置的安全组件，用于控制网络流量。攻击者可能通过命令（如`netsh advfirewall set <profile> state off`）或停止相关服务（如`net stop mpssvc`）禁用防火墙，从而绕过网络防护。关闭防火墙可能是恶意活动（如间谍软件、勒索软件）的早期迹象，应立即触发管理员调查。

## 测试案例

### 测试1：使用netsh关闭Windows防火墙

攻击者使用`netsh advfirewall`命令关闭Windows防火墙的公共配置文件（或其他配置文件，如`domain`、`private`）。

**攻击命令**（需管理员权限）：
```cmd
netsh advfirewall set publicprofile state off
```

**恢复命令**：
```cmd
netsh advfirewall set publicprofile state on
```

**说明**：
- 命令禁用公共配置文件的防火墙规则，允许未经限制的网络流量。
- 其他配置文件（`domainprofile`、`privateprofile`）也可类似操作。

### 测试2：停止Windows防火墙服务

攻击者通过停止`mpssvc`服务禁用防火墙。

**攻击命令**（需管理员权限）：
```cmd
net stop mpssvc
```

**恢复命令**：
```cmd
net start mpssvc
```

**说明**：
- `mpssvc`（Windows Defender Firewall服务）是防火墙的核心服务，停止它将禁用所有防火墙功能。

## 检测日志

- **Windows系统日志**：Event ID 7036（服务状态变更），记录`mpssvc`服务停止或启动。
- **Windows安全日志**：Event ID 4688（进程创建），记录`netsh.exe`或`net.exe`的执行（需启用进程跟踪审核）。
- **Sysmon日志**：
  - Event ID 1（进程创建），捕获`netsh.exe`或`net.exe`的命令行参数。
  - Event ID 13（注册表修改），可能记录防火墙配置更改。

## 测试复现

### 测试1：使用netsh关闭防火墙

**测试环境**：Windows 7

**攻击命令**：
```cmd
C:\Windows\system32>netsh advfirewall set publicprofile state off
确定。
```

**结果**：
- 公共配置文件防火墙成功禁用，网络流量不再受限。
- 系统日志记录`mpssvc`服务状态变更（若服务被影响）。

### 测试2：停止mpssvc服务

**测试环境**：Windows 7

**攻击命令**：
```cmd
C:\Windows\system32>net stop mpssvc
Windows Firewall 服务正在停止.
Windows Firewall 服务已成功停止。
```

**结果**：
- `mpssvc`服务停止，防火墙功能完全禁用。
- 系统日志记录服务停止事件。

## 测试留痕

### Windows系统日志（Event ID 7036：服务状态变更）

```xml
日志名称: System
来源: Service Control Manager
日期: 2023/10/01 10:00:00
事件 ID: 7036
任务类别: None
级别: 信息
用户: N/A
计算机: WIN7-TEST
描述:
Windows Firewall 服务处于 停止 状态。
```

**分析**：
- 日志记录`mpssvc`服务停止，表明防火墙被禁用。
- 可能由`net stop mpssvc`或`netsh`间接触发。

### Windows安全日志（Event ID 4688：进程创建）

```xml
日志名称: Security
来源: Microsoft-Windows-Security-Auditing
日期: 2023/10/01 10:00:00
事件 ID: 4688
任务类别: Process Creation
级别: 信息
用户: SYSTEM
计算机: WIN7-TEST
描述:
已创建新进程。

创建者主题:
  安全 ID: WIN7-TEST\Administrator
  帐户名: Administrator
  帐户域: WIN7-TEST
  登录 ID: 0x3E7

目标主题:
  安全 ID: NULL SID
  帐户名: -
  帐户域: -
  登录 ID: 0x0

进程信息:
  新进程 ID: 0x1234
  新进程名称: C:\Windows\System32\netsh.exe
  令牌提升类型: %%1936
  强制性标签: Mandatory Label\High Mandatory Level
  创建者进程 ID: 0x5678
  创建者进程名称: C:\Windows\System32\cmd.exe
  进程命令行: netsh advfirewall set publicprofile state off
```

**分析**：
- 日志记录`netsh.exe`执行，命令行明确包含`set publicprofile state off`。
- 父进程为`cmd.exe`，提示通过命令提示符触发。

## 检测规则/思路

### Sigma规则

```yaml
title: 检测使用netsh关闭Windows防火墙
description: Detects execution of netsh to disable Windows Firewall or stopping of the mpssvc service.
status: experimental
author: 12306Bro
date: 2023/10/01
references:
  - https://attack.mitre.org/techniques/T1562/001/
logsource:
  product: windows
  category: process_creation
detection:
  selection_netsh:
    EventID:
      - 4688 # Windows安全日志
      - 1    # Sysmon日志
    Image|endswith: '\netsh.exe'
    CommandLine|contains:
      - 'advfirewall set'
      - 'state off'
  selection_service:
    EventID:
      - 4688 # Windows安全日志
      - 1    # Sysmon日志
    Image|endswith: '\net.exe'
    CommandLine|contains: 'stop mpssvc'
  selection_system:
    EventID: 7036
    EventData|contains: 'Windows Firewall 服务处于 停止 状态'
  condition: selection_netsh or selection_service or selection_system
fields:
  - Image
  - CommandLine
  - ParentImage
  - EventData
falsepositives:
  - Legitimate administrative firewall adjustments
level: high
tags:
  - attack.defense_evasion
  - attack.t1562.001
```

**规则说明**：
- 检测`netsh.exe`执行禁用防火墙的命令（如`set publicprofile state off`）。
- 检测`net.exe`停止`mpssvc`服务。
- 检测系统日志中`mpssvc`服务停止事件（Event ID 7036）。
- 规则为实验性，需测试以减少合法管理员操作的误报。

### 建议

1. **监控防火墙操作**：
   - 使用Sysmon（Event ID 1）捕获`netsh.exe`和`net.exe`的进程创建，检查命令行是否包含`state off`或`stop mpssvc`。
   - 监控Event ID 13（注册表修改），检测防火墙配置更改（如`HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess`）。

2. **启用命令行审计**：
   - 配置Windows安全策略，启用进程跟踪审核（Event ID 4688）并记录命令行参数（需Windows 7+支持）。
   - 确保Sysmon配置包含命令行信息。

3. **基线化行为**：
   - 建立防火墙配置和服务的正常基线，生产环境中禁用防火墙应极为罕见。
   - 监控非管理员用户或非预期父进程（如`powershell.exe`、`rundll32.exe`）执行防火墙操作。

4. **部署SIEM系统**：
   - 使用SIEM工具（如Splunk、Elastic）分析系统日志和安全日志，检测防火墙禁用行为。
   - 设置高优先级告警，针对`mpssvc`停止或`netsh`禁用命令。

5. **行为链关联**：
   - 将防火墙禁用与其他可疑行为（如网络连接、文件下载、提权）关联，识别攻击链。
   - 例如，检测禁用防火墙后是否出现异常的C2通信。

6. **限制高危操作**：
   - 使用AppLocker或组策略限制`netsh.exe`和`net.exe`的执行，仅允许特定管理账户使用。
   - 配置防火墙服务（`mpssvc`）为自动启动，防止手动停止。

7. **响应措施**：
   - 检测到防火墙禁用后，立即恢复防火墙（`netsh advfirewall set allprofiles state on`或`net start mpssvc`）。
   - 调查攻击来源，检查是否有后续恶意活动。

8. **测试与验证**：
   - 在测试环境中模拟禁用防火墙，验证检测规则有效性。
   - 调整规则阈值，排除合法管理员操作的误报。

## 参考推荐

- MITRE ATT&CK T1562.001  
  <https://attack.mitre.org/techniques/T1562/001/>
- Microsoft文档：netsh advfirewall命令  
  <https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-advfirewall>
- Atomic Red Team T1562.001  
  <https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md>
