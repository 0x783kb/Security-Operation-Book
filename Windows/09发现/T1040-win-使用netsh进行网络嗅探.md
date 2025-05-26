# T1040-Win-使用netsh进行网络嗅探

## 来自ATT&CK的描述

攻击者通过网络嗅探（T1040）使用系统上的网络接口监视或捕获通过有线或无线连接发送的数据，以获取用户凭据（尤其是通过不安全协议如 FTP、HTTP、Telnet 发送的明文凭据）、网络配置细节（如运行服务、版本号、IP 地址、主机名、VLAN ID）或其他支持横向移动、防御逃避的网络特征。在 Windows 系统中，攻击者可能利用内置工具 `netsh trace` 将网络接口置于混杂模式，捕获传输中的数据并保存为 ETL 文件（通常位于 `%temp%\trace.etl`），或使用第三方工具如 Wireshark、tcpdump（通过 WSL）。攻击者还可能通过跨接端口或 ARP 欺骗捕获更广泛的流量。捕获的数据可用于识别高价值目标、规划攻击路径或窃取敏感信息。攻击者可能通过重命名 `netsh`、更改输出路径或结合其他工具规避检测。本文档聚焦于 Windows 平台使用 `netsh trace` 的检测和防御。

## 测试案例

### 环境
- 操作系统：Windows Server 2019 / Windows 10
- 权限：管理员权限
- 工具：CMD、`netsh`

### 测试案例 1：基本网络嗅探
```dos
netsh trace start capture=yes tracefile=%temp%\trace.etl maxsize=10
```
**输出示例**:
```
跟踪配置:
-------------------------------------------------------------------
状态:             正在运行
跟踪文件:         C:\Users\heihei\AppData\Local\Temp\trace.etl
附加:             关闭
循环:           启用
最大大小:           10 MB
报告:             关闭
```
**清除命令**:
```dos
netsh trace stop >nul 2>&1
timeout /t 5 >nul 2>&1
del %temp%\trace.etl >nul 2>&1
del %temp%\trace.cab >nul 2>&1
```
**说明**:
- 启动网络嗅探，捕获数据保存至 `%temp%\trace.etl`，最大文件大小 10 MB。
- 清除命令停止嗅探并删除生成的 ETL 和 CAB 文件，`timeout` 确保文件释放。

### 测试案例 2：自定义输出路径
```dos
netsh trace start capture=yes tracefile=C:\Temp\custom_trace.etl maxsize=50 report=yes
```
**输出示例**:
```
跟踪配置:
-------------------------------------------------------------------
状态:             正在运行
跟踪文件:         C:\Users\heihei\ustom_trace.etl
附加:             关闭
循环:           启用
最大大小:           50 MB
报告:             启用
```
**清除命令**:
```dos
netsh trace stop >nul 2>&1
timeout /t 5 >nul 2>&1
del C:\Users\heihei\ustom_trace.etl >nul 2>&1
del C:\Users\heihei\ustom_trace.cab >nul 2>&1
```
**说明**:
- 使用自定义输出路径 `C:\Users\heihei\ustom_trace.etl`，启用报告生成（`report=yes`）。
- 攻击者可能使用非默认路径规避检测。

**注意**:
- 所有命令需以管理员权限运行。
- ETL 文件可用 Microsoft Network Monitor 或 Wireshark 分析。

## 检测日志

- **安全日志**:
  - 事件 ID 4688: 进程创建，记录 `netsh.exe` 的执行。
- **Sysmon 日志**:
  - 事件 ID 1: 进程创建，记录 `netsh trace start` 的命令行参数。
  - 事件 ID 11: 文件创建，记录 `trace.etl` 或 `trace.cab` 文件的生成。
- **PowerShell 日志**:
  - 事件 ID 4103/4104: 若通过 PowerShell 执行 `netsh`，记录相关脚本块。
- **网络日志**:
  - 异常流量模式，如大量 ICMP、ARP 或未加密协议（如 FTP、HTTP）流量。
- **要求**:
  - 启用 `Audit Process Creation`（安全日志）。
  - 部署 Sysmon，配置进程创建（事件 ID 1）和文件创建（事件 ID 11）监控。
  - 启用 PowerShell `Script Block Logging` 和 `Module Logging`.
  - 使用网络监控工具（如 Zeek 或 Suricata）检测异常流量。

## 测试留痕

- **进程相关**:
  - 进程创建: `netsh.exe`。
  - 父进程: 如 `cmd.exe` 或 `powershell.exe`。
  - 命令行参数: 如 `netsh trace start capture=yes tracefile=C:\Temp\trace.etl maxsize=10`.
- **文件相关**:
  - 文件创建: `trace.etl` 和 `trace.cab`（默认路径 `%temp%` 或自定义路径如 `C:\Temp`）。
  - 可能的输出重定向文件（如 `netsh trace start > output.txt`）。
- **网络痕迹**:
  - 混杂模式启用，可能触发网络接口状态变化。
  - 异常流量，如大量 ARP 请求、未加密协议流量（FTP、HTTP、Telnet）。
- **注册表相关**:
  - 可能的临时配置存储在 `HKLM\System\CurrentControlSet\Services\Tcpip\Parameters`.
- **隐藏手段**:
  - 重命名 `netsh.exe`（如 `svc.exe`）。
  - 使用非默认输出路径（如 `C:\Windows\Temp\hidden.etl`）。
  - 立即删除 `trace.etl` 和 `trace.cab` 文件。
  - 通过 PowerShell 或脚本调用 `netsh` 规避命令行检测.
  - 使用 ARP 欺骗或中间人攻击隐藏嗅探行为。

## 检测规则/思路

### Sigma 规则

```yml
title: Windows使用netsh进行网络嗅探
description: 检测通过netsh trace命令执行网络嗅探的行为，测试于Windows Server 2019
references:
  - https://attack.mitre.org/techniques/T1040/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1040/T1040.md
tags:
  - attack.collection
  - attack.t1040
status: experimental
author: 0x783kb
logsource:
  product: windows
  category: process_creation
detection:
  selection_cmd:
    EventID: 1 # Sysmon 进程创建
    Image|endswith: '\netsh.exe'
    CommandLine|contains:
      - 'trace start'
      - 'capture=yes'
  selection_file:
    EventID: 11 # Sysmon 文件创建
    TargetFilename|endswith:
      - '\trace.etl'
      - '\trace.cab'
  condition: selection_cmd or selection_file
  timeframe: 5m
fields:
  - Image
  - CommandLine
  - TargetFilename
level: medium
falsepositives:
  - 管理员使用netsh trace进行网络诊断
  - 合法的IT管理工具（如网络监控软件）触发类似行为
```

### 检测思路

1. **进程监控**:
   - 监控 `netsh.exe` 的进程创建（Sysmon 事件 ID 1），关注命令行参数中包含 `trace start` 和 `capture=yes` 的行为。
2. **文件监控**:
   - 检测 `trace.etl` 和 `trace.cab` 文件的创建（Sysmon 事件 ID 11），包括默认路径（`%temp%`）和自定义路径。
3. **网络监控**:
   - 使用网络监控工具检测混杂模式启用、大量 ARP 请求或未加密协议流量（如 FTP、HTTP）。
   - 监控 ARP 欺骗或中间人攻击的迹象，如异常 ARP 广播。
4. **行为分析**:
   - 检测短时间内高频的 `netsh trace` 执行或文件创建（5 分钟内多次触发）。
   - 结合上下文，如异常用户账户、非常规时间段或未知父进程。
5. **PowerShell 监控**:
   - 若通过 PowerShell 调用 `netsh`，检测相关脚本块（事件 ID 4103/4104）。

## 建议

1. **防御措施**:
   - 限制普通用户对 `netsh.exe` 的执行权限，需管理员权限运行。
   - 启用组策略，监控或阻止 `%temp%` 或自定义路径下的 `.etl` 和 `.cab` 文件创建。
   - 部署 EDR 工具，检测异常 `netsh` 执行或网络接口状态变化。
   - 使用防火墙阻止未经授权的 ARP 广播或异常流量（如 FTP、HTTP 明文协议）。
   - 强制使用加密协议（如 HTTPS、SFTP）减少明文凭据泄露。
2. **检测优化**:
   - 监控短时间内高频的 `netsh trace` 执行或文件创建（5 分钟内多次触发）。
   - 结合上下文分析，如异常用户账户、非常规时间段或未知父进程。
   - 检测异常网络流量模式，如大量 ARP 请求、未加密协议流量或混杂模式启用。
   - 使用网络监控工具（如 Zeek、Suricata）检测 ARP 欺骗或中间人攻击。
3. **降低误报**:
   - 排除管理员用于网络诊断的合法 `netsh trace` 操作。
   - 配置白名单，过滤已知IT管理工具（如 Microsoft Network Monitor）。
4. **其他工具**:
   - 攻击者可能使用第三方工具（如Wireshark、tcpdump）或自定义脚本，建议监控未知可执行文件的运行和异常网络流量。

## 参考推荐

- MITRE ATT&CK - T1040
  <https://attack.mitre.org/techniques/T1040/>
- Atomic Red Team - T1040 测试用例
  <https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1040/T1040.md>
- Zeek 网络监控
  <https://docs.zeek.org/en/master/>