# T1049/1069-Win-Windows BloodHound和SharpHound使用

## 来自ATT&CK的描述

**T1049 - 系统网络连接发现**：攻击者通过系统网络连接发现（T1049）获取受感染系统与网络上其他系统之间的连接信息，以绘制网络拓扑、识别活跃服务或为横向移动、权限提升或数据窃取做准备。工具如 BloodHound（通过 SharpHound 收集器）可枚举 Active Directory（AD）环境中的网络会话（如 SMB 会话、Kerberos 票据），揭示主机之间的连接关系。

**T1069 - 权限组发现**：攻击者通过权限组发现（T1069）收集本地系统或域级别的组和权限设置信息，以识别高权限账户（如域管理员）、组成员关系或权限配置漏洞。BloodHound 通过查询 LDAP 和 GPO（组策略对象）收集域用户、组及其权限关系，生成攻击路径图。

**BloodHound 概述**：BloodHound 是一个开源的 Active Directory 侦察工具，结合 SharpHound（数据收集器）和 BloodHound GUI（基于 Neo4j 数据库的 JavaScript Web 应用程序），用于分析 AD 环境的权限关系和网络连接。攻击者使用 BloodHound 识别复杂的攻击路径（如从普通用户到域管理员的提权路径），而防御者可利用其发现并修复权限配置漏洞。SharpHound 通过 PowerShell 或 C# 脚本收集 AD 数据（如用户、组、计算机、会话、ACL），生成 JSON 文件或 ZIP 压缩包，供 BloodHound 分析。攻击者可能通过 BloodHound 枚举网络会话（T1049）、权限组（T1069）或信任关系，规划横向移动或权限提升。本文档聚焦于 Windows 平台下 BloodHound 和 SharpHound 的检测与防御。

## 测试案例

### 环境
- 操作系统：Windows Server 2016/Windows 10，域环境
- 权限：域用户权限（部分操作需要域管理员权限）
- 工具：SharpHound.exe、PowerShell、BloodHound GUI（需Neo4j数据库）
- 前提：已安装BloodHound和SharpHound，域内可访问域控制器

### 测试案例 1：SharpHound - 完整收集（All）
**关联技术**：T1049（会话枚举）、T1069（组和权限枚举）
```dos
SharpHound.exe -c All --ZipFileName bloodhound_data.zip
```
**输出示例**:
```
2025-05-25 19:08:14 INFO  - SharpHound Enumeration Started
2025-05-25 19:08:15 INFO  - Collecting Group Memberships
2025-05-25 19:08:16 INFO  - Collecting Active Sessions
2025-05-25 19:08:17 INFO  - Collecting ACLs
2025-05-25 19:08:18 INFO  - Writing output to C:\Users\user1\bloodhound_data.zip
2025-05-25 19:08:19 INFO  - Enumeration Completed
```
**说明**：
- 使用 `-c All` 收集所有 AD 数据（用户、组、计算机、会话、ACL、GPO）。
- 生成 ZIP 文件（`bloodhound_data.zip`）包含 JSON 数据。
- T1049：枚举活跃会话（如 SMB 会话）。
- T1069：收集组成员和权限关系。

### 测试案例 2：SharpHound - 会话收集（Session）
**关联技术**：T1049（网络会话枚举）
```dos
SharpHound.exe -c Session --JsonFolder C:\Temp\bloodhound_session
```
**输出示例**:
```
2025-05-25 19:08:20 INFO  - SharpHound Enumeration Started
2025-05-25 19:08:21 INFO  - Collecting Active Sessions
2025-05-25 19:08:22 INFO  - Writing output to C:\Temp\bloodhound_session\sessions.json
2025-05-25 19:08:23 INFO  - Enumeration Completed
```
**说明**：
- 使用 `-c Session` 仅收集网络会话数据（如用户登录的计算机）。
- 输出 JSON 文件到指定文件夹。
- T1049：聚焦于网络连接和会话发现。

### 测试案例 3：SharpHound - 域控制器收集（DCOnly）
**关联技术**：T1069（域权限枚举）
```dos
SharpHound.exe -c DCOnly --NoSaveCache
```
**输出示例**:
```
2025-05-25 19:08:24 INFO  - SharpHound Enumeration Started
2025-05-25 19:08:25 INFO  - Collecting Domain Controller Data
2025-05-25 19:08:26 INFO  - Writing output to default JSON files
2025-05-25 19:08:27 INFO  - Enumeration Completed
```
**说明**：
- 使用 `-c DCOnly` 收集域控制器相关数据（如 GPO、信任关系）。
- `--NoSaveCache` 避免缓存数据，减少留痕。
- T1069：聚焦于域级权限和组信息。

### 测试案例 4：PowerShell - Invoke-BloodHound
**关联技术**：T1049、T1069
```powershell
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Temp\bloodhound_output
```
**输出示例**:
```
[*] Starting BloodHound data collection
[*] Collecting Group Memberships
[*] Collecting Active Sessions
[*] Collecting ACLs
[*] Output written to C:\Temp\bloodhound_output
[*] Data collection completed
```
**说明**：
- 使用 PowerShell 脚本 `Invoke-BloodHound` 收集 AD 数据。
- 输出 JSON 文件到指定目录。
- T1049：枚举会话；T1069：收集组和权限。

**注意**：
- 所有命令需在域环境中运行，普通域用户权限通常足够。
- 输出文件（JSON 或 ZIP）可导入 BloodHound GUI 进行分析。
- 攻击者可能将输出文件传输到外部系统以规避检测。

## 检测日志

- **安全日志**：
  - 事件 ID 4688：进程创建，记录 `SharpHound.exe`、`powershell.exe` 或 `BloodHound.exe` 的执行。
  - 事件 ID 5145：网络共享对象访问，记录对 AD 对象的查询（如 SMB 会话）。
- **Sysmon 日志**：
  - 事件 ID 1：进程创建，记录命令行参数（如 `-c All`）。
  - 事件 ID 3：网络连接，记录 LDAP（389/636）或 SMB（445）查询。
  - 事件 ID 11：文件创建，记录 JSON 或 ZIP 文件的生成。
- **PowerShell 日志**：
  - 事件 ID 4103/4104：记录 PowerShell 脚本执行，如 `Invoke-BloodHound` 或 `Get-BloodHoundData`.
- **网络日志**：
  - 异常 LDAP 查询（端口 389/636），如高频查询用户、组或 ACL。
  - SMB 流量（端口 445），用于会话枚举。
  - Kerberos 票据请求（端口 88），用于认证。
- **要求**：
  - 启用 `Audit Process Creation` 和 `Audit Object Access`（安全日志）。
  - 部署 Sysmon，配置进程创建（事件 ID 1）、文件创建（事件 ID 11）和网络连接（事件 ID 3）监控。
  - 启用 PowerShell `Script Block Logging` 和 `Module Logging`.
  - 使用网络监控工具（如 Zeek 或 Suricata）检测异常 LDAP 或 SMB 流量。

## 测试留痕

- **进程相关**：
  - 进程创建：`SharpHound.exe`、`BloodHound.exe`、`powershell.exe`。
  - 父进程：如 `cmd.exe` 或 `powershell.exe`。
  - 命令行参数：如 `SharpHound.exe -c All`、`Invoke-BloodHound -CollectionMethod All`。
- **文件相关**：
  - 文件创建：JSON 文件（如 `sessions.json`）、ZIP 压缩包（如 `bloodhound_data.zip`）。
  - 默认路径：当前目录或指定路径（如 `C:\Temp\bloodhound_output`）。
  - 可能的输出重定向文件（如 `SharpHound.exe > output.txt`）。
- **网络痕迹**：
  - LDAP 查询（端口 389/636），用于收集用户、组、ACL。
  - SMB 流量（端口 445），用于会话枚举。
  - Kerberos 票据请求（端口 88），用于认证。
- **注册表相关**：
  - 可能的临时配置存储在 `HKLM\Software` 或 `HKCU\Software`（如 Neo4j 配置）。
- **隐藏手段**：
  - 重命名 `SharpHound.exe`（如 `svc.exe`）。
  - 使用编码后的 PowerShell 脚本（如 `Invoke-Obfuscation`）。
  - 立即删除 JSON 或 ZIP 文件。
  - 通过网络传输输出文件（如 FTP、HTTP）以减少本地痕迹。
  - 使用 `--NoSaveCache` 参数避免缓存数据。

## 检测规则/思路

### Sigma 规则

```yml
title: Windows BloodHound和SharpHound活动检测
description: 检测 BloodHound和SharpHound在Windows环境中执行的系统网络连接和权限组发现行为
references:
  - https://attack.mitre.org/techniques/T1049/
  - https://attack.mitre.org/techniques/T1069/
  - https://github.com/BloodHoundAD/BloodHound
  - https://github.com/BloodHoundAD/SharpHound
tags:
  - attack.discovery
  - attack.t1049
  - attack.t1069
status: experimental
author: 0x783kb
logsource:
  product: windows
  category: process_creation
detection:
  selection_process:
    EventID: 1 # Sysmon 进程创建
    Image|endswith:
      - '\BloodHound.exe'
      - '\SharpHound.exe'
      - '\powershell.exe'
    CommandLine|contains:
      - '-c All'
      - '-CollectionMethod All'
      - '-c Session'
      - '-c DCOnly'
      - '--NoSaveCache'
      - 'Invoke-BloodHound'
      - 'Get-BloodHoundData'
  selection_file:
    EventID: 11 # Sysmon 文件创建
    TargetFilename|endswith:
      - '.json'
      - '.zip'
    TargetFilename|contains: 'bloodhound'
  selection_network:
    EventID: 3 # Sysmon 网络连接
    DestinationPort|in:
      - 389
      - 636
      - 445
      - 88
    Image|endswith:
      - '\SharpHound.exe'
      - '\powershell.exe'
  condition: selection_process or selection_file or selection_network
  timeframe: 5m
fields:
  - Image
  - CommandLine
  - TargetFilename
  - DestinationPort
level: medium
falsepositives:
  - 管理员或安全团队使用BloodHound进行AD安全审计
  - 合法程序生成类似JSON或ZIP文件
  - 合法PowerShell脚本包含类似关键词
```

### 检测思路

1. **进程监控**：
   - 监控 `BloodHound.exe`、`SharpHound.exe` 和 `powershell.exe` 的进程创建（Sysmon 事件 ID 1）。
   - 关注命令行参数中包含 `-c All`、`-c Session`、`-c DCOnly`、`Invoke-BloodHound` 或 `Get-BloodHoundData` 的行为。
2. **文件监控**：
   - 检测 JSON 或 ZIP 文件的创建（Sysmon 事件 ID 11），特别是文件名包含 `bloodhound` 的文件。
3. **网络监控**：
   - 监控 LDAP（389/636）、SMB（445）和 Kerberos（88）流量（Sysmon 事件 ID 3），识别 AD 查询行为。
4. **PowerShell 监控**：
   - 检测 PowerShell 脚本执行（事件 ID 4103/4104），如 `Invoke-BloodHound` 或 `Get-BloodHoundData`。
5. **行为分析**：
   - 检测短时间内高频的 AD 查询或文件创建（5 分钟内多次触发）。
   - 结合上下文，如异常用户账户、非常规时间段或未知父进程。

## 建议

1. **防御措施**：
   - 限制非管理员用户执行 `SharpHound.exe` 或 `BloodHound.exe`，需管理员权限运行。
   - 启用组策略，监控或阻止 PowerShell 脚本执行（如 `Invoke-BloodHound`）。
   - 部署 EDR 工具，检测异常 AD 查询或文件创建行为。
   - 使用防火墙阻止未经授权的 LDAP（389/636）、SMB（445）或 Kerberos（88）流量。
   - 定期审计 AD 权限配置，修复过度权限（如非必要的域管理员账户）。
2. **检测优化**：
   - 监控短时间内高频的 AD 查询或文件创建（5 分钟内多次触发）。
   - 结合上下文分析，如异常用户账户、非常规时间段或未知父进程。
   - 检测异常 LDAP、SMB 或 Kerberos 流量，识别 BloodHound 活动。
   - 使用网络监控工具（如 Zeek、Suricata）检测高频 AD 查询。
3. **降低误报**：
   - 排除管理员或安全团队用于 AD 审计的合法 BloodHound 操作。
   - 配置白名单，过滤已知安全工具（如 BloodHound 用于蓝队测试）。
   - 验证 JSON 或 ZIP 文件的内容，确保与 BloodHound 相关。
4. **其他工具**：
   - 攻击者可能使用其他 AD 侦察工具（如 PowerView、ADRecon），建议监控类似 LDAP/SMB 查询行为。
   - 检测未知可执行文件的运行和异常网络流量。

## 参考推荐

- MITRE ATT&CK - T1049: <https://attack.mitre.org/techniques/T1049/>
- MITRE ATT&CK - T1069: <https://attack.mitre.org/techniques/T1069/>
- BloodHound 官方 GitHub: <https://github.com/BloodHoundAD/BloodHound>
- SharpHound 官方 GitHub: <https://github.com/BloodHoundAD/SharpHound>
- Atomic Red Team - T1049 测试用例: <https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1049/T1049.md>
- Atomic Red Team - T1069 测试用例: <https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069/T1069.md>
- Sysmon 配置指南: <https://github.com/SwiftOnSecurity/sysmon-config>
- PowerShell 日志配置指南: <https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging>
- Elastic SIEM 检测规则: <https://www.elastic.co/guide/en/security/current/detection-rules.html>
- Active Directory 安全指南: <https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices>
- BloodHound 域分析详解: <https://www.cnblogs.com/KevinGeorge/p/10513211.html>