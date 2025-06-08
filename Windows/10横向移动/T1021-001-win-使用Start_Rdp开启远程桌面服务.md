# T1021-001-Win-使用Start_Rdp开启远程桌面服务

## 描述

攻击者可能利用有效帐户通过远程桌面协议（RDP）登录目标系统，从而以登录用户身份执行操作。RDP是Windows操作系统中的常见功能，允许用户通过图形界面访问远程系统，微软将其实现称为远程桌面服务（RDS）。如果RDP服务已启用且攻击者拥有有效凭据，他们可以通过RDP连接扩展访问权限、执行横向移动或实现持久化。攻击者可能通过凭据获取技术（如凭据转储、键盘记录）获得RDP所需的凭据。

`Start_Rdp.exe`是一个开源工具（https://github.com/Ryze-T/Windows_API_Tools），用于通过修改注册表启用RDP服务，攻击者可能利用此类工具快速开启目标系统的远程桌面功能。

## 测试案例

### 用例
- **启用RDP服务**：攻击者使用`Start_Rdp.exe`修改注册表，启用目标系统的RDP服务以便后续访问。
- **持久化**：通过脚本或计划任务定期运行`Start_Rdp.exe`，确保RDP服务保持开启。
- **横向移动**：结合有效凭据，通过RDP登录目标系统执行进一步操作。

### 示例场景
- 攻击者在受损的Windows系统上运行`Start_Rdp.exe`，修改注册表键`HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections`为`0`，启用RDP服务。
- 使用有效凭据通过RDP连接目标系统，执行命令或提取数据。

### 路径
`Start_Rdp.exe`通常由攻击者手动部署，路径取决于执行位置：
```yml
- C:\Windows_API_Tools-main\Start_Rdp.exe
- C:\Temp\Start_Rdp.exe
```

### 所需权限
- 管理员权限（修改注册表以启用RDP服务）。
- 用户权限（若仅通过RDP登录）。

### 操作系统
- Windows 7、Windows 8、Windows 8.1、Windows 10、Windows 11、Windows Server 2008、2012、2016、2019、2022。

## 检测日志

### Windows安全日志
- **事件ID 4688**：记录`Start_Rdp.exe`或其他进程（如`reg.exe`）的创建及命令行参数（需启用命令行审核）。
- **事件ID 4657**：记录注册表值的修改（如`fDenyTSConnections`）。

### Sysmon日志
- **事件ID 1**：捕获`Start_Rdp.exe`进程创建及命令行参数。
- **事件ID 13**：记录注册表修改事件（如`HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections`）。
- **事件ID 3**：记录RDP相关的网络连接（若攻击者通过RDP登录）。

### 网络日志
- 捕获RDP协议（TCP 3389）的入站或出站流量。

## 测试复现

### 环境准备
- **靶机**：Windows Server 2012、Windows 10/11或Windows Server 2016/2019。
- **权限**：管理员权限。
- **工具**：
  - `Start_Rdp.exe`（从https://github.com/Ryze-T/Windows_API_Tools获取）。
  - Sysmon（用于进程和注册表监控）。
  - Wireshark（捕获RDP网络流量）。
- **网络**：隔离网络环境，允许TCP 3389流量。
- **日志**：启用Windows安全日志、Sysmon日志和网络日志。

### 攻击步骤
1. **获取Start_Rdp.exe**：
   - 下载并解压Windows_API_Tools（https://github.com/Ryze-T/Windows_API_Tools）。
   - 复制`Start_Rdp.exe`到靶机（如`C:\Windows_API_Tools-main\Start_Rdp.exe`）。
2. **运行Start_Rdp.exe**：
   ```bash
   C:\Windows_API_Tools-main>Start_Rdp.exe
   success
   ```
   - 命令修改注册表键`HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections`为`0`，启用RDP服务。
3. **验证结果**：
   - 检查注册表键值：
     ```bash
     reg query HKLM\System\CurrentControlSet\Control\Terminal Server /v fDenyTSConnections
     ```
     - 预期输出：`fDenyTSConnections    REG_DWORD    0x0`
   - 使用RDP客户端（如`mstsc.exe`）尝试连接目标系统，确认RDP服务已启用。
   - 验证Sysmon日志是否记录进程创建和注册表修改。
4. **清理**：
   - 禁用RDP服务：
     ```bash
     reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
     ```
   - 删除`Start_Rdp.exe`：
     ```bash
     del C:\Windows_API_Tools-main\Start_Rdp.exe
     ```

## 测试留痕
以下为Sysmon日志示例（事件ID 1，进程创建）：
```log
EventID: 1
RuleName: technique_id=T1059,technique_name=Command-Line Interface
UtcTime: 2025-06-08T04:19:46.909Z
ProcessGuid: {4a363fee-27c2-623c-decd-3f0000000000}
ProcessId: 2796
Image: C:\Windows_API_Tools-main\Start_Rdp.exe
FileVersion: -
Description: -
Product: -
Company: -
OriginalFileName: -
CommandLine: Start_Rdp.exe
CurrentDirectory: C:\Windows_API_Tools-main\
User: WEIDONG\Administrator
LogonGuid: {4a363fee-2447-623c-df16-080000000000}
LogonId: 0x816DF
TerminalSessionId: 1
IntegrityLevel: High
Hashes: SHA1=9805144590D86D7BF4D6D01BB368047BC94EF174,MD5=14148598AD98D05A820462F0BBD07B9F,SHA256=98579200636025AA468A3EEC8B217273630FD4658F6ABDBB035C8A094650311A
ParentProcessGuid: {4a363fee-246e-623c-4a6d-0f0000000000}
ParentProcessId: 3472
ParentImage: C:\Windows\System32\cmd.exe
ParentCommandLine: "C:\Windows\System32\cmd.exe"
ParentUser: WEIDONG\Administrator
```

以下为Sysmon日志示例（事件ID 13，注册表修改）：
```log
EventID: 13
RuleName: technique_id=T1112,technique_name=Modify Registry
EventType: SetValue
UtcTime: 2025-06-08T04:19:46.909Z
ProcessGuid: {4a363fee-27c2-623c-decd-3f0000000000}
ProcessId: 2796
Image: C:\Windows_API_Tools-main\Start_Rdp.exe
TargetObject: HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections
Details: DWORD (0x00000000)
User: WEIDONG\Administrator
```

## 检测方法/思路

### Sigma规则
基于Sigma规则，检测`Start_Rdp.exe`或其他工具启用RDP服务的行为：

```yml
title: Suspicious RDP Service Activation
id: f7a8c9d5-4b3c-5e6d-9f8e-3a4b5c6d7e8f
status: experimental
description: Detects enabling of Windows Remote Desktop Service via registry modification
references:
- https://attack.mitre.org/techniques/T1021/001
- https://github.com/Ryze-T/Windows_API_Tools
logsource:
  product: windows
  category: registry_event
detection:
  selection:
    EventID: 13
    TargetObject|endswith: '\Control\Terminal Server\fDenyTSConnections'
    Details: DWORD (0x00000000)
  condition: selection
falsepositives:
- Legitimate administrative actions enabling RDP
- System configuration changes by IT staff
level: medium
```

### 检测思路
1. **注册表监控**：
   - 检测`HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections`被设置为`0`的修改事件。
   - 使用Sysmon事件ID 13捕获注册表操作。
2. **进程监控**：
   - 检测`Start_Rdp.exe`或其他可疑进程（如`reg.exe`）的创建，尤其是命令行涉及RDP配置。
   - 监控异常父进程（如`cmd.exe`、`powershell.exe`）。
3. **网络监控**：
   - 检测TCP 3389端口的入站或出站流量，确认RDP连接。
   - 检查连接的目标IP是否为已知C2服务器。
4. **行为基线**：
   - 建立组织内RDP服务的正常启用模式，识别异常行为（如夜间运行、非管理员用户）。
5. **文件监控**：
   - 检测`Start_Rdp.exe`或其他非系统工具的创建或执行。

### 检测建议
- **Sysmon配置**：配置Sysmon监控注册表修改（事件ID 13）、进程创建（事件ID 1）和网络连接（事件ID 3）。
- **EDR监控**：使用EDR工具（如Microsoft Defender for Endpoint）监控RDP相关注册表和网络活动。
- **防火墙规则**：监控TCP 3389端口流量，限制未授权的RDP连接。
- **误报过滤**：排除IT管理员或合法脚本启用RDP的行为，结合上下文（如用户身份、时间）降低误报率。

## 缓解措施
1. **RDP限制**：
   - 通过组策略禁用RDP服务（设置`fDenyTSConnections`为`1`），除非必要。
   - 限制RDP访问，仅允许特定用户或IP范围。
2. **注册表保护**：
   - 限制非管理员用户修改`HKLM\System\CurrentControlSet\Control\Terminal Server`。
3. **应用白名单**：
   - 使用AppLocker或WDAC限制`Start_Rdp.exe`或非系统工具的执行。
4. **网络监控**：
   - 部署IDS/IPS，检测异常RDP流量（如连接到可疑IP）。
5. **凭据保护**：
   - 启用多因素认证（MFA）保护RDP登录，降低凭据泄露风险。

## 参考推荐
- MITRE ATT&CK T1021.001  
  https://attack.mitre.org/techniques/T1021/001  
- 系统监视器(Sysmon)工具的使用  
  https://blog.csdn.net/ducc20180301/article/details/119350200  
- Windows_API_Tools  
  https://github.com/Ryze-T/Windows_API_Tools
