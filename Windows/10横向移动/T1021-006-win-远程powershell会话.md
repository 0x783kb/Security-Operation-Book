# T1021-006-Win-远程PowerShell会话

## 描述

攻击者可能利用有效帐户通过Windows远程管理（WinRM）协议与远程系统交互，以登录用户身份执行操作。WinRM是Windows内置的服务和协议，允许远程执行命令、修改注册表、管理服务或运行可执行文件。攻击者可通过`winrm`命令行工具或PowerShell（如`Enter-PSSession`）调用WinRM，结合有效凭据实现横向移动、数据收集或持久化。WinRM默认使用TCP 5985（HTTP）或5986（HTTPS）端口，依赖Kerberos或NTLM认证。

## 测试案例

### 用例
- **远程命令执行**：使用`Enter-PSSession`在远程系统上执行PowerShell命令（如文件操作、配置修改）。
- **横向移动**：通过WinRM登录目标系统，运行恶意脚本或Payload。
- **持久化**：通过远程PowerShell创建计划任务或服务。
- **数据窃取**：远程访问目标系统，提取敏感文件或凭据。

### 示例场景
- 攻击者使用有效管理员凭据通过`Enter-PSSession`建立远程PowerShell会话，运行命令收集系统信息。
- 结合`Invoke-Command`在多台远程系统上批量执行恶意脚本。

### 路径
- WinRM相关进程：
  ```yml
  - C:\Windows\System32\svchost.exe (WinRM服务宿主)
  - C:\Windows\System32\wsmprovhost.exe (PowerShell远程会话宿主)
  - C:\Windows\System32\dllhost.exe (COM+组件，可能与WinRM相关)
  ```

### 所需权限
- 管理员权限（执行远程PowerShell会话）。
- 有效凭据（域或本地账户）。

### 操作系统
- Windows 7、Windows 8、Windows 8.1、Windows 10、Windows 11、Windows Server 2008、2012、2016、2019、2022。

## 检测日志

### Windows安全日志
- **事件ID 4688**：记录`wsmprovhost.exe`或`dllhost.exe`进程创建（需启用命令行审核）。
- **事件ID 4624**：记录WinRM登录事件（类型3，网络登录）。
- **事件ID 4672**：记录分配给新登录的安全特权（如管理员权限）。

### Sysmon日志
- **事件ID 1**：捕获`wsmprovhost.exe`或`dllhost.exe`进程创建及命令行参数。
- **事件ID 3**：记录WinRM相关的网络连接（TCP 5985/5986）。
- **事件ID 11**：记录远程会话生成的文件（如脚本输出）。

### PowerShell日志
- **事件ID 4104**：记录PowerShell脚本块执行（如`Enter-PSSession`）。
- **事件ID 600**：记录PowerShell远程会话的建立。

### 网络日志
- 捕获TCP 5985（HTTP）或5986（HTTPS）端口的WinRM流量。

## 测试复现

### 环境准备
- **靶机**：Windows Server 2016或Windows 10/11（已启用WinRM）。
- **权限**：域管理员或本地管理员凭据。
- **工具**：
  - PowerShell（系统自带）。
  - Sysmon（监控进程和网络活动）。
  - Wireshark（捕获WinRM流量）。
- **网络**：隔离网络环境，允许TCP 5985/5986流量。
- **日志**：启用Windows安全日志、Sysmon日志和PowerShell日志。
- **WinRM配置**：
  - 确保WinRM服务启用：
    ```powershell
    Enable-PSRemoting -Force
    ```
  - 检查WinRM监听器：
    ```powershell
    winrm enumerate winrm/config/listener
    ```

### 攻击步骤
1. **验证凭据**：
   - 确保拥有目标系统的管理员凭据（如`WEIDONG\Administrator:Password123`）。
2. **建立远程PowerShell会话**：
   ```powershell
   Enter-PSSession -ComputerName 192.168.1.100 -Credential (Get-Credential)
   ```
   - 输入凭据后，进入远程会话。
3. **执行测试命令**：
   - 在远程会话中运行：
     ```powershell
     Get-Process
     ```
   - 或保存输出到文件：
     ```powershell
     Get-Process > C:\Temp\processes.txt
     ```
4. **验证结果**：
   - 检查目标系统是否生成`C:\Temp\processes.txt`。
   - 使用Wireshark捕获TCP 5985/5986流量。
   - 验证Sysmon日志是否记录`wsmprovhost.exe`或`dllhost.exe`进程创建。
5. **清理**：
   - 删除生成的文件：
     ```powershell
     Remove-Item C:\Temp\processes.txt -ErrorAction Ignore
     ```
   - 退出会话：
     ```powershell
     Exit-PSSession
     ```

## 测试留痕
以下为Windows安全日志示例（事件ID 4688，进程创建）：
```yml
EventID: 4688
TimeCreated: 2025-06-08T04:50:23.456Z
Channel: Security
Hostname: TARGET-SRV
SubjectUserSid: S-1-5-21-1234567890-123456789-1234567890-500
SubjectUserName: Administrator
SubjectDomainName: WEIDONG
SubjectLogonId: 0x3E7
NewProcessId: 0x1a2c
NewProcessName: C:\Windows\System32\wsmprovhost.exe
ProcessCommandLine: C:\Windows\System32\wsmprovhost.exe -Embedding
CreatorProcessId: 0x4b0
CreatorProcessName: C:\Windows\System32\svchost.exe
TokenElevationType: %%1936
```

以下为Sysmon日志示例（事件ID 1，进程创建）：
```yml
EventID: 1
UtcTime: 2025-06-08T04:50:23.789Z
ProcessGuid: {4a363fee-27c2-623c-decd-3f0000000000}
ProcessId: 6704
Image: C:\Windows\System32\wsmprovhost.exe
CommandLine: C:\Windows\System32\wsmprovhost.exe -Embedding
CurrentDirectory: C:\Windows\system32\
User: WEIDONG\Administrator
LogonId: 0x3E7
IntegrityLevel: High
Hashes: SHA1=A17C21B909C56D93D978014E63FB06926EAEA8E7
ParentProcessId: 1024
ParentImage: C:\Windows\System32\svchost.exe
```

## 检测方法/思路

### Sigma规则
基于Sigma规则，检测远程PowerShell会话的活动：

```yml
title: Suspicious Remote PowerShell Session
id: e8f9d7c6-7a5b-8c9d-0e1f-6a7b8c9d0e1f
status: experimental
description: Detects remote PowerShell sessions via WinRM involving wsmprovhost.exe or dllhost.exe
references:
- https://attack.mitre.org/techniques/T1021/006
- https://www.cnblogs.com/gamewyd/p/6805595.html
logsource:
  product: windows
  category: process_creation
detection:
  selection1:
    EventID: 4688
    Image|endswith: '\dllhost.exe'
    ParentImage|endswith: '\svchost.exe'
  selection2:
    EventID: 4688
    Image|endswith: '\wsmprovhost.exe'
    ParentImage|endswith: '\svchost.exe'
    CommandLine|contains: '-Embedding'
  timeframe: 2s
  condition: selection1 or selection2
falsepositives:
- Legitimate administrative use of PowerShell remoting
- IT management scripts
level: medium
```

### 检测思路
1. **进程监控**：
   - 检测`wsmprovhost.exe`或`dllhost.exe`进程创建，尤其是父进程为`svchost.exe`且命令行包含`-Embedding`。
   - 监控异常父进程（如`powershell.exe`）调用WinRM相关进程。
2. **网络监控**：
   - 检测TCP 5985（HTTP）或5986（HTTPS）端口的WinRM流量。
   - 检查流量是否涉及可疑源IP或目标IP。
3. **PowerShell监控**：
   - 检查PowerShell事件ID 4104，捕获`Enter-PSSession`或`Invoke-Command`的执行。
4. **文件监控**：
   - 检测远程会话生成的文件（如`C:\Temp\processes.txt`）。
5. **行为基线**：
   - 建立组织内WinRM和PowerShell的正常使用模式，识别异常行为（如夜间会话、非管理员用户）。

### 检测建议
- **Sysmon配置**：配置Sysmon监控进程创建（事件ID 1）、网络连接（事件ID 3）和文件操作（事件ID 11）。
- **PowerShell日志**：启用PowerShell模块、脚本块和命令行日志，捕获`Enter-PSSession`相关活动。
- **EDR监控**：使用EDR工具（如Microsoft Defender for Endpoint）检测WinRM相关进程和网络活动。
- **误报过滤**：排除IT管理员的合法PowerShell远程操作，结合上下文（如用户身份、时间）降低误报率。

## 缓解措施
1. **WinRM限制**：
   - 禁用不必要的WinRM服务：
     ```powershell
     Disable-PSRemoting -Force
     ```
   - 限制WinRM访问，仅允许特定用户或IP：
     ```powershell
     Set-PSSessionConfiguration -Name Microsoft.PowerShell -ShowSecurityDescriptorUI
     ```
2. **凭据保护**：
   - 启用多因素认证（MFA）保护管理员账户。
   - 限制NTLM认证，优先使用Kerberos。
3. **网络限制**：
   - 配置防火墙阻止未经授权的TCP 5985/5986流量。
   - 使用网络分段隔离敏感系统。
4. **PowerShell限制**：
   - 配置PowerShell执行策略（如`ConstrainedLanguageMode`），限制未签名脚本。
   - 使用AppLocker或WDAC限制`powershell.exe`执行。
5. **监控与告警**：
   - 部署IDS/IPS，检测异常WinRM流量。
   - 配置SIEM实时告警远程PowerShell会话。

## 参考推荐
- MITRE ATT&CK T1021.006  
  https://attack.mitre.org/techniques/T1021/006  
- WinRM Service  
  https://www.cnblogs.com/gamewyd/p/6805595.html
