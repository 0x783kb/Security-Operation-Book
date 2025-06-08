# T1068-Win-权限提升-带有Headless参数的Windows ConHost

## 描述

攻击者可能利用软件漏洞或滥用系统可执行文件（如`conhost.exe`）来提升权限或规避防御机制。T1068技术涉及利用程序、服务或操作系统内核中的编程错误执行恶意代码，或通过可信二进制文件（如`conhost.exe`）代理执行恶意进程，以绕过安全限制。`conhost.exe`是Windows控制台主机进程，负责托管命令行应用程序，自Windows 7和Windows Server 2008起引入，用于增强控制台应用程序的安全性。然而，攻击者可能利用`conhost.exe`的`--headless`参数隐藏子进程窗口，执行恶意程序（如`calc.exe`），从而规避检测或实现特权操作。这种行为在合法操作中极少使用，表明潜在的可疑活动，可能用于权限提升或防御逃逸。

## 测试案例

### 用例
- **防御规避**：使用`conhost.exe`作为代理二进制文件，隐藏恶意子进程（如`calc.exe`）的执行。
- **窗口隐藏**：通过`--headless`参数运行子进程，防止弹出可见窗口，降低用户察觉风险。
- **权限提升**：结合漏洞或高权限上下文，利用`conhost.exe`启动特权进程。
- **持久化**：通过脚本或计划任务调用`conhost.exe`，运行恶意代码。

### 示例场景
- 攻击者运行`conhost.exe --headless calc.exe`，以`conhost.exe`作为父进程启动计算器，隐藏窗口。
- 攻击者利用`conhost.exe`代理执行恶意Payload，规避基于父进程的检测。

### 路径
- 相关工具路径：
  ```yml
  - C:\Windows\System32\conhost.exe
  - C:\Windows\System32\calc.exe
  ```

### 所需权限
- 本地用户权限（运行`conhost.exe`和子进程）。
- 管理员权限（若涉及特权操作或漏洞利用）。

### 操作系统
- Windows 7、Windows 8、Windows 8.1、Windows 10、Windows 11、Windows Server 2008、2012、2016、2019、2022。

## 检测日志

### Windows安全日志
- **事件ID 4688**：记录`conhost.exe`及其子进程（如`calc.exe`）的创建，包含命令行参数（如`--headless`）。
- **事件ID 4672**：记录分配给新进程的安全特权（如高权限）。

### Sysmon日志
- **事件ID 1**：捕获`conhost.exe`及其子进程的创建，包含命令行参数。
- **事件ID 10**：记录`conhost.exe`对子进程的访问，可能涉及代理执行。

### 其他日志
- **网络日志**：若子进程涉及网络通信，可捕获相关流量。

## 测试复现

### 环境准备
- **靶机**：Windows 10/11或Windows Server 2016。
- **权限**：本地用户权限。
- **工具**：
  - 原生Windows工具（`conhost.exe`、`cmd.exe`）。
  - Sysmon（监控进程活动）。
  - Wireshark（可选，监控网络活动，若子进程涉及通信）。
- **网络**：隔离网络环境，无需特定端口。
- **日志**：启用Windows安全日志（事件ID 4688）、Sysmon日志（事件ID 1）。
- **环境检查**：
  - 验证`conhost.exe`存在：
    ```powershell
    Get-Item -Path "C:\Windows\System32\conhost.exe"
    ```

### 攻击步骤
1. **执行无Headless参数**：
   ```cmd
   conhost.exe calc.exe
   ```
   - 以`conhost.exe`作为父进程启动计算器，观察窗口是否可见。
2. **执行带Headless参数**：
   ```cmd
   conhost.exe --headless calc.exe
   ```
   - 启动计算器，验证窗口是否隐藏。
3. **验证结果**：
   - 检查计算器进程是否运行：
     ```powershell
     Get-Process -Name calc
     ```
   - 验证Windows安全日志，确认事件ID 4688记录`conhost.exe`和`calc.exe`的进程创建。
   - 检查Sysmon日志，捕获`--headless`命令行参数。
4. **清理**：
   - 终止计算器进程：
     ```cmd
     taskkill /IM calc.exe /F
     ```

## 测试留痕
以下为Windows安全日志示例（事件ID 4688，进程创建）：
```yml
EventID: 4688
TimeCreated: 2025-06-08T05:50:23.456Z
Channel: Security
Hostname: MAJACKD3D7
SubjectUserSid: S-1-5-21-4139220405-2433135684-1686031733-1000
SubjectUserName: jackma
SubjectDomainName: MAJACKD3D7
SubjectLogonId: 0x1f9f5
NewProcessId: 0x16b4
NewProcessName: C:\Windows\System32\conhost.exe
TokenElevationType: %%1938
ProcessId: 0x670
CommandLine: conhost.exe --headless calc.exe
TargetUserSid: S-1-0-0
TargetUserName: -
TargetDomainName: -
TargetLogonId: 0x0
ParentProcessName: C:\Windows\System32\cmd.exe
MandatoryLabel: S-1-16-8192
```

以下为Sysmon日志示例（事件ID 1，进程创建）：
```yml
EventID: 1
UtcTime: 2025-06-08T05:50:23.789Z
ProcessGuid: {b2c3d4e5-6789-61df-0f12-000000000900}
ProcessId: 5812
Image: C:\Windows\System32\conhost.exe
CommandLine: conhost.exe --headless calc.exe
ParentProcessId: 1648
ParentImage: C:\Windows\System32\cmd.exe
User: MAJACKD3D7\jackma
IntegrityLevel: Medium
Hashes: SHA1=A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6
```

## 检测方法/思路

### Sigma规则
```yml
title: Suspicious Windows ConHost with Headless Parameter
id: e0f1a2b3-4c5d-6e7f-8a9b-0c1d2e3f4g5h
status: experimental
description: Detects use of conhost.exe with --headless parameter, indicative of potential privilege escalation or defense evasion
references:
  - https://attack.mitre.org/techniques/T1068
  - https://lolbas-project.github.io/lolbas/Binaries/Conhost/
  - https://research.splunk.com/endpoint/d5039508-998d-4cfc-8b5e-9dcd679d9a62/
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID: 1
    Image|endswith: '\conhost.exe'
    CommandLine|contains: '--headless'
  condition: selection
falsepositives:
  - Rare legitimate use of conhost.exe with --headless in automation scripts
level: high
```

### 检测思路
1. **进程监控**：
   - 检测`conhost.exe`进程创建，关注命令行参数包含`--headless`。
   - 监控`conhost.exe`的子进程（如`calc.exe`、`powershell.exe`），检查是否为异常程序。
2. **父子进程关系**：
   - 检查`conhost.exe`的父进程（如`cmd.exe`）是否为非预期脚本或工具。
3. **行为基线**：
   - 建立组织内`conhost.exe`的正常使用模式，识别`--headless`的异常调用。
4. **文件监控**：
   - 检测`conhost.exe`的异常部署路径（如非`C:\Windows\System32`）。
5. **权限监控**：
   - 检测`conhost.exe`启动的子进程是否以高权限运行（结合事件ID 4672）。

### 检测建议
- **Sysmon配置**：配置Sysmon监控进程创建（事件ID 1）和命令行参数。
- **日志配置**：启用Windows安全日志的进程创建审核（事件ID 4688）。
- **EDR监控**：使用EDR工具（如Microsoft Defender for Endpoint）检测`conhost.exe`的异常行为。
- **误报过滤**：排除罕见的合法自动化脚本，结合上下文（如用户、子进程）降低误报率。

## 缓解措施
1. **可执行文件限制**：
   - 使用AppLocker或WDAC限制`conhost.exe`的非标准使用：
     ```powershell
     New-AppLockerPolicy -RuleType Path -Path "C:\Windows\System32\conhost.exe" -User Everyone -Action Allow
     ```
2. **命令行监控**：
   - 配置安全策略，限制`conhost.exe`的命令行参数（如`--headless`）。
3. **权限管理**：
   - 最小化用户权限，防止滥用系统二进制文件。
   - 启用UAC，确保特权操作触发提示。
4. **监控与告警**：
   - 配置SIEM实时告警`conhost.exe`的`--headless`使用。
   - 部署IDS/IPS，检测异常子进程行为。
5. **补丁管理**：
   - 定期更新Windows系统，修复潜在漏洞。

## 参考推荐
- MITRE ATT&CK T1068  
  https://attack.mitre.org/techniques/T1068  
- LOLBAS Conhost  
  https://lolbas-project.github.io/lolbas/Binaries/Conhost/  
- Splunk ConHost Headless检测  
  https://research.splunk.com/endpoint/d5039508-998d-4cfc-8b5e-9dcd679d9a62/
