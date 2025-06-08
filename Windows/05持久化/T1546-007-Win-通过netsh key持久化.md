# T1546-007-Win-通过Netsh Helper DLL持久化

## 描述

攻击者可能通过注册Netsh Helper DLL实现持久化执行恶意代码（T1546.007）。`Netsh.exe`是Windows提供的命令行工具，用于配置和监控网络设置（如接口、防火墙、路由）。Netsh通过加载Helper DLL（动态链接库）扩展功能，这些DLL存储在注册表`HKLM\SOFTWARE\Microsoft\Netsh`中，定义了特定Netsh命令（如`interface`、`firewall`）的处理程序。

攻击者可通过添加恶意DLL到Netsh Helper注册表键，使其在`netsh.exe`执行特定命令时加载，触发任意代码执行。由于`netsh.exe`可能由系统进程、第三方软件（如VPN）或管理员操作触发，攻击行为隐蔽性较高。检测重点在于监控Netsh注册表键的修改、异常DLL加载及`netsh.exe`的命令行活动。

## 测试案例

1. **注册恶意Netsh Helper DLL**  
   攻击者将恶意DLL注册为Netsh Helper，在执行`netsh`命令（如`netsh interface show interface`）时触发。  
2. **结合其他持久化技术**  
   攻击者通过计划任务或服务定期运行`netsh.exe`，确保恶意DLL持续执行。  

### 示例命令
- **注册恶意DLL**（需管理员权限）：
  ```cmd
  netsh add helper C:\Windows\System32\malicious.dll
  ```
  - 将`malicious.dll`注册到`HKLM\SOFTWARE\Microsoft\Netsh`。  
- **触发执行**：
  ```cmd
  netsh interface show interface
  ```
  - 运行Netsh命令，加载注册的DLL。  

参考测试案例：[Window权限维持（十）：Netsh Helper DLL](https://www.cnblogs.com/xiaozi/p/11834533.html)

## 检测日志

**Windows安全日志**  
- **事件ID 4688**：记录`netsh.exe`或`reg.exe`的进程创建。  

**Sysmon日志**  
- **事件ID 1**：记录进程创建，包含`netsh.exe`的命令行参数。  
- **事件ID 7**：记录DLL加载，检测`netsh.exe`加载的异常DLL。  
- **事件ID 13**：记录注册表修改，如`HKLM\SOFTWARE\Microsoft\Netsh`的更改。  
- **事件ID 11**：记录DLL文件的创建或写入。  

**配置日志记录**  
- 启用注册表审核：`计算机配置 > 策略 > Windows设置 > 安全设置 > 高级审核策略配置 > 对象访问 > 审核注册表`。  
- 启用命令行参数记录：`计算机配置 > 管理模板 > 系统 > 审核进程创建 > 在进程创建事件中加入命令行 > 启用`。  
- 部署Sysmon以增强注册表、进程和模块监控。

## 测试复现

### 环境准备
- **靶机**：Windows 10或Windows Server 2012+。  
- **权限**：管理员权限（修改注册表和执行`netsh`需提升权限）。  
- **工具**：`netsh.exe`（系统自带）、测试用DLL（模拟恶意DLL）、Sysmon。  
- **测试DLL**：创建简单DLL（或使用`msfvenom`生成）：
  ```bash
  msfvenom -p windows/x64/messagebox TEXT="Netsh Helper DLL" -f dll -o malicious.dll
  ```
- **日志**：启用Windows安全日志和Sysmon。  

### 攻击步骤
1. **部署恶意DLL**  
   - 将测试DLL复制到`C:\Windows\System32\`：
     ```cmd
     copy malicious.dll C:\Windows\System32\malicious.dll
     ```

2. **注册Netsh Helper DLL**  
   - 使用`netsh`添加Helper：
     ```cmd
     netsh add helper C:\Windows\System32\malicious.dll
     ```
   - 验证注册表：
     ```powershell
     Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Netsh"
     ```

3. **触发执行**  
   - 运行Netsh命令：
     ```cmd
     netsh interface show interface
     ```
   - 观察DLL是否加载（如弹出消息框）。

4. **验证结果**  
   - 检查注册表：
     ```powershell
     Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Netsh" | Select-Object malicious
     ```
   - 检查日志：  
     - **Windows安全日志（事件ID 4688）**：
       ```powershell
       Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4688 -and $_.Message -match "netsh.exe" }
       ```
     - **Sysmon日志（事件ID 13）**：
       ```powershell
       Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object { $_.Id -eq 13 -and $_.Message -match "Netsh" }
       ```

5. **清理**  
   - 删除注册表键：
     ```cmd
     reg delete "HKLM\SOFTWARE\Microsoft\Netsh" /v malicious /f
     ```
   - 删除DLL：
     ```cmd
     del C:\Windows\System32\malicious.dll
     ```

### 示例输出
```cmd
netsh add helper C:\Windows\System32\malicious.dll
OK

netsh interface show interface
<触发DLL执行，可能弹出消息框>

reg delete "HKLM\SOFTWARE\Microsoft\Netsh" /v malicious /f
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
  Image: C:\Windows\System32\netsh.exe
  TargetObject: HKLM\SOFTWARE\Microsoft\Netsh\malicious
  Details: C:\Windows\System32\malicious.dll
  User: CONTOSO\Administrator
  ```

- **Sysmon日志（事件ID 1，进程创建）**：
  ```plaintext
  EventID: 1
  UtcTime: 2025-06-10 03:00:00.234
  ProcessGuid: {12345678-abcd-1234-abcd-1234567890ab}
  ProcessId: 1234
  Image: C:\Windows\System32\netsh.exe
  CommandLine: netsh add helper C:\Windows\System32\malicious.dll
  ParentImage: C:\Windows\System32\cmd.exe
  User: CONTOSO\Administrator
  IntegrityLevel: High
  ```

- **Sysmon日志（事件ID 7，DLL加载）**：
  ```plaintext
  EventID: 7
  UtcTime: 2025-06-10 03:00:00.345
  ProcessGuid: {12345678-abcd-1234-abcd-1234567890ab}
  Image: C:\Windows\System32\netsh.exe
  ImageLoaded: C:\Windows\System32\malicious.dll
  User: CONTOSO\Administrator
  ```

- **注册表项**：
  ```plaintext
  HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Netsh
  Name: malicious
  Type: REG_SZ
  Data: C:\Windows\System32\malicious.dll
  ```

## 检测规则/思路

**检测规则**  
通过监控注册表修改、DLL加载和`netsh.exe`执行日志，检测Netsh Helper DLL的异常注册及使用。以下是具体思路：

1. **日志分析**：
   - 监控Sysmon事件ID 13，检测`HKLM\SOFTWARE\Microsoft\Netsh`的修改。  
   - 监控Sysmon事件ID 1，检测`netsh.exe`执行`add helper`命令。  
   - 监控Sysmon事件ID 7，检测`netsh.exe`加载的异常DLL。  
   - 监控Sysmon事件ID 11，检测DLL文件的创建（如`C:\Windows\System32\malicious.dll`）。  
   - 监控Windows安全日志事件ID 4688，检测`netsh.exe`或`reg.exe`的异常使用。  

2. **Sigma规则（Netsh Helper DLL注册表修改）**：
   ```yaml
   title: Netsh Helper DLL注册表修改检测
   id: l34567890-abcd123456-xyz789012345
   status: stable
   description: 检测Netsh Helper DLL的注册表修改，可能用于持久化恶意代码
   date: 2020/11/29
   references:
     - https://attack.mitre.org/techniques/T1546/007/
     - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.007/T1546.007.md
     - https://www.cnblogs.com/xiaozi/p/11834533.html
   tags:
     - attack.persistence
     - attack.t1546.007
     - attack.t1112
   logsource:
     product: windows
     service: sysmon
   detection:
     selection:
       EventID: 13
       TargetObject|contains: '\SOFTWARE\Microsoft\Netsh'
     condition: selection
   fields:
     - TargetObject
     - Details
     - Image
     - User
   falsepositives:
     - 合法Netsh Helper DLL注册（如VPN软件）
   level: high
   ```

3. **Sigma规则（Netsh Helper DLL执行）**：
   ```yaml
   title: Netsh Helper DLL注册执行检测
   id: m45678901-abcd234567-abc890123456
   status: experimental
   description: 检测netsh.exe执行add helper命令，可能注册恶意DLL
   logsource:
     product: windows
     service: sysmon
   detection:
     selection:
       EventID: 1
       Image|endswith: '\netsh.exe'
       CommandLine|contains: 'add helper'
     condition: selection
   fields:
     - Image
     - CommandLine
     - ParentImage
     - User
   falsepositives:
     - 合法网络管理操作
   level: high
   ```

4. **SIEM规则**：
   - 检测Netsh Helper DLL注册及执行。
   - 示例Splunk查询：
     ```spl
     (source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventID=13 TargetObject="*SOFTWARE\Microsoft\Netsh*") OR (EventID=1 Image="*netsh.exe" CommandLine="*add helper*") OR (EventID=7 ImageLoaded="*.dll" Image="*netsh.exe")) | stats count by Image, CommandLine, TargetObject, ImageLoaded, User, ComputerName
     ```

5. **注册表监控**：
   - 检查Netsh Helper配置：
     ```powershell
     Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Netsh"
     ```

6. **工具支持**：
   - 使用Sysinternals Autoruns检查Netsh Helper DLL：
     ```cmd
     autoruns -a | findstr "Netsh"
     ```
   - 使用Process Monitor捕获实时注册表和DLL加载活动。

7. **威胁情报整合**：
   - 检查DLL文件哈希或路径是否与已知恶意样本匹配，结合威胁情报平台（如VirusTotal、AlienVault）。  

## 建议

### 缓解措施

防御Netsh Helper DLL攻击需从注册表保护、DLL监控和权限管理入手：

1. **锁定注册表键**  
   - 限制`HKLM\SOFTWARE\Microsoft\Netsh`的写权限：
     ```powershell
     $acl = Get-Acl "HKLM:\SOFTWARE\Microsoft\Netsh"
     $acl.SetAccessRuleProtection($true, $false)
     Set-Acl -Path "HKLM:\SOFTWARE\Microsoft\Netsh" -AclObject $acl
     ```

2. **限制netsh命令使用**  
   - 使用AppLocker限制非管理员执行`netsh.exe`：
     ```powershell
     New-AppLockerPolicy -RuleType Path -Path "C:\Windows\System32\netsh.exe" -Action Deny -User "Everyone"
     ```

3. **白名单DLL**  
   - 仅允许系统默认Netsh Helper DLL：
     ```powershell
     Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Netsh" | Where-Object { $_.PSChildName -notmatch "^(interface|firewall|advfirewall|http|ras|wlan)$" }
     ```

4. **加强权限管理**  
   - 限制非管理员用户修改System32目录：
     ```powershell
     icacls "C:\Windows\System32" /deny "Users:(W)"
     ```

5. **日志和监控**  
   - 启用Sysmon事件ID 1、7、11、13，检测Netsh相关活动。  
   - 配置SIEM监控Netsh Helper DLL注册及加载。  
   - 使用EDR工具检测异常DLL行为。  

6. **定期审计**  
   - 检查Netsh Helper配置：
     ```powershell
     Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Netsh"
     ```
   - 审计System32目录中的DLL文件：
     ```powershell
     Get-ChildItem -Path "C:\Windows\System32" -Filter "*.dll" | Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-7) }
     ```

## 参考推荐

- MITRE ATT&CK: T1546.007  
  <https://attack.mitre.org/techniques/T1546/007/>  
- Atomic Red Team: T1546.007  
  <https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.007/T1546.007.md>  
- Window权限维持（十）：Netsh Helper DLL  
  <https://www.cnblogs.com/xiaozi/p/11834533.html>  
- EQlib Analytics: Netsh Helper DLL  
  <https://eqllib.readthedocs.io/en/latest/analytics/5f9a71f4-f5ef-4d35-aff8-f67d63d3c896.html>