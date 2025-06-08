# T1546-015-Win-组件对象模型劫持-Dllhost.exe

## 描述

攻击者通过劫持Windows组件对象模型（COM）对象的注册表引用，插入恶意代码以实现持久化（T1546.015）。COM是Windows用于组件间交互的核心机制，相关引用存储在注册表（如`HKLM\SOFTWARE\Classes\CLSID`或`HKCU\SOFTWARE\Classes\CLSID`）。攻击者可修改COM对象的`InProcServer32`或`LocalServer32`键，替换合法DLL或可执行文件路径为恶意负载，当系统或应用程序调用该COM对象时触发恶意代码。

**Dllhost.exe**（位于`C:\Windows\System32\`或`C:\Windows\SysWOW64\`）是COM代理进程，负责托管COM服务器（如DLL）。攻击者可通过注册或劫持COM对象的CLSID（类标识符），利用`dllhost.exe /Processid:{CLSID}`加载恶意DLL，伪装为合法COM操作。攻击通常针对高频调用的COM对象以保持持久性，同时避免明显功能异常以降低检测风险。检测重点在于监控COM注册表修改、异常`dllhost.exe`网络活动及加载的非预期DLL。

## 测试案例

1. **劫持COM对象加载恶意DLL**  
   攻击者修改COM对象的注册表键，指向恶意DLL，由`dllhost.exe`加载。  
2. **通过CLSID直接触发**  
   攻击者使用`dllhost.exe /Processid:{CLSID}`执行已注册或劫持的COM服务器。  
3. **伪装合法COM调用**  
   攻击者选择常用COM对象（如ShellWindows），替换其服务器路径以隐藏恶意行为。  

### 示例命令
- **触发COM对象**（用户权限）：
  ```cmd
  dllhost.exe /Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}
  ```
  - **用例**：执行指定CLSID的COM服务器，可能加载恶意DLL。  
  - **所需权限**：用户权限。  
  - **操作系统**：Windows 10及更早版本。  

- **注册恶意COM对象**（需管理员权限）：
  ```cmd
  reg add "HKLM\SOFTWARE\Classes\CLSID\{12345678-1234-1234-1234-1234567890AB}\InProcServer32" /ve /d "C:\Malicious\evil.dll" /f
  ```

## 检测日志

**Windows安全日志**  
- **事件ID 4688**：记录`dllhost.exe`或`reg.exe`的进程创建。  

**Sysmon日志**  
- **事件ID 1**：记录进程创建，包含`dllhost.exe`的命令行参数（如`/Processid:{CLSID}`）。  
- **事件ID 3**：记录`dllhost.exe`的网络连接，检测异常公网通信。  
- **事件ID 7**：记录`dllhost.exe`加载的DLL，识别非预期模块。  
- **事件ID 13**：记录COM注册表修改，如`HKLM\SOFTWARE\Classes\CLSID`。  

**配置日志记录**  
- 启用注册表审核：`计算机配置 > 策略 > Windows设置 > 安全设置 > 高级审核策略配置 > 对象访问 > 审核注册表`。  
- 启用命令行参数记录：`计算机配置 > 管理模板 > 系统 > 审核进程创建 > 在进程创建事件中加入命令行 > 启用`。  
- 部署Sysmon以增强注册表、进程、网络和模块监控。

## 测试复现

### 环境准备
- **靶机**：Windows 10或Windows Server 2012+。  
- **权限**：用户权限（触发COM对象）或管理员权限（注册COM对象）。  
- **工具**：`dllhost.exe`（系统自带）、测试用DLL（如`msfvenom`生成）、Sysmon、注册表编辑器。  
- **测试DLL**：生成简单DLL：
  ```bash
  msfvenom -p windows/x64/messagebox TEXT="COM Hijack Test" -f dll -o evil.dll
  ```
- **日志**：启用Windows安全日志和Sysmon。  

### 攻击步骤
1. **创建恶意DLL**  
   - 复制测试DLL到可控路径：
     ```cmd
     copy evil.dll C:\Malicious\evil.dll
     ```

2. **注册恶意COM对象**  
   - 创建CLSID并配置`InProcServer32`：
     ```cmd
     reg add "HKLM\SOFTWARE\Classes\CLSID\{12345678-1234-1234-1234-1234567890AB}\InProcServer32" /ve /d "C:\Malicious\evil.dll" /f
     reg add "HKLM\SOFTWARE\Classes\CLSID\{12345678-1234-1234-1234-1234567890AB}\InProcServer32" /v ThreadingModel /d Apartment /f
     ```

3. **触发COM对象**  
   - 使用`dllhost.exe`加载：
     ```cmd
     dllhost.exe /Processid:{12345678-1234-1234-1234-1234567890AB}
     ```
   - 观察DLL是否执行（如弹出消息框）。

4. **验证结果**  
   - 检查注册表：
     ```powershell
     Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\CLSID\{12345678-1234-1234-1234-1234567890AB}\InProcServer32"
     ```
   - 检查日志：  
     - **Windows安全日志（事件ID 4688）**：
       ```powershell
       Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4688 -and $_.Message -match "dllhost.exe" }
       ```
     - **Sysmon日志（事件ID 13）**：
       ```powershell
       Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object { $_.Id -eq 13 -and $_.Message -match "CLSID" }
       ```
     - **Sysmon日志（事件ID 7）**：
       ```powershell
       Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object { $_.Id -eq 7 -and $_.Message -match "evil.dll" }
       ```

5. **清理**  
   - 删除注册表键：
     ```cmd
     reg delete "HKLM\SOFTWARE\Classes\CLSID\{12345678-1234-1234-1234-1234567890AB}" /f
     ```
   - 删除DLL：
     ```cmd
     del C:\Malicious\evil.dll
     ```

**注意**：此复现仅用于学习和测试目的，需在合法授权的测试环境中进行，切勿用于非法活动。

## 测试留痕

- **Sysmon日志（事件ID 1，进程创建）**：
  ```plaintext
  EventID: 1
  UtcTime: 2025-06-10 03:00:00.123
  ProcessGuid: {12345678-abcd-1234-abcd-1234567890ab}
  ProcessId: 1234
  Image: C:\Windows\System32\dllhost.exe
  CommandLine: dllhost.exe /Processid:{12345678-1234-1234-1234-1234567890AB}
  ParentImage: C:\Windows\System32\cmd.exe
  User: CONTOSO\User
  IntegrityLevel: Medium
  ```

- **Sysmon日志（事件ID 7，DLL加载）**：
  ```plaintext
  EventID: 7
  UtcTime: 2025-06-10 03:00:00.234
  ProcessGuid: {12345678-abcd-1234-abcd-1234567890ab}
  Image: C:\Windows\System32\dllhost.exe
  ImageLoaded: C:\Malicious\evil.dll
  Hashes: SHA256=ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890
  User: CONTOSO\User
  ```

- **Sysmon日志（事件ID 13，注册表修改）**：
  ```plaintext
  EventID: 13
  EventType: SetValue
  UtcTime: 2025-06-10 03:00:00.345
  ProcessGuid: {12345678-abcd-1234-abcd-1234567890ac}
  Image: C:\Windows\System32\reg.exe
  TargetObject: HKLM\SOFTWARE\Classes\CLSID\{12345678-1234-1234-1234-1234567890AB}\InProcServer32
  Details: C:\Malicious\evil.dll
  User: CONTOSO\Administrator
  ```

- **Sysmon日志（事件ID 3，网络连接，异常情况）**：
  ```plaintext
  EventID: 3
  UtcTime: 2025-06-10 03:00:00.456
  ProcessGuid: {12345678-abcd-1234-abcd-1234567890ab}
  Image: C:\Windows\System32\dllhost.exe
  DestinationIp: 203.0.113.1
  DestinationPort: 443
  User: CONTOSO\User
  ```

## 检测规则/思路

**检测规则**  
通过监控COM注册表修改、`dllhost.exe`的异常行为及网络活动，检测COM劫持攻击。以下是具体思路：

1. **日志分析**：
   - 监控Sysmon事件ID 13，检测`HKLM\SOFTWARE\Classes\CLSID`或`HKCU\SOFTWARE\Classes\CLSID`的修改，尤其是`InProcServer32`或`LocalServer32`键。  
   - 监控Sysmon事件ID 1，检测`dllhost.exe`执行，检查命令行是否包含`/Processid:{CLSID}`。  
   - 监控Sysmon事件ID 7，检测`dllhost.exe`加载的非系统DLL。  
   - 监控Sysmon事件ID 3，检测`dllhost.exe`的异常公网连接（排除私有IP）。  
   - 监控Windows安全日志事件ID 4688，检测`dllhost.exe`或`reg.exe`的异常进程创建。  

2. **Sigma规则（Dllhost异常网络连接）**：
   ```yaml
   title: Dllhost异常网络连接检测
   id: cfed2f44-16df-4bf3-833a-79405198b277
   status: stable
   description: 检测dllhost.exe与公网IP的通信，可能与COM劫持相关
   author: bartblaze
   date: 2020/07/13
   references:
     - https://attack.mitre.org/techniques/T1546/015/
     - https://lolbas-project.github.io/lolbas/Binaries/Dllhost/
   tags:
     - attack.persistence
     - attack.t1546.015
     - attack.execution
   logsource:
     category: network_connection
     product: windows
   detection:
     selection:
       Image|endswith: '\dllhost.exe'
       Initiated: 'true'
     filter:
       DestinationIp|startswith:
         - '10.'
         - '192.168.'
         - '172.16.'
         - '172.17.'
         - '172.18.'
         - '172.19.'
         - '172.20.'
         - '172.21.'
         - '172.22.'
         - '172.23.'
         - '172.24.'
         - '172.25.'
         - '172.26.'
         - '172.27.'
         - '172.28.'
         - '172.29.'
         - '172.30.'
         - '172.31.'
         - '127.'
     condition: selection and not filter
   fields:
     - Image
     - DestinationIp
     - DestinationPort
     - User
   falsepositives:
     - 合法应用程序通过dllhost.exe的公网通信（如云服务）
   level: medium
   ```

3. **Sigma规则（COM注册表修改）**：
   ```yaml
   title: COM对象注册表修改检测
   id: g78901234-abcd-5678-9012-34567890abcd
   status: experimental
   description: 检测COM对象注册表键的修改，可能与COM劫持相关
   logsource:
     product: windows
     service: sysmon
   detection:
     selection:
       EventID: 13
       TargetObject|contains:
         - '\SOFTWARE\Classes\CLSID'
         - '\InProcServer32'
         - '\LocalServer32'
     condition: selection
   fields:
     - TargetObject
     - Details
     - Image
     - User
   falsepositives:
     - 合法软件安装或更新
   level: high
   ```

4. **Sigma规则（Dllhost异常DLL加载）**：
   ```yaml
   title: Dllhost异常DLL加载检测
   id: h89012345-abcd-6789-0123-45678901bcde
   status: experimental
   description: 检测dllhost.exe加载非系统DLL，可能与COM劫持相关å
   logsource:
     product: windows
     service: sysmon
   detection:
     selection:
       EventID: 7
       Image|endswith: '\dllhost.exe'
       ImageLoaded|contains: '.dll'
     filter:
       ImageLoaded|startswith:
         - 'C:\Windows\System32\'
         - 'C:\Windows\SysWOW64\'
     condition: selection and not filter
   fields:
     - Image
     - ImageLoaded
     - User
   falsepositives:
     - 第三方合法COM服务器
   level: high
   ```

5. **SIEM规则**：
   - 检测COM劫持及`dllhost.exe`异常行为。
   - 示例Splunk查询：
     ```spl
     (source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventID=13 TargetObject IN ("*CLSID*InProcServer32*","*CLSID*LocalServer32*")) OR (EventID=1 Image="*dllhost.exe" CommandLine="*/Processid:*") OR (EventID=7 Image="*dllhost.exe" ImageLoaded="*.dll" NOT ImageLoaded IN ("C:\Windows\System32\*","C:\Windows\SysWOW64\*")) OR (EventID=3 Image="*dllhost.exe" NOT DestinationIp IN ("10.*","192.168.*","172.16.*","172.31.*","127.*"))) | stats count by Image, CommandLine, TargetObject, ImageLoaded, DestinationIp, User, ComputerName
     ```

6. **注册表监控**：
   - 检查COM对象配置：
     ```powershell
     Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\CLSID\*\InProcServer32" -ErrorAction SilentlyContinue | Where-Object { $_.'(Default)' -notmatch 'C:\\Windows\\System32|C:\\Windows\\SysWOW64' }
     ```

7. **工具支持**：
   - 使用Sysinternals Autoruns检查COM对象：
     ```cmd
     autoruns -c | findstr "CLSID"
     ```
   - 使用Process Monitor捕获实时注册表和DLL加载活动。

8. **威胁情报整合**：
   - 检查DLL文件哈希或CLSID是否与已知恶意样本匹配，结合威胁情报平台（如VirusTotal、AlienVault）。  

## 建议

### 缓解措施

防御COM劫持攻击需从注册表保护、DLL监控和权限管理入手：

1. **锁定注册表键**  
   - 限制`HKLM\SOFTWARE\Classes\CLSID`的写权限：
     ```powershell
     $acl = Get-Acl "HKLM:\SOFTWARE\Classes\CLSID"
     $acl.SetAccessRuleProtection($true, $false)
     Set-Acl -Path "HKLM:\SOFTWARE\Classes\CLSID" -AclObject $acl
     ```

2. **限制dllhost.exe行为**  
   - 使用AppLocker限制`dllhost.exe`加载非系统DLL：
     ```powershell
     New-AppLockerPolicy -RuleType Path -Path "C:\Windows\System32\*.dll" -Action Allow -User "Everyone"
     ```

3. **白名单COM对象**  
   - 定期审计COM对象，移除非必要CLSID：
     ```powershell
     Get-Item -Path "HKLM:\SOFTWARE\Classes\CLSID\*" | Where-Object { $_.GetSubKeyNames() -contains "InProcServer32" } | Select-Object PSChildName
     ```

4. **加强权限管理**  
   - 限制非管理员用户修改注册表：
     ```powershell
     icacls "C:\Windows\System32\reg.exe" /deny "Users:(X)"
     ```

5. **日志和监控**  
   - 启用Sysmon事件ID 1、3、7、13，检测COM注册表修改和`dllhost.exe`异常行为。  
   - 配置SIEM监控COM相关事件。  
   - 使用EDR工具检测异常DLL加载和网络活动。  

6. **定期审计**  
   - 检查COM对象配置：
     ```powershell
     Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\CLSID\*\InProcServer32" -ErrorAction SilentlyContinue
     ```
   - 审计`dllhost.exe`加载的DLL：
     ```powershell
     Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object { $_.Id -eq 7 -and $_.Message -match "dllhost.exe" }
     ```

## 参考推荐

- MITRE ATT&CK: T1546.015  
  <https://attack.mitre.org/techniques/T1546/015/>  
- Dllhost.exe LOLBAS  
  <https://lolbas-project.github.io/lolbas/Binaries/Dllhost/>  
- Sigma规则：Dllhost网络连接  
  <https://github.com/Neo23x0/sigma/blob/master/rules/windows/network_connection/sysmon_rundll32_net_connections.yml>