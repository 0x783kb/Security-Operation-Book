# T1137-0047-Win-Office应用启动程序-Outlook主页

## 描述

攻击者可能利用Microsoft Outlook的“主页”（Home Page）功能实现系统持久化（T1137.004）。Outlook主页允许为特定文件夹（如收件箱）设置自定义HTML页面，在打开文件夹时加载内部或外部URL的内容。攻击者可配置恶意HTML文件，包含JavaScript或其他可执行代码，在Outlook访问目标文件夹时触发，从而执行恶意有效负载。  

此功能为Outlook早期版本的遗留特性，允许自定义文件夹视图，但可被滥用为持久化机制。恶意主页在Outlook启动并加载目标文件夹（如收件箱）时执行，隐蔽性较高。攻击者需具备用户权限以修改注册表（如`HKCU`），或管理员权限以影响全局配置。检测重点在于监控Outlook相关注册表键的修改及异常HTML加载行为。

## 测试案例

1. **Outlook主页持久化**  
   攻击者通过修改注册表，为Outlook收件箱设置恶意HTML页面URL，在文件夹加载时执行代码。  
2. **伪装合法HTML**  
   攻击者使用看似合法的HTML文件名或托管在可信域的URL，降低被发现风险。  

## 检测日志

**Windows安全日志**  
- **事件ID 4688**：记录进程创建，可能涉及`reg.exe`或`outlook.exe`的执行。  

**Sysmon日志**  
- **事件ID 1**：记录进程创建，包含`reg.exe`或`outlook.exe`的命令行参数。  
- **事件ID 13**：记录注册表值修改，如`HKCU\Software\Microsoft\Office\<version>\Outlook\WebView\<folder>`的创建或更新。  
- **事件ID 3**：记录网络连接，检测Outlook加载外部URL的活动。  

**配置日志记录**  
- 启用注册表审核：`计算机配置 > 策略 > Windows设置 > 安全设置 > 高级审核策略配置 > 对象访问 > 审核注册表`。  
- 启用命令行参数记录：`计算机配置 > 管理模板 > 系统 > 审核进程创建 > 在进程创建事件中加入命令行 > 启用`。  
- 部署Sysmon以增强注册表、进程和网络监控。

## 测试复现

### 环境准备
- **靶机**：Windows 10或Windows Server 2012+，安装Microsoft Outlook（2016+，版本16.0）。  
- **权限**：用户权限（修改`HKCU`）。  
- **工具**：测试用HTML文件（如`T1137.004.html`），Sysmon及Windows安全日志启用。  
- **测试文件路径**：`C:\Users\Administrator.ZHULI\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1137.004\src\T1137.004.html`。

### 攻击步骤
1. **添加Outlook主页注册表键**  
   以用户权限运行CMD，为收件箱设置恶意HTML页面：
   ```dos
   reg.exe add HKCU\Software\Microsoft\Office\16.0\Outlook\WebView\Inbox /v URL /t REG_SZ /d "C:\Users\Administrator.ZHULI\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1137.004\src\T1137.004.html" /f
   ```

   **真实测试结果**：
   ```dos
   C:\Users\Administrator.ZHULI>reg.exe add HKCU\Software\Microsoft\Office\16.0\Outlook\WebView\Inbox /v URL /t REG_SZ /d C:\Users\Administrator.ZHULI\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1137.004\src\T1137.004.html /f
   操作成功完成。
   ```

2. **触发持久化**  
   启动Outlook并打开收件箱，加载恶意HTML页面。  

3. **清理注册表（测试后）**  
   删除注册表键：
   ```dos
   reg.exe delete HKCU\Software\Microsoft\Office\16.0\Outlook\WebView\Inbox /v URL /f >nul 2>&1
   ```

4. **验证结果**  
   - 检查注册表键：
     ```dos
     reg query HKCU\Software\Microsoft\Office\16.0\Outlook\WebView\Inbox
     ```
   - 检查日志：  
     - **Sysmon日志（事件ID 1）**：
       ```plaintext
       EventID: 1
       RuleName: technique_id=T1112,technique_name=Modify Registry
       UtcTime: 2022-01-11 06:54:50.664
       ProcessGuid: {78c84c47-29ba-61dd-b821-000000000800}
       ProcessId: 6040
       Image: C:\Windows\System32\reg.exe
       CommandLine: reg.exe add HKCU\Software\Microsoft\Office\16.0\Outlook\WebView\Inbox /v URL /t REG_SZ /d C:\Users\Administrator.ZHULI\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1137.004\src\T1137.004.html /f
       User: ZHULI\Administrator
       IntegrityLevel: High
       ```
     - **Sysmon日志（事件ID 13）**：
       ```plaintext
       EventID: 13
       EventType: SetValue
       UtcTime: 2022-01-11 06:54:50.675
       ProcessId: 6040
       Image: C:\Windows\System32\reg.exe
       TargetObject: HKU\S-1-5-21-2729552704-1545692732-1695105048-500\Software\Microsoft\Office\16.0\Outlook\WebView\Inbox\URL
       Details: C:\Users\Administrator.ZHULI\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1137.004\src\T1137.004.html
       User: ZHULI\Administrator
       ```

**注意**：此复现仅用于学习和测试目的，需在合法授权的测试环境中进行，切勿用于非法活动。

## 测试留痕

- **Sysmon日志（事件ID 1）**：
  ```plaintext
  EventID: 1
  RuleName: technique_id=T1112,technique_name=Modify Registry
  UtcTime: 2022-01-11 06:54:50.664
  ProcessGuid: {78c84c47-29ba-61dd-b821-000000000800}
  ProcessId: 6040
  Image: C:\Windows\System32\reg.exe
  CommandLine: reg.exe add HKCU\Software\Microsoft\Office\16.0\Outlook\WebView\Inbox /v URL /t REG_SZ /d C:\Users\Administrator.ZHULI\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1137.004\src\T1137.004.html /f
  User: ZHULI\Administrator
  IntegrityLevel: High
  Hashes: SHA1=429DF8371B437209D79DC97978C33157D1A71C4B,MD5=8A93ACAC33151793F8D52000071C0B06,SHA256=19316D4266D0B776D9B2A05D5903D8CBC8F0EA1520E9C2A7E6D5960B6FA4DCAF
  ```
- **Sysmon日志（事件ID 13）**：
  ```plaintext
  EventID: 13
  EventType: SetValue
  UtcTime: 2022-01-11 06:54:50.675
  ProcessGuid: {78c84c47-29ba-61dd-b821-000000000800}
  ProcessId: 6040
  Image: C:\Windows\System32\reg.exe
  TargetObject: HKU\S-1-5-21-2729552704-1545692732-1695105048-500\Software\Microsoft\Office\16.0\Outlook\WebView\Inbox\URL
  Details: C:\Users\Administrator.ZHULI\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1137.004\src\T1137.004.html
  User: ZHULI\Administrator
  ```
- **Sysmon日志（事件ID 3，加载外部URL）**：
  ```plaintext
  EventID: 3
  Image: C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE
  DestinationIp: <External_IP>
  DestinationPort: 80
  Protocol: tcp
  Initiated: true
  User: ZHULI\Administrator
  ```

## 检测规则/思路

**检测规则**  
通过分析Sysmon和Windows安全日志，检测Outlook主页注册表键的修改及异常网络活动。以下是具体思路：

1. **日志分析**：
   - 监控Sysmon事件ID 13，检测`HKCU\Software\Microsoft\Office\<version>\Outlook\WebView\<folder>`的修改。  
   - 监控Sysmon事件ID 1或Windows事件ID 4688，检测`reg.exe`的异常命令行（如添加`Outlook\WebView`键）。  
   - 监控Sysmon事件ID 3，检测`outlook.exe`发起的异常网络连接（如加载外部URL）。  
   - 监控事件ID 4624，检测新主页触发的异常登录行为。

2. **Sigma规则（注册表修改）**：
   ```yaml
   title: Outlook主页注册表键修改
   id: r3s4t5u6-v7w8-9012-xyza-3456789012
   status: stable
   description: 检测Outlook主页注册表键的创建或修改，可能表明持久化攻击
   references:
     - https://attack.mitre.org/techniques/T1137/004/
     - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1137.004/T1137.004.yaml
   tags:
     - attack.persistence
     - attack.t1137.004
   logsource:
     product: windows
     service: sysmon
   detection:
     selection:
       EventID: 13
       TargetObject|contains: '\Software\Microsoft\Office\*\Outlook\WebView\'
     condition: selection
   fields:
     - TargetObject
     - Details
     - Image
   falsepositives:
     - 合法的Outlook主页配置
   level: high
   ```

3. **Sigma规则（异常网络连接）**：
   ```yaml
   title: Outlook异常网络连接
   id: s4t5u6v7-w8x9-0123-yzab-4567890123
   status: experimental
   description: 检测Outlook加载外部URL的异常网络活动，可能与主页持久化相关
   logsource:
     product: windows
     service: sysmon
   detection:
     selection:
       EventID: 3
       Image|endswith: '\outlook.exe'
       DestinationPort: 
         - 80
         - 443
       Initiated: true
     condition: selection
   fields:
     - Image
     - DestinationIp
     - DestinationPort
   falsepositives:
     - 合法的Outlook插件或网页内容加载
   level: medium
   ```

4. **SIEM规则**：
   - 检测Outlook主页注册表修改及网络活动。
   - 示例Splunk查询：
     ```spl
     source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=13 TargetObject="*Outlook\WebView*") OR (EventCode=3 Image="*outlook.exe" DestinationPort IN (80,443)) | stats count by EventCode, TargetObject, Image, DestinationIp, ComputerName
     ```

5. **注册表监控**：
   - 监控`HKCU\Software\Microsoft\Office\<version>\Outlook\WebView`的创建或修改。  
   - 示例PowerShell查询：
     ```powershell
     Get-ItemProperty -Path "HKCU:\Software\Microsoft\Office\*\Outlook\WebView\*" -ErrorAction SilentlyContinue
     ```

6. **威胁情报整合**：
   - 检查HTML文件或URL是否与已知恶意样本相关，结合威胁情报平台（如VirusTotal、AlienVault）。

## 建议

### 缓解措施

防御Outlook主页持久化需从注册表保护、网络监控和Outlook配置入手：

1. **限制注册表访问**  
   - 配置ACL，限制非管理员用户对`HKCU\Software\Microsoft\Office\<version>\Outlook\WebView`的写入权限。  

2. **禁用Outlook主页功能**  
   - 配置组策略禁用Web视图：  
     `用户配置 > 管理模板 > Microsoft Outlook > 禁用Web视图`。  
   - 或设置注册表：
     ```powershell
     Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\Options\WebView" -Name "Enable" -Value 0
     ```

3. **加强Outlook安全**  
   - 启用Outlook攻击面减少（ASR）规则，限制脚本执行。  
   - 配置组策略：`计算机配置 > 管理模板 > Microsoft Outlook > 安全设置 > 阻止不受信任的HTML内容`。

4. **凭据保护**  
   - 启用多因素认证（MFA）保护Outlook账户。  
   - 使用强密码策略，避免弱凭据。

5. **日志和监控**  
   - 启用Sysmon事件ID 13和3，检测注册表修改及异常网络连接。  
   - 配置SIEM监控`Outlook\WebView`相关事件。  
   - 使用EDR工具检测Outlook进程的非标准行为。

6. **定期审计**  
   - 检查Outlook WebView注册表键是否存在。  

7. **使用Microsoft工具**  
   - 运行Microsoft提供的PowerShell脚本，检测和修复Outlook主页或表单注入：  
     <https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-outlook-rules-forms-attack>.

## 参考推荐

- MITRE ATT&CK: T1137.004  
  <https://attack.mitre.org/techniques/T1137/004/>  
- Atomic Red Team: T1137.004  
  <https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1137.004/T1137.004.yaml>  
- Detect and Remediate Outlook Rules and Forms Attacks  
  <https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-outlook-rules-forms-attack?view=o365-worldwide>