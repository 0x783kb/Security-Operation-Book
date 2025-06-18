# T1003-Win-Vaultcmd获取系统凭据基本信息

## 描述

凭据导出是指攻击者从操作系统或软件中提取账户登录名和密码（明文或哈希）以进行横向移动或访问受限资源。Windows Credential Manager存储用户凭据（如Web、Windows、证书等），攻击者可通过`vaultcmd.exe`（Windows内置工具）查询和提取这些凭据信息。`vaultcmd`允许列出凭据保管库（Vault）、凭据概要及其属性，但无法直接提取明文密码（需结合其他工具如Mimikatz）。此技术通常用于初始凭据收集或权限提升。

## 测试案例

**测试环境**：
- 系统：Windows Server 2016/2019或Windows10
- 工具：vaultcmd.exe（系统自带）
- 要求：本地管理员权限或普通用户权限（视凭据访问权限而定）、启用Windows安全日志或Sysmon
- 域环境：lab.local（可选）

**测试准备**：
1. 确保系统启用了Credential Manager（默认启用）。
2. 启用Windows安全日志审计（组策略：计算机配置>策略>Windows设置>安全设置>本地策略>审核策略>进程跟踪）。
3. 安装Sysmon（可选，增强进程监控）。
4. 保存测试用凭据（如浏览器保存的Web凭据）。

**测试步骤**：
1. **列出所有凭据保管库**：
   ```cmd
   vaultcmd/list
   ```
   预期输出：
   ```
   Currentlyavailablecredentialvaults:
   Vault:WebCredentials
     VaultGUID:{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}
   Vault:WindowsCredentials
     VaultGUID:{77BC582B-0E2E-4F8E-B8A6-3F4A5B6C7D8E}
   ```
2. **列出保管库概要和GUID**：
   ```cmd
   vaultcmd/listschema
   ```
   预期输出：
   ```
   Vault schema:
   Name: Web Credentials
    GUID: {4BF4C442-9B8A-41A0-B380-DD4A704DDB28}
   Name: Windows Credentials
    GUID: {77BC582B-0E2E-4F8E-B8A6-3F4A5B6C7D8E}
   ```
3. **列出“WebCredentials”保管库的凭据**：
   ```cmd
   vaultcmd /listcreds:"WebCredentials"
   ```
   或（中文系统，使用GUID）：
   ```cmd
   vaultcmd /listcreds:{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}
   ```
   预期输出：
   ```
   Credential:https://example.com
   ResourceName:example.com
   UserName:testuser
   LastModified:2025-06-17 10:30:00 AM
   ```
4. **列出保管库属性**：
   ```cmd
   vaultcmd /listproperties:{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}
   ```
   预期输出：
   ```
   Vaultproperties:
     VaultGUID:{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}
     Location:C:\Users\testuser\AppData\Local\Microsoft\Vault\{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}
     CredentialCount:1
     ProtectionMethod:DPAPI
   ```

**参考资源**：
- WindowsCredentialManager信息获取：<https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-Windows%E4%B8%ADCredential-Manager%E7%9A%84%E4%BF%A1%E6%81%AF%E8%8E%B7%E5%8F%96/>
- MITREATT&CKT1003：<https://attack.mitre.org/techniques/T1003/>

## 检测日志

**数据来源**：
- **Windows安全日志**：
  - 事件ID4688：新进程创建（vaultcmd.exe）
- **Sysmon日志**（推荐）：
  - 事件ID1：进程创建（vaultcmd.exe）
  - 事件ID3：网络连接（若凭据涉及远程服务）
- **PowerShell日志**（可选）：
  - 事件ID4103/4104：若通过PowerShell调用vaultcmd
- **文件访问日志**：
  - 监控`%localappdata%\Microsoft\Vault\`路径的文件访问（需启用对象访问审计）。

**关键日志字段**：
- 事件ID4688/1：
  - `ProcessName`：C:\Windows\System32\VaultCmd.exe
  - `CommandLine`：包含`/list`、`/listschema`、`/listcreds`、`/listproperties`
  - `ParentProcessName`：C:\Windows\System32\cmd.exe
- 事件ID3（Sysmon）：
  - `DestinationPort`：可能涉及Web服务端口（如80、443）

## 测试复现

**环境配置**：
- 系统：Windows10
- 工具：vaultcmd.exe
- 用户：testuser（普通用户或管理员）
- 凭据：保存Web凭据（如浏览器登录example.com）

**复现步骤**：
1. 打开CMD（以testuser身份）：
   ```cmd
   C:\Users\testuser>vaultcmd /list
   ```
   输出：
   ```
   Currentlyavailablecredentialvaults:
   Vault:WebCredentials
     VaultGUID:{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}
   ```
2. 查询WebCredentials凭据：
   ```cmd
   C:\Users\testuser>vaultcmd /listcreds:{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}
   ```
   输出：
   ```
   Credential:https://example.com
     ResourceName:example.com
     UserName:testuser
     LastModified:2025-06-17
   ```
3. 查询保管库属性：
   ```cmd
   C:\Users\testuser>vaultcmd /listproperties:{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}
   ```
   输出：
   ```
   Vaultproperties:
     VaultGUID:{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}
     Location:C:\Users\testuser\AppData\Local\Microsoft\Vault\{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}
     CredentialCount:1
     ProtectionMethod:DPAPI
   ```
4. 验证日志：检查事件ID4688（Windows安全日志）或事件ID1（Sysmon）。

## 测试留痕

**Windows安全日志**：
- **事件ID4688**（进程创建）：
  ```xml
  <Event>
    <EventData>
      <DataName="ProcessName">C:\Windows\System32\VaultCmd.exe</Data>
      <DataName="CommandLine">vaultcmd /listcreds:{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}</Data>
      <DataName="ParentProcessName">C:\Windows\System32\cmd.exe</Data>
      <DataName="SubjectUserName">testuser</Data>
    </EventData>
  </Event>
  ```

**Sysmon日志**：
- **事件ID1**（进程创建）：
  ```xml
  <Event>
    <EventData>
      <DataName="Image">C:\Windows\System32\VaultCmd.exe</Data>
      <DataName="CommandLine">vaultcmd /listcreds:{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}</Data>
      <DataName="ParentImage">C:\Windows\System32\cmd.exe</Data>
      <DataName="User">LAB\testuser</Data>
    </EventData>
  </Event>
  ```

**文件访问日志**（需启用对象访问审计）：
- 访问路径：`C:\Users\testuser\AppData\Local\Microsoft\Vault\{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}`

**注意**：`vaultcmd`本身不直接提取明文密码，日志仅记录查询行为。若攻击者结合Mimikatz提取明文，需监控Mimikatz相关进程（参考T1003.001）。

## 检测规则/思路

### Sigma规则

**规则一：检测vaultcmd凭据查询行为**：
```yaml
title: VaultCmd凭据查询检测
id: h8c9d0e1-2f3g-4h9i-cj4d-1e2f3g4h5i6j
status: stable
description: 检测使用vaultcmd.exe查询Windows Credential Manager凭据的行为
references:
  -https://attack.mitre.org/techniques/T1003/
  -https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-Windows%E4%B8%ADCredential-Manager%E7%9A%84%E4%BF%A1%E6%81%AF%E8%8E%B7%E5%8F%96/
tags:
  -attack.credential_access
  -attack.t1003
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID|in:
      -4688
      -1
    Image|endswith: '\VaultCmd.exe'
    CommandLine|contains:
      -'/list'
      -'/listschema'
      -'/listcreds'
      -'/listproperties'
  condition: selection
fields:
  -ComputerName
  -User
  -Image
  -CommandLine
falsepositives:
  -管理员合法查询CredentialManager
  -系统维护脚本调用vaultcmd
level: medium
```

**规则优化说明**：
- 聚焦`vaultcmd.exe`的典型命令行参数（`/list`、`/listschema`、`/listcreds`、`/listproperties`）。
- 支持Windows安全日志（4688）和Sysmon（1），提高覆盖率。
- 排除合法管理员操作，降低误报。

### 检测思路

1. **日志监控**：
   - 监控事件ID4688/1，检测`vaultcmd.exe`进程创建及命令行参数。
   - 检查`ParentProcessName`，关注非预期父进程（如cmd.exe而非管理工具）。

2. **行为分析**：
   - 检测非管理员用户运行`vaultcmd`的异常行为。
   - 监控短时间内多次`vaultcmd`执行，可能是自动化脚本。

3. **文件监控**：
   - 启用对象访问审计，监控`%localappdata%\Microsoft\Vault\`路径的访问。
   - 检查异常进程（如非系统进程）访问Vault文件。

4. **关联分析**：
   - 结合事件ID4624（登录成功），检测`vaultcmd`执行后的异常登录行为。
   - 若发现`mimikatz.exe`或其他凭据提取工具，关联分析以确认明文凭据提取。

5. **Sysmon增强**：
   - 使用事件ID1监控`vaultcmd.exe`进程。
   - 事件ID11监控Vault文件夹的文件操作。

## 防御建议

1. **权限管理**：
   - 限制普通用户对CredentialManager的访问权限。
   - 使用组策略禁用非必要用户对`%localappdata%\Microsoft\Vault\`的写权限。

2. **日志与监控**：
   - 启用事件ID4688（进程创建）和对象访问审计，监控`vaultcmd.exe`和Vault文件夹。
   - 部署Sysmon，记录事件ID1（进程创建）和11（文件操作）。
   - 使用SIEM（如Splunk）关联`vaultcmd`执行和异常登录行为。

3. **凭据保护**：
   - 启用DPAPI增强保护，防止凭据被轻易解密。
   - 定期清理不必要的保存凭据（如浏览器Web凭据）。

4. **工具限制**：
   - 使用AppLocker或WDAC限制`vaultcmd.exe`的非管理员执行。
   - 监控Mimikatz等工具，防止结合`vaultcmd`提取明文凭据。

5. **主动防御**：
   - 部署诱捕凭据（HoneyCredentials），监控异常访问。
   - 使用EDR工具检测`vaultcmd.exe`和可疑父进程（如cmd.exe）。

## 参考推荐

- MITREATT&CK:CredentialDumping(T1003)  
  <https://attack.mitre.org/techniques/T1003/>
- WindowsCredentialManager信息获取  
  <https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-Windows%E4%B8%ADCredential-Manager%E7%9A%84%E4%BF%A1%E6%81%AF%E8%8E%B7%E5%8F%96/>
- WindowsVault命令参考  
  <https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/vaultcmd>