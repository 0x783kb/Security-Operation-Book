# T1003-Win-使用Windows任务管理器转储Lsass.exe内存

## 描述

凭据转储（CredentialDumping,MITREATT&CKT1003）是指攻击者从操作系统或软件中提取账户登录名和密码（明文或哈希）以进行横向移动或访问受限资源。Windows系统中，用户登录凭据存储在本地安全机构子系统服务（LSASS）进程内存中。攻击者可通过Windows任务管理器以管理员权限转储`lsass.exe`内存，生成`.dmp`文件，随后使用Mimikatz等工具离线提取凭据。此技术简单且无需额外工具，但需管理员权限，且转储文件可能被安全软件检测。

## 测试案例

**测试环境**：
- 系统：WindowsServer2016/2019或Windows10
- 工具：Windows任务管理器（内置）、Mimikatz（可选，离线分析）
- 要求：本地管理员权限、域环境（可选，lab.local）
- 用户：Administrator（测试账户）
- 日志：Sysmon（推荐，事件ID1、11）、Windows安全日志（可选）

**测试准备**：
1. 确保以管理员身份登录（普通用户需提权）。
2. 安装Sysmon（可选，配置事件ID1：进程创建，11：文件操作）。
3. 启用Windows安全日志审计（组策略：计算机配置>策略>Windows设置>安全设置>本地策略>审核策略>进程跟踪、对象访问）。
4. 下载Mimikatz（<https://github.com/gentilkiwi/mimikatz>）用于离线凭据提取（可选）。
5. 确保系统有活跃用户会话（凭据存储在LSASS）。

**测试步骤**：
1. **打开任务管理器**：
   - 按`Ctrl+Alt+Del`，选择“任务管理器”；或右键任务栏，选择“任务管理器”。
   - 若以管理员运行，点击“详细信息”标签。
2. **显示所有用户进程**：
   - 若`lsass.exe`不可见，点击“显示所有用户的进程”或以管理员身份重新打开任务管理器（右键任务管理器图标>以管理员身份运行）。
3. **转储lsass.exe内存**：
   - 在“进程”标签中找到`lsass.exe`（通常为“本地安全机构进程”）。
   - 右键`lsass.exe`，选择“创建转储文件”。
   - 弹出对话框显示转储文件路径（如`C:\Users\Administrator\AppData\Local\Temp\lsass.DMP`）。
4. **验证转储文件**：
   - 导航到转储文件路径，确认`.dmp`文件存在（大小约50-100MB）。
5. **离线提取凭据**（可选）：
   - 将`.dmp`文件传输到本地分析系统（通过SMB、USB等）。
   - 使用Mimikatz提取凭据：
     ```cmd
     mimikatz.exe"sekurlsa::minidumplsass.DMP""sekurlsa::logonpasswords"exit
     ```
     预期输出：
     ```
     msv:
       *Username:Administrator
       *Domain:LAB
       *NTLM:<NTLMHash>
     wdigest:
       *Username:Administrator
       *Domain:LAB
       *Password:Password123
     ```

**参考资源**：
- LSASS内存转储技术：<https://www.cnblogs.com/zUotTe0/p/14553082.html>
- Mimikatz文档：<https://github.com/gentilkiwi/mimikatz>
- MITREATT&CKT1003：<https://attack.mitre.org/techniques/T1003/>

## 检测日志

**数据来源**：
- **Sysmon日志**（推荐）：
  - 事件ID1：进程创建（taskmgr.exe）
  - 事件ID11：文件操作（lsass.DMP创建）
- **Windows安全日志**：
  - 事件ID4688：新进程创建（taskmgr.exe，可能不记录转储行为）
  - 事件ID4656：文件访问（需启用对象访问审计，捕获lsass.DMP）
- **文件系统日志**：
  - 监控`%localappdata%\Temp\`或`C:\Windows\Temp\`的`.dmp`文件创建（需启用文件审计）。
- **网络流量**（若涉及文件传输）：
  - 捕获`.dmp`文件传输（SMB445/TCP、FTP21/TCP等）。

**关键日志字段**：
- 事件ID1（Sysmon）：
  - `Image`：C:\Windows\System32\taskmgr.exe
  - `ParentImage`：explorer.exe或cmd.exe
- 事件ID11（Sysmon）：
  - `TargetFilename`：C:\Users\*\AppData\Local\Temp\lsass.DMP
  - `Image`：C:\Windows\System32\taskmgr.exe
- 事件ID4688（Windows安全日志）：
  - `ProcessName`：C:\Windows\System32\taskmgr.exe
  - `CommandLine`：（通常为空）

**注意**：Windows安全日志默认不记录`lsass.exe`转储行为，需依赖Sysmon或文件审计增强检测。

## 测试复现

**环境配置**：
- 系统：Windows10
- 工具：任务管理器（内置）
- 用户：Administrator（密码：Password123）
- 日志：Sysmon（事件ID1、11）
- 路径：C:\Users\Administrator\AppData\Local\Temp\

**复现步骤**：
1. 以管理员身份打开任务管理器：
   - 按`Ctrl+Shift+Esc`或右键任务栏>任务管理器。
   - 点击“详细信息”标签。
2. 找到`lsass.exe`：
   - 滚动进程列表，定位“本地安全机构进程”（lsass.exe）。
3. 创建转储文件：
   - 右键`lsass.exe`>“创建转储文件”。
   - 记录转储路径（如`C:\Users\Administrator\AppData\Local\Temp\lsass.DMP`）。
4. 验证转储文件：
   - 打开文件资源管理器，导航到`C:\Users\Administrator\AppData\Local\Temp\`。
   - 确认`lsass.DMP`存在（约50MB）。
5. （可选）离线分析：
   - 传输`lsass.DMP`到本地系统。
   - 使用Mimikatz：
     ```cmd
     C:\Tools\mimikatz>mimikatz.exe"sekurlsa::minidumplsass.DMP""sekurlsa::logonpasswords"exit
     wdigest:
       *Username:Administrator
       *Domain:LAB
       *Password:Password123
     ```
6. 验证日志：检查Sysmon事件ID11（lsass.DMP创建）。

## 测试留痕

**Sysmon日志**：
- **事件ID1**（进程创建，taskmgr.exe）：
  ```xml
  <Event>
    <EventData>
      <DataName="Image">C:\Windows\System32\taskmgr.exe</Data>
      <DataName="CommandLine">C:\Windows\System32\taskmgr.exe</Data>
      <DataName="ParentImage">C:\Windows\explorer.exe</Data>
      <DataName="User">LAB\Administrator</Data>
    </EventData>
  </Event>
  ```
- **事件ID11**（文件创建，lsass.DMP）：
  ```xml
  <Event>
    <EventData>
      <DataName="TargetFilename">C:\Users\Administrator\AppData\Local\Temp\lsass.DMP</Data>
      <DataName="Image">C:\Windows\System32\taskmgr.exe</Data>
      <DataName="User">LAB\Administrator</Data>
    </EventData>
  </Event>
  ```

**Windows安全日志**（若启用对象访问审计）：
- **事件ID4656**（文件访问）：
  ```xml
  <Event>
    <EventData>
      <DataName="ObjectName">C:\Users\Administrator\AppData\Local\Temp\lsass.DMP</Data>
      <DataName="ProcessName">C:\Windows\System32\taskmgr.exe</Data>
      <DataName="SubjectUserName">Administrator</Data>
    </EventData>
  </Event>
  ```

**文件系统**：
- 文件：`C:\Users\Administrator\AppData\Local\Temp\lsass.DMP`（约50-100MB）

**注意**：Windows安全日志默认不记录`lsass.exe`转储的具体行为，Sysmon事件ID11是主要检测点。

## 检测规则/思路

### Sigma规则

**规则一：检测任务管理器创建lsass.DMP文件**：
```yaml
title:任务管理器转储LSASS内存检测
id:k1f2g3h4-5i6j-7k8l-fm7g-4h5i6j7k8l9m
status:stable
description:检测通过Windows任务管理器转储LSASS进程内存的行为
references:
  -https://attack.mitre.org/techniques/T1003/
  -https://www.cnblogs.com/zUotTe0/p/14553082.html
tags:
  -attack.credential_access
  -attack.t1003
logsource:
  category:file_event
  product:windows
detection:
  selection:
    EventID:11
    Image|endswith:'\taskmgr.exe'
    TargetFilename|contains:'lsass.DMP'
  condition:selection
fields:
  -ComputerName
  -User
  -Image
  -TargetFilename
falsepositives:
  -管理员合法调试LSASS进程
  -系统诊断工具生成转储文件
level:high
```

**规则优化说明**：
- 聚焦Sysmon事件ID11，检测`taskmgr.exe`创建`lsass.DMP`文件。
- 限制`TargetFilename`包含`lsass.DMP`，提高检测精准性。
- 考虑合法调试场景，降低误报。

### 检测思路

1. **日志监控**：
   - 监控Sysmon事件ID11，检测`taskmgr.exe`创建`lsass.DMP`文件。
   - 监控事件ID1，捕获`taskmgr.exe`异常启动（非explorer.exe父进程）。

2. **文件监控**：
   - 启用文件审计，监控`%localappdata%\Temp\`和`C:\Windows\Temp\`的`.dmp`文件创建。
   - 检查`lsass.DMP`文件的异常访问或传输。

3. **行为分析**：
   - 检测非管理员用户以管理员权限启动任务管理器。
   - 监控短时间内多次`.dmp`文件生成。

4. **网络监控**：
   - 捕获`.dmp`文件传输流量（SMB445/TCP、FTP21/TCP）。
   - 示例Snort规则：
     ```snort
     alerttcpanyany->any445(msg:"LSASSDMPFileTransfer";content:"lsass.DMP";sid:1000006;)
     ```

5. **关联分析**：
   - 结合事件ID4624（登录成功），检测转储后的异常登录。
   - 监控Mimikatz执行（事件ID1，`mimikatz.exe`）。

## 防御建议

1. **权限管理**：
   - 限制普通用户对`lsass.exe`的访问权限（通过组策略）。
   - 仅允许必要管理员运行任务管理器的高权限操作。

2. **日志与监控**：
   - 部署Sysmon，启用事件ID1（进程创建）、11（文件操作）。
   - 启用对象访问审计，监控`%localappdata%\Temp\lsass.DMP`。
   - 使用SIEM（如Splunk）关联`taskmgr.exe`和`.dmp`文件创建。

3. **凭据保护**：
   - 启用CredentialGuard（Windows10/2016+），防止LSASS存储明文凭据。
   - 禁用WDigest协议（组策略：计算机配置>管理模板>MSSecurityGuide>WDigestAuthentication）。

4. **工具限制**：
   - 使用AppLocker或WDAC限制`taskmgr.exe`的非预期执行。
   - 监控Mimikatz等工具的运行，防止离线凭据提取。

5. **主动防御**：
   - 部署诱捕凭据（HoneyCredentials），监控异常LSASS访问。
   - 使用EDR工具检测`taskmgr.exe`的异常行为或`.dmp`文件生成。

## 参考推荐

- MITREATT&CK:CredentialDumping(T1003)  
  <https://attack.mitre.org/techniques/T1003/>
- LSASS内存转储技术  
  <https://www.cnblogs.com/zUotTe0/p/14553082.html>
- Mimikatz文档  
  <https://github.com/gentilkiwi/mimikatz>
- LSASS凭据提取防御  
  <https://adsecurity.org/?p=1760>
- Windows任务管理器参考  
  <https://docs.microsoft.com/en-us/windows/win32/taskschd/task-manager>