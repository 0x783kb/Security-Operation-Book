# T1014-Win-Rootkit

## 描述

攻击者可能利用rootkit隐藏程序、文件、网络连接、服务、驱动程序及其他系统组件的存在。Rootkit通过拦截、钩挂和修改操作系统API调用来隐藏恶意软件的存在，从而规避系统信息的正常报告。Rootkit可能运行于操作系统的用户层或内核层，甚至更低层次，如管理程序、主引导记录（MBR）或系统固件。在Windows、Linux和Mac OS X系统中均已发现rootkit的踪迹。

## 测试案例

### 测试1：Windows签名驱动程序Rootkit测试

此测试利用已签名的驱动程序（如`capcom.sys`）在内核中执行代码，模拟rootkit行为以隐藏进程。测试工具为`puppetstrings.exe`，结合易受攻击的签名驱动程序`capcom.sys`（SHA1: C1D5CF8C43E7679B782630E93F5E6420CA1749A7）。PoC漏洞利用程序的哈希值为SHA1: DD8DA630C00953B6D5182AA66AF999B1E117F441。

**攻击命令**（需以管理员权限在命令提示符中运行）：
```batch
#{puppetstrings_path} #{driver_path}
```

- `driver_path`: `C:\Drivers\driver.sys`
- `puppetstrings_path`: `PathToAtomicsFolder\T1014\bin\puppetstrings.exe`

**依赖性检查**（使用PowerShell运行）：
```powershell
if (Test-Path #{puppetstrings_path}) {exit 0} else {exit 1}
```

**获取依赖性**（使用PowerShell下载`puppetstrings.exe`）：
```powershell
Invoke-WebRequest "https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1014/bin/puppetstrings.exe" -OutFile "#{puppetstrings_path}"
```

## 检测日志

本地复现测试表明，Windows安全日志、PowerShell操作日志未记录相关行为，但Sysmon日志可捕获部分活动（详见“日志留痕”）。

## 测试复现

### 测试1：Windows签名驱动程序Rootkit测试

以下为在Windows Server 2019环境中的复现尝试：

```powershell
PS C:\Windows\system32> C:\Users\zhuli\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1014\bin\puppetstrings.exe C:\Drivers\driver.sys
Look for process in tasklist.exe
请按任意键继续. . .
puppetstrings failed - error: 00000003
请按任意键继续. . .
```

**复现结果**：
- 测试未成功，错误代码`00000003`可能表明驱动程序加载失败或环境配置问题。
- 建议在测试环境中验证`capcom.sys`驱动的兼容性，并确保驱动文件存在于指定路径。

## 日志留痕

### Sysmon日志（Event ID 1：进程创建）

以下为Sysmon记录的`puppetstrings.exe`执行行为：

```xml
日志名称: Microsoft-Windows-Sysmon/Operational
来源: Microsoft-Windows-Sysmon
日期: 2022/1/10 14:58:52
事件 ID: 1
任务类别: Process Create (rule: ProcessCreate)
级别: 信息
关键字:
用户: SYSTEM
计算机: zhuli.qax.com
描述:
Process Create:
RuleName: technique_id=T1086,technique_name=PowerShell
UtcTime: 2022-01-10 06:58:52.494
ProcessGuid: {78c84c47-d92c-61db-450c-000000000800}
ProcessId: 7608
Image: C:\Users\zhuli\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1014\bin\puppetstrings.exe
FileVersion: -
Description: -
Product: -
Company: -
OriginalFileName: -
CommandLine: "C:\Users\zhuli\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1014\bin\puppetstrings.exe" C:\Drivers\driver.sys
CurrentDirectory: C:\Windows\system32\
User: QAX\Administrator
LogonGuid: {78c84c47-d270-61db-d56a-010100000000}
LogonId: 0x1016AD5
TerminalSessionId: 1
IntegrityLevel: High
Hashes: SHA1=DD8DA630C00953B6D5182AA66AF999B1E117F441,MD5=676ED2C5D31006FC4CBC1B0E0D564F4F,SHA256=1184228AC822F0F8C7C8242325052F91B500AD7C08E4A9B266211E8E623CAE8E,IMPHASH=1B1B5BBC1BB70593CD761304457481AC
ParentProcessGuid: {78c84c47-d270-61db-4a0b-000000000800}
ParentProcessId: 4560
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentCommandLine: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
ParentUser: QAX\Administrator
```

**分析**：
- Sysmon记录了`puppetstrings.exe`的进程创建事件，包括命令行参数和文件哈希。
- 未记录驱动程序加载或内核级操作的详细行为，可能需额外配置Sysmon或使用其他工具（如驱动监控）。

## 检测规则/思路

### Sigma规则

```yaml
title: Suspicious Signed Driver Rootkit Activity
description: Detects execution of processes associated with signed driver rootkits, such as those using puppetstrings.exe or similar tools.
references:
  - https://attack.mitre.org/techniques/T1014/
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image|endswith: '\puppetstrings.exe'
  condition: selection
fields:
  - Image
  - CommandLine
  - User
  - Hashes
falsepositives:
  - Legitimate use of signed drivers for system maintenance
level: high
```

**规则说明**：
- 检测运行`puppetstrings.exe`的进程创建事件，可能指示rootkit相关活动。
- 需结合环境测试，调整误报过滤条件（如排除合法驱动程序维护工具）。

### 建议

1. **部署反rootkit工具**：
   - 使用专用rootkit检测工具（如GMER、RootkitRevealer）扫描系统，识别异常的内核模块或API钩子。
   - 定期运行反病毒软件，检查是否存在已知rootkit行为。

2. **监控驱动程序加载**：
   - 配置Sysmon记录驱动程序加载事件（Event ID 6），关注非标准路径或未签名驱动的加载。
   - 使用Windows事件日志监控`Microsoft-Windows-Kernel-PnP`通道，检测新驱动安装。

3. **检查系统完整性**：
   - 定期验证主引导记录（MBR）、系统固件和内核模块的完整性。
   - 监控未识别的DLL、设备或服务的注册行为。

4. **增强Sysmon配置**：
   - 启用Sysmon的驱动程序加载（Event ID 6）和模块加载（Event ID 7）记录。
   - 关注高权限进程（如SYSTEM或Administrator）加载的异常驱动或模块。

5. **部署SIEM系统**：
   - 使用SIEM工具（如Splunk、Elastic）分析Sysmon和内核事件日志，检测rootkit相关行为。
   - 设置告警规则，针对非标准驱动加载或`puppetstrings.exe`等工具的执行。

6. **限制驱动程序安装**：
   - 使用组策略限制非管理员账户安装驱动程序。
   - 启用Windows驱动签名验证，防止加载未签名驱动。

## 参考推荐

- MITRE ATT&CK T1014  
  <https://attack.mitre.org/techniques/T1014>
- Atomic Red Team T1014  
  <https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1014>
- Fuzzy Security Rootkit Tutorial  
  <http://www.fuzzysecurity.com/tutorials/28.html>
- Puppet Strings Rootkit PoC  
  <https://zerosum0x0.blogspot.com/2017/07/puppet-strings-dirty-secret-for-free.html>
