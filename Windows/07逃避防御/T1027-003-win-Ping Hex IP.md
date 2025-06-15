# T1027.003-Win-Ping Hex IP

## 描述

攻击者可能通过加密、编码或其他方式混淆可执行文件或系统中传输的内容，以规避检测和分析。这种行为在多个平台和网络中常见，旨在隐藏恶意活动。

有效载荷可能被压缩、存档或加密，以避免被安全工具检测到。这些有效载荷可能在初始访问阶段或后续活动中使用。某些情况下，用户需要执行特定操作（如打开文件或输入密码）以解码或解密受保护的压缩/加密文件。攻击者还可能使用脚本（如JavaScript）进行混淆。

此外，攻击者可能对文件的部分内容进行编码以隐藏明文字符串，或将有效载荷拆分为多个看似无害的文件，仅在重组后显示恶意功能。命令行界面执行的命令也可能通过环境变量、别名或特定语义进行混淆，以绕过基于签名的检测和白名单机制。

具体到本技术（T1027.003），攻击者可能使用十六进制编码的IP地址执行网络命令（如`ping`），以掩盖真实目标地址，增加检测难度。

## 测试案例

### 测试1：使用十六进制编码的IP地址执行Ping命令

攻击者通过将目标IP地址编码为十六进制格式，执行`ping`命令以探测主机，从而隐藏真实目标地址，规避基于字符串匹配的检测。

**攻击命令**（在命令提示符或PowerShell中运行）：
```cmd
ping 0x7F000001
```

**说明**：
- `0x7F000001`为IP地址`127.0.0.1`的十六进制表示，用于本地回环地址的探测。
- 此技术可用于探测任意IP地址，只需将目标IP转换为十六进制格式。

## 检测日志

- **Windows安全日志**：可能记录`ping.exe`的执行事件（需启用进程创建审核）。
- **Sysmon日志**：通过Sysmon的进程创建事件（Event ID 1）捕获`ping`命令的执行及其参数。

## 测试复现

### 测试1：Ping十六进制IP地址

在Windows Server 2012及以上版本中复现：

```cmd
C:\> ping 0x7F000001

Pinging 127.0.0.1 with 32 bytes of data:
Reply from 127.0.0.1: bytes=32 time<1ms TTL=128
Reply from 127.0.0.1: bytes=32 time<1ms TTL=128
Reply from 127.0.0.1: bytes=32 time<1ms TTL=128
Reply from 127.0.0.1: bytes=32 time<1ms TTL=128

Ping statistics for 127.0.0.1:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 0ms, Average = 0ms
```

![Ping复现](https://i.postimg.cc/SKRFh1KT/1.png)

**说明**：
- 命令成功执行，表明Windows解析了十六进制IP地址`0x7F000001`为`127.0.0.1`并完成探测。
- 输出与直接使用`ping 127.0.0.1`一致，但命令行参数使用了混淆形式。

## 日志留痕

### Sysmon日志（Event ID 1：进程创建）

![Ping日志](https://i.postimg.cc/bNh7JwJ2/ping2.png)

**示例日志**（基于Sysmon Event ID 1）：
```xml
日志名称: Microsoft-Windows-Sysmon/Operational
来源: Microsoft-Windows-Sysmon
日期: 2023/10/01 10:00:00
事件 ID: 1
任务类别: Process Create (rule: ProcessCreate)
级别: 信息
用户: QAX\Administrator
计算机: hostname.qax.com
描述:
Process Create:
RuleName: technique_id=T1027.003,technique_name=Obfuscated Files or Information
UtcTime: 2023-10-01 02:00:00.123
ProcessGuid: {12345678-1234-5678-1234-567890123456}
ProcessId: 1234
Image: C:\Windows\System32\PING.EXE
CommandLine: ping 0x7F000001
CurrentDirectory: C:\Users\Administrator
User: QAX\Administrator
LogonGuid: {12345678-1234-5678-1234-567890123457}
LogonId: 0x123456
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA1=...,MD5=...,SHA256=...
ParentProcessGuid: {12345678-1234-5678-1234-567890123458}
ParentProcessId: 5678
ParentImage: C:\Windows\System32\cmd.exe
ParentCommandLine: cmd.exe
ParentUser: QAX\Administrator
```

**分析**：
- Sysmon记录了`ping.exe`的执行及其命令行参数`0x7F000001`，表明使用了十六进制编码的IP地址。
- 日志未直接解析十六进制IP为标准格式，需结合规则进行检测。

## 检测规则/思路

### Sigma规则

```yaml
title: Ping Hex IP
description: Detects execution of ping commands using hexadecimal-encoded IP addresses, indicating potential obfuscation attempts.
references:
  - https://github.com/Neo23x0/sigma/blob/master/rules/windows/process_creation/win_susp_ping_hex_ip.yml
status: experimental
author: 12306Bro
date: 2023/10/01
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image|endswith: '\ping.exe'
    CommandLine|contains:
      - ' 0x'
  condition: selection
fields:
  - Image
  - CommandLine
  - User
falsepositives:
  - Legitimate use of hexadecimal IP addresses in network diagnostics
level: high
```

**规则说明**：
- 检测`ping.exe`执行时命令行参数包含`0x`的进程创建事件，表明可能使用了十六进制编码的IP地址。
- 规则为实验性，需在实际环境中测试以减少误报（如合法网络诊断工具）。

### 建议

1. **监控命令行参数**：
   - 使用Sysmon（Event ID 1）捕获`ping.exe`的执行，重点检查命令行参数是否包含`0x`等十六进制模式。
   - 扩展检测至其他网络工具（如`tracert`、`netcat`）的类似行为。

2. **启用详细日志**：
   - 配置Sysmon记录进程创建事件，确保包含完整的命令行参数。
   - 启用Windows安全日志的进程跟踪（Event ID 4688），捕获`ping.exe`相关活动。

3. **部署SIEM系统**：
   - 使用SIEM工具（如Splunk、Elastic）分析Sysmon和安全日志，检测十六进制IP地址的异常使用。
   - 设置告警规则，针对短时间内多次执行`ping 0x*`的行为。

4. **解析十六进制IP**：
   - 在SIEM或脚本中加入IP地址解析逻辑，将`0x`格式的IP转换为标准点分十进制格式，便于关联分析。
   - 参考工具：<https://tool.520101.com/wangluo/jinzhizhuanhuan/>

5. **测试与验证**：
   - 在测试环境中模拟十六进制IP的`ping`命令，验证检测规则的有效性。
   - 调整规则阈值，排除合法网络诊断场景的误报。

## 参考推荐

- MITRE ATT&CK T1027.003  
  <https://attack.mitre.org/techniques/T1027/003/>
- Sigma规则：win_susp_ping_hex_ip  
  <https://github.com/Neo23x0/sigma/blob/master/rules/windows/process_creation/win_susp_ping_hex_ip.yml>
- IP地址进制转换工具  
  <https://tool.520101.com/wangluo/jinzhizhuanhuan/>
