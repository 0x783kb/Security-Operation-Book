# T1505-003-Web服务关联可疑进程识别WebShell行为

## 描述

攻击者可能通过在可公开访问的Web服务器上部署Web Shell实现持久化访问（T1505.003）。Web Shell是运行在Web服务器上的恶意脚本（如PHP、ASP、JSP），提供命令执行、文件操作或网络通信功能，允许攻击者通过HTTP/HTTPS协议控制目标系统。Web Shell可伪装为合法Web内容，具有高隐蔽性，常用于信息收集、权限提升或内网横向移动。

Web Shell可能通过服务器端脚本（如[China Chopper](https://attack.mitre.org/software/S0020)）或客户端工具与Web服务器交互。攻击者利用Web Shell执行系统命令（如`whoami`、`ipconfig`）或启动可疑进程（如`cmd.exe`、`powershell.exe`），这些行为在Web服务器进程（如`w3wp.exe`、`httpd.exe`）的子进程中表现明显。检测重点在于识别Web服务器进程衍生的异常子进程（如脚本解释器或管理工具）及其命令行参数。

## 测试案例

1. **Web Shell执行信息收集命令**  
   攻击者通过Web Shell运行`whoami`、`ipconfig`或`net user`等命令，收集系统信息。  
2. **Web Shell启动可疑进程**  
   攻击者通过Web Shell启动`powershell.exe`或`bitsadmin.exe`，下载或执行恶意负载。  
3. **伪装合法Web应用**  
   攻击者将Web Shell嵌入合法Web页面（如`login.php`），执行隐蔽命令。  

## 检测日志

**Windows日志**  
- **Windows安全日志**：  
  - **事件ID 4688**：记录进程创建，包含父进程（如`w3wp.exe`）和子进程（如`cmd.exe`）的命令行参数。  
- **Sysmon日志**：  
  - **事件ID 1**：记录进程创建，包含详细的父/子进程信息和命令行参数。  
  - **事件ID 3**：记录网络连接，检测Web Shell发起的C2通信。  
  - **事件ID 11**：记录文件创建，检测Web Shell文件的写入。  
- **EDR产品日志**：记录进程树、命令行参数和网络活动。

**Linux日志**  
- **Syslog**：记录Web服务器进程（如`httpd`、`nginx`）的活动。  
- **Auditd日志**：记录进程创建（如`bash`、`sh`）和文件操作。  
- **Web服务器日志**：记录HTTP请求（如`access.log`），可能包含Web Shell的URL调用。  

**配置日志记录**  
- Windows：  
  - 启用进程创建审核：`计算机配置 > 策略 > Windows设置 > 安全设置 > 高级审核策略配置 > 详细跟踪 > 审核进程创建`。  
  - 启用命令行参数记录：`计算机配置 > 管理模板 > 系统 > 审核进程创建 > 在进程创建事件中加入命令行 > 启用`。  
  - 部署Sysmon以增强进程、网络和文件监控。  
- Linux：  
  - 启用`auditd`：配置规则监控`execve`系统调用和文件操作。  
  - 启用Web服务器详细日志：记录完整的URL和HTTP头。  

## 测试复现

### 环境准备
- **靶机**：Windows Server（IIS/Apache）或Linux（Apache/Nginx），运行Web服务。  
- **权限**：Web服务器用户权限（如`www-data`或`NETWORK SERVICE`）。  
- **工具**：测试用Web Shell（如`simple-backdoor.php`）、Sysmon（Windows）、`auditd`（Linux）。  
- **日志**：启用Windows安全日志、Sysmon、Web服务器日志和Linux审计日志。

### 攻击步骤
1. **部署Web Shell**  
   - 上传Web Shell到Web服务器（如`/var/www/html/shell.php`或`C:\inetpub\wwwroot\shell.aspx`）。  
     ```php
     <?php
     system($_GET['cmd']);
     ?>
     ```

2. **执行命令**  
   - 通过浏览器或`curl`访问Web Shell，执行命令：
     ```bash
     curl "http://<web_server>/shell.php?cmd=whoami"
     curl "http://<web_server>/shell.php?cmd=powershell%20-c%20Get-Process"
     ```

3. **触发可疑进程**  
   - 使用Web Shell启动`cmd.exe`或`powershell.exe`：
     ```bash
     curl "http://<web_server>/shell.php?cmd=net%20user"
     ```

4. **验证结果**  
   - 检查Web服务器日志：
     ```bash
     cat /var/log/apache2/access.log | grep "shell.php"
     ```
   - 检查Windows日志（事件ID 4688/Sysmon事件ID 1）：
     ```powershell
     Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4688 -and $_.Message -match "cmd.exe|powershell.exe" }
     ```
   - 检查Linux审计日志：
     ```bash
     ausearch -ts today -m execve | grep "httpd|nginx"
     ```

5. **清理（测试后）**  
   - 删除Web Shell：
     ```bash
     rm /var/www/html/shell.php
     ```
   - 重启Web服务：
     ```bash
     systemctl restart apache2
     ```

**注意**：此复现仅用于学习和测试目的，需在合法授权的测试环境中进行，切勿用于非法活动。

## 测试留痕

### Windows日志
- **Windows安全日志（事件ID 4688）**：
  ```xml
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" />
      <EventID>4688</EventID>
      <Version>2</Version>
      <Level>0</Level>
      <Task>13312</Task>
      <Opcode>0</Opcode>
      <Keywords>0x8020000000000000</Keywords>
      <TimeCreated SystemTime="2015-11-12T02:24:52.377352500Z" />
      <EventRecordID>2814</EventRecordID>
      <Correlation />
      <Execution ProcessID="4" ThreadID="400" />
      <Channel>Security</Channel>
      <Computer>WIN-GG82ULGC9GO.contoso.local</Computer>
      <Security />
    </System>
    <EventData>
      <Data Name="SubjectUserSid">S-1-5-18</Data>
      <Data Name="SubjectUserName">WIN-GG82ULGC9GO$</Data>
      <Data Name="SubjectDomainName">CONTOSO</Data>
      <Data Name="SubjectLogonId">0x3e7</Data>
      <Data Name="NewProcessId">0x2bc</Data>
      <Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>
      <Data Name="TokenElevationType">%%1938</Data>
      <Data Name="ProcessId">0xe74</Data>
      <Data Name="CommandLine">cmd.exe /c whoami</Data>
      <Data Name="ParentProcessName">C:\Windows\System32\w3wp.exe</Data>
      <Data Name="MandatoryLabel">S-1-16-8192</Data>
    </EventData>
  </Event>
  ```

- **Sysmon日志（事件ID 1）**：
  ```plaintext
  EventID: 1
  UtcTime: 2025-06-10 02:30:00.123
  ProcessGuid: {12345678-abcd-1234-abcd-1234567890ab}
  ProcessId: 1234
  Image: C:\Windows\System32\cmd.exe
  CommandLine: cmd.exe /c whoami
  ParentImage: C:\Windows\System32\w3wp.exe
  ParentProcessId: 5678
  User: NT AUTHORITY\NETWORK SERVICE
  IntegrityLevel: Medium
  ```

### Linux日志
- **Auditd日志**：
  ```plaintext
  type=EXECVE msg=audit(1623379200.123:456): argc=2 a0="bash" a1="-c whoami"
  type=SYSCALL msg=audit(1623379200.123:456): arch=c000003e syscall=59 success=yes exit=0 ppid=1234 pid=5678 uid=33 gid=33 euid=33 egid=33 comm="bash" exe="/bin/bash"
  type=PATH msg=audit(1623379200.123:456): name="/bin/bash" dev=sda1 inode=123456
  type=PROCTITLE msg=audit(1623379200.123:456): proctitle="httpd"
  ```
- **Apache访问日志**：
  ```plaintext
  192.168.1.100 - - [10/Jun/2025:02:30:00 +0000] "GET /shell.php?cmd=whoami HTTP/1.1" 200 1234
  ```

## 检测规则/思路

**检测规则**  
通过分析Windows/Linux日志，检测Web服务器进程衍生的异常子进程（如`cmd.exe`、`bash`）及其命令行参数。以下是具体思路：

1. **日志分析**：
   - **Windows**：  
     - 监控事件ID 4688或Sysmon事件ID 1，检测Web服务器进程（如`w3wp.exe`、`httpd.exe`）衍生的子进程（如`cmd.exe`、`powershell.exe`）。  
     - 检查命令行参数，识别信息收集命令（如`whoami`、`ipconfig`）或管理命令（如`net user`）。  
     - 监控Sysmon事件ID 3，检测子进程的网络连接。  
     - 监控Sysmon事件ID 11，检测Web Shell文件写入。  
   - **Linux**：  
     - 监控`auditd`日志，检测Web服务器进程（如`httpd`、`nginx`）执行的`execve`调用（如`bash`）。  
     - 检查Web服务器日志，识别异常HTTP请求（如`GET /shell.php?cmd=`）。  

2. **Sigma规则（Windows Web Shell进程）**：
   ```yaml
   title: Web服务器衍生可疑进程
   id: z12345678-abcd901234-abc567890123
   status: stable
   description: 检测Web服务器进程衍生的可疑子进程，可能表明Web Shell活动
   references:
     - https://attack.mitre.org/techniques/T1505/003/
     - https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries
   tags:
     - attack.persistence
     - attack.t1505.003
     - attack.t1190
   logsource:
     category: process_creation
     product: windows
   detection:
     selection:
       ParentImage|endswith:
         - '\w3wp.exe'
         - '\httpd.exe'
         - '\nginx.exe'
         - '\php-cgi.exe'
         - '\tomcat.exe'
       Image|endswith:
         - '\cmd.exe'
         - '\powershell.exe'
         - '\bitsadmin.exe'
         - '\cscript.exe'
         - '\wscript.exe'
         - '\net.exe'
         - '\net1.exe'
         - '\ping.exe'
         - '\whoami.exe'
         - '\ipconfig.exe'
     condition: selection
   fields:
     - Image
     - ParentImage
     - CommandLine
     - ParentCommandLine
   falsepositives:
     - 合法Web应用调用系统命令（如ipconfig、whoami）
   level: high
   ```

3. **Sigma规则（Linux Web Shell进程）**：
   ```yaml
   title: Linux Web服务器衍生可疑Shell进程
   id: a23456789-abcd012345-bcd678901234
   status: experimental
   description: 检测Linux Web服务器进程衍生的可疑Shell进程，可能表明Web Shell活动
   references:
     - https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_shell_activity_by_web_server.toml
   tags:
     - attack.persistence
     - attack.t1505.003
   logsource:
     category: process_creation
     product: linux
   detection:
     selection:
       process.parent.name|contains:
         - 'httpd'
         - 'nginx'
         - 'apache2'
       process.name:
         - 'bash'
         - 'sh'
         - 'dash'
       user.name:
         - 'apache'
         - 'nginx'
         - 'www-data'
     condition: selection
   fields:
     - process.name
     - process.parent.name
     - process.args
   falsepositives:
     - 合法Web应用调用Shell脚本
   level: high
   ```

4. **SIEM规则**：
   - 检测Web服务器衍生进程。
   - 示例Splunk查询：
     ```spl
     (source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 ParentImage IN ("*w3wp.exe","*httpd.exe","*nginx.exe","*php-cgi.exe","*tomcat.exe") Image IN ("*cmd.exe","*powershell.exe","*net.exe","*whoami.exe")) OR (source="linux:audit" process.parent.name IN ("httpd","nginx","apache2") process.name IN ("bash","sh","dash") user.name IN ("apache","nginx","www-data")) | stats count by Image, ParentImage, CommandLine, ComputerName
     ```

5. **动态调整规则**：
   - 根据环境白名单常见命令（如`ipconfig`在特定Web应用的合法调用）。  
   - 添加更多可疑命令（如`tasklist`、`schtasks`）到规则中。  

6. **威胁情报整合**：
   - 检查Web Shell文件哈希或C2 URL是否与已知恶意样本匹配，结合威胁情报平台（如VirusTotal、AlienVault）。  

## 备注

检测思路基于攻击者通过Web Shell执行系统命令（如信息收集、管理操作）的行为模式。在Windows/Linux环境中，这些行为表现为Web服务器进程（如`w3wp.exe`、`httpd`）衍生异常子进程（如`cmd.exe`、`bash`）。规则需根据具体环境调整，避免误报（如合法Web应用调用`whoami`）。可扩展规则，纳入更多攻击者常用的命令（如`tasklist`、`netstat`）。

## 建议

### 缓解措施

防御Web Shell需从Web服务器安全、进程监控和检测入手：

1. **Web服务器加固**  
   - 定期扫描Web目录，检测未授权文件（如`.php`、`.jsp`）。  
     ```bash
     find /var/www -name "*.php" -exec grep "system(" {} \;
     ```
   - 限制Web目录写权限：
     ```bash
     chmod -R 755 /var/www/html
     chown -R www-data:www-data /var/www/html
     ```

2. **限制脚本执行**  
   - 禁用不必要的脚本引擎（如PHP、ASP）。  
   - 配置WAF拦截异常HTTP请求（如`cmd=`）。  

3. **进程控制**  
   - 使用AppLocker（Windows）或SELinux（Linux）限制Web服务器进程执行可疑二进制文件。  
     ```powershell
     New-AppLockerPolicy -RuleType Path -Path "C:\Windows\System32\cmd.exe" -Action Deny -User "NETWORK SERVICE"
     ```

4. **网络控制**  
   - 限制Web服务器的出站连接，仅允许必要服务：
     ```bash
     iptables -A OUTPUT -p tcp --dport 80,443 -j ACCEPT
     iptables -A OUTPUT -j DROP
     ```

5. **日志和监控**  
   - 启用Sysmon（Windows）或`auditd`（Linux）监控进程创建和命令行参数。  
   - 配置SIEM监控Web服务器衍生进程。  
   - 使用EDR工具检测Web Shell行为。  

## 参考推荐

- MITRE ATT&CK: T1505.003  
  <https://attack.mitre.org/techniques/T1505/003/>  
- Web服务器执行可疑应用程序  
  <https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Execution/Webserver%20Executing%20Suspicious%20Applications.md>  
- Elastic检测规则：Web服务器Shell活动  
  <https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_shell_activity_by_web_server.toml>