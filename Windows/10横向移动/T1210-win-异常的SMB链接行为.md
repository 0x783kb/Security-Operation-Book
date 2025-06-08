# T1210-Win-异常的SMB链接行为

## 描述

攻击者在网络中建立立足点后，可能利用远程服务的漏洞（如服务器消息块协议，SMB）获得对内部系统的未授权访问。T1210技术涉及利用程序、服务或操作系统内核中的编程错误执行恶意代码，以实现横向移动或权限提升。攻击者可能通过网络服务扫描（如端口445的SMB扫描）识别易受攻击的系统，寻找已知漏洞（如EternalBlue）或弱配置。SMB（TCP 445）是Windows文件共享的常见协议，广泛用于访问共享资源（如`C$`、`ADMIN$`）。异常的SMB连接（如用户级进程发起的445端口连接）可能指示端口扫描、漏洞利用或横向移动行为。服务器和端点系统均可能成为目标，尤其是提供访问其他资源的系统。

## 测试案例

### 用例
- **端口扫描**：攻击者使用工具（如Nmap）扫描网络中的SMB服务（TCP 445）。
- **漏洞利用**：利用SMB漏洞（如MS17-010）在目标系统上执行代码。
- **横向移动**：通过SMB访问`IPC$`共享，运行远程命令或上传恶意文件。
- **异常连接**：非系统进程（如`dns.exe`）发起SMB连接，可能表示恶意行为。

### 示例场景
- 攻击者使用自定义工具发起TCP 445连接，尝试访问目标系统的`C$`共享。
- 非内核进程（如`dns.exe`）建立出站SMB连接，可能是恶意软件或横向移动的迹象。

### 路径
- SMB共享路径：
  ```yml
  - \\<target_hostname>\C$
  - \\<target_hostname>\ADMIN$
  - \\<target_hostname>\IPC$
  ```

### 所需权限
- 有效凭据（域或本地账户，访问共享）。
- 无需凭据（某些漏洞利用，如EternalBlue）。
- 网络访问权限（TCP 445）。

### 操作系统
- Windows 7、Windows 8、Windows 8.1、Windows 10、Windows 11、Windows Server 2008、2012、2016、2019、2022。

## 检测日志

### Windows安全日志
- **事件ID 5156**：记录Windows筛选平台（WFP）允许的网络连接（如TCP 445）。
- **事件ID 5140**：记录网络共享访问（如`C$`、`IPC$`）。
- **事件ID 4624**：记录SMB会话的网络登录（Logon Type 3）。
- **事件ID 4688**：记录发起SMB连接的进程创建（需启用命令行审核）。

### Sysmon日志
- **事件ID 3**：记录TCP 445的网络连接（源IP、目标IP、进程）。
- **事件ID 1**：捕获发起SMB连接的进程创建及命令行参数。
- **事件ID 11**：记录共享中文件的创建或修改。

### 网络日志
- 捕获TCP 445端口的Netflow或PCAP数据，记录SMB流量。

## 测试复现

### 环境准备
- **靶机**：Windows Server 2016或Windows 10/11（已启用SMB）。
- **攻击机**：Kali Linux或其他支持SMB测试工具的系统。
- **权限**：有效凭据或无需凭据（漏洞利用）。
- **工具**：
  - Nmap（扫描TCP 445）。
  - Metasploit（SMB漏洞利用，如MS17-010）。
  - `net.exe`（测试SMB共享访问）。
  - Sysmon（监控进程和网络活动）。
  - Wireshark（捕获SMB流量）。
- **网络**：隔离网络环境，允许TCP 445流量。
- **日志**：启用Windows安全日志（事件ID 5156）、Sysmon日志和Netflow日志。

### 攻击步骤
1. **扫描SMB服务**：
   ```bash
   nmap -p 445 192.168.1.100
   ```
   - 确认目标系统开放TCP 445端口。
2. **尝试SMB连接**：
   ```bash
   net use \\192.168.1.100\IPC$ /user:WEIDONG\Administrator Password123
   ```
   - 建立`IPC$`共享连接。
3. **模拟异常进程连接**：
   - 使用自定义脚本（如Python）模拟非系统进程发起SMB连接：
     ```python
     from smb.SMBConnection import SMBConnection
     conn = SMBConnection("Administrator", "Password123", "ATTACKER", "TARGET", domain="WEIDONG")
     conn.connect("192.168.1.100", 445)
     ```
4. **验证结果**：
   - 检查Windows安全日志，确认事件ID 5156（TCP 445连接）。
   - 使用Wireshark捕获TCP 445流量。
   - 验证Sysmon日志是否记录非系统进程（如`python.exe`）的网络连接。
5. **清理**：
   - 断开SMB连接：
     ```bash
     net use \\192.168.1.100\IPC$ /delete
     ```

## 测试留痕
以下为Windows安全日志示例（事件ID 5156，网络连接）：
```yml
EventID: 5156
TimeCreated: 2025-06-08T05:30:23.456Z
Channel: Security
Hostname: TARGET-SRV
ProcessId: 1752
Application: \device\harddiskvolume1\windows\system32\dns.exe
Direction: Outbound
SourceAddress: 10.45.45.103
SourcePort: 50146
DestinationAddress: 10.45.45.104
DestinationPort: 445
Protocol: 6
FilterRunTimeId: 5
LayerName: Connect
LayerRunTimeId: 48
```

以下为Sysmon日志示例（事件ID 3，网络连接）：
```yml
EventID: 3
UtcTime: 2025-06-08T05:30:23.789Z
ProcessGuid: {4a363fee-27c2-623c-decd-3f0000000000}
ProcessId: 1752
Image: C:\Windows\System32\dns.exe
User: NT AUTHORITY\SYSTEM
Protocol: tcp
SourceIp: 10.45.45.103
SourcePort: 50146
DestinationIp: 10.45.45.104
DestinationPort: 445
```

## 检测方法/思路

### Sigma规则
基于Sigma规则，检测异常的SMB连接行为：

```yml
title: Suspicious SMB Connection Behavior
id: a7b8c9d6-9a5b-0c8d-1e2f-8a6b7c8d9e3f
status: experimental
description: Detects abnormal SMB connections on port 445 by non-system processes
references:
- https://attack.mitre.org/techniques/T1210
- https://www.elastic.co/guide/en/siem/guide/current/direct-outbound-smb-connection.html
- https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=5156
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    EventID: 5156
    DestinationPort: 445
  filter:
    DestinationAddress:
      - 127.0.0.1
      - ::1
    ProcessId: 4  # System process
  condition: selection and not filter
falsepositives:
- Legitimate SMB connections by administrative tools
- File sharing or backup processes
level: medium
```

### Elastic Rule Query
```yml
event.action:"Network connection detected (rule: NetworkConnect)" and
destination.port:445 and not process.pid:4 and not
destination.ip:(127.0.0.1 or "::1")
```

### 检测思路
1. **网络连接监控**：
   - 检测TCP 445端口的出站或入站连接，尤其是非系统进程（如`dns.exe`、`python.exe`）发起的连接。
   - 排除本地回环地址（127.0.0.1、::1）和系统进程（PID 4）。
2. **进程监控**：
   - 检测发起SMB连接的异常进程，关注非典型应用（如浏览器、脚本解释器）。
   - 检查事件ID 4688，捕获进程的命令行参数。
3. **共享访问监控**：
   - 检测`C$`、`ADMIN$`或`IPC$`共享的访问（事件ID 5140）。
4. **行为基线**：
   - 建立组织内SMB连接的正常模式，识别异常行为（如夜间连接、未知源IP）。
5. **漏洞扫描检测**：
   - 监控TCP 445的频繁扫描行为，可能指示攻击者寻找易受攻击的系统。

### 检测建议
- **Sysmon配置**：配置Sysmon监控网络连接（事件ID 3）、进程创建（事件ID 1）和共享访问（事件ID 11）。
- **日志配置**：启用Windows安全日志的网络连接审核（事件ID 5156）。
- **EDR监控**：使用EDR工具（如Microsoft Defender for Endpoint）检测异常SMB连接和进程行为。
- **误报过滤**：排除合法文件共享、备份工具或管理员操作，结合上下文（如进程、IP）降低误报率。

## 缓解措施
1. **补丁管理**：
   - 应用SMB相关漏洞补丁（如MS17-010）。
   - 定期更新Windows系统，防止已知漏洞利用。
2. **网络限制**：
   - 配置防火墙阻止未经授权的TCP 445流量。
   - 使用网络分段隔离敏感系统，减少SMB暴露面。
3. **共享访问控制**：
   - 禁用不必要的管理员共享：
     ```bash
     reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f
     ```
   - 限制对`C$`、`ADMIN$`和`IPC$`的访问。
4. **凭据保护**：
   - 启用多因素认证（MFA）保护管理员账户。
   - 限制NTLM认证，优先使用Kerberos。
5. **监控与告警**：
   - 部署IDS/IPS，检测异常SMB流量或扫描行为。
   - 配置SIEM实时告警非系统进程的SMB连接。

## 参考推荐
- MITRE ATT&CK T1210  
  https://attack.mitre.org/techniques/T1210  
- Elastic SMB连接检测  
  https://www.elastic.co/guide/en/siem/guide/current/direct-outbound-smb-connection.html  
- Windows事件ID 5156  
  https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=5156  
- 删除/切换Samba共享连接  
  https://blog.csdn.net/u013038461/article/details/39934061
