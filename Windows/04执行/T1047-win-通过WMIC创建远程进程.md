# T1047-Win-通过WMIC创建远程进程

## 描述

攻击者可能利用Windows Management Instrumentation（WMI）与本地或远程系统交互，执行多种战术功能，如信息收集、远程命令执行或横向移动（T1047）。WMI是Windows管理功能的核心组件，提供统一的环境来访问系统组件，依赖WMI服务（`winmgmt`）以及服务器消息块（SMB，端口445）和远程过程调用（RPC，端口135）进行远程访问。

WMIC（WMI Command-line）是WMI的命令行接口，允许攻击者通过`wmic.exe`执行远程进程创建，例如使用`process call create`命令在目标主机上启动可执行文件或脚本。这种技术常用于横向移动，因为WMIC是Windows内置工具，属于白名单进程，难以被传统安全工具检测。攻击者可能通过构造类似`wmic.exe /node:"<hostname>" process call create "<command>"`的命令，远程执行恶意Payload。

## 测试案例

1. **远程执行恶意可执行文件**  
   攻击者使用WMIC在远程主机上启动恶意可执行文件（如`malware.exe`），实现横向移动。

2. **运行恶意脚本**  
   攻击者通过WMIC远程调用PowerShell脚本，执行恶意操作，如下载Payload或建立反弹Shell。


## 检测日志

**Windows安全日志**  
- **事件ID 4688**：记录进程创建，包含WMIC的命令行参数、父进程和子进程信息。
- **事件ID 4624/4625**：记录远程登录成功或失败，可能涉及WMI使用的凭据。
  
**Sysmon日志**  
- **事件ID 1**：记录进程创建，包含WMIC的完整命令行和父进程信息。
- **事件ID 3**：记录网络连接，可能涉及WMI的SMB或RPC流量。
- **事件ID 7**：记录模块加载，可能涉及加载恶意DLL。

**网络日志**  
- 记录SMB（端口445）或RPC（端口135）的异常流量，表明WMI远程访问。

**配置日志记录**  
- 启用命令行参数记录：`本地计算机策略 > 计算机配置 > 管理模板 > 系统 > 审核进程创建 > 在进程创建事件中加入命令行 > 启用`。
- 部署Sysmon以增强进程和网络活动监控。

## 测试复现

源主机执行：wmic.exe /node:"\<hostname\>" process

![test](https://s2.ax1x.com/2019/12/10/QDncB4.png)

## 测试留痕

事件ID，进程命令行参数，进程名称

## 检测规则/思路

**检测规则**  
通过分析Sysmon和Windows安全日志，检测WMIC远程创建进程的异常行为。以下是具体思路：

1. **日志分析**：
   - 收集Sysmon事件ID 1或Windows安全事件ID 4688，提取WMIC进程（`wmic.exe`）的命令行参数。
   - 检测包含`/node`和`process call create`的命令，表明远程进程创建。

2. **Sigma规则**：
   ```yaml
   title: 通过WMIC创建远程进程
   id: 6a7b8c9d-4f2a-4b1c-a9e5-1f2e3c4d5e6f
   status: stable
   description: 检测WMIC通过远程进程创建执行命令，可能表明横向移动
   author: 12306Bro
   date: 2025/06/06
   logsource:
     category: process_creation
     product: windows
   detection:
     selection:
       EventID: 4688 # 进程创建
       Image|endswith: '\wmic.exe'
       CommandLine|contains:
         - '/node:'
         - 'process call create'
     condition: selection
   falsepositives:
     - 合法的WMI管理脚本
     - 管理员运行的远程维护任务
   level: medium
   ```

3. **SIEM规则**：
   - 检测WMIC的远程进程创建行为。
   - 示例Splunk查询：
     ```spl
     source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\wmic.exe" CommandLine="*/node:*process call create*" | stats count by Image, CommandLine, ComputerName, User
     ```

4. **网络流量分析**：
   - 监控SMB（端口445）和RPC（端口135）的异常流量，检测WMI远程连接。
   - 示例Wireshark过滤器：
     ```plaintext
     tcp.port == 445 or tcp.port == 135 and ip.src == <attacker_ip>
     ```

5. **威胁情报整合**：
   - 检查WMIC命令的目标主机或命令行参数是否涉及已知恶意IP/文件，结合威胁情报平台（如VirusTotal、AlienVault）。

## 建议

### 缓解措施

防御WMIC远程进程创建需从访问控制、权限管理和监控入手：

1. **限制WMI访问**  
   - 配置防火墙，限制SMB（端口445）和RPC（端口135）的外部访问，仅允许白名单IP。  
   - 禁用WMI服务（`winmgmt`）或限制其远程访问，除非必要。

2. **应用程序白名单**  
   - 使用AppLocker或类似工具，限制非授权用户运行`wmic.exe`。  

3. **凭据保护**  
   - 启用多因素认证（MFA），降低凭据被盗导致的WMI远程访问风险。  
   - 使用强密码策略，避免弱密码或密码重用。

4. **日志和监控**  
   - 启用命令行参数记录，增强Windows安全日志（事件ID 4688）或Sysmon（事件ID 1）监控。  
   - 配置SIEM检测WMIC的`/node`和`process call create`命令。

### 检测

检测工作应集中在WMIC的远程进程创建行为上，包括但不限于：  
- **进程行为监控**：分析Sysmon或Windows安全日志，检测WMIC的`/node`和`process call create`命令。  
- **网络流量分析**：监控SMB和RPC端口的异常连接，识别WMI远程访问。  
- **行为分析**：通过EDR检测WMIC执行后的异常活动（如启动恶意进程）。  
- **威胁情报整合**：结合威胁情报，检查目标主机或命令行参数是否与已知恶意活动相关。

## 参考推荐

- MITRE ATT&CK: T1047  
  <https://attack.mitre.org/techniques/T1047/>  
- CAR-2016-03-002: 通过WMIC创建远程进程  
  <https://car.mitre.org/analytics/CAR-2016-03-002/>  
- WMIC命令收集与整理  
  <https://blog.csdn.net/qq_20307987/article/details/7322203>  
- WMIC内网使用  
  <https://www.cnblogs.com/0xdd/p/11393392.html>
