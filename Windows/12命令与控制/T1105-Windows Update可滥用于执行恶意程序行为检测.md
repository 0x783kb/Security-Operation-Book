# T1105-Win-入口工具转移-wuauclt.exe(白名单)

## 描述

攻击者可能通过命令和控制通道从外部系统将工具或其他文件转移到被攻陷的环境中，以将恶意工具或有效载荷引入目标网络。文件传输可通过专用工具（如FTP）或替代协议（如scp、rsync、sftp）实现，适用于Windows、Mac和Linux系统。攻击者常利用系统内置的白名单工具（如`wuauclt.exe`）来规避传统防病毒检测或安全机制。

## 测试案例

根据Bleeping Computer报道，MDSec研究人员David Middlehurst发现，攻击者可利用Windows Update客户端`wuauclt.exe`（位于`C:\Windows\System32\wuauclt.exe`）加载特制的DLL文件，从而在Windows 10及以上系统中执行恶意代码。此技术通过`/UpdateDeploymentProvider`和`/RunHandlerComServer`命令行参数实现，可能绕过用户账户控制（UAC）和Windows Defender应用程序控制（WDAC），用于在已受损系统上实现持久化或代码执行。

### 路径
```yml
- C:\Windows\System32\wuauclt.exe
```

### 示例命令
从指定路径加载恶意DLL：
```yml
wuauclt.exe /UpdateDeploymentProvider [path_to_dll] /RunHandlerComServer
```

### 用例
- 加载恶意DLL以执行攻击者控制的代码。
- 所需权限：用户权限（可能需要管理员权限加载特定DLL）。
- 操作系统：Windows 10、Windows 11、Windows Server 2016、Windows Server 2019、Windows Server 2022。

## 检测日志

### Windows安全日志
- **事件ID 4688**：记录`wuauclt.exe`进程创建及命令行参数（需启用命令行审核）。

### Sysmon日志
- **事件ID 1**：捕获`wuauclt.exe`进程创建及命令行参数。
- **事件ID 7**：记录DLL加载事件，检测是否加载了非系统DLL。
- **事件ID 3**：记录可能的网络连接（若DLL发起网络活动）。

### EDR日志
- 其他EDR类产品（如CrowdStrike、Microsoft Defender for Endpoint）可能记录`wuauclt.exe`的异常行为或DLL加载事件。

## 测试复现

### 环境准备
- **靶机**：Windows 10或Windows 11。
- **权限**：用户权限（部分场景可能需要管理员权限）。
- **工具**：
  - `wuauclt.exe`（系统自带，路径`C:\Windows\System32\wuauclt.exe`）。
  - Sysmon（用于进程和DLL加载监控）。
  - 测试DLL（需在合法授权环境中创建模拟恶意DLL）。
- **网络**：视DLL功能，可能涉及网络连接，建议在隔离网络中测试。
- **日志**：启用Windows安全日志、Sysmon日志及EDR监控。

### 攻击步骤
1. **准备恶意DLL**：
   - 创建或获取测试用DLL（需在合法授权环境中模拟）。
2. **执行命令**：
   ```bash
   C:\Windows\System32\wuauclt.exe /UpdateDeploymentProvider C:\path\to\malicious.dll /RunHandlerComServer
   ```
   - 命令加载指定路径的DLL并执行其代码。
3. **验证结果**：
   - 检查DLL是否被加载（通过Sysmon事件ID 7）。
   - 监控后续行为（如网络连接或文件操作）。
4. **清理**：
   - 删除测试DLL，终止相关进程。

**注意**：测试需在合法授权的隔离环境中进行，避免对生产环境或未经授权的系统造成影响。

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
新进程 ID: 0x1f4c
新进程名称: C:\Windows\System32\wuauclt.exe
令牌提升类型: %%1938
强制性标签: Mandatory Label\Medium Mandatory Level
创建者进程 ID: 0x1a30
创建者进程名称: C:\Windows\System32\cmd.exe
进程命令行: wuauclt.exe /UpdateDeploymentProvider C:\path\to\malicious.dll /RunHandlerComServer
```

## 检测方法/思路

### Sigma规则
基于Sigma规则，检测`wuauclt.exe`的异常执行行为：

```yml
title: Windows Update Client Abused Execution
id: a9b8c7d4-2e3f-4c6a-9e8f-4d3b6c7a8e9b
status: experimental
description: Detects code execution via the Windows Update client (wuauclt.exe) with suspicious parameters
author: David Middlehurst, adapted by Grok
date: 2022/04/20
references:
- https://www.nruan.com/75037.html
- https://attack.mitre.org/techniques/T1105
tags:
- attack.command_and_control
- attack.execution
- attack.t1105
- attack.t1218
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\wuauclt.exe'
    CommandLine|contains|all:
      - '/UpdateDeploymentProvider'
      - '/RunHandlerComServer'
  condition: selection
falsepositives:
- Legitimate Windows Update operations (rare with these specific parameters)
level: high
```

### 检测思路
1. **进程监控**：
   - 检查`wuauclt.exe`的命令行参数是否包含`/UpdateDeploymentProvider`和`/RunHandlerComServer`。
   - 监控异常父进程（如`cmd.exe`、`powershell.exe`）。
2. **DLL加载监控**：
   - 使用Sysmon事件ID 7检测`wuauclt.exe`加载的DLL，重点关注非系统路径的DLL。
3. **网络监控**：
   - 检测`wuauclt.exe`或加载的DLL发起的异常网络连接。
4. **行为监控**：
   - 检测`wuauclt.exe`在非Windows Update场景下的运行。
5. **关联分析**：
   - 结合Sysmon事件ID 1（进程创建）、7（DLL加载）和3（网络连接）进行关联，识别完整攻击链。

### 检测建议
- **告警规则**：基于Sigma规则，配置SIEM系统（如Splunk、Elastic）检测`wuauclt.exe`的异常命令行参数和DLL加载。
- **基线对比**：建立`wuauclt.exe`的正常使用基线（通常与Windows Update相关），排除合法行为。
- **DLL白名单**：限制`wuauclt.exe`加载非系统DLL。
- **EDR增强**：使用EDR工具（如Microsoft Defender for Endpoint）监控`wuauclt.exe`的异常行为。

## 缓解措施
1. **限制DLL加载**：
   - 配置Windows Defender应用程序控制（WDAC）限制`wuauclt.exe`加载非受信任DLL。
2. **加强日志监控**：
   - 启用命令行参数记录和Sysmon日志，覆盖进程、DLL加载和网络活动。
3. **白名单管理**：
   - 使用应用白名单工具（如AppLocker）限制`wuauclt.exe`的执行场景。
4. **权限管理**：
   - 限制普通用户运行`wuauclt.exe`加载自定义DLL的能力。
5. **定期审查**：
   - 检查系统内`wuauclt.exe`的异常使用记录，结合威胁情报分析潜在风险。

## 参考推荐
- MITRE ATT&CK T1105  
  https://attack.mitre.org/techniques/T1105  
- Windows Update被发现可滥用于执行恶意程序  
  https://www.nruan.com/75037.html
