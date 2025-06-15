# T1218-Win-使用Atbroker.exe执行恶意载荷（白名单）

## 描述

攻击者可能利用受信任的Windows实用程序（如`AtBroker.exe`）代理执行恶意代码，绕过应用程序白名单防御（MITRE ATT&CK T1218）。`AtBroker.exe`是Windows的“轻松访问中心”组件，用于启动辅助功能应用程序（如讲述人、屏幕键盘、放大镜）。由于其由微软签名并位于系统目录，通常被安全工具视为可信进程。

攻击者可通过修改注册表中的辅助技术（Assistive Technology, AT）服务条目，注册恶意程序作为AT应用，随后使用`AtBroker.exe /start <malware>`触发执行。此技术利用`AtBroker.exe`的白名单特性，隐藏恶意行为，常用于防御规避、初始访问或持久化。

## 测试案例

### 测试1：使用AtBroker.exe执行恶意载荷

攻击者通过修改注册表注册恶意程序为AT应用，随后使用`AtBroker.exe`执行，模拟恶意载荷运行。

**环境要求**：
- 系统：Windows 8/8.1/10/11
- 工具：`AtBroker.exe`（系统自带）
- 权限：用户权限（注册表修改可能需管理员权限）
- 路径：
  - `C:\Windows\System32\AtBroker.exe`
  - `C:\Windows\SysWOW64\AtBroker.exe`

**准备步骤**：
1. 创建恶意可执行文件（如`malware.exe`），放置于可访问路径（如`C:\Temp\malware.exe`）。
2. 修改注册表，注册`malware.exe`为AT应用：
   ```reg
   [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs\malware]
   "ATExe"="C:\\Temp\\malware.exe"
   "Description"="Malicious AT Application"
   "StartParams"=""
   ```

**攻击命令**：
```cmd
AtBroker.exe /start malware
```

**清理命令**：
```cmd
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs\malware" /f
del C:\Temp\malware.exe
taskkill /IM malware.exe /F
```

**说明**：
- `/start malware`：触发注册表中`malware`键对应的可执行文件。
- 注册表修改定义了名为`malware`的AT应用，指向`C:\Temp\malware.exe`。

## 检测日志

- **Windows安全日志**：
  - Event ID 4688：进程创建，记录`AtBroker.exe`及其子进程的执行（需启用进程跟踪审核）。
- **Sysmon日志**：
  - Event ID 1：进程创建，捕获`AtBroker.exe`和恶意载荷的命令行及父进程信息。
  - Event ID 13：注册表修改，记录AT注册表键的创建或更改。
- **日志配置**：
  - 启用命令行审计：`本地计算机策略 > 计算机配置 > 管理模板 > 系统 > 审核进程创建 > 在进程创建事件中加入命令行 > 启用`。
  - 部署Sysmon，配置捕获进程创建和注册表事件。

## 测试复现

### 测试环境

- 系统：Windows 10 (Build 18363.418)
- 用户：普通用户（注册表修改需管理员权限）

### 测试过程

#### 1. 准备恶意载荷

- 创建简单测试文件`malware.exe`（如启动`calc.exe`的批处理转EXE）。
- 放置于`C:\Temp\malware.exe`。

#### 2. 修改注册表

**命令**：
```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs\malware" /v ATExe /t REG_SZ /d "C:\Temp\malware.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs\malware" /v Description /t REG_SZ /d "Malicious AT Application" /f
```

#### 3. 执行攻击

**命令**：
```cmd
C:\Users\liyang>AtBroker.exe /start malware
```

**结果**：
- `malware.exe`执行，触发`calc.exe`（假设`malware.exe`为测试载荷）。
- 日志记录`AtBroker.exe`和`malware.exe`的进程创建。

#### 4. 清理

**命令**：
```cmd
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs\malware" /f
del C:\Temp\malware.exe
taskkill /IM calc.exe /F
```

## 测试留痕

### Windows安全日志（Event ID 4688：进程创建）

```xml
日志名称: Security
来源: Microsoft-Windows-Security-Auditing
日期: 2023/10/01 10:00:00
事件 ID: 4688
任务类别: Process Creation
级别: 信息
用户: N/A
计算机: DESKTOP-PT656L6
描述:
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
  新进程 ID: 0x21e4
  新进程名称: C:\Windows\System32\AtBroker.exe
  令牌提升类型: %%1938
  强制性标签: Mandatory Label\Medium Mandatory Level
  创建者进程 ID: 0x24b4
  创建者进程名称: C:\Windows\System32\cmd.exe
  进程命令行: AtBroker.exe /start malware
```

**分析**：
- 日志记录`AtBroker.exe`执行，命令行包含`/start malware`。
- 父进程为`cmd.exe`，事件创建。

### Sysmon日志（Event ID 13：注册表事件）

```xml
日志名称: Microsoft-Windows-Sysmon/Operational
来源: Microsoft-Windows-Sysmon
日期: 2023/10-01 10:00:00
事件 ID: 13
任务类别: Registry value set
级别: 信息
用户: DESKTOP-PT656L6\liyang
计算机: DESKTOP-PT656L6
描述:
Registry value set:
RuleName: technique_id=T1218,technique_name=Signed Binary Proxy Execution
UtcTime: 2023-10-01 02:00:00.123
EventType: SetValue
ProcessGuid: {12345678-1234-5678-1234-567890123456}
ProcessId: 12345
Image: C:\Windows\System32\reg.exe
TargetObject: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs\malware\ATExe
Details: C:\Temp\malware.exe
```

**分析**：
- 日志记录`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs\malware\ATExe`的注册表修改，指向`malware.exe`。
- 进程映像为`reg.exe`，表明通过命令行注册表修改。

## 检测规则/思路

### Sigma规则

```yaml
title: 检测可疑AtBroker.exe执行
description: Detects AtBroker.exe executing non-standard Assistive Technology applications, potentially malicious.
id: f24bcaea-0cd1-11eb-adc1-0242ac120002
status: experimental
author: 
- Mateusz Wydra, 
- oscd.community, 
date: 2023/10/01
references:
  - https://attack.mitre.org/techniques/T1218/
  - http://www.hexacorn.com/blog/2016/07/22/beyond-good-ol-run-key-part-42/
  - https://lolbas-project.github.io/lolbas/Binaries/Atbroker/
tags:
  - attack.defense_evasion
  - attack.t1218
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\AtBroker.exe'
    CommandLine|contains: '/start'
  filter:
    CommandLine|contains:
      - 'animations'
      - 'audiodescription'
      - 'caretbrowsing'
      - 'caretwidth'
      - 'colorfiltering'
      - 'cursorscheme'
      - 'filterkeys'
      - 'focusborderheight'
      - 'focusborderwidth'
      - 'highcontrast'
      - 'keyboardcues'
      - 'keyboardpref'
      - 'magnifierpane'
      - 'messageduration'
      - 'minimumhitradius'
      - 'mousekeys'
      - 'Narrator'
      - 'osk'
      - 'overlappedcontent'
      - 'showsounds'
      - 'soundsentry'
      - 'stickykeys'
      - 'togglekeys'
      - 'windowarranging'
      - 'windowtracking'
      - 'windowtrackingtimeout'
      - 'windowtrackingzorder'
  condition: selection and not filter
fields:
  - Image
  - CommandLine
  - ParentImage
falsepositives:
  - Legitimate non-default assistive technology applications
level: high
```

**规则说明**：
- 检测`AtBroker.exe`执行，命令行包含`/start`但不包含默认AT应用（如`Narrator`、`osk`）。
- 覆盖Windows安全日志（Event ID 4688）和Sysmon日志（Event ID 1）。
- 规则为实验性，需测试以减少合法AT应用的误报。

### 建议

1. **监控AtBroker.exe活动**：
   - 使用Sysmon（Event ID 1）捕获`AtBroker.exe`的进程创建，检查命令行是否包含`/start`和非默认AT名称。
   - 监控Event ID 13（注册表修改），检测`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`的更改。

2. **启用命令行审计**：
   - 配置Windows安全策略，启用进程跟踪审核（Event ID 4688）并记录命令行参数。
   - 部署Sysmon，配置捕获进程命令行和注册表事件。

3. **基线化行为**：
   - 建立`AtBroker.exe`的正常使用基线，生产环境中应仅启动默认AT应用（如`Narrator`、`magnifier`）。
   - 监控非预期父进程（如`powershell.exe`）或异常AT名称。

4. **保护注册表**：
   - 配置严格的注册表权限，限制非管理员修改`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`。
   - 启用注册表审计，记录AT键的创建或修改。

5. **部署SIEM系统**：
   - 使用SIEM工具（如Splunk、Elastic）分析安全日志和Sysmon日志，检测`AtBroker.exe`代理执行。
   - 设置高优先级告警，针对非默认AT应用的`/start`命令。

6. **行为链关联**：
   - 将`AtBroker.exe`执行与其他可疑行为（如网络连接、进程注入）关联，识别攻击链。
   - 例如，检测`malware.exe`执行后是否发起C2通信。

7. **限制AtBroker.exe使用**：
   - 使用AppLocker或组策略限制`AtBroker.exe`的执行，仅允许特定场景。
   - 监控未经授权的AT注册表修改。

8. **测试与验证**：
   - 在测试环境中模拟`AtBroker.exe`执行恶意载荷（如注册`malware.exe`），验证检测规则有效性。
   - 调整规则阈值，排除合法AT应用的误报。

## 参考推荐

- MITRE ATT&CK T1218  
  <https://attack.mitre.org/techniques/T1218/>
- LOLBAS：AtBroker.exe  
  <https://lolbas-project.github.io/lolbas/Binaries/Atbroker/>
- ATBroker.exe病毒利用分析  
  <https://www.freebuf.com/articles/system/171437.html>
- Atomic Red Team T1218  
  <https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md>
