# T1562-Win-使用Bcdedit禁用DEP安全机制

## 描述

攻击者可能通过修改系统组件来禁用或削弱防御机制，以规避检测（MITRE ATT&CK T1562）。这包括破坏预防性防御（如防火墙、防病毒软件）以及用于审核和识别恶意行为的检测功能（如事件日志、EDR）。其中一种技术是通过`bcdedit.exe`修改Windows的**数据执行保护（DEP）**设置，禁用此安全机制以便执行恶意代码。

**数据执行保护（DEP）**是一种安全功能，旨在防止数据页面（如堆、栈、内存池）执行代码，通过设置内存页的**NX/XD（No-Execute/Execute Disable）**属性实现。它分为软件DEP（如SafeSEH）和硬件DEP，保护系统免受缓冲区溢出等攻击。DEP有四种工作模式：

- **OptIn**：仅保护Windows系统组件（默认模式）。
- **OptOut**：为非排除列表的程序和服务启用DEP。
- **AlwaysOn**：对所有进程启用DEP。
- **AlwaysOff**：对所有进程禁用DEP（高风险）。

攻击者可能使用`bcdedit.exe /set {current} nx AlwaysOff`禁用DEP，允许恶意代码在数据页面执行，规避安全限制。

### DEP局限性

1. 并非所有CPU支持硬件DEP。
2. 兼容性问题可能导致DEP对某些第三方插件或老旧程序（如ATL7.1以前版本）默认禁用。
3. `/NXCOMPAT`编译选项仅在Windows Vista及以上有效，早期系统可能忽略。
4. 早期Windows系统提供API（如`NtSetInformationProcess`）可动态修改DEP状态。

## 测试案例

### 测试1：使用bcdedit.exe禁用DEP

攻击者通过`bcdedit.exe`将DEP设置为`AlwaysOff`，禁用所有进程的DEP保护。

**攻击命令**（需以管理员权限在命令提示符中运行）：
```cmd
bcdedit.exe /set {current} nx AlwaysOff
```

**恢复命令**（恢复默认OptIn模式）：
```cmd
bcdedit.exe /set {current} nx OptIn
```

**说明**：
- `nx AlwaysOff`禁用DEP，增加系统被缓冲区溢出攻击利用的风险。
- 需重启系统使更改生效。
- `OptIn`恢复默认设置，仅保护系统组件。

## 检测日志

- **Windows安全日志**：通过Event ID 4688（进程创建）记录`bcdedit.exe`的执行（需启用进程跟踪审核）。
- **Sysmon日志**：通过Event ID 1（进程创建）捕获详细的命令行参数和父进程信息。

## 测试复现

### 测试1：禁用DEP

**测试环境**：Windows Server 2019

**攻击命令**：
```cmd
C:\Users\Administrator>bcdedit.exe /set {current} nx AlwaysOff
操作成功完成。
```

**结果**：
- 命令成功执行，DEP设置为`AlwaysOff`（需重启生效）。
- 未生成错误提示，表明系统接受了配置更改。

**验证命令**：
```cmd
bcdedit.exe /enum {current}
```

**输出示例**：
```
Windows Boot Loader
-------------------
identifier              {current}
...
nx                      AlwaysOff
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
用户: SYSTEM
计算机: JACKMA
描述:
已创建新进程。

创建者主题:
  安全 ID: JACKMA\Administrator
  帐户名: Administrator
  帐户域: JACKMA
  登录 ID: 0x73509

目标主题:
  安全 ID: NULL SID
  帐户名: -
  帐户域: -
  登录 ID: 0x0

进程信息:
  新进程 ID: 0x15e4
  新进程名称: C:\Windows\System32\bcdedit.exe
  令牌提升类型: %%1936 (TokenElevationTypeDefault)
  强制性标签: Mandatory Label\High Mandatory Level
  创建者进程 ID: 0xaf0
  创建者进程名称: C:\Windows\System32\cmd.exe
  进程命令行: bcdedit.exe /set {current} nx AlwaysOff
```

**分析**：
- 日志记录了`bcdedit.exe`的执行，命令行明确包含`nx AlwaysOff`，表明DEP禁用尝试。
- 父进程为`cmd.exe`，提示通过命令提示符触发。
- 高完整性级别（High Mandatory Level）表明需要管理员权限。

## 检测规则/思路

### Sigma规则

```yaml
title: 使用bcdedit.exe禁用Windows DEP安全机制
description: Detects execution of bcdedit.exe to disable Data Execution Prevention (DEP) by setting nx to AlwaysOff.
status: experimental
date: 2023/10/01
references:
  - https://attack.mitre.org/techniques/T1562/
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID:
      - 4688 # Windows安全日志
      - 1    # Sysmon日志
    Image|endswith: '\bcdedit.exe'
    CommandLine|contains: 'nx AlwaysOff'
  condition: selection
fields:
  - Image
  - CommandLine
  - ParentImage
  - User
falsepositives:
  - Legitimate administrative changes to DEP settings for compatibility issues
level: high
tags:
  - attack.defense_evasion
  - attack.t1562
```

**规则说明**：
- 检测`bcdedit.exe`执行时命令行包含`nx AlwaysOff`的进程创建事件，表明DEP禁用行为。
- 覆盖Windows安全日志（Event ID 4688）和Sysmon日志（Event ID 1）。
- 规则为实验性，需测试以减少合法兼容性调整的误报。

### 建议

1. **监控bcdedit执行**：
   - 使用Sysmon（Event ID 1）捕获`bcdedit.exe`的进程创建事件，检查命令行是否包含`nx AlwaysOff`。
   - 关注非管理员用户或非预期环境（如生产服务器）运行`bcdedit.exe`的行为。

2. **启用命令行审计**：
   - 配置Windows安全策略，启用进程跟踪审核（Event ID 4688）并记录命令行参数（需Windows 7+支持）。
   - 确保Sysmon配置包含命令行和父进程信息。

3. **基线化DEP设置**：
   - 定期检查系统DEP状态（`bcdedit.exe /enum {current}`），记录合法配置（如`OptIn`或`OptOut`）。
   - 生产环境中禁用DEP（`AlwaysOff`）应极为罕见，视为高危行为。

4. **权限监控**：
   - `bcdedit.exe`修改DEP需要管理员权限，监控非预期账户尝试执行的`bcdedit.exe`行为。
   - 检测失败的尝试（可能因权限不足），可能是攻击者进行探测。

5. **部署SIEM系统**：
   - 使用SIEM工具（如Splunk、Elastic）分析安全日志和Sysmon日志，检测`bcdedit.exe`异常执行。
   - 设置高优先级告警，针对`nx AlwaysOff`的命令。

6. **行为链关联**：
   - 将`bcdedit.exe`执行与其他可疑行为（如提权、代码注入、网络连接）关联，识别攻击链。
   - 例如，检测禁用DEP后是否出现异常的进程执行或C2通信。

7. **限制bcdedit使用**：
   - 使用AppLocker或组策略限制`bcdedit.exe`的执行，仅允许在特定管理场景下运行。
   - 监控未经授权的`bcdedit.exe`调用。

8. **响应措施**：
   - 检测到DEP禁用后，立即恢复DEP设置（`bcdedit.exe /set {current} nx OptIn`）并重启系统。
   - 调查攻击来源，检查是否有后续恶意代码执行。

9. **测试与验证**：
   - 在测试环境中模拟禁用DEP，验证检测规则有效性。
   - 调整规则阈值，排除合法兼容性调整的误报。

## 参考推荐

- MITRE ATT&CK T1562  
  <https://attack.mitre.org/techniques/T1562/>
- Windows安全机制：数据执行保护（DEP）  
  <https://blog.csdn.net/m0_37809075/article/details/83008617>
- Atomic Red Team T1562  
  <https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562/T1562.md>
- Microsoft文档：bcdedit命令  
  <https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit-commands>
