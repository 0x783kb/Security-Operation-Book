# T1059-Win-进程生成CMD

## 描述

攻击者可能利用命令行界面（如Windows的`cmd.exe`）与系统交互，执行命令或启动其他软件，以实现信息收集、恶意代码执行或横向移动（T1059）。`cmd.exe`是Windows操作系统内置的命令提示符，提供命令行环境，支持运行内置命令（如`dir`、`copy`、`mkdir`）、批处理脚本（`.bat`）以及外部程序。攻击者可通过本地交互、远程桌面、反向Shell会话等方式运行`cmd.exe`，命令以当前进程的权限级别执行，除非涉及权限上下文更改（如计划任务T1053）。

`cmd.exe`因其白名单特性常被攻击者滥用，典型场景包括通过异常父进程（如`winword.exe`或`acrord32.exe`）启动`cmd.exe`，表明可能的恶意文档加载或漏洞利用。检测重点在于识别异常的父进程或可疑的命令行参数，结合上下文分析攻击行为。

## 测试案例

1. **恶意文档触发CMD**  
   攻击者通过Office文档（Word/Excel）中的宏或漏洞利用，启动`cmd.exe`执行恶意命令。

2. **异常父进程生成CMD**  
   非典型父进程（如`acrord32.exe`或`outlook.exe`）启动`cmd.exe`，运行可疑脚本或命令。

## 检测日志

**Windows安全日志**  
- **事件ID 4688**：记录进程创建，包含`cmd.exe`的命令行参数、父进程和子进程信息。  
  - 在Windows 10及以上版本中，事件ID 4688记录父进程信息。  
- **事件ID 4689**：记录进程终止，可能用于关联进程生命周期。

**Sysmon日志**  
- **事件ID 1**：记录进程创建，包含`cmd.exe`的完整命令行、父进程和子进程信息。  
- **事件ID 3**：记录网络连接，可能涉及`cmd.exe`执行的命令引发的网络活动。

**配置日志记录**  
- 启用命令行参数记录：`本地计算机策略 > 计算机配置 > 管理模板 > 系统 > 审核进程创建 > 在进程创建事件中加入命令行 > 启用`。  
- 部署Sysmon以增强父进程和子进程关联监控。

## 测试复现

### 环境准备
- **靶机**：Windows 7/10，启用Sysmon和Windows安全日志。  
- **权限**：测试账户需具备本地权限。  
- **工具**：无特殊工具，系统自带`cmd.exe`。

### 攻击步骤
1. **模拟正常CMD执行**  
   在靶机上通过命令提示符或PowerShell运行`cmd.exe`：
   ```cmd
   cmd.exe
   ```

2. **模拟异常父进程**  
   使用PowerShell模拟非典型父进程（如`notepad.exe`）启动`cmd.exe`：
   ```powershell
   Start-Process -FilePath "notepad.exe" -ArgumentList "/c cmd.exe /c dir > C:\temp\output.txt"
   ```

## 测试留痕

- **Sysmon日志（事件ID 1）**：
  ```plaintext
  EventID: 1
  Image: C:\Windows\System32\cmd.exe
  FileVersion: 6.1.7600.16385
  Description: Windows Command Processor
  CommandLine: cmd.exe /c dir > C:\temp\output.txt
  ParentImage: C:\Windows\System32\notepad.exe
  User: <domain>\12306Br0
  IntegrityLevel: Medium
  ```
- **Windows安全日志（事件ID 4688，Windows 10）**：
  ```plaintext
  EventID: 4688
  New Process ID: 0x1234
  New Process Name: C:\Windows\System32\cmd.exe
  Process Command Line: cmd.exe /c dir > C:\temp\output.txt
  Creator Process Name: C:\Windows\System32\notepad.exe
  Token Elevation Type: TokenElevationTypeLimited (3)
  ```
- **Windows安全日志（事件ID 4688，Windows 7）**：
  ```plaintext
  EventID: 4688
  New Process ID: 0x1234
  New Process Name: C:\Windows\System32\cmd.exe
  Process Command Line: cmd.exe /c dir > C:\temp\output.txt
  Creator Process Name: N/A (Windows 7不记录父进程)
  ```

## 检测规则/思路

**检测规则**  
通过分析Sysmon和Windows安全日志，检测`cmd.exe`的异常父进程或可疑命令行参数。以下是具体思路：

1. **日志分析**：
   - 收集Sysmon事件ID 1或Windows安全事件ID 4688，提取`cmd.exe`的父进程和命令行参数。  
   - 检测异常父进程（如`winword.exe`、`acrord32.exe`、`outlook.exe`）或可疑命令行（如运行脚本或网络工具）。

2. **Sigma规则**：
   ```yaml
   title: 检测异常父进程生成CMD
   id: 1a2b3c4d-5e6f-7a8b-9c0d-1e2f3c4d5e6f
   status: stable
   description: 检测cmd.exe由异常父进程生成，可能表明恶意行为
   references:
     - https://attack.mitre.org/techniques/T1059/
   tags:
     - attack.execution
     - attack.t1059
   logsource:
     category: process_creation
     product: windows
   detection:
     selection:
       EventID:
         - 1 # Sysmon
         - 4688 # Windows安全日志
       Image|endswith: '\cmd.exe'
       ParentImage|endswith:
         - '\winword.exe'
         - '\excel.exe'
         - '\powerpnt.exe'
         - '\acrord32.exe'
         - '\outlook.exe'
         - '\java.exe'
         - '\firefox.exe'
         - '\chrome.exe'
     condition: selection
   falsepositives:
     - 合法的自动化脚本或管理工具
     - 第三方软件调用cmd.exe
   level: medium
   ```

3. **ELK规则**：
   ```plaintext
   process = search Process:Create
   cmd = filter process where (exe == "cmd.exe" and parent.exe in ("winword.exe", "excel.exe", "acrord32.exe", "outlook.exe"))
   output cmd
   ```

4. **SIEM规则**：
   - 检测异常父进程生成的`cmd.exe`。
   - 示例Splunk查询：
     ```spl
     source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\cmd.exe" ParentImage IN ("*\winword.exe", "*\excel.exe", "*\acrord32.exe", "*\outlook.exe") | stats count by Image, CommandLine, ParentImage, ComputerName, User
     ```

5. **威胁情报整合**：
   - 检查`cmd.exe`的命令行参数或后续行为（如网络连接、文件操作）是否与已知恶意活动相关，结合威胁情报平台（如VirusTotal、AlienVault）。

## 参考推荐

- MITRE ATT&CK: T1059  
  <https://attack.mitre.org/techniques/T1059/>  
- Windows重点监控事件ID表  
  <https://www.96007.club/2019/08/21/21/>  
- Windows Command Prompt  
  <https://en.wikipedia.org/wiki/cmd.exe>