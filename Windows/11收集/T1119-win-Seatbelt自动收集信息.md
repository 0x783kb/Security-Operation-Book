# T1119-Win-Seatbelt自动收集信息

## 描述

攻击者在系统或网络中建立立足点后，可能使用自动化技术收集内部信息。自动化收集可通过命令行脚本、PowerShell脚本或专用工具（如Seatbelt）实现，搜索并复制符合攻击者需求的数据（如特定文件类型、配置文件、浏览器历史记录）。这些工具可能内置于恶意软件或远程访问工具中，并常结合其他技术（如文件和目录发现、横向工具传输）以定位和移动文件。Seatbelt是一个功能强大的C#工具，能够快速收集主机安全配置和敏感信息，广泛用于渗透测试和红队行动。

## 测试案例

### 用例
- **系统信息收集**：使用Seatbelt收集主机配置，如操作系统版本、补丁状态、用户账户。
- **浏览器历史记录**：提取Chrome、Edge等浏览器的访问历史，获取内部站点域名或IP。
- **凭据收集**：扫描注册表或配置文件，获取保存的凭据或令牌。
- **网络信息**：收集网络共享、连接信息或ARP表。

### 示例场景
- 攻击者在受损主机上运行Seatbelt，执行`-group=user`命令收集用户信息和浏览器历史，提升内网资产摸索效率。
- 自动化脚本定期运行Seatbelt，将收集的数据通过C2通道传输。

### 路径
Seatbelt通常以可执行文件形式运行，路径取决于攻击者部署位置：
```yml
- C:\Users\[username]\Desktop\Seatbelt.exe
- C:\Temp\Seatbelt.exe
```

### 所需权限
- 用户权限（执行Seatbelt）。
- 管理员权限（部分检查功能，如注册表操作，可能需要提升权限）。

### 操作系统
- Windows 7、Windows 8、Windows 8.1、Windows 10、Windows 11、Windows Server 2008、2012、2016、2019、2022。

## 检测日志

### Windows安全日志
- **事件ID 4688**：记录`Seatbelt.exe`进程创建及命令行参数（需启用命令行审核）。
- **事件ID 4663**：记录`Seatbelt.exe`访问敏感对象（如注册表键）。

### Sysmon日志
- **事件ID 1**：捕获`Seatbelt.exe`进程创建及命令行参数。
- **事件ID 11**：记录Seatbelt生成的文件（如输出日志）。
- **事件ID 13**：记录注册表操作（如查询Chrome路径）。
- **事件ID 3**：记录可能的网络连接（若数据通过网络传输）。

### PowerShell日志
- **事件ID 4104**：若Seatbelt通过PowerShell脚本调用，记录相关脚本块。

## 测试复现

### 环境准备
- **靶机**：Windows 10/11或Windows Server 2016。
- **权限**：用户权限（管理员权限可能提升某些功能）。
- **工具**：
  - Seatbelt源码或预编译二进制文件（https://github.com/GhostPack/Seatbelt）。
  - Visual Studio 2017+（编译Seatbelt）。
  - Sysmon（用于进程和文件监控）。
  - Wireshark（若涉及网络传输，捕获流量）。
- **网络**：隔离网络环境，允许可能的出站流量。
- **日志**：启用Windows安全日志、Sysmon日志和PowerShell日志。

### 攻击步骤
1. **编译Seatbelt**：
   - 下载源码：https://github.com/GhostPack/Seatbelt。
   - 使用Visual Studio 2017+编译，支持.NET 3.5或4.0：
     ```bash
     msbuild Seatbelt.sln /p:Configuration=Release
     ```
   - 输出路径：`bin\Release\Seatbelt.exe`。
2. **运行Seatbelt**：
   - 复制`Seatbelt.exe`到靶机（如`C:\Users\wardog\Desktop\Seatbelt.exe`）。
   - 执行命令收集用户信息：
     ```bash
     C:\Users\wardog\Desktop\Seatbelt.exe -group=user
     ```
   - 或运行所有检查：
     ```bash
     C:\Users\wardog\Desktop\Seatbelt.exe -group=all -full
     ```
3. **验证结果**：
   - 检查输出文件或控制台日志，确认收集的信息（如用户账户、浏览器历史）。
   - 使用Wireshark捕获网络流量（若数据通过网络传输）。
   - 验证Sysmon日志是否记录`Seatbelt.exe`进程和注册表操作。
4. **清理**：
   - 删除`Seatbelt.exe`和输出文件。
   - 清除相关日志（测试环境）。

## 测试留痕
以下为Windows安全日志示例（事件ID 4688）：
```yml
EventID: 4688
TimeCreated: 2020-11-02T04:39:11.671Z
Channel: Security
Hostname: WORKSTATION5
SubjectUserSid: S-1-5-21-3940915590-64593676-1414006259-500
SubjectUserName: wardog
SubjectDomainName: WORKSTATION5
SubjectLogonId: 0xC61D9
NewProcessId: 0x2f04
NewProcessName: C:\Users\wardog\Desktop\Seatbelt.exe
ProcessCommandLine: Seatbelt.exe -group=user
CreatorProcessId: 0x3048
CreatorProcessName: C:\Windows\System32\cmd.exe
TokenElevationType: %%1936
MandatoryLabel: S-1-16-12288
```

以下为Windows安全日志示例（事件ID 4663，注册表访问）：
```yml
EventID: 4663
TimeCreated: 2020-11-02T04:39:11.847Z
Channel: Security
Hostname: WORKSTATION5
SubjectUserSid: S-1-5-21-3940915590-64593676-1414006259-500
SubjectUserName: wardog
SubjectDomainName: WORKSTATION5
SubjectLogonId: 0xC61D9
ObjectServer: Security
ObjectType: Key
ObjectName: \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe
HandleId: 0x2b4
AccessList: %%4432
AccessMask: 0x1
ProcessId: 0x2f04
ProcessName: C:\Users\wardog\Desktop\Seatbelt.exe
```

## 检测方法/思路

### Sigma规则
基于Sigma规则，检测Seatbelt的执行行为：

```yml
title: Suspicious Seatbelt Execution
id: b8c9d7e6-2f3a-4d5b-8e7c-1a2b3c4d5e6f
status: experimental
description: Detects execution of Seatbelt, a tool used for automated host information collection
references:
- https://attack.mitre.org/techniques/T1119
- https://github.com/GhostPack/Seatbelt
- https://github.com/OTRF/Security-Datasets/blob/master/datasets/atomic/windows/discovery/host/cmd_seatbelt_group_user.zip
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID: 4688
    Image|endswith: '\Seatbelt.exe'
  condition: selection
falsepositives:
- Legitimate use of Seatbelt by security teams for auditing
level: high
```

### 检测思路
1. **进程监控**：
   - 检测`Seatbelt.exe`进程的创建，尤其是命令行参数包含`-group=user`、`-group=all`或`-full`。
   - 监控异常父进程（如`cmd.exe`、`powershell.exe`）。
2. **注册表监控**：
   - 检测`Seatbelt.exe`访问敏感注册表键（如Chrome路径、凭据存储）。
   - 使用Sysmon事件ID 13捕获注册表查询或修改。
3. **文件监控**：
   - 检测Seatbelt生成的文件（如输出日志，`.txt`或`.json`格式）。
4. **网络监控**：
   - 检测收集数据通过网络传输的行为（如上传到C2服务器）。
5. **行为基线**：
   - 建立组织内正常信息收集工具的使用基线，识别异常执行（如非安全团队运行Seatbelt）。

### 检测建议
- **Sysmon配置**：配置Sysmon监控`Seatbelt.exe`的进程创建（事件ID 1）、文件创建（事件ID 11）和注册表操作（事件ID 13）。
- **命令行分析**：解析`Seatbelt.exe`的命令行参数，检测特定选项（如`-group=user`）。
- **EDR监控**：使用EDR工具（如Microsoft Defender for Endpoint）监控Seatbelt的执行和后续行为。
- **误报过滤**：排除安全团队或管理员的合法Seatbelt使用，结合上下文（如用户身份、时间）降低误报率。

## 缓解措施
1. **应用白名单**：
   - 使用AppLocker或WDAC限制`Seatbelt.exe`的执行，仅允许受信任用户或进程。
2. **文件监控**：
   - 部署文件完整性监控（FIM）工具，检测异常输出文件创建。
3. **注册表保护**：
   - 限制非管理员用户访问敏感注册表键（如凭据存储）。
4. **网络限制**：
   - 监控并限制收集数据通过网络传输的行为，阻止未经授权的数据泄露。
5. **用户培训**：
   - 教育用户识别可疑工具执行行为，避免运行未知可执行文件。

## 参考推荐
- MITRE ATT&CK T1119  
  https://attack.mitre.org/techniques/T1119  
- Seatbelt GitHub  
  https://github.com/GhostPack/Seatbelt  
- 内存加载Seatbelt的实现  
  https://anquan.baidu.com/article/1153  
- Security-Datasets: Seatbelt Dataset  
  https://github.com/OTRF/Security-Datasets/blob/master/datasets/atomic/windows/discovery/host/cmd_seatbelt_group_user.zip