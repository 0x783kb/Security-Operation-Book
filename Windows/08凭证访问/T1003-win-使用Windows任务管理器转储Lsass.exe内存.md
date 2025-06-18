# T1003-Win-使用Windows任务管理器转储Lsass.exe内存

## 描述

凭据转储（Credential Dumping，MITRE ATT&CK T1003）是指攻击者从操作系统或软件中提取用户登录凭据（明文密码、NTLM哈希或Kerberos票据）以实现横向移动或访问受限资源。在Windows系统中，本地安全机构子系统服务（LSASS）进程（lsass.exe）存储用户会话的凭据信息。攻击者可通过Windows任务管理器以管理员权限转储`lsass.exe`内存，生成`.dmp`文件，随后使用Mimikatz等工具离线提取凭据。此技术无需外部工具，操作简单，但需本地管理员权限，且转储文件可能被安全软件检测。

## 测试案例

### 测试环境
- 系统：Windows Server 2019或Windows 10
- 工具：Windows任务管理器（内置）、Mimikatz（可选，离线分析）
- 要求：本地管理员权限、域环境（lab.local，可选）
- 用户：Administrator（密码：Password123）
- 日志：Sysmon（事件ID1、11）、Windows安全日志（事件ID4688、4656）

### 测试准备
1. 确认管理员权限：
   ```cmd
   whoami /priv
   ```
   - 确保具有`SeDebugPrivilege`权限。
2. 安装Sysmon（可选）：
   - 下载：<https://docs.microsoft.com/sysinternals/downloads/sysmon>
   - 配置：启用事件ID1（进程创建）、11（文件操作）。
   - 示例配置：`sysmon.exe -i sysmonconfig.xml`
3. 启用安全日志审计：
   - 组策略：计算机配置 > 策略 > Windows设置 > 安全设置 > 本地策略 > 审核策略 > 进程跟踪、对象访问 > 启用成功和失败审计。
4. 下载Mimikatz（可选）：
   - URL：<https://github.com/gentilkiwi/mimikatz>
   - 放置于本地（C:\Tools\mimikatz）。
5. 确保活跃用户会话：
   - 登录Administrator或其他用户，生成LSASS凭据。

### 测试步骤
1. **打开任务管理器**：
   - 按`Ctrl+Shift+Esc`或右键任务栏 > 任务管理器。
   - 若非管理员模式，右键任务管理器图标 > 以管理员身份运行。
2. **定位lsass.exe**：
   - 切换到“详细信息”标签，找到`lsass.exe`（本地安全机构进程）。
3. **转储内存**：
   - 右键`lsass.exe` > 创建转储文件。
   - 记录转储路径（如`C:\Users\Administrator\AppData\Local\Temp\lsass.DMP`）。
4. **验证转储文件**：
   - 导航到`C:\Users\Administrator\AppData\Local\Temp\`。
   - 确认`lsass.DMP`存在（约50-100MB）。
5. **离线提取凭据**（可选）：
   - 复制`lsass.DMP`到分析系统。
   - 使用Mimikatz：
     ```cmd
     mimikatz.exe "sekurlsa::minidump lsass.DMP" "sekurlsa::logonpasswords" exit
     ```
     - 输出示例：
       ```
       msv:
         * Username: Administrator
         * Domain: LAB
         * NTLM: <NTLMHash>
       wdigest:
         * Username: Administrator
         * Domain: LAB
         * Password: Password123
       ```

### 参考资源
- LSASS内存转储技术：<https://www.cnblogs.com/zUotTe0/p/14553082.html>
- Mimikatz文档：<https://github.com/gentilkiwi/mimikatz>
- MITRE ATT&CK T1003：<https://attack.mitre.org/techniques/T1003/>

## 检测日志

### 数据来源
- **Sysmon日志**：
  - 事件ID1：进程创建（taskmgr.exe）
  - 事件ID11：文件创建（lsass.DMP）
- **Windows安全日志**：
  - 事件ID4688：进程创建（taskmgr.exe）
  - 事件ID4656：文件访问（lsass.DMP，需启用对象访问审计）
- **文件系统**：
  - 监控`%localappdata%\Temp\`或`C:\Windows\Temp\`的`.dmp`文件
- **网络流量**（可选）：
  - 捕获`.dmp`文件传输（SMB 445/TCP、FTP 21/TCP）

### 日志示例
- **Sysmon事件ID1**（taskmgr.exe进程创建）：
  ```xml
  <Event>
    <EventData>
      <Data Name="Image">C:\Windows\System32\taskmgr.exe</Data>
      <Data Name="CommandLine">C:\Windows\System32\taskmgr.exe</Data>
      <Data Name="ParentImage">C:\Windows\explorer.exe</Data>
      <Data Name="User">LAB\Administrator</Data>
    </EventData>
  </Event>
  ```
- **Sysmon事件ID11**（lsass.DMP文件创建）：
  ```xml
  <Event>
    <EventData>
      <Data Name="TargetFilename">C:\Users\Administrator\AppData\Local\Temp\lsass.DMP</Data>
      <Data Name="Image">C:\Windows\System32\taskmgr.exe</Data>
      <Data Name="User">LAB\Administrator</Data>
    </EventData>
  </Event>
  ```
- **Windows事件ID4656**（文件访问，需启用审计）：
  ```xml
  <Event>
    <EventData>
      <Data Name="ObjectName">C:\Users\Administrator\AppData\Local\Temp\lsass.DMP</Data>
      <Data Name="ProcessName">C:\Windows\System32\taskmgr.exe</Data>
      <Data Name="SubjectUserName">Administrator</Data>
    </EventData>
  </Event>
  ```

## 测试复现

### 环境配置
- 系统：Windows 10
- 工具：任务管理器
- 用户：Administrator（密码：Password123）
- 日志：Sysmon（事件ID1、11）
- 路径：C:\Users\Administrator\AppData\Local\Temp\

### 复现步骤
1. **启动任务管理器**：
   ```cmd
   taskmgr
   ```
   - 或按`Ctrl+Shift+Esc`。
2. **转储lsass.exe**：
   - 切换到“详细信息”标签，右键`lsass.exe` > 创建转储文件。
   - 记录路径（如`C:\Users\Administrator\AppData\Local\Temp\lsass.DMP`）。
3. **验证文件**：
   ```cmd
   dir C:\Users\Administrator\AppData\Local\Temp\lsass.DMP
   ```
   - 输出：确认文件存在。
4. **离线分析**（可选）：
   ```cmd
   mimikatz.exe "sekurlsa::minidump C:\Users\Administrator\AppData\Local\Temp\lsass.DMP" "sekurlsa::logonpasswords" exit
   ```
   - 输出：
     ```
     wdigest:
       * Username: Administrator
       * Domain: LAB
       * Password: Password123
     ```
5. **检查日志**：
   - Sysmon事件ID11：确认`lsass.DMP`创建。

## 测试留痕

### Sysmon日志
- **事件ID1**：
  ```xml
  <Event>
    <EventData>
      <Data Name="Image">C:\Windows\System32\taskmgr.exe</Data>
      <Data Name="CommandLine">C:\Windows\System32\taskmgr.exe</Data>
      <Data Name="ParentImage">C:\Windows\explorer.exe</Data>
      <Data Name="User">LAB\Administrator</Data>
    </EventData>
  </Event>
  ```
- **事件ID11**：
  ```xml
  <Event>
    <EventData>
      <Data Name="TargetFilename">C:\Users\Administrator\AppData\Local\Temp\lsass.DMP</Data>
      <Data Name="Image">C:\Windows\System32\taskmgr.exe</Data>
      <Data Name="User">LAB\Administrator</Data>
    </EventData>
  </Event>
  ```

### Windows安全日志
- **事件ID4656**（需启用审计）：
  ```xml
  <Event>
    <EventData>
      <Data Name="ObjectName">C:\Users\Administrator\AppData\Local\Temp\lsass.DMP</Data>
      <Data Name="ProcessName">C:\Windows\System32\taskmgr.exe</Data>
      <Data Name="SubjectUserName">Administrator</Data>
    </EventData>
  </Event>
  ```

### 文件系统
- 文件：`C:\Users\Administrator\AppData\Local\Temp\lsass.DMP`（50-100MB）

## 检测规则/思路

### 检测方法
1. **日志监控**：
   - Sysmon事件ID11：检测`taskmgr.exe`创建`lsass.DMP`。
   - Sysmon事件ID1：监控`taskmgr.exe`异常启动（非explorer.exe父进程）。
2. **文件监控**：
   - 审计`%localappdata%\Temp\`和`C:\Windows\Temp\`的`.dmp`文件创建。
   - 监控`lsass.DMP`的异常访问或传输。
3. **行为分析**：
   - 检测非预期管理员启动任务管理器。
   - 监控短时间内多次`.dmp`文件生成。
4. **网络监控**：
   - 捕获`.dmp`文件传输（SMB 445/TCP、FTP 21/TCP）。
5. **关联分析**：
   - 结合事件ID4624，检测转储后的异常登录。
   - 监控Mimikatz执行（事件ID1，`mimikatz.exe`）。

### Sigma规则
#### 规则一：任务管理器转储LSASS
```yaml
title: 任务管理器转储LSASS内存检测
id: k1f2g3h4-5i6j-7k8l-fm7g-4h5i6j7k8l9m
status: stable
description: 检测任务管理器创建lsass.DMP文件的LSASS内存转储行为
references:
  - https://attack.mitre.org/techniques/T1003/
tags:
  - attack.credential_access
  - attack.t1003
logsource:
  product: windows
  category: file_event
detection:
  selection:
    EventID: 11
    Image|endswith: '\taskmgr.exe'
    TargetFilename|contains: 'lsass.DMP' 
  condition: selection
fields:
  - ComputerName
  - User
  - Image
  - TargetFilename
falsepositives:
  - 管理员合法调试
  - 系统诊断工具生成转储
level: high
```

#### 规则二：异常任务管理器启动
```yaml
title: 异常任务管理器启动检测
id: l2g3h4i5-6j7k-8l9m-gn8h-5i6j7k8l9m0n
status: stable
description: 检测任务管理器异常启动，可能与LSASS转储相关
references:
  - https://attack.mitre.org/techniques/T1003/
tags:
  - attack.credential_access
  - attack.t1003
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID|in:
      - 4688
      - 1
    Image|endswith: '\taskmgr.exe'
    ParentImage|notcontains:
      - '\explorer.exe'
      - '\cmd.exe'
  condition: selection
fields:
  - ComputerName
  - User
  - Image
  - ParentImage
falsepositives:
  - 管理员通过脚本启动任务管理器
level: medium
```

### Splunk规则
```spl
index=sysmon EventCode=11 Image="*taskmgr.exe" TargetFilename="*lsass.DMP"
OR (EventCode IN (1,4688) Image="*taskmgr.exe" NOT (ParentImage IN ("*explorer.exe","*cmd.exe")))
| fields EventCode,Image,TargetFilename,ParentImage,User
```

规则说明：
- 检测`taskmgr.exe`创建`lsass.DMP`或异常启动。
- 减少误报：排除常见父进程。

## 防御建议
1. **权限控制**：
   - 限制`SeDebugPrivilege`权限，仅授权必要管理员。
   - 使用组策略禁止普通用户访问`lsass.exe`。
2. **日志监控**：
   - 部署Sysmon，启用事件ID1、11。
   - 启用对象访问审计，监控`lsass.DMP`。
   - 使用SIEM关联`taskmgr.exe`和`.dmp`事件。
3. **凭据保护**：
   - 启用Credential Guard（Windows 10/2016+）。
   - 禁用WDigest协议（组策略）。
4. **工具限制**：
   - 使用AppLocker限制`taskmgr.exe`非预期执行。
   - 监控Mimikatz运行。
5. **主动防御**：
   - 部署诱捕凭据，监控LSASS访问。
   - 使用EDR检测`taskmgr.exe`异常行为。

## 参考推荐
- MITRE ATT&CK T1003:  
  <https://attack.mitre.org/techniques/T1003/>
- LSASS内存转储技术:  
  <https://www.cnblogs.com/zUotTe0/p/14553082.html>
- Mimikatz文档:  
  <https://github.com/gentilkiwi/mimikatz>
- LSASS防御最佳实践:  
  <https://adsecurity.org/?p=1760>
- Sysmon配置指南:  
  <https://github.com/SwiftOnSecurity/sysmon-config>