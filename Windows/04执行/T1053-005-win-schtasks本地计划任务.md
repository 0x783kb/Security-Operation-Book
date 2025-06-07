# T1053-005-Win-schtasks本地计划任务

## 描述

攻击者可能利用Windows任务调度器，通过`schtasks.exe`实用程序在特定时间或系统启动时执行程序或脚本，实现持久性、横向移动、权限提升或以指定账户上下文运行进程（T1053.005）。与`at.exe`不同，`schtasks`是Windows XP及更高版本中用于管理计划任务的主要工具，支持本地和远程任务调度。远程调度任务需要通过RPC（端口135）进行身份认证，并启用文件和打印机共享（SMB，端口445），通常要求目标系统的管理员权限。

攻击者可通过`schtasks`创建本地计划任务，定期运行恶意脚本或可执行文件，以维持系统访问或执行恶意操作。常见场景包括在系统启动时运行恶意Payload、定期下载新Payload或通过高权限账户上下文执行命令。由于`schtasks`是Windows内置工具，属于白名单进程，其行为可能被误认为是合法操作，增加检测难度。

## 测试案例

1. **本地持久化**  
   攻击者使用`schtasks`创建本地计划任务，在系统启动时运行恶意脚本，实现持久化。

2. **定时恶意执行**  
   攻击者通过`schtasks`调度任务，在指定时间运行恶意可执行文件（如勒索软件）。

## 检测日志

**Windows安全日志**  
- **事件ID 4688**：记录进程创建，包含`schtasks.exe`的命令行参数和子进程信息。  
- **事件ID 4624/4625**：记录登录成功或失败，可能涉及计划任务的凭据使用。

**Sysmon日志**  
- **事件ID 1**：记录进程创建，包含`schtasks.exe`的完整命令行和父进程信息。  
- **事件ID 11**：记录文件创建，可能涉及任务配置文件（`%systemroot%\System32\Tasks`）的修改。

**任务调度器日志**  
- **Microsoft-Windows-TaskScheduler/Operational**：记录计划任务的创建、更新或删除事件。  
  - 事件ID 106（Windows 7/2008 R2）：任务注册。  
  - 事件ID 4698（Windows 10/2016）：任务创建。  
  - 事件ID 4699/141：任务删除。  
  - 事件ID 4700/4701：任务启用/禁用。  
  - 事件ID 4702/140：任务更新。

**配置日志记录**  
- 启用命令行参数记录：`本地计算机策略 > 计算机配置 > 管理模板 > 系统 > 审核进程创建 > 在进程创建事件中加入命令行 > 启用`。  
- 部署Sysmon以增强进程和文件活动监控。

## 测试复现

### 环境准备
- **靶机**：Windows 7/10/2016，启用任务调度器服务。  
- **日志**：配置Sysmon和Windows安全日志，记录进程创建（事件ID 4688、Sysmon ID 1）。  
- **权限**：测试账户需具备本地管理员权限。

### 攻击步骤
1. **创建本地计划任务**  
   执行以下命令，创建本地计划任务：
   ```cmd
   schtasks /create /tn "MaliciousTask" /tr "cmd.exe /c calc.exe" /sc onstart
   ```

2. **验证任务**  
   - 检查任务是否创建：
     ```cmd
     schtasks /query /tn "MaliciousTask"
     ```
   - 重启系统，观察`calc.exe`是否启动。

## 测试留痕

- **Sysmon日志（事件ID 1）**：
  ```plaintext
  EventID: 1
  Image: C:\Windows\System32\schtasks.exe
  FileVersion: 10.0.19041.1
  Description: Task Scheduler Configuration Tool
  CommandLine: schtasks /create /tn "MaliciousTask" /tr "cmd.exe /c calc.exe" /sc onstart
  User: <domain>\Administrator
  IntegrityLevel: High
  ```
- **Windows安全日志（事件ID 4688）**：
  ```plaintext
  EventID: 4688
  New Process ID: 0x1234
  New Process Name: C:\Windows\System32\schtasks.exe
  Process Command Line: schtasks /create /tn "MaliciousTask" /tr "cmd.exe /c calc.exe" /sc onstart
  Creator Process Name: C:\Windows\System32\cmd.exe
  ```
- **任务调度器日志（事件ID 4698）**：
  ```plaintext
  EventID: 4698
  Task Name: MaliciousTask
  Task Action: cmd.exe /c calc.exe
  Trigger: On system start
  User: <domain>\Administrator
  ```
- **文件系统**：任务配置文件创建于`%systemroot%\System32\Tasks\MaliciousTask`。

## 检测规则/思路

**检测规则**  
通过分析Sysmon、Windows安全日志和任务调度器日志，检测`schtasks`创建或修改本地计划任务的异常行为。以下是具体思路：

1. **日志分析**：
   - 收集Sysmon事件ID 1或Windows安全事件ID 4688，提取`schtasks.exe`的命令行参数，重点关注`/create`、`/run`、`/change`等参数。
   - 监控任务调度器日志（事件ID 4698、4700、4702），检测新任务创建或异常更新。
   - 检查`%systemroot%\System32\Tasks`目录的更改，识别未知任务文件。

2. **Sigma规则**：
   ```yaml
   title: schtasks本地计划任务
   id: 4a7b8c9d-6f2a-4b1c-a9e6-2f3e4c5d6e7b
   status: stable
   description: 检测可疑的schtasks本地计划任务，可能表明持久性或恶意执行
   author: 12306Bro
   date: 2025/06/06
   references:
     - https://attack.mitre.org/techniques/T1053/005/
     - https://www.elastic.co/guide/en/siem/guide/current/local-scheduled-task-commands.html
   tags:
     - attack.persistence
     - attack.t1053.005
   logsource:
     category: process_creation
     product: windows
   detection:
     selection:
       EventID:
         - 1 # Sysmon进程创建
         - 4688 # Windows安全日志进程创建
       Image|endswith: '\schtasks.exe'
       CommandLine|contains:
         - '/create'
         - '-create'
         - '/run'
         - '-run'
         - '/change'
         - '-change'
     condition: selection
   falsepositives:
     - 合法的软件安装或更新
     - 管理员手动创建的任务
   level: medium
   ```

3. **Elastic规则**：
   ```plaintext
   event.action:"Process Create (rule: ProcessCreate)" and
   process.name:schtasks.exe and process.args:(-change or -create or -run or /change or /create or /run)
   ```

4. **任务调度器日志规则**：
   - 监控任务创建、启用或更新事件。
   - Splunk查询：
     ```spl
     source="Microsoft-Windows-TaskScheduler/Operational" (EventCode=4698 OR EventCode=4700 OR EventCode=4702) | stats count by TaskName, Action, User, ComputerName
     ```

5. **文件系统监控**：
   - 监控`%systemroot%\System32\Tasks`目录的创建或修改。
   - Sysmon配置：
     ```xml
     <Sysmon schemaversion="4.81">
       <EventFiltering>
         <FileCreate onmatch="include">
           <TargetFilename condition="contains">%SystemRoot%\System32\Tasks</TargetFilename>
         </FileCreate>
       </EventFiltering>
     </Sysmon>
     ```

6. **威胁情报整合**：
   - 检查任务执行的命令或文件路径是否与已知恶意活动相关，结合威胁情报平台（如VirusTotal、AlienVault）。

## 建议

### 缓解措施

防御`schtasks`本地计划任务的恶意使用需从权限控制、系统加固和监控入手：

1. **限制schtasks使用**  
   - 配置AppLocker或组策略，限制非管理员用户运行`schtasks.exe`。  

2. **禁用不必要的计划任务**  
   - 配置组策略，禁止非管理员创建计划任务：  
     - 路径：`计算机配置 > 管理模板 > Windows组件 > 任务计划程序 > 禁止非管理员创建任务`。

3. **网络访问控制**  
   - 限制RPC（端口135）和SMB（端口445）的外部访问，仅允许白名单IP。  
   - 配置防火墙阻止未经授权的远程任务调度。

4. **凭据保护**  
   - 启用多因素认证（MFA）保护管理员账户。  
   - 实施强密码策略，避免凭据泄露。

5. **日志和监控**  
   - 启用命令行参数记录，增强Windows安全日志（事件ID 4688）或Sysmon（事件ID 1）监控。  
   - 配置SIEM检测`schtasks.exe`的异常命令行模式和任务调度器日志。

6. **定期审计**  
   - 使用Sysinternals Autoruns检查`%systemroot%\System32\Tasks`中的任务，识别与已知软件无关的异常任务。

### 检测

检测工作应集中在`schtasks`创建或修改本地计划任务的行为上，包括但不限于：  
- **进程行为监控**：分析Sysmon或Windows安全日志，检测`schtasks.exe`使用`/create`、`/run`、`/change`等参数。  
- **任务调度器监控**：检查任务调度器日志（事件ID 4698、4700、4702），识别异常任务创建或更新。  
- **文件系统监控**：监控`%systemroot%\System32\Tasks`目录的更改，检测未知任务文件。  
- **威胁情报整合**：结合威胁情报，检查任务执行的命令或文件是否与已知恶意活动相关。

## 参考推荐

- MITRE ATT&CK: T1053.005  
  <https://attack.mitre.org/techniques/T1053/005/>  
- Schtasks命令详解  
  <https://www.cnblogs.com/daimaxuejia/p/12957644.html>  
- Elastic: Local Scheduled Task Commands  
  <https://www.elastic.co/guide/en/siem/guide/current/local-scheduled-task-commands.html>