# T1059-Win-使用wusa卸载系统更新

## 描述

攻击者可能利用Windows命令行界面工具（如`wusa.exe`）与系统交互，执行恶意操作以实现防御规避或持久性（T1059）。`wusa.exe`（Windows Update Standalone Installer）是Windows操作系统内置的命令行工具，用于安装或卸载Windows更新补丁（`.msu`文件）。攻击者可滥用`wusa.exe`卸载特定的系统更新（如KB890830，Windows恶意软件删除工具），以移除安全补丁或检测工具，从而为后续攻击铺路。由于`wusa.exe`是白名单进程，其行为可能被误认为是合法操作，增加检测难度。

常见攻击场景包括通过`wusa.exe`的`/uninstall`参数静默卸载安全更新，结合`/quiet`和`/norestart`选项避免用户察觉。检测重点在于监控`wusa.exe`的命令行参数（如`/uninstall`或`/extract`）以及异常的父进程和上下文。

## 测试案例

1. **卸载安全更新**  
   攻击者使用`wusa.exe /uninstall /kb:890830 /quiet /norestart`卸载Windows恶意软件删除工具（KB890830）。

2. **提取更新内容**  
   攻击者通过`wusa.exe /extract`提取更新包内容，可能用于分析或篡改。

## 检测日志

**Windows安全日志**  
- **事件ID 4688**：记录进程创建，包含`wusa.exe`的命令行参数（需启用命令行记录）。  
- **事件ID 4689**：记录进程终止，可能用于关联进程生命周期。

**Sysmon日志**  
- **事件ID 1**：记录进程创建，包含`wusa.exe`的完整命令行、父进程和子进程信息。  
- **事件ID 11**：记录文件创建或写入，可能涉及提取的更新文件。

**Windows更新日志**  
- **Microsoft-Windows-WindowsUpdateClient/Operational**：记录更新安装或卸载事件。  
  - 事件ID 19：更新安装完成。  
  - 事件ID 20：更新卸载完成。

**配置日志记录**  
- 启用命令行参数记录：  
  - 路径：`本地计算机策略 > 计算机配置 > 管理模板 > 系统 > 审核进程创建 > 在进程创建事件中加入命令行 > 启用`（Windows Server 2008及以上）。  
- 部署Sysmon以增强进程和文件活动监控。

## 测试复现

### 环境准备
- **靶机**：Windows Server 2019或Windows 10，安装Sysmon并启用Windows安全日志。  
- **权限**：测试账户需具备管理员权限（`wusa.exe`卸载更新需要高权限）。  
- **更新**：确保目标更新（如KB890830）已安装，可通过`wmic qfe list`检查。

### 攻击步骤
1. **检查已安装更新**  
   在靶机上运行以下命令，确认KB890830是否存在：
   ```cmd
   wmic qfe list | findstr "890830"
   ```

2. **执行卸载命令**  
   在命令提示符（以管理员身份运行）中执行：
   ```cmd
   wusa /uninstall /kb:890830 /quiet /norestart
   ```

## 测试留痕

```yml
日志名称:          Security
来源:            Microsoft-Windows-Security-Auditing
日期:            2022/12/26 16:33:23
事件 ID:         4688
任务类别:          Process Creation
级别:            信息
关键字:           审核成功
用户:            暂缺
计算机:           WIN-SAPNNP06AE5.jackma.com
描述:
已创建新进程。

创建者主题:
	安全 ID:		JACKMA\Administrator
	帐户名:		Administrator
	帐户域:		JACKMA
	登录 ID:		0x73509

目标主题:
	安全 ID:		NULL SID
	帐户名:		-
	帐户域:		-
	登录 ID:		0x0

进程信息:
	新进程 ID:		0xf88
	新进程名称:	C:\Windows\System32\wusa.exe
	令牌提升类型:	%%1936
	强制性标签:		Mandatory Label\High Mandatory Level
	创建者进程 ID:	0xa78
	创建者进程名称:	C:\Windows\System32\cmd.exe
	进程命令行:	wusa  /uninstall /kb:890830 /quiet /norestart
```

## 检测规则/思路

**检测规则**  
通过分析Sysmon、Windows安全日志和Windows更新日志，检测`wusa.exe`卸载系统更新的异常行为。以下是具体思路：

1. **日志分析**：
   - 收集Sysmon事件ID 1或Windows安全事件ID 4688，提取`wusa.exe`的命令行参数，重点关注`/uninstall`、`/extract`、`/quiet`和`/norestart`。  
   - 监控Windows更新日志（事件ID 20），检测关键安全更新的卸载事件。  
   - 检查`wusa.exe`的父进程，识别是否由异常进程（如`powershell.exe`）启动。

2. **Sigma规则**：
   ```yaml
   title: 使用wusa卸载系统更新
   id: 4d5e6f7a-8b9c-0d1e-2f3c-4d5e6f7a8b9c
   status: stable
   description: 检测wusa.exe卸载系统更新补丁，可能表明防御规避行为
   references:
     - https://attack.mitre.org/techniques/T1059/
     - https://jingyan.baidu.com/article/75ab0bcbe20d5b97864db2ff.html
   tags:
     - attack.execution
     - attack.defense_evasion
     - attack.t1059
   logsource:
     category: process_creation
     product: windows
   detection:
     selection:
       Image|endswith: '\wusa.exe'
       CommandLine|contains:
         - '/uninstall'
         - '-uninstall'
         - '/extract'
         - '-extract'
     condition: selection
   fields:
     - CommandLine
     - ParentCommandLine
   falsepositives:
     - 合法的系统维护操作
     - 管理员手动卸载更新
   level: medium
   ```

3. **SIEM规则**：
   - 检测`wusa.exe`的卸载或提取行为。
   - 示例Splunk查询：
     ```spl
     source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\wusa.exe" (CommandLine="*uninstall*" OR CommandLine="*extract*") | stats count by Image, CommandLine, ParentImage, ComputerName, User
     ```

4. **更新日志监控**：
   - 检测关键安全更新的卸载事件。
   - 示例Splunk查询：
     ```spl
     source="WinEventLog:Microsoft-Windows-WindowsUpdateClient/Operational" EventCode=20 UpdateTitle="*KB890830*" | stats count by UpdateTitle, Status, ComputerName
     ```

5. **威胁情报整合**：
   - 检查卸载的更新（如KB890830）是否为已知安全补丁，结合威胁情报平台（如VirusTotal、AlienVault）分析后续行为。

## 建议

### 缓解措施

防御`wusa.exe`的恶意使用需从权限控制、系统加固和监控入手：

1. **限制Wusa执行**  
   - 配置AppLocker或组策略，限制非管理员用户运行`wusa.exe`。  

2. **限制更新卸载**  
   - 配置组策略，禁止用户卸载Windows更新：  
     - 路径：`计算机配置 > 管理模板 > Windows组件 > Windows更新 > 配置自动更新`。

3. **权限控制**  
   - 确保`wusa.exe`操作需要管理员权限，限制普通用户执行高权限命令。  
   - 启用用户账户控制（UAC），提示高权限操作。

4. **凭据保护**  
   - 启用多因素认证（MFA）保护管理员账户。  
   - 实施强密码策略，避免凭据泄露。

5. **日志和监控**  
   - 启用命令行参数记录，增强Windows安全日志（事件ID 4688）或Sysmon（事件ID 1）监控。  
   - 配置SIEM检测`wusa.exe`的`/uninstall`或`/extract`行为。  
   - 使用EDR/EPP工具监控`wusa.exe`的命令行参数和进程行为。

6. **定期审计**  
   - 使用`wmic qfe list`或PowerShell命令（如`Get-HotFix`）定期检查系统更新状态，识别异常卸载。  

### 检测

检测工作应集中在`wusa.exe`的卸载或提取行为上，包括但不限于：  
- **进程行为监控**：分析Sysmon或Windows安全日志，检测`wusa.exe`使用`/uninstall`或`/extract`参数。  
- **更新状态监控**：检查Windows更新日志，识别关键安全补丁的卸载事件。  
- **父进程分析**：检测`wusa.exe`是否由异常父进程（如`powershell.exe`）启动。  
- **威胁情报整合**：结合威胁情报，分析卸载的更新是否与已知攻击活动相关。

## 参考推荐

- MITRE ATT&CK: T1059  
  <https://attack.mitre.org/techniques/T1059/>  
- Win10 wusa命令卸载系统更新  
  <https://jingyan.baidu.com/article/75ab0bcbe20d5b97864db2ff.html>