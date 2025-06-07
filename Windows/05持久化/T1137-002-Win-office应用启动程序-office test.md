# T1137-002-Win-Office应用启动程序-Office Test

## 描述

攻击者可能滥用Microsoft Office的“Office Test”注册表键实现系统持久化（T1137.002）。该注册表键允许用户指定任意DLL，在每次启动Office应用程序（如Word、Excel）时加载执行。此功能原为Microsoft开发Office时的测试和调试用途，默认安装不创建相关键。攻击者可通过添加或修改以下注册表位置，加载恶意DLL：

```plaintext
HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf
HKEY_LOCAL_MACHINE\Software\Microsoft\Office test\Special\Perf
```

`HKCU`键影响当前用户，`HKLM`键影响所有用户。攻击者需具备相应权限（如管理员权限修改`HKLM`），并将恶意DLL路径写入注册表。Office启动时会加载该DLL，执行恶意代码，实现持久化。此技术隐蔽性较高，因其不依赖常见持久化机制（如启动项）。检测重点在于监控注册表键的创建/修改及Office进程的异常DLL加载。

## 测试案例

1. **Office Test注册表持久化**  
   攻击者通过`reg add`命令创建`Office Test`注册表键，指定恶意DLL路径，在Office启动时执行。  
2. **伪装合法DLL**  
   攻击者将恶意DLL命名为类似系统DLL的名称（如`msvcr.dll`），降低被发现风险。  

## 检测日志

**Windows安全日志**  
- **事件ID 4688**：记录进程创建，可能涉及`reg.exe`或Office应用程序的执行。  

**Sysmon日志**  
- **事件ID 1**：记录进程创建，包含`reg.exe`或Office应用程序（如`winword.exe`）的命令行参数。  
- **事件ID 13**：记录注册表值修改，如`Office test\Special\Perf`键的创建或更新。  
- **事件ID 7**：记录DLL加载，检测Office进程加载的异常DLL。  

**配置日志记录**  
- 启用注册表审核：`计算机配置 > 策略 > Windows设置 > 安全设置 > 高级审核策略配置 > 对象访问 > 审核注册表`。  
- 启用命令行参数记录：`计算机配置 > 管理模板 > 系统 > 审核进程创建 > 在进程创建事件中加入命令行 > 启用`。  
- 部署Sysmon以增强注册表、进程和DLL加载监控。

## 测试复现

### 环境准备
- **靶机**：Windows 10或Windows Server 2012+，安装Microsoft Office（2016+）。  
- **权限**：本地管理员权限（修改`HKCU`无需管理员权限，修改`HKLM`需要）。  
- **工具**：测试用DLL（如`test.dll`），Sysmon及Windows安全日志启用。  

### 攻击步骤
1. **添加Office Test注册表键**  
   以管理员权限运行CMD，添加`HKCU`注册表键，指定DLL路径：
   ```dos
   reg add "HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf" /t REG_SZ /d "C:\Users\Administrator.ZHULI\Desktop\test.dll"
   ```

   **真实测试结果**：
   ```dos
   C:\Users\Administrator.ZHULI>reg add "HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf" /t REG_SZ /d "C:\Users\Administrator.ZHULI\Desktop\test.dll"
   操作成功完成。
   ```

2. **启动Office应用程序**  
   打开Word或Excel，触发DLL加载。  

3. **清理注册表（测试后）**  
   删除注册表键：
   ```dos
   reg delete "HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf" /f >nul 2>&1
   ```

   **真实测试结果**：
   ```dos
   C:\Users\Administrator.ZHULI>reg delete "HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf" /f >nul 2>&1
   ```

4. **验证结果**  
   - 检查注册表键：
     ```dos
     reg query "HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf"
     ```
   - 检查日志：  
     - **Sysmon日志（事件ID 13）**：
       ```plaintext
       EventID: 13
       EventType: SetValue
       UtcTime: 2022-01-11 06:27:59.168
       ProcessGuid: {78c84c47-236f-61dd-cf20-000000000800}
       ProcessId: 3312
       Image: C:\Windows\System32\reg.exe
       TargetObject: HKU\S-1-5-21-2729552704-1545692732-1695105048-500\Software\Microsoft\Office test\Special\Perf\(Default)
       Details: C:\Users\Administrator.ZHULI\Desktop\test.dll
       User: ZHULI\Administrator
       ```
     - **Sysmon日志（事件ID 7，DLL加载）**：
       ```plaintext
       EventID: 7
       Image: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
       ImageLoaded: C:\Users\Administrator.ZHULI\Desktop\test.dll
       User: ZHULI\Administrator
       ```

**注意**：此复现仅用于学习和测试目的，需在合法授权的测试环境中进行，切勿用于非法活动。

## 测试留痕

- **Sysmon日志（事件ID 1）**：
  ```plaintext
  EventID: 1
  RuleName: technique_id=T1112,technique_name=Modify Registry
  UtcTime: 2022-01-11 06:27:59.157
  ProcessGuid: {78c84c47-236f-61dd-cf20-000000000800}
  ProcessId: 3312
  Image: C:\Windows\System32\reg.exe
  CommandLine: reg add "HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf" /t REG_SZ /d "C:\Users\Administrator.ZHULI\Desktop\test.dll"
  User: ZHULI\Administrator
  IntegrityLevel: High
  ```
- **Sysmon日志（事件ID 13）**：
  ```plaintext
  EventID: 13
  EventType: SetValue
  UtcTime: 2022-01-11 06:27:59.168
  ProcessId: 3312
  Image: C:\Windows\System32\reg.exe
  TargetObject: HKU\S-1-5-21-2729552704-1545692732-1695105048-500\Software\Microsoft\Office test\Special\Perf\(Default)
  Details: C:\Users\Administrator.ZHULI\Desktop\test.dll
  User: ZHULI\Administrator
  ```
- **Sysmon日志（事件ID 7）**：
  ```plaintext
  EventID: 7
  Image: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
  ImageLoaded: C:\Users\Administrator.ZHULI\Desktop\test.dll
  Hashes: SHA256=<DLL_HASH>
  User: ZHULI\Administrator
  ```

## 检测规则/思路

**检测规则**  
通过分析Sysmon和Windows安全日志，检测Office Test注册表键的创建/修改及异常DLL加载。以下是具体思路：

1. **日志分析**：
   - 监控Sysmon事件ID 13，检测`HKCU\Software\Microsoft\Office test\Special\Perf`或`HKLM\Software\Microsoft\Office test\Special\Perf`的修改。  
   - 监控Sysmon事件ID 7，检测Office进程（如`winword.exe`）加载的非Office标准DLL。  
   - 监控Sysmon事件ID 1或Windows事件ID 4688，检测`reg.exe`的异常命令行（如添加`Office test`键）。  
   - 监控事件ID 4624，检测新DLL触发的异常登录行为。

2. **Sigma规则（注册表修改）**：
   ```yaml
   title: Office Test注册表键修改
   id: p1q2r3s4-t5u6-7890-vwxy-z1234567890
   status: stable
   description: 检测Office Test注册表键的创建或修改，可能表明持久化攻击
   references:
     - https://attack.mitre.org/techniques/T1137/002/
     - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1137.002/T1137.002.yaml
   tags:
     - attack.persistence
     - attack.t1137.002
   logsource:
     product: windows
     service: sysmon
   detection:
     selection:
       EventID: 13
       TargetObject|contains: '\Software\Microsoft\Office test\Special\Perf'
     condition: selection
   fields:
     - TargetObject
     - Details
     - Image
   falsepositives:
     - 合法的Office开发测试
   level: high
   ```

3. **Sigma规则（DLL加载）**：
   ```yaml
   title: Office进程加载异常DLL
   id: q2r3s4t5-u6v7-8901-wxyz-2345678901
   status: experimental
   description: 检测Office应用程序加载非标准DLL，可能与Office Test持久化相关
   logsource:
     product: windows
     service: sysmon
   detection:
     selection:
       EventID: 7
       Image|endswith:
         - '\winword.exe'
         - '\excel.exe'
         - '\powerpnt.exe'
       ImageLoaded|contains: '.dll'
       ImageLoaded|not_contains:
         - '\Microsoft Office\'
         - '\Windows\System32\'
         - '\Windows\SysWOW64\'
     condition: selection
   fields:
     - Image
     - ImageLoaded
     - User
   falsepositives:
     - 第三方Office插件
     - 开发环境中的合法DLL
   level: medium
   ```

4. **SIEM规则**：
   - 检测Office Test注册表修改及DLL加载。
   - 示例Splunk查询：
     ```spl
     source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=13 TargetObject="*Office test\Special\Perf*") OR (EventCode=7 Image IN ("*winword.exe","*excel.exe","*powerpnt.exe") ImageLoaded="*.dll" NOT ImageLoaded IN ("*Microsoft Office*","*System32*","*SysWOW64*")) | stats count by EventCode, TargetObject, Image, ImageLoaded, ComputerName
     ```

5. **注册表监控**：
   - 监控`HKCU\Software\Microsoft\Office test\Special\Perf`和`HKLM\Software\Microsoft\Office test\Special\Perf`的创建或修改。  
   - 示例PowerShell查询：
     ```powershell
     Get-ItemProperty -Path "HKCU:\Software\Microsoft\Office test\Special\Perf" -ErrorAction SilentlyContinue
     ```

6. **威胁情报整合**：
   - 检查DLL文件哈希或路径是否与已知恶意样本相关，结合威胁情报平台（如VirusTotal、AlienVault）。

## 建议

### 缓解措施

防御Office Test持久化需从注册表保护、DLL加载监控和权限控制入手：

1. **限制注册表访问**  
   - 配置ACL，限制非管理员用户对`HKCU\Software\Microsoft\Office test`和`HKLM\Software\Microsoft`的写入权限。  

3. **加强Office安全**  
   - 启用Office攻击面减少（ASR）规则，限制未知DLL加载。  
   - 配置组策略：`计算机配置 > 管理模板 > Microsoft Office > 安全设置 > 阻止不受信任的DLL`。

4. **网络访问控制**  
   - 限制Office应用程序的出站连接，防止恶意DLL发起网络通信。  

5. **凭据保护**  
   - 启用多因素认证（MFA）保护管理员账户。  
   - 使用强密码策略，避免弱凭据。

6. **日志和监控**  
   - 启用Sysmon事件ID 13和7，检测注册表修改及异常DLL加载。  
   - 配置SIEM监控`Office test\Special\Perf`相关事件。  
   - 使用EDR工具检测Office进程的非标准行为。

7. **定期审计**  
   - 检查Office Test注册表键是否存在。  

### 检测

检测工作应集中在注册表和DLL加载行为：  
- **注册表监控**：检测`Office test\Special\Perf`键的创建或修改（Sysmon事件ID 13）。  
- **DLL加载监控**：检测Office进程加载非标准DLL（Sysmon事件ID 7）。  
- **进程监控**：检测`reg.exe`的异常命令行（如添加`Office test`键，事件ID 4688或Sysmon事件ID 1）。  
- **多事件关联**：结合注册表修改和DLL加载事件，提高检测准确性。  
- **威胁情报整合**：分析DLL哈希或路径是否与已知恶意样本匹配。

## 参考推荐

- MITRE ATT&CK: T1137.002  
  <https://attack.mitre.org/techniques/T1137/002/>  
- Atomic Red Team: T1137.002  
  <https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1137.002/T1137.002.yaml>