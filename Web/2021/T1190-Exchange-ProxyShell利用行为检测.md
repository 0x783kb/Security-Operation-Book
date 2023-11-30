# T1190-Exchange-ProxyShell利用行为检测

## 来自ATT&CK的描述

使用软件，数据或命令来利用面向Internet的计算机系统或程序中的弱点，从而导致意外或无法预期的行为。系统的弱点可能是错误、故障或设计漏洞。这些应用程序通常是网站，但是可以包括数据库（例如SQL），标准服务（例如SMB 或SSH）以及具有Internet可访问开放的任何其他应用程序，例如Web服务器和相关服务。根据所利用的缺陷，这可能包括“利用防御防卫”。

如果应用程序托管在基于云的基础架构上，则对其进行利用可能会导致基础实际应用受到损害。这可以使攻击者获得访问云API或利用弱身份和访问管理策略的路径。

对于网站和数据库，OWASP排名前10位和CWE排名前25位突出了最常见的基于Web的漏洞。

## ProxyShell

ProxyShell攻击链是2021年8月由安全研究员Kevin Beaumont发现的一系列Microsoft Exchange服务器漏洞。这些漏洞影响了Exchange Server 2016、Exchange Server 2019、Exchange Server 2021和Exchange Online。

ProxyShell攻击链由三个CVE漏洞组成：

- CVE-2021-34473：未经身份验证的用户可以通过修改请求头来访问Exchange服务器中的PowerShell端点。
- CVE-2021-34523：攻击者可以通过修改请求头来绕过Exchange服务器的身份验证。
- CVE-2021-31207：攻击者可以通过修改请求头来执行任意PowerShell脚本。

## 测试案例

参考Freebuf文章：MS Exchange攻击日志分析三

## 检测日志

MSExchange CmdletLogs

## 测试留痕

暂无

## 检测规则/思路

### sigma规则

```
title: Use MSExchange CmdletLogs or Powershell logs to monitor ProxShell vulnerability exploitation behavior
description: windows server 2016
author: DHZN
logsource:
    product: windows
    service: MSExchange CmdletLogs/PoweShell
detection:
    selection1:
        EventID: 1
        Message|contains|all: 
              - 'New-MailboxExportRequest'
              - 'FilePath'
    selection2:
        EventID: 4104
        Message|contains|all: 'Get-MailboxExportRequest'    
    condition: selection
level: medium
```

### 建议

暂无

## 参考推荐

[pst-want-shell-proxyshell-exploiting-microsoft-exchange-servers](https://www.mandiant.com/resources/blog/pst-want-shell-proxyshell-exploiting-microsoft-exchange-servers)

[ProxyShell漏洞复现](https://ad-calcium.github.io/2021/08/exchange-proxyshell%E5%A4%8D%E7%8E%B0/)
