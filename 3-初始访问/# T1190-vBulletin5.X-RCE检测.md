# T1190-vBulletin5.X-RCE检测

## 来自ATT&CK的描述

使用软件，数据或命令来利用面向Internet的计算机系统或程序中的弱点，从而导致意外或无法预期的行为。系统的弱点可能是错误、故障或设计漏洞。这些应用程序通常是网站，但是可以包括数据库（例如SQL），标准服务（例如SMB 或SSH）以及具有Internet可访问开放的任何其他应用程序，例如Web服务器和相关服务。根据所利用的缺陷，这可能包括“利用防御防卫”。

如果应用程序托管在基于云的基础架构上，则对其进行利用可能会导致基础实际应用受到损害。这可以使攻击者获得访问云API或利用弱身份和访问管理策略的路径。

对于网站和数据库，OWASP排名前10位和CWE排名前25位突出了最常见的基于Web的漏洞。

## 影响范围

```yml
Microsoft Exchange Server 2019 Cumulative Update 9
Microsoft Exchange Server 2019 Cumulative Update 8
Microsoft Exchange Server 2016 Cumulative Update 20
Microsoft Exchange Server 2016 Cumulative Update 19
Microsoft Exchange Server 2013 Cumulative Update 23
```

## 漏洞简介

ProxyShell是利用了Exchange服务器对于路径的不准确过滤导致的路径混淆生成的SSRF，进而使攻击者通过访问PowerShell端点。而在PowerShell端点可以利用Remote PowerShell来将邮件信息打包到外部文件，而攻击者可以通过构造恶意邮件内容，利用文件写入写出webshell，从而达成命令执行。

## 环境准备

Windows server 2012、Exchange 2016

## 漏洞POC

参考以下地址：

<https://github.com/dmaasland/proxyshell-poc>

<https://github.com/ktecv2000/ProxyShell>

## 检测日志

IIS日志、HTTP日志（多数加密，无法解密）

## 测试留痕

暂无，缺省

## 检测特征

```yml
#CVE-2021-34473-SSRF
W3CIISLog
| where sPort == 444
| where csUserName endswith "$"
| where csUriStem <> ```/rpc/rpcproxy.dll```
| where csUserAgent !has "EwsStoreDataProvider"
| where csUserAgent !has "EDiscovery"
| where csUserAgent <> ```ExchangeInternalEwsClient-AuditLog-ComplianceAuditService-AdminAuditWriter```
| where csUriStem <> ```/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application```
| project TimeGenerated, csMethod, csUriStem, csUriQuery, sPort, csUserAgent, csUserName, csCookie, scStatus
```

```yml
# Exchange-Powershell-via-SSRF
W3CIISLog
| where csUriStem == "/autodiscover/autodiscover.json"
| where csUriQuery has "PowerShell" | where csMethod == "POST"
```

```yml
#Exchange-ProxyShell-RBAC
Event 
| where Source == ```MSExchange RBAC```
| where EventID == 23
```

```yml
#Exchange-ProxyShell-SSRF
W3CIISLog
| where csUriStem == "/autodiscover/autodiscover.json"
| where csUriQuery has "&Email"
```

参考地址：<https://github.com/GossiTheDog/ThreatHunting/tree/master/AzureSentinel>

真实有效性未知，仅作参考。

## 参考推荐

MITRE-ATT&CK-T1190

<https://attack.mitre.org/techniques/T1190/>

Exchange ProxyShell漏洞复现及分析

<https://blog.riskivy.com/exchange-proxyshell%E6%BC%8F%E6%B4%9E%E5%A4%8D%E7%8E%B0%E5%8F%8A%E5%88%86%E6%9E%90/>

Exchange ProxyShell远程代码执行漏洞复现

<https://www.chainnews.com/articles/442832948653.htm>

FROM PWN2OWN 2021: A NEW ATTACK SURFACE ON MICROSOFT EXCHANGE - PROXYSHELL!

<https://www.zerodayinitiative.com/blog/2021/8/17/from-pwn2own-2021-a-new-attack-surface-on-microsoft-exchange-proxyshell>
