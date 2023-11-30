# T1190-CVE-2020-0688漏洞利用检测

## 来自ATT&CK的描述

使用软件，数据或命令来利用面向Internet的计算机系统或程序中的弱点，从而导致意外或无法预期的行为。系统的弱点可能是错误、故障或设计漏洞。这些应用程序通常是网站，但是可以包括数据库（例如SQL），标准服务（例如SMB 或SSH）以及具有Internet可访问开放的任何其他应用程序，例如Web服务器和相关服务。根据所利用的缺陷，这可能包括“利用防御防卫”。

如果应用程序托管在基于云的基础架构上，则对其进行利用可能会导致基础实际应用受到损害。这可以使攻击者获得访问云API或利用弱身份和访问管理策略的路径。

对于网站和数据库，OWASP排名前10位和CWE排名前25位突出了最常见的基于Web的漏洞。

## ProxyLogon

在2023年3月份，微软公布了多个Microsoft Exchange的高危漏洞，通过组合利用这些漏洞可以在未经身份验证的情况下远程获取服务器权限。这套组合拳被称为ProxyLogon。安全研究员Orange Tsai于2020年底发现该系列漏洞并命名。

CVE-2021-26855是一个SSRF漏洞，利用该漏洞可以绕过Exchange的身份验证，CVE-2021-27065是一个文件写入漏洞。二者结合可以在未登录的状态下写入webshell。

想要成功的利用该漏洞，整个攻击链接可能经过以下步骤：

* 通过SSRF漏洞攻击，访问autodiscover.xml泄露LegacyDN信息。
* 在通过LegacyDN，获取SID。
* 然后通过合法的SID，获取exchange的有效cookie。
* 最后通过有效的cookie，对OABVirtualDirectory对象进行恶意操作，写入一句话木马，达到控制目标的效果。

## 测试案例

参考Freebuf文章：MS Exchange攻击日志分析三

## 检测日志

MSExchange CmdletLogs

## 测试留痕

暂无

## 检测规则/思路

### sigma规则

```
title: MSExchange CmdletLogs monitors ProxyLogon webshell writing behavior
description: windows server 2016
author: DHZN
logsource:
    product: windows
    service: MSExchange CmdletLogs
detection:
    selection:
        EventID: 1
        Message|contains|all: 
              - 'Set-'
              - 'VirtualDirectory'
              - '-ExternalUrl'
              - 'script'
    condition: selection
level: medium
```

### 建议

暂无

## 参考推荐

[ProxyLogon漏洞分析](https://hosch3n.github.io/2021/08/22/ProxyLogon%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/)

[Exchange漏洞分析（一）：SSRF RCE（CVE-2021-26855、CVE-2021-27065）](https://www.anquanke.com/post/id/259902)

[复现Microsoft Exchange Proxylogon漏洞利用链](https://xz.aliyun.com/t/9305#toc-8)

[Falcon Complete Stops Microsoft Exchange Server Zero-Day Exploits](https://www.crowdstrike.com/blog/falcon-complete-stops-microsoft-exchange-server-zero-day-exploits/)

[HAFNIUM targeting Exchange Servers with 0-day exploits](https://www.microsoft.com/en-us/security/blog/2021/03/02/hafnium-targeting-exchange-servers/)


