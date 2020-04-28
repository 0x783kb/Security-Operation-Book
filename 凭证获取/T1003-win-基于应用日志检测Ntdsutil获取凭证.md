# T1003-win-基于应用日志检测Ntdsutil获取

## 来自ATT&CK的描述

凭证获取是从操作系统和软件中获取登录信息和密码的过程，通常为HASH散列或明文密码。然后使用凭证进行横向移动访问其他系统。

### NTDS.dit

Ntds.dit文件是存储Active Directory数据的数据库，包括有关用户对象，组和组成员身份的信息。它包括域中所有用户的密码哈希值。域控制器（DC）上的ntds.dit文件只能由可以登录到DC的用户访问。很明显，保护这个文件至关重要，因为攻击者访问这个文件会导致整个域沦陷。

**默认情况下，NTDS文件将位于域控制器的％SystemRoot％\NTDS\Ntds.dit中。**但通常存储在其他逻辑驱动器上）。AD数据库是一个Jet数据库引擎，它使用可扩展存储引擎（ESE）提供数据存储和索引服务。通过ESE级别索引，可以快速定位对象属性。

## 测试案例

参考链接：
域渗透——获得域控服务器的NTDS.dit文件：<https://blog.csdn.net/Fly_hps/article/details/80641987>

## 检测日志

windows 应用日志

## 测试复现

![ntds0](https://s2.ax1x.com/2020/01/14/lqUbDJ.png)

## 测试留痕

windows 应用日志留痕文件：<https://github.com/12306Bro/Threathunting-book/blob/master/Eventdata/ntds.evtx>

## 检测规则/思路

```yml
title: 应用日志检测ntdsutil获取NTDS.dit文件
description: windows server 2008 + AD域控
references: https://blog.csdn.net/Fly_hps/article/details/80641987
tags: T1003
status: experimental
author: 12306Bro
logsource:
    product: windows
    service: application
detection:
    selection1:
        EventID: 2005
        Message: 'lsass (*) 卷影复制实例 * 正在启动。这将是一次完整的卷影复制。' #*号代表任意数值匹配
    selection2:
        EventID: 2001
        Message: 'lsass (*) 卷影副本实例 * 冻结已开始。' #*号代表任意数值匹配
    selection3:
        EventID: 2003
        Message: 'lsass (*) 卷影副本实例 * 冻结已停止。' #*号代表任意数值匹配
    selection4:
        EventID: 2006
        Message: 'lsass (*) 卷影复制实例 * 已成功完成。' #*号代表任意数值匹配
    selection5:
        EventID: 300
        Message: lsass (*) 数据库引擎正在初始化恢复步骤。 #*号代表任意数值匹配
    selection6:
        EventID: 216 #期间触发大量216事件
        Message: 'lsass (*) 检测到数据库位置从“C:\Windows\NTDS\ntds.dit”更改为“\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy*1*\Windows\NTDS\ntds.dit”。' #*号代表任意数值匹配
    selection7:
        EventID: 302
        Message: 'lsass (*) 数据库引擎已成功完成恢复步骤。' #*号代表任意数值匹配
​    timeframe: last 10S #自定义时间范围
    condition: all of them
level: medium
```

注意：此检测仅适用于windows AD域控主机。

## 参考推荐

MITRE-ATT&CK-T1003

<https://attack.mitre.org/techniques/T1003/>

域渗透——获得域控服务器的NTDS.dit文件

<https://xz.aliyun.com/t/2187>

NTDS.dit密码快速提取工具

<https://www.secpulse.com/archives/6301.html>

MITRE ATT&CK攻击知识库（企业）中文版

<https://hansight.github.io/#/>
