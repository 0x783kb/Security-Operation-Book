# T1049/1069-bloodhound使用

## 来自ATT&CK的描述

T1049:攻击者可能会通过查询网络上的信息来尝试获取与他们当前正在访问的受感染系统之间或从远程系统获得的网络连接的列表。
T1069:攻击者可能会尝试查找本地系统或域级别的组和权限设置。

## 测试案例

BloodHound是一种单页的JavaScript的Web应用程序，构建在Linkurious上，用Electron编译，NEO4J数据库是PowerShell/C# ingestor.
BloodHound使用可视化图来显示Active Directory环境中隐藏的和相关联的主机内容。攻击者可以使用BloodHound轻松识别高度复杂的攻击路径，否则很难快速识别。防御者可以使用BloodHound来识别和防御那些相同的攻击路径。蓝队和红队都可以使用BloodHound轻松深入了解Active Directory环境中的权限关系。

## 检测日志

windows 安全日志

## 测试复现

```dos
 SharpHound.exe -c ALL
```

## 测试留痕

windows安全日志、5145

## 检测规则/思路

```yml
title: win-bloodhound使用
description: windows server 2012
references:
tags: T1049/1069
status: experimental
author: 12306Bro
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5145 #已检查网络共享对象是否可以授予客户端所需的访问权限。
        Objecttype: 'File' #网络信息>对象类型
        Sourceaddress: '*' #网络信息>源地址
        sourceport: '*' #网络信息>源端口
        ShareName: '\\*\IPC$' #共享信息>共享名称
        Relativetargetname:  #共享信息>相对目标名称
        - NETLOGON
        - lsarpc
        - samr
        - srvsvc
        - winreg
        - wkssvc
    timeframe: last 30s #可根据实际情况调整
    condition: all of them
level: medium
```

注意，短时间内同一IP产生多个事件，多个事件中的相对目标名称包含以上特征值，其中源IP、源端口固定。

## 参考推荐

MITRE-ATT&CK-T1049：<https://attack.mitre.org/techniques/T1049/>
MITRE-ATT&CK-T1069：<https://attack.mitre.org/techniques/T1069/>
bloodhound：<https://github.com/BloodHoundAD/BloodHound>
域分析神器：<https://www.cnblogs.com/KevinGeorge/p/10513211.html>
