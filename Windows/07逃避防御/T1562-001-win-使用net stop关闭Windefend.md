# T1562-001-win-使用net stop关闭部分服务

## 来自ATT&CK的描述

攻击者可能试图阻止由监测软件或进程捕获到的告警，以及事件日志被收集和分析。这可能包括修改配置文件或注册表项中的监测软件的设置，以达到逃避追踪的目的。

间谍软件和恶意软件仍然是一个严重的问题，微软开发了安全服务即Windows Defender和Windows防火墙，协助用户对抗这种威胁。如果关闭Windows Defender或Windows防火墙，应当引起管理员的注意，立即恢复windows Defender或windows防火墙，使其处于正常工作状态，调查并确定异常情况是否由用户正常操作引起的。

## 测试案例

Windows server 2019（注意权限问题）

```yml
net stop WinDefend
net stop SDRSVC
net stop vds
 
net stop SysMain
net stop FontCache
```

## 检测日志

windows安全日志

## 测试复现

```yml
C:\Users\Administrator>net stop windefend
发生系统错误 5。

拒绝访问。
```

## 测试留痕

```yml
日志名称:          Security
来源:            Microsoft-Windows-Security-Auditing
日期:            2022/12/26 16:54:49
事件 ID:         4688
任务类别:          Process Creation
级别:            信息
关键字:           审核成功
用户:            暂缺
计算机:           WIN-SAPNNP06AE5.jackma.com
描述:
已创建新进程。

创建者主题:
	安全 ID:		JACKMA\Administrator
	帐户名:		Administrator
	帐户域:		JACKMA
	登录 ID:		0x73509

目标主题:
	安全 ID:		NULL SID
	帐户名:		-
	帐户域:		-
	登录 ID:		0x0

进程信息:
	新进程 ID:		0x3c4
	新进程名称:	C:\Windows\System32\net.exe
	令牌提升类型:	%%1936
	强制性标签:		Mandatory Label\High Mandatory Level
	创建者进程 ID:	0xaf0
	创建者进程名称:	C:\Windows\System32\cmd.exe
	进程命令行:	net  stop windefend

已创建新进程。

创建者主题:
	安全 ID:		JACKMA\Administrator
	帐户名:		Administrator
	帐户域:		JACKMA
	登录 ID:		0x73509

目标主题:
	安全 ID:		NULL SID
	帐户名:		-
	帐户域:		-
	登录 ID:		0x0

进程信息:
	新进程 ID:		0xa20
	新进程名称:	C:\Windows\System32\net1.exe
	令牌提升类型:	%%1936
	强制性标签:		Mandatory Label\High Mandatory Level
	创建者进程 ID:	0x3c4
	创建者进程名称:	C:\Windows\System32\net.exe
	进程命令行:	C:\Windows\system32\net1  stop windefend
```

## 检测规则/思路

### sigma规则

```yml
title: 使用Net命令关闭系统服务
description: Windows server 2019测试，使用net stop关闭Windows defend服务。
status: experimental
logsource:
​    product: windows
​    service: security
detection:
​    selection:
​        EventID: 4688
​        CommandLine: 'net stop'
​    condition: selection
level: medium
```

### 建议

暂无

## 参考推荐

MITRE-ATT&CK-T1562-001

<https://attack.mitre.org/techniques/T1562/001/>
