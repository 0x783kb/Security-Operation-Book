# T1059-win-使用wusa卸载系统更新

## 来自ATT&CK的描述

命令行界面是与计算机系统交互的一种方式，并且是很多操作系统平台的常见特性。例如，Windows系统上的命令行界面cmd可用于执行许多任务，包括执行其他软件。命令行界面可在本地交互或者通过远程桌面应用、反向shell会话等远程交互。执行的命令以命令行界面进程的当前权限级别运行，除非该命令需要调用进程来更改权限上下文（例如，定时任务）。

攻击者可能会使用命令行界面与系统交互并在操作过程中执行其他软件。

如果想要卸载恶意软件删除工具，需要知道它的编号(比如KB890830)，那么就可以根据这个来卸载它。输入并回车执行'wusa /uninstall /kb:890830 /quiet /norestart'命令。命令代表使用Windows更新程序在静默且不重启的模式下来卸载编号为890830的更新。

更多使用方法可在powershell管理员权限下输入wusa，查看提示。

## 检测日志

Windows 安全日志

## 测试复现

```yml
C:\Users\Administrator>wusa

C:\Users\Administrator>wusa /uninstall /kb:890830 /quiet /norestart
```

## 测试留痕

```yml
日志名称:          Security
来源:            Microsoft-Windows-Security-Auditing
日期:            2022/12/26 16:33:23
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
	新进程 ID:		0xf88
	新进程名称:	C:\Windows\System32\wusa.exe
	令牌提升类型:	%%1936
	强制性标签:		Mandatory Label\High Mandatory Level
	创建者进程 ID:	0xa78
	创建者进程名称:	C:\Windows\System32\cmd.exe
	进程命令行:	wusa  /uninstall /kb:890830 /quiet /norestart

“令牌提升类型”表示根据用户帐户控制策略分配给新进程的令牌类型。

类型 1 是未删除特权或未禁用组的完全令牌。完全令牌仅在禁用了用户帐户控制或者用户是内置管理员帐户或服务帐户的情况下使用。

类型 2 是未删除特权或未禁用组的提升令牌。当启用了用户帐户控制并且用户选择使用“以管理员身份运行”选项启动程序时，会使用提升令牌。当应用程序配置为始终需要管理特权或始终需要最高特权并且用户是管理员组的成员时，也会使用提升令牌。

类型 3 是删除了管理特权并禁用了管理组的受限令牌。当启用了用户帐户控制，应用程序不需要管理特权并且用户未选择使用“以管理员身份运行”选项启动程序时，会使用受限令牌。
```

## 检测规则/思路

### sigma规则

```yml
title: 使用wusa卸载系统更新
status: experimental
description: windows server 2019测试，使用wusa卸载系统更新补丁。
tags:
    - attack.t1059
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine1: 'wusa'
        CommandLine2: 
		   - 'uninstall'
		   - 'extract'
    condition: selection all
level: medium
```

### 建议

建议使用EDR/EPP等对进程命令行参数进行监测。如果能够采集到精准的Windows安全日志/Sysmon日志，可以基本此两类日志进行监测。

## 参考推荐

MITRE-ATT&CK-T1059

<https://attack.mitre.org/techniques/T1059/>

Win10 wusa命令卸载系统更新

<https://jingyan.baidu.com/article/75ab0bcbe20d5b97864db2ff.html>
