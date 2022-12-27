# T1562-win-使用Bcdedit禁用DEP安全机制

## 来自ATT&CK的描述

攻击者可能会恶意修改被攻击环境的组件，以阻碍或禁用防御机制。这不仅涉及损害预防性防御（如防火墙和防病毒），还涉及防御者可用于审核活动和识别恶意行为的检测功能。

## Windows安全机制-DEP（数据执行保护）

### 数据执行保护原理

DEP的主要作用是阻止数据页（默认的堆，栈以及内存池页）执行代码。分为软件DEP和硬件DEP，其中软件DEP就是SafeSEH。而硬件DEP操作系统会通过设置内存页的NX/XD属性标记是否运行在本页执行指令。

DEP分为4种工作态：

- Optin：默认仅保护Windows系统组件；
- Optout：为排除列表程序外的所有程序和服务启用DEP；
- AlwaysOn：对所有进程启用DEP保护；
- AlwaysOff：对所有进程都禁用DEP；

Visual Studio 2008之后默认开启DEP保护，编译的程序会在PE头中设置 IMAGE_DLLCHARACTERISTICS_NX_COMPAT标识，这个标识就在结构体IMAGE_OPTIONAL_HEADER 中DllCharacteristics，如果这个值被设为了0x0100表示采用了DEP保护编译。

### 局限性

1.并不是所有的CPU都支持DEP。
2.由于兼容性，不可能对所有的进程开辟DEP保护，这样会出现异常。对一些第三方插件DLL和ATL7.1或以前的程序版本，不会开启。
3.编译器中的/NXCOMPAT选项生成的程序，只会在Windows Vista以上的系统有效，在之前的系统会被忽略。
4.系统提供了某些API函数可以来控制DEP状态，早期的一些系统可以调用这些函数。


## 测试案例

Windows server 2019（测试）

```yml
1.bcdedit.exe /set {current} nx Alwaysoff ——关闭DEP
2.bcdedit.exe /set {current} nx Optin ——开启DEP
```

## 检测日志

windows安全日志

## 测试复现

```yml
C:\Users\Administrator>bcdedit.exe /set {current} nx Alwaysoff
操作成功完成。
```

## 测试留痕

```yml
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
	新进程 ID:		0x15e4
	新进程名称:	C:\Windows\System32\bcdedit.exe
	令牌提升类型:	%%1936
	强制性标签:		Mandatory Label\High Mandatory Level
	创建者进程 ID:	0xaf0
	创建者进程名称:	C:\Windows\System32\cmd.exe
	进程命令行:	bcdedit.exe  /set {current} nx Alwaysoff
```

## 检测规则/思路

### sigma规则

```yml
title: 使用bcdedit.exe关闭Windows DEP安全机制
status: experimental
logsource:
​    product: windows
​    service: security
detection:
​    selection:
​        EventID: 4688
​        CommandLine: 'bcdedit.exe * nx *'
​    condition: selection
level: medium
```

### 建议

主要以命令行参数作为监测依据，发现异常后可结合上下文告警信息进行确认分析。

## 参考推荐

MITRE-ATT&CK-T1562

<https://attack.mitre.org/techniques/T1562/>

Windows安全机制---数据执行保护：DEP机制

<https://blog.csdn.net/m0_37809075/article/details/83008617>
