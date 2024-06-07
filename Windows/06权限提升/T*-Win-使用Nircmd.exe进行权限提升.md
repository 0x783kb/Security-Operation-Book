# T*-Win-使用Nircmd.exe进行权限提升

## 来自ATT&CK的描述

暂无编号，无描述

## 测试案例

Nircmd.exe是一个Windows命令行工具，由NirSoft开发，用于执行各种系统命令而无需显示用户界面。它包括一个名为elevate的参数，该参数可以用于以管理员权限运行命令或程序。

以下是一些关于使用Nircmd.exe进行权限提升的例子：

### 以管理员权限运行程序：

使用Nircmd.exe的elevate参数可以启动一个程序或命令，使其以管理员权限运行。例如：

```bash
nircmd.exe elevate "C:\Program Files\SomeProgram\program.exe"
```

### 以管理员权限执行命令：

如果需要执行系统命令，比如重启服务，可以使用以下命令：

```bash
nircmd.exe elevate net stop "SomeServiceName"
```

### 在脚本中使用：

在自动化脚本中，特别是在需要管理员权限执行操作时，可以将Nircmd.exe与elevate参数结合使用。例如，在批处理脚本中：

```bash
nircmd.exe elevate "cmd /c your-command-here"
```

### 在Java应用程序中使用：

如果你在Java应用程序中需要以管理员权限执行命令，可以使用Runtime.exec()方法，并结合Nircmd.exe：

```bash
Runtime.getRuntime().exec("c:\\path\\to\\nircmd.exe elevate your-command-here");
```

### 解决权限不足问题：

当Java应用程序尝试执行需要更高权限的操作时，可能会遇到权限不足的问题。使用Nircmd.exe的elevate参数可以解决这个问题。

## 检测日志

Windows安全日志

## 测试复现

```bash
Microsoft Windows [版本 10.0.14393]
(c) 2016 Microsoft Corporation。保留所有权利。

C:\Users\jackma\Desktop\nircmd-x64>nircmd.exe elevate c:\Windows\System32\cmd.exe
```

在实际测试过程中，会有弹窗提醒，点击确认后，cmd.exe以管理员身份打开。

## 测试留痕

Windows安全事件4688

```yml
EventData 

  SubjectUserSid S-1-5-18 
  SubjectUserName MAJACK2F2D$ 
  SubjectDomainName ABD 
  SubjectLogonId 0x3e7 
  NewProcessId 0x1b4c 
  NewProcessName C:\Windows\System32\cmd.exe 
  TokenElevationType %%1937 
  ProcessId 0x39a8 
  CommandLine "C:\Windows\System32\cmd.exe"  
  TargetUserSid S-1-5-21-1383307475-1342307136-805210941-1000 
  TargetUserName jackma 
  TargetDomainName ABD 
  TargetLogonId 0x17a295 
  ParentProcessName C:\Users\jackma\Desktop\nircmd-x64\nircmd.exe 
  MandatoryLabel S-1-16-12288 
```

## 检测规则/思路

### sigma规则

```yml
title: 使用Nircmd.exe进行权限提升
author: 0x783kb
date: 2024/06/07
logsource:
    product: Windows
    service: security
detection:
    selection:
        EventID: 4688
    ParentProcessName: 'nircmd.exe'
    condition: selection
level: Medium
```

### 建议

如果应用程序是合法使用的，则可能会出现误报，并根据需要按用户或终端进行过滤。

## 参考推荐

Nircmd主页

<https://www.nirsoft.net/utils/nircmd.html>

官方64位下载地址

<http://www.nirsoft.net/utils/nircmd-x64.zip>
