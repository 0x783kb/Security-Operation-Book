# T1064-linux-脚本

## 来自ATT&CK的描述

攻击者可以使用脚本来帮助操作并执行多个操作，否则这些操作将是手动执行的。脚本执行对于加速操作任务和减少访问关键资源所需的时间非常有用。一些脚本语言可用于通过在API级别直接与操作系统交互而不是调用其他程序来绕过进程监视机制。Windows的常用脚本语言包括VBScript和PowerShell，但也可以采用命令行批处理脚本的形式。

脚本可以作为宏嵌入Office文档中，可以设置为在鱼叉式钓鱼附件或其他类型的鱼叉式网页钓鱼中使用的文件，在受害者打开时执行。 恶意嵌入式宏是一种替代的执行方式，而不是通过客户端执行漏洞利用软件，其中攻击者会将文件附加到鱼叉式网络钓鱼电子邮件中，并且通常依靠用户执行来获取执行权。

网络上公开了很多优秀的攻击框架，他们允许安全测试人员和攻击者以脚本的形式进行攻击测试。Metasploit、vial、powersploit是渗透测试人员在漏洞利用和后渗透阶段中经常用到的三款典型工具，包括逃避防御检测的功能。

## 测试案例

如何在linux下进行模拟和测试？我们可以创建一个简单bash脚本，并执行它。观察它在日志中留下的痕迹。

## 检测日志

linux audit日志 （值得注意的是：Ubuntu默认情况下没有audit，需要下载安装并配置相关策略）

## 测试复现

icbc@icbc:/hacker$ bash 1.bash

## 测试留痕

icbc@icbc:/$ cat /var/log/audit/audit.log

type=SYSCALL msg=audit(1565352677.388:1524): arch=c000003e syscall=59 success=yes exit=0 a0=564608ddc330 a1=564608dbd8c0 a2=564608de3970 a3=8 items=2 ppid=2095 pid=2807 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=4 comm="bash" exe="/usr/bin/bash" key="auditcmd"
type=EXECVE msg=audit(1565352677.388:1524): argc=2 a0="bash" a1="1.bash"
type=CWD msg=audit(1565352677.388:1524): cwd="/hacker"
type=PATH msg=audit(1565352677.388:1524): item=0 name="/usr/bin/bash" inode=2228277 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0

## 检测规则/思路

index = linux sourcetype = linux_audit syscall = 59  | table host，syscall，syscall_name，exe，auid

值得注意的是：我们只是把环境中的脚本执行行为记录下来，如果没有设置白名单，那么我们需要消耗大量的精力用于处理误报。

## 参考推荐

MITRE-ATT&CK-T1064

<https://attack.mitre.org/techniques/T1064/>

Audit配置手册

s<https://www.cnblogs.com/bldly1989/p/7204358.html>
