# T1003-003-Win-ToDesk_向日葵密码读取

## 来自ATT&CK的描述

凭证获取是从操作系统和软件中获取登录信息和密码的过程，通常为HASH散列或明文密码。然后使用凭证进行横向移动访问其他系统。可通过T00ls论坛公布的工具，进行测试。

本次选取的测试工具如下：

<https://www.t00ls.com/viewthread.php?tid=72447&highlight=todesk>

<https://github.com/flydyyg/readTdose-xiangrikui>

## 测试案例

BypassAvGetToDeskInfo.exe

## 检测日志

Windows 安全日志

## 测试复现

测试环境：Windows10专业版 Todesk V4.7.4.8

### 测试一：BypassAvGetToDeskInfo.exe

测试环境下准备该工具，登录todesk账号密码：

<img width="961" alt="image" src="https://github.com/user-attachments/assets/e7d52e42-63e6-47d8-8cb8-eb1fa947e367">

### 测试二：readTdose-xiangrikui

通过Github下载该工具，对go文件进行编译，编译后放在Windows10环境下执行即可。

<img width="962" alt="image" src="https://github.com/user-attachments/assets/69672c4e-5dc4-441d-9716-d2561cb9c3fc">

## 测试留痕

### 测试一留痕

<img width="1120" alt="image" src="https://github.com/user-attachments/assets/869fe8a7-8c4e-4a47-a808-50651b26ba90">

<img width="1119" alt="image" src="https://github.com/user-attachments/assets/5d9ec78e-3c30-41ff-8efb-ae1cd1c24e82">

<img width="1108" alt="image" src="https://github.com/user-attachments/assets/9ccd12cc-b1dd-473d-a04b-bbcc104656fd">

<img width="1104" alt="image" src="https://github.com/user-attachments/assets/676e472c-698a-4fee-bea0-49fa7024e2d0">

在程序执行后，4688事件多次出现，可重点关注进程cdb.exe、conhost.exe以及进程命令行参数。

### 测试二留痕

<img width="1118" alt="image" src="https://github.com/user-attachments/assets/11d498d2-1941-4757-9c57-0fc0d885baeb">

<img width="1116" alt="image" src="https://github.com/user-attachments/assets/ae79df19-517a-45b9-92c9-b64ab270a227">

通过Windows安全日志未观测到具体留痕信息。

## 检测规则/思路

### sigma规则

```yml
title: 使用BypassAvGetToDeskInfo获取todesk账号密码
description: Windows10
status: experimental
author: 0x783kb
logsource:
    product: Windows
    service: Security
detection:
    selection:
        CommandLine: '*/cdb.exe -pv -p * -c *'
        NewProcessName: '*/cdb.exe'
    condition: selection
```

## 参考推荐

MITRE-ATT&CK-T1003

<https://attack.mitre.org/techniques/T1003/>

免杀-ToDesk密码查看工具

<https://www.t00ls.com/viewthread.php?tid=72447&highlight=todesk>

一键读取Todesk和向日葵密码

<https://www.t00ls.com/viewthread.php?tid=72452&highlight=todesk>









