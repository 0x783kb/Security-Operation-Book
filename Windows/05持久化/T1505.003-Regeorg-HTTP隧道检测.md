# T1505-003-Regeorg-HTTP隧道检测

## 描述

攻击者可能通过部署Web Shell在Web服务器上创建后门，以实现对目标系统的持久化访问（T1505.003）。Web Shell是一种运行在可公开访问Web服务器上的脚本，提供命令执行或系统交互接口，允许攻击者通过HTTP/HTTPS协议控制受害网络。Web Shell可以是服务器端脚本（如PHP、JSP、ASP）或客户端工具，具有高隐蔽性，常用于渗透内网。

**ReGeorg**是Web Shell工具reDuh的继任者，利用SOCKS5协议在会话层创建HTTP隧道，结合代理工具（如Proxifier）实现高效内网穿透。攻击者通过上传ReGeorg脚本（如`tunnel.jsp`）到受控Web服务器，配置HTTP隧道，访问内网资源（如RDP、Web服务）。ReGeorg通过伪装为正常HTTP流量，规避传统防火墙检测。检测重点在于识别ReGeorg的特征性URL参数（如`cmd=connect`）和异常流量模式。

## 测试案例

1. **ReGeorg HTTP隧道搭建**  
   攻击者在受控Web服务器上部署ReGeorg脚本，创建SOCKS5隧道，访问内网主机（如`172.17.0.2:80`）。  
2. **结合Proxifier代理**  
   攻击者使用Proxifier将本地流量通过ReGeorg隧道转发至内网。  
3. **伪装正常流量**  
   攻击者通过分块传输（`Transfer-Encoding: chunked`）或伪造合法HTTP头（如`User-Agent`）隐藏隧道流量。

参考测试案例：<https://cloud.tencent.com/developer/article/1779195>

## 检测日志

**Web服务器日志（HTTP日志）**  
- 记录HTTP请求的URL、查询参数、头信息（如`X-CMD`、`X-TARGET`）和响应状态。  
- 示例日志文件：`access.log`（Apache）、`iis.log`（IIS）。  

**网络流量日志**  
- 记录TCP/HTTP流量，包含源/目标IP、端口、协议和负载数据。  
- 工具：Wireshark、`tcpdump`。  

**Sysmon日志（Windows服务器）**  
- **事件ID 3**：记录Web服务器进程（如`apache.exe`）的网络连接。  
- **事件ID 11**：记录Web Shell脚本（如`tunnel.jsp`）的写入。  

**配置日志记录**  
- 启用Web服务器详细日志：记录完整的URL查询参数和HTTP头。  
- 配置WAF/IDS：捕获异常HTTP请求。  
- 部署Sysmon：监控Web服务器的文件和网络活动。  
- 使用`tcpdump`或NetFlow捕获网络流量。

## 测试复现

### 环境准备
- **靶机**：Web服务器（如Apache/Tomcat，IP：`182.x.x.x:8080`），运行ReGeorg脚本（如`tunnel.jsp`）。  
- **内网主机**：目标服务（如`172.17.0.2:80`，运行Web应用）。  
- **攻击机**：Kali Linux，安装`tcpdump`、Wireshark、Proxifier和ReGeorg。  
- **工具**：ReGeorg源码（<https://github.com/sensepost/reGeorg>）。  
- **日志**：启用Web服务器日志、Sysmon和网络流量捕获。

### 攻击步骤
1. **部署ReGeorg Web Shell**  
   - 将`tunnel.jsp`上传至受控Web服务器（如`/var/www/html/tunnel.jsp`）。  
   - 验证访问：`http://182.x.x.x:8080/tunnel.jsp`。  

2. **启动ReGeorg隧道**  
   - 在Kali上运行ReGeorg：
     ```bash
     python reGeorgSocksProxy.py -u http://182.x.x.x:8080/tunnel.jsp -p 1080
     ```
   - 配置Proxifier，将本地SOCKS5代理设置为`127.0.0.1:1080`。  

3. **访问内网资源**  
   - 使用`curl`通过隧道访问内网Web服务：
     ```bash
     curl -x socks5://127.0.0.1:1080 http://172.17.0.2/login.php
     ```

4. **捕获流量**  
   - 在Kali上使用`tcpdump`抓包：
     ```bash
     tcpdump -i eth0 -w kali.pcap
     ```
   - 在Web服务器上抓包：
     ```bash
     tcpdump -i eth0 -w server.pcap
     ```
   - 使用Wireshark分析流量，追踪TCP流。

5. **清理（测试后）**  
   - 删除Web Shell：`rm /var/www/html/tunnel.jsp`。  
   - 终止ReGeorg进程：`Ctrl+C`。  
   - 移除Proxifier代理配置。

### 流量特征
- **Kali抓包**：显示HTTP请求（如`GET /login.php`）和ReGeorg命令（`cmd=connect`、`cmd=forward`）。  
- **Web服务器抓包**：显示ReGeorg的POST请求，包含`X-CMD`头（如`CONNECT`、`READ`、`FORWARD`、`DISCONNECT`）和内网目标（如`X-TARGET: 172.17.0.2`）。  
- **内网主机抓包**：显示Web服务器作为跳板，请求内网资源（如`/login.php`）。

**注意**：此复现仅用于学习和测试目的，需在合法授权的测试环境中进行，切勿用于非法活动。

## 测试留痕

### Kali（攻击机）
- **tcpdump/Wireshark抓包**：
  ```plaintext
  GET /login.php HTTP/1.1
  Host: 172.17.0.2
  User-Agent: curl/7.68.0
  Accept: */*
  HTTP/1.1 200 OK
  Date: Thu, 17 Dec 2020 16:39:09 GMT
  Server: Apache/2.4.7 (Ubuntu)
  Content-Length: 1567
  Content-Type: text/html;charset=utf-8
  ```

### Web服务器（ServerA）
- **连接请求（cmd=connect）**：
  ```plaintext
  POST http://182.x.x.x:8080/tunnel.jsp?cmd=connect&target=172.17.0.2&port=80 HTTP/1.1
  Host: 182.x.x.x:8080
  Accept-Encoding: identity
  X-CMD: CONNECT
  X-TARGET: 172.17.0.2
  X-PORT: 80
  User-Agent: python-urllib3/1.26.2
  HTTP/1.1 200 OK
  Server: Apache-Coyote/1.1
  X-STATUS: OK
  Content-Length: 0
  ```
- **读取请求（cmd=read）**：
  ```plaintext
  POST /tunnel.jsp?cmd=read HTTP/1.1
  Host: 182.x.x.x:8080
  Accept-Encoding: identity
  X-CMD: READ
  Transfer-Encoding: chunked
  User-Agent: python-urllib3/1.26.2
  HTTP/1.1 200 OK
  X-STATUS: OK
  ```
- **转发请求（cmd=forward）**：
  ```plaintext
  POST /tunnel.jsp?cmd=forward HTTP/1.1
  Host: 182.x.x.x:8080
  Accept-Encoding: identity
  Content-Length: 83
  X-CMD: FORWARD
  GET /login.php HTTP/1.1
  Host: 172.17.0.2
  User-Agent: curl/7.68.0
  Accept: */*
  HTTP/1.1 200 OK
  X-STATUS: OK
  ```
- **断开请求（cmd=disconnect）**：
  ```plaintext
  POST /tunnel.jsp?cmd=disconnect HTTP/1.1
  Host: 182.x.x.x:8080
  Accept-Encoding: identity
  X-CMD: DISCONNECT
  HTTP/1.1 200 OK
  X-STATUS: OK
  ```

### 内网服务器
- **内网请求**：
  ```plaintext
  GET /login.php HTTP/1.1
  Host: 172.17.0.2
  User-Agent: curl/7.68.0
  Accept: */*
  HTTP/1.1 200 OK
  Server: Apache/2.4.7 (Ubuntu)
  Content-Length: 1567
  Content-Type: text/html;charset=utf-8
  ```

## 检测规则/思路

**检测规则**  
通过分析Web服务器日志和网络流量，检测ReGeorg的特征性HTTP请求和隧道行为。以下是具体思路：

1. **日志分析**：
   - 监控Web服务器日志，检测URL查询参数中的ReGeorg命令（如`cmd=connect`、`cmd=read`、`cmd=forward`、`cmd=disconnect`）。  
   - 检测HTTP头中的ReGeorg标记（如`X-CMD`、`X-TARGET`、`X-PORT`）。  
   - 监控Sysmon事件ID 3，检测Web服务器进程的异常网络连接（如内网IP）。  
   - 监控Sysmon事件ID 11，检测Web Shell文件的创建（如`tunnel.jsp`）。  

2. **Sigma规则（ReGeorg URL参数检测）**：
   ```yaml
   title: ReGeorg HTTP隧道检测
   id: x90123456-abcd789012-zab345678901
   status: stable
   description: 检测ReGeorg HTTP隧道的特征性URL参数和HTTP头
   references:
     - https://attack.mitre.org/techniques/T1505/003/
     - https://cloud.tencent.com/developer/article/1779195
     - https://github.com/sensepost/reGeorg
   tags:
     - attack.persistence
     - attack.t1505.003
   logsource:
     category: webserver
   detection:
     selection:
       uri_query|contains:
         - 'cmd=connect'
         - 'cmd=read'
         - 'cmd=forward'
         - 'cmd=disconnect'
       http_header|contains:
         - 'X-CMD:'
         - 'X-TARGET:'
         - 'X-PORT:'
     filter:
       http_method: POST
       http_referer: null
     condition: selection and filter
   fields:
     - uri_query
     - http_header
     - http_method
     - http_user_agent
   falsepositives:
     - 合法Web应用使用类似URL参数
   level: high
   ```

3. **Sigma规则（Web服务器异常网络连接）**：
   ```yaml
   title: Web服务器异常内网连接
   id: y01234567-abcd890123-abc456789012
   status: experimental
   description: 检测Web服务器向内网主机的异常连接，可能与HTTP隧道相关
   logsource:
     product: windows
     service: sysmon
   detection:
     selection:
       EventID: 3
       Image|endswith:
         - '\apache.exe'
         - '\httpd.exe'
         - '\tomcat.exe'
       DestinationIp|startswith:
         - '172.'
         - '10.'
         - '192.168.'
       DestinationPort:
         - 80
         - 443
         - 3389
     condition: selection
   fields:
     - Image
     - DestinationIp
     - DestinationPort
   falsepositives:
     - 合法内网Web服务调用
   level: medium
   ```

4. **SIEM规则**：
   - 检测ReGeorg请求和网络活动。
   - 示例Splunk查询：
     ```spl
     source="http:access_log" (uri_query IN ("*cmd=connect*","*cmd=read*","*cmd=forward*","*cmd=disconnect*") OR http_header IN ("X-CMD:*","X-TARGET:*","X-PORT:*")) method=POST | stats count by uri_query, http_header, src_ip, dest_ip
     ```

5. **流量分析**：
   - 使用Wireshark过滤ReGeorg流量：`http.request.uri contains "cmd="`。  
   - 检查分块传输（`Transfer-Encoding: chunked`）和异常`User-Agent`（如`python-urllib3`）。  

6. **威胁情报整合**：
   - 检查Web Shell文件哈希或C2 URL是否与已知恶意样本匹配，结合威胁情报平台（如VirusTotal、AlienVault）。  

## 建议

### 缓解措施

防御ReGeorg HTTP隧道需从Web服务器安全、流量监控和检测入手：

1. **Web服务器加固**  
   - 定期扫描Web目录，检测未授权文件（如`tunnel.jsp`）。  
     ```bash
     find /var/www -name "*.jsp" -exec grep "cmd=" {} \;
     ```
   - 限制Web服务器目录写权限：
     ```bash
     chmod -R 755 /var/www/html
     chown -R www-data:www-data /var/www/html
     ```

2. **限制Web Shell执行**  
   - 配置WAF规则，拦截包含`cmd=`、`X-CMD`的请求。  
   - 禁用不必要的脚本引擎（如PHP、JSP）。  

3. **网络控制**  
   - 限制Web服务器访问内网资源：
     ```bash
     iptables -A OUTPUT -p tcp -d 172.0.0.0/8 -j DROP
     ```
   - 配置IDS/IPS检测SOCKS5隧道特征。  

4. **日志和监控**  
   - 启用详细HTTP日志，记录URL参数和头信息。  
   - 配置Sysmon监控Web服务器的文件和网络活动。  
   - 使用EDR工具检测Web Shell行为。  

5. **定期审计**  
   - 检查Web服务器日志中的异常POST请求：
     ```bash
     grep "cmd=" /var/log/apache2/access.log
     ```
   - 审计Web服务器文件完整性：
     ```bash
     tripwire --check
     ```

## 参考推荐

- MITRE ATT&CK: T1505.003  
  <https://attack.mitre.org/techniques/T1505/003/>  
- ReGeorg HTTP隧道分析  
  <https://cloud.tencent.com/developer/article/1779195>  
- ReGeorg GitHub  
  <https://github.com/sensepost/reGeorg>