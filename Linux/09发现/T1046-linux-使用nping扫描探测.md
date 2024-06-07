# T1046-Linux-使用nping扫描探测

## 来自ATT&CK的描述

攻击者可能会尝试获取在远程主机和本地网络基础设施设备上运行的服务列表，包括那些可能容易受到远程软件利用的服务。获取此信息的常用方法包括使用系统自带的工具进行端口或漏洞扫描。

## 测试案例

Nping允许用户发送多种协议（TCP、UDP、ICMP和ARP协议）的数据包。可以调整协议头中的字段，例如可以设置TCP和UDP的源端口和目的端口。

主要功能 

- 发送ICMP echo请求
- 对网络进行压力测试
- ARP毒化攻击
- DoS攻击
- 支持多种探测模式
- 可以探测多个主机的多个端口

nping常用参数：

用法：nping [Probe mode][Options] {target specification}

Probe mode（探测模式）

    --tcp-connect 无特权的tcp连接探测模式；
    --tcp TCP探测模式
    --udp --icmp --arp
    -tr,--traceroute 路由跟踪模式（仅能和tcp、udp、icmp模式一起使用）
    -p, --dest-port 目标端口
    -g, --source-port 源端口
    --seq 设置序列号
    --flags 设置tcp标识（ack,psh,rst,syn,fin）
    --ack 设置ack数
    -S，--source-ip 设置源IP地址
    --dest-ip  目的IP地址
    -c 设置次数
    -e，--interface 接口
    -H，--hide-sent 不显示发送的包
    -N,--no-capture 不抓获回复包
    -v 增加冗余等级
    -q 减少冗余登记

## 检测日志

linux日志

## 测试复现

向目标主机的22端口发送一次TCP数据包，用于查看主机是否开启SSH服务。

```bash
liu@Parallels:/var/log$ sudo nping -c 1 -p 22 192.168.50.128-129 --tcp

Starting Nping 0.7.60 ( https://nmap.org/nping ) at 2022-09-24 23:53 CST
SENT (0.0589s) TCP 10.211.55.48:15023 > 192.168.50.128:22 S ttl=64 id=64729 iplen=40  seq=125735927 win=1480 
SENT (1.0599s) TCP 10.211.55.48:15023 > 192.168.50.129:22 S ttl=64 id=64729 iplen=40  seq=125735927 win=1480 
 
Statistics for host 192.168.50.128:
 |  Probes Sent: 1 | Rcvd: 0 | Lost: 1  (100.00%)
 |_ Max rtt: N/A | Min rtt: N/A | Avg rtt: N/A
Statistics for host 192.168.50.129:
 |  Probes Sent: 1 | Rcvd: 0 | Lost: 1  (100.00%)
 |_ Max rtt: N/A | Min rtt: N/A | Avg rtt: N/A
Raw packets sent: 2 (80B) | Rcvd: 0 (0B) | Lost: 2 (100.00%)
Nping done: 2 IP addresses pinged in 2.10 seconds
```

## 测试留痕

暂无

## 检测规则/思路

### Elastic

```yml
query = '''
event.category:process and event.type:(start or process_started) and process.name:nping
'''
```

### 建议

暂无

## 参考推荐

MITRE-ATT&CK-T1046

<https://attack.mitre.org/techniques/T1046/>

Nping Process Activity

<https://github.com/elastic/detection-rules/blob/main/rules/linux/discovery_linux_nping_activity.toml>

Kali基本扫描工具

<https://cloud.tencent.com/developer/article/1821351>