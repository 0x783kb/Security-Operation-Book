# T1082-win-系统信息发现

## 来自ATT&CK的描述

攻击者可能试图获取有关操作系统和硬件的详细信息，包括版本，补丁，修补程序，服务包和目录结构。攻击者可以在发现过程中使用系统信息中发现的信息来决定后续的操作，包括攻击者是否完全感染了目标或尝试了特定操作。

## 测试案例

hping是用于生成和解析TCPIP协议数据包的开源工具。创作者是Salvatore Sanfilippo。目前最新版是hping3，支持使用tcl脚本自动化地调用其API。hping是安全审计、防火墙测试等工作的标配工具。hping优势在于能够定制数据包的各个部分，因此用户可以灵活对目标机进行细致地探测。

## 检测日志

Linux audit日志

## 测试复现

```bash
yyds@12306Br0:/var/log/audit$ sudo hping3 -I enp0s5 -S 10.211.55.35 -p 22
[sudo] yyds 的密码： 
HPING 10.211.55.35 (enp0s5 10.211.55.35): S set, 40 headers + 0 data bytes
len=40 ip=10.211.55.35 ttl=64 DF id=0 sport=22 flags=RA seq=0 win=0 rtt=7.3 ms
len=40 ip=10.211.55.35 ttl=64 DF id=0 sport=22 flags=RA seq=1 win=0 rtt=8.4 ms
len=40 ip=10.211.55.35 ttl=64 DF id=0 sport=22 flags=RA seq=2 win=0 rtt=6.6 ms
len=40 ip=10.211.55.35 ttl=64 DF id=0 sport=22 flags=RA seq=3 win=0 rtt=6.3 ms
len=40 ip=10.211.55.35 ttl=64 DF id=0 sport=22 flags=RA seq=4 win=0 rtt=1.8 ms
len=40 ip=10.211.55.35 ttl=64 DF id=0 sport=22 flags=RA seq=5 win=0 rtt=6.0 ms
len=40 ip=10.211.55.35 ttl=64 DF id=0 sport=22 flags=RA seq=6 win=0 rtt=8.5 ms
```

注意权限问题，权限过低会报错

## 测试留痕

```yml
type=SYSCALL msg=audit(1654607530.513:15004): arch=c000003e syscall=59 success=yes exit=0 a0=55b2b32403f8 a1=55b2b31eacb0 a2=55b2b3241ed0 a3=0 items=2 ppid=36880 pid=36881 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts2 ses=2 comm="hping3" exe="/usr/sbin/hping3" subj=? key="rootcmd"ARCH=x86_64 SYSCALL=execve AUID="yyds" UID="root" GID="root" EUID="root" SUID="root" FSUID="root" EGID="root" SGID="root" FSGID="root"
type=EXECVE msg=audit(1654607530.513:15004): argc=7 a0="hping3" a1="-I" a2="enp0s5" a3="-S" a4="10.211.55.35" a5="-p" a6="22"
```

## 检测规则/思路

### elastic规则

```yml
query = '''
event.category:process and event.type:(start or process_started) and process.name:(hping or hping2 or hping3)
'''
```

### 建议

暂无

## 参考推荐

MITRE-ATT&CK-T1082

<https://attack.mitre.org/techniques/T1082/>

discovery_linux_hping_activity

<https://github.com/elastic/detection-rules/blob/main/rules/linux/discovery_linux_hping_activity.toml>

kali工具-信息收集之存活主机识别（Hping）

<https://blog.csdn.net/weixin_45761101/article/details/116696018>
