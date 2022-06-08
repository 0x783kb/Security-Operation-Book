# T1070-002-linux-清除Linux或Mac系统日志

## 来自ATT&CK的描述

攻击者可能会清除系统日志以隐藏入侵证据。macOS和Linux都通过系统日志跟踪系统或用户启动的操作。大多数本机系统日志记录存储在/var/log/目录。 此目录中的子文件夹按其相关功能对日志进行分类，例如：

- /var/log/messages:：一般和系统相关的消息
- /var/log/secure或者/var/log/auth.log: 认证日志
- /var/log/utmp或者/var/log/wtmp: 登录记录
- /var/log/kern.log: 内核日志
- /var/log/cron.log: Cron 日志
- /var/log/maillog: 邮件服务器日志
- /var/log/httpd/: Web 服务器访问和错误日​​志

## 测试案例

删除/var/log/auth.log日志文件

## 检测日志

linux audit日志 （值得注意的是：Ubuntu默认情况下没有audit，需要下载安装并配置相关策略）

## 测试复现

```bash
yyds@12306Br0:/var/log/audit$ sudo rm -r /var/log/auth.log
```

## 测试留痕

基于audit日志

```yml
type=EXECVE msg=audit(1654605114.800:8206): argc=3 a0="rm" a1="-r" a2="/var/log/auth.log"
```

## 检测规则/思路

### elastic规则

```yml
query = '''
file where event.type == "deletion" and 
  file.path : 
    (
    "/var/run/utmp", 
    "/var/log/wtmp", 
    "/var/log/btmp", 
    "/var/log/lastlog", 
    "/var/log/faillog",
    "/var/log/syslog", 
    "/var/log/messages", 
    "/var/log/secure", 
    "/var/log/auth.log"
    )
```

### 建议

暂无

## 参考推荐

MITRE-ATT&CK-T1070-002

<https://attack.mitre.org/techniques/T1070/002/>

defense_evasion_log_files_deleted

<https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_log_files_deleted.toml>
