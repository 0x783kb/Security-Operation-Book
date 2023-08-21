# Security-operation-book

## 简介

Security-operation-book目前已覆盖116个TID，328个场景。主要涵盖Web、Windows AD、Linux，涉及ATT&CK技术、模拟测试、检测思路、检测所需数据源等。

![覆盖图](img/index.png)

## 规则说明

Web_Attck检测规则为Suricata、Sigma两种格式，端点检测规则为Sigma格式为主。

## 整体目录结构

├── ATT&CK
│   └── 零基础学习ATT&CK™.pdf
├── Linux
│   ├── 04执行
│   │   ├── T1059-004-linux-脚本.md
│   │   ├── T1059-006-linux-通过Python生成的交互shell.md
│   │   ├── T1059-linux-通过Perl生成的交互式shell.md
│   │   └── T1154-linux-trap.md
│   ├── 05权限维持
│   │   ├── T1098-004-linux-账户操纵-SSH Authorized Keys.md
│   │   ├── T1136-001-linux-创建账户.md
│   │   ├── T1546-004-linux-.bash_profile and .bashrc.md
│   │   └── T1548-001-linux-Setuid and Setgid.md
│   ├── 06权限提升
│   │   ├── T1548-003-linux-CVE-2019-14287.md
│   │   └── T1548-003-linux-Sudo.md
│   ├── 07逃避防御
│   │   ├── T1027-005-linux-主机上的监测组件删除.md
│   │   ├── T1070-002-linux-清除Linux或Mac系统日志.md
│   │   ├── T1070-003-linux-清除历史记录.md
│   │   ├── T1070-004-linux-文件删除.md
│   │   ├── T1222-002-linux-文件权限修改.md
│   │   ├── T1562-003-linux-Histcontrol.md
│   │   └── T1564-001-linux-隐藏文件和目录.md
│   ├── 08凭证访问
│   │   ├── T1110-003-linux-ssh爆破.md
│   │   ├── T1552-001-linux-文件中的凭据.md
│   │   ├── T1552-003-linux-Bash历史.md
│   │   └── T1552-004-linux-私钥.md
│   └── 09发现
│       ├── T1040-linux-网络嗅探.md
│       ├── T1046-linux-使用nping扫描探测.md
│       ├── T1082-linux-Hping存活主机发现.md
│       ├── T1087-001-linux-本地账户发现.md
│       └── T1557-002-linux-ARP网络嗅探.md
├── README.md
├── Web
│   ├── 2020
│   │   ├── T1190-CVE-2020-0618-SQLserver远程代码执行漏洞.md
│   │   ├── T1190-CVE-2020-0688-漏洞利用检测.md
│   │   ├── T1190-CVE-2020-13925-Apache Kylin远程操作系统命令注入漏洞.md
│   │   ├── T1190-CVE-2020-14882-Weblogic Console HTTP 协议远程代码执行漏洞.md
│   │   ├── T1190-CVE-2020-1938-漏洞利用检测.md
│   │   ├── T1190-CVE-2020-1947-Apache ShardingSphere远程代码执行漏洞.md
│   │   ├── T1190-CVE-2020-25540-目录遍历文件读取漏洞.md
│   │   ├── T1190-CVE-2020-25790-Typesetter CMS文件上传漏洞.md
│   │   ├── T1190-CVE-2020-35754-QuickCms访问控制错误漏洞.md
│   │   ├── T1190-CVE-2020-5902-F5_BIG-IP_远程代码执行漏洞.md
│   │   └── T1190-CVE-2020-8193-CVE-2020-8195.md
│   ├── 2021
│   │   ├── T1190-CVE-2021-2109_Weblogic_LDAP_远程代码执行漏洞.md
│   │   ├── T1190-CVE-2021-21402-Jellyfin任意文件读取漏洞.md
│   │   ├── T1190-CVE-2021-21972 Vmware vcenter未授权任意文件读取:RCE漏洞.md
│   │   ├── T1190-CVE-2021-41277-Metabase 敏感信息泄露漏洞.md
│   │   ├── T1190-CVE-2021-41773-Apache HTTP Server 2.4.49 路径穿越漏洞.md
│   │   ├── T1190-CVE-2021-42013-Apache HTTP Server 2.4.50 路径穿越漏洞.md
│   │   └── T1190-CVE-2021-43798-Grafana任意文件读取漏洞.md
│   ├── 2022
│   │   ├── T1190-CNVD-2022-03672-向日葵RCE漏洞.md
│   │   ├── T1190-CVE-2022-1388-F5BIG-IP未授权RCE.md
│   │   ├── T1190-CVE-2022-22947-Spring Cloud Gateway远程代码执行漏洞.md
│   │   ├── T1190-CVE-2022-22954-VMware Workspace ONE Access SSTI远程代码执行.md
│   │   ├── T1190-CVE-2022-24124-Casdoor SQL注入漏洞.md
│   │   ├── T1190-CVE-2022-26134-Confluence OGNL表达式注入命令执行漏洞.md
│   │   ├── T1190-CVE-2022-40127 Apache Airflow代码注入.md
│   │   └── T1190-CVE-2022-42889 Apache Commons Text RCE.md
│   ├── 2023
│   │   ├── CVE-2023-23752
│   │   │   ├── 1.png
│   │   │   ├── 2.png
│   │   │   ├── 3.png
│   │   │   ├── 4.png
│   │   │   ├── CVE-2023-23752.pcap
│   │   │   └── T1190-CVE-2023-23752.md
│   │   ├── CVE-2023-25157
│   │   │   ├── 1.png
│   │   │   ├── CVE-2023-25157.pcapng
│   │   │   └── T1190-CVE-2023-25157.md
│   │   ├── CVE-2023-28432
│   │   │   ├──  CVE-2023-28432.pcap
│   │   │   ├── 1.png
│   │   │   └── T1190-CVE-2023-28432.md
│   │   ├── CVE-2023-32315
│   │   │   ├── 1.png
│   │   │   ├── CVE-2023-32315.pcapng
│   │   │   ├── T1190-CVE-2023-32315-Openfire管理后台认证绕过.md
│   │   │   ├── T1190-CVE-2023-32315.md
│   │   │   ├── csrftoken.png
│   │   │   └── jsessionid.png
│   │   ├── CVE-2023-34843
│   │   │   ├── CVE-2023-34843.png
│   │   │   └── T1190-CVE-2023-34843.md
│   │   ├── CVE-2023-35843
│   │   │   ├── 1.png
│   │   │   └── T1190-CVE-2023-35843.md
│   │   └── other
│   │       ├── NginxWebUI run Cmd远程命令执行.md
│   │       ├── Sapido路由器远程命令执行.md
│   │       ├── Smartbi商业智能软件绕过登录.md
│   │       ├── 金蝶K3Cloud反序列化.md
│   │       ├── 用友NC Cloud存在前台远程命令执行.md
│   │       ├── 泛微e-cology前台任意用户登录.md
│   │       ├── 蓝凌oa远程代码执行.md
│   │       └── 瑞友天翼应用虚拟化系统存在远程代码执行.md
│   └── long time
│       ├── T1133-001-深信服VPN任意密码重置.md
│       ├── T1190- Apache Log4j2漏洞利用检测.md
│       ├── T1190-CNVD-2017-02833-fastjson1.2.24远程代码执行.md
│       ├── T1190-CNVD-2018-24942-thinkphp5.x任意代码执行漏洞.md
│       ├── T1190-CVE-2010-1870-S2-005远程代码执行.md
│       ├── T1190-CVE-2016-10033-PHPMailer<5.2.18远程代码执行.md
│       ├── T1190-CVE-2018-2894-Weblogic任意文件上传检测.md
│       ├── T1190-CVE-2019-19781-远程代码执行检测.md
│       ├── T1190-CVE-2019-3398-Confluence路径穿越漏洞.md
│       ├── T1190-CVE-2019-6339-Drupal远程代码执行漏洞.md
│       ├── T1190-Influxdb<1.7.6未授权访问漏洞.md
│       ├── T1190-IvBulletin5.X-RCE检测.md
│       ├── T1190-JumpServer v2.6.1 RCE攻击检测.md
│       ├── T1190-Thinkphp 5.x远程命令执行检测.md
│       ├── T1190-泛微OA任意文件读取.md
│       ├── T1190-通达V11.6-RCE.md
│       ├── T1190-联软任意文件上传.md
│       ├── T1505-003-webshell-冰蝎v2.0.md
│       └── T1505-003-webshell-冰蝎v3.0.md
├── Windows
│   ├── 00其他
│   │   └── T8000-win-使用User_Del删除用户.md
│   ├── 01侦察
│   │   ├── T1589-001-收集目标组织身份信息-凭证.md
│   │   ├── T1589-002-收集目标组织身份信息-邮件地址.md
│   │   ├── T1589-003-收集目标组织身份信息-员工姓名.md
│   │   ├── T1590-001-收集目标组织网络信息-域属性.md
│   │   ├── T1590-002-收集目标组织网络信息-DNS.md
│   │   ├── T1590-003-收集目标组织网络信息-网络信任关系.md
│   │   ├── T1590-004-收集目标组织网络信息-网络拓扑.md
│   │   ├── T1590-005-收集目标组织网络信息-IP地址.md
│   │   ├── T1590-006-收集目标组织网络信息-网络安全设备.md
│   │   ├── T1590-win-DNS记录获取.md
│   │   ├── T1591-001-收集目标组织信息-确定物理位置.md
│   │   ├── T1591-002-收集目标组织信息-业务关系.md
│   │   ├── T1591-003-收集目标组织信息-确定业务节奏.md
│   │   ├── T1591-004-收集目标组织信息-确定角色.md
│   │   ├── T1592-001-收集目标组织主机信息-硬件信息.md
│   │   ├── T1592-002-收集目标组织主机信息-软件信息.md
│   │   ├── T1592-003-收集目标组织主机信息-固件信息.md
│   │   ├── T1592-004-收集目标组织主机信息-客户端配置.md
│   │   ├── T1593-001-搜索开放的域和网站-社交媒体.md
│   │   ├── T1593-002-搜索开放的域和网站-搜索引擎.md
│   │   ├── T1594-搜索目标组织所拥有的网站.md
│   │   ├── T1595-001-主动扫描-IP地址.md
│   │   ├── T1595-002-主动扫描-漏洞扫描.md
│   │   ├── T1596-001-搜索开放的技术数据库-DNS_被动DNS.md
│   │   ├── T1596-002-搜索开放的技术数据库-WHOIS.md
│   │   ├── T1596-003-搜索开放的技术数据库-数字签名.md
│   │   ├── T1596-004-搜索开放的技术数据库-CDN.md
│   │   └── T1596-005-搜索开放的技术数据库-公开的扫描数据库.md
│   ├── 02资源开发
│   │   ├── T1583-001-获取基础设施-域名.md
│   │   ├── T1583-002-获取基础设施-DNS服务.md
│   │   ├── T1583-003-获取基础设施-虚拟专用服务器.md
│   │   ├── T1583-004-获取基础设施-服务器.md
│   │   ├── T1583-005-获取基础设施-僵尸网络.md
│   │   ├── T1583-006-获取基础设施-web服务.md
│   │   ├── T1584-001-入侵基础设施-域名.md
│   │   ├── T1584-002-入侵基础设施-DNS服务.md
│   │   ├── T1584-003-入侵基础设施-虚拟专用服务器.md
│   │   ├── T1584-004-入侵基础设施-服务器.md
│   │   ├── T1584-005-入侵基础设施-僵尸网络.md
│   │   ├── T1584-006-入侵基础设施-web服务.md
│   │   ├── T1585-001-创建账户-社交媒体账户.md
│   │   ├── T1585-002-创建账户-电子邮箱账户.md
│   │   ├── T1586-001-盗取账户-社交媒体账户.md
│   │   ├── T1586-002-盗取账户-电子邮箱账户.md
│   │   ├── T1587-001-开发能力-恶意软件.md
│   │   ├── T1587-002-开发能力-代码签名证书.md
│   │   ├── T1587-003-开发能力-数字证书.md
│   │   ├── T1587-004-开发能力-漏洞利用.md
│   │   ├── T1588-001-获取能力-恶意软件.md
│   │   ├── T1588-002-获取能力-工具.md
│   │   ├── T1588-003-获取能力-代码签名证书.md
│   │   ├── T1588-004-获取能力-数字证书.md
│   │   ├── T1588-005-获取能力-漏洞利用.md
│   │   ├── T1588-006-获取能力-漏洞.md
│   │   ├── T1608-001-部署能力-部署恶意软件.md
│   │   ├── T1608-002-部署能力-部署工具.md
│   │   ├── T1608-003-部署能力-安装数字证书.md
│   │   ├── T1608-004-部署能力-部署路过式攻击资源.md
│   │   └── T1608-005-部署能力-部署链接目标资源.md
│   ├── 03初始访问
│   │   ├── T1078-003-win-账户登录失败.md
│   │   ├── T1078-003-win-多账户同时登陆.md
│   │   ├── T1078-003-win-来自公网的登陆失败行为.md
│   │   ├── T1133-外部远程服务.md
│   │   ├── T1190-SQL server滥用.md
│   │   ├── T1190-可疑的SQL错误消息.md
│   │   ├── T1190-邮箱暴力破解攻击流量分析.md
│   │   └── T1566-001-win-可疑的MS Office子进程.md
│   ├── 04执行
│   │   ├── T1047-win-通过WMIC创建远程进程.md
│   │   ├── T1047-win-使用Wmic执行payload(白名单).md
│   │   ├── T1053-002-win-通过GPO计划任务进行大规模的持久性和执行.md
│   │   ├── T1053-002-win-交互式at计划任务.md
│   │   ├── T1053-005-win-schtasks本地计划任务.md
│   │   ├── T1059-001-win-检测PowerShell2.0版本执行.md
│   │   ├── T1059-001-win-检测PowerShell下载文件.md
│   │   ├── T1059-001-win-使用Powershell.exe执行Payload(白名单).md
│   │   ├── T1059-win-powershell.md
│   │   ├── T1059-win-使用Certutil.exe执行Payload(白名单).md
│   │   ├── T1059-win-使用Ftp.exe执行Payload(白名单).md
│   │   ├── T1059-win-使用wusa卸载系统更新.md
│   │   ├── T1059-win-进程生成CMD.md
│   │   ├── T1559-001-win-利用进程间通信执行-组件对象模型-COM.md
│   │   ├── T1559-002-win-利用进程间通信执行-动态数据交换-DDE.md
│   │   └── T1559-002-win-利用进程间通讯执行-动态数据交换-OLE.md
│   ├── 05权限维持
│   │   ├── T1078-001-win-DSRM重置密码.md
│   │   ├── T1098-win-AdminSDHolder.md
│   │   ├── T1098-win-万能密码.md
│   │   ├── T1098-win-账户操作.md
│   │   ├── T1136-001-win-创建本地账户.md
│   │   ├── T1137-002-win-office应用启动程序-office test.md
│   │   ├── T1137-004-win-office应用启动程序-outlook主页.md
│   │   ├── T1176-浏览器扩展.md
│   │   ├── T1197-win-BITS Jobs权限维持.md
│   │   ├── T1505-003-Regeorg-HTTP隧道检测.md
│   │   ├── T1505-003-T1505-003-web服务关联可疑进程识别webshell行为.md
│   │   ├── T1505-003-win-中间件关联命令参数来识别webshell.md
│   │   ├── T1543-003-windows服务-Dnscmd.exe(白名单).md
│   │   ├── T1546-001-win-事件触发执行-更改默认文件关联.md
│   │   ├── T1546-002-win-事件触发执行-屏幕保护程序.md
│   │   ├── T1546-007-win-通过netsh key持久化.md
│   │   ├── T1546-012-win-事件触发执行-图片文件执行选项注入.md
│   │   ├── T1546-015-win-组件对象模型劫持-Dllhost.exe(白名单).md
│   │   ├── T1547-005-win-SSP权限维持.md
│   │   └── T1548-002-win-绕过用户账户控制-Eventvwr.exe(白名单).md
│   ├── 06权限提升
│   │   ├── T1037-001-win-Boot或logon初始化脚本-登录脚本.md
│   │   ├── T1078-003-win-帐户篡改-可疑的失败登录原因.md
│   │   ├── T1134-001-win-CVE-2020-1472.md
│   │   ├── T1134-001-win-访问令牌操作-Runas命令.md
│   │   ├── T1134-005-win-SID历史记录注入.md
│   │   └── T1574-001-win-劫持执行流程-DLL搜索顺序劫持.md
│   ├── 07逃避防御
│   │   ├── T1006-win-直接访问卷.md
│   │   ├── T1014-win-Rootkit.md
│   │   ├── T1027-003-win-Ping Hex IP.md
│   │   ├── T1027-004-win-使用Csc.exe执行payload（白名单）.md
│   │   ├── T1027-004-win-传输后编译csc.exe(白名单).md
│   │   ├── T1027-005-win-SDelete删除文件.md
│   │   ├── T1027-win-使用pubprn.vbs下载文件(白名单) .md
│   │   ├── T1036-003-win-重命名程序名称.md
│   │   ├── T1036-004-win-伪装服务或任务.md
│   │   ├── T1036-win-隐藏用户账户带$符号.md
│   │   ├── T1070-001-win-检测cipher.exe删除数据.md
│   │   ├── T1070-001-win-使用wevtutil命令删除日志.md
│   │   ├── T1070-001-win-清除事件日志.md
│   │   ├── T1070-004-win-使用Fsutil删除卷USN日志.md
│   │   ├── T1070-004-win-文件删除.md
│   │   ├── T1070-005-win-删除网络共享连接.md
│   │   ├── T1070-006-win-Timestamp.md
│   │   ├── T1127-win-使用Msbuild.exe执行payload(白名单).md
│   │   ├── T1127-win-受信任的开发者实用程序代理执行-Aspnet_compiler.exe(白名单).md
│   │   ├── T1127-win-受信任的开发者实用程序代理执行-Jsc.exe(白名单).md
│   │   ├── T1140-win-去混淆解码文件或信息.md
│   │   ├── T1202-win-间接命令执行-基于Explorer.exe执行payload(白名单).md
│   │   ├── T1202-win-间接命令执行-基于Forfiles执行payload(白名单).md
│   │   ├── T1202-win-间接命令执行-基于Pcalua执行payload(白名单).md
│   │   ├── T1216-001-win-签名脚本代理执行-PubPrn.md
│   │   ├── T1216-win-签名脚本代理执行.md
│   │   ├── T1218-001-win-使用Compiler.exe执行payload(白名单).md
│   │   ├── T1218-001-win-签名的二进制代理执行-编译HTML文件.md
│   │   ├── T1218-002-win-签名的二进制代理执行-Control.exe(白名单).md
│   │   ├── T1218-003-win-使用Cmstp.exe执行Payload(白名单).md
│   │   ├── T1218-004-win-使用Installutil.exe执行payload(白名单).md
│   │   ├── T1218-005-win-使用Mshta.exe执行payload(白名单).md
│   │   ├── T1218-007-win-使用Msiexec.exe执行Payload(白名单).md
│   │   ├── T1218-007-win-签名的二进制代理执行-Msiexec.md
│   │   ├── T1218-008-win-使用Odbcconf.exe执行Payload(白名单).md
│   │   ├── T1218-009-win-使用Regasm.exe执行payload(白名单).md
│   │   ├── T1218-010-win-使用Regsvr32执行payload(白名单).md
│   │   ├── T1218-011-win-使用Rundll32.exe执行payload(白名单).md
│   │   ├── T1218-011-win-通过Rundll32的异常网络链接.md
│   │   ├── T1218-011-win-使用URL.dll执行payload(白名单).md
│   │   ├── T1218-win-使用Atbroker.exe执行恶意载荷(白名单).md
│   │   ├── T1218-win-使用Zipfldr.dll执行Payload(白名单).md
│   │   ├── T1220-win-XSL Script Processing.md
│   │   ├── T1221-win-模板注入.md
│   │   ├── T1222-001-win-fltmc卸载筛选器驱动程序.md
│   │   ├── T1222-001-win-文件权限修改.md
│   │   ├── T1550-003-win-黄金票据.md
│   │   ├── T1562-001-win-使用net stop关闭Windefend.md
│   │   ├── T1562-001-win-使用netsh关闭windows防火墙.md
│   │   ├── T1562-001-win-停止sysmon服务.md
│   │   ├── T1562-001-win-卸载安全工具使用的驱动程序-fltMC.exe(白名单).md
│   │   ├── T1562-006-win-停止日志采集.md
│   │   ├── T1562-win-使用Bcdedit禁用DEP安全机制.md
│   │   ├── T1564-001-win-隐藏的文件和目录.md
│   │   ├── T1564-001-win-发现攻击者在回收站中隐藏恶意软件.md
│   │   └── T1564-003-win-隐藏窗口.md
│   ├── 08凭证访问
│   │   ├── T1003-002-win-基于Sam-reg凭证转储.md
│   │   ├── T1003-003-win-ntds凭证获取.md
│   │   ├── T1003-003-win-vssown.vbs获取NTDS.dit.md
│   │   ├── T1003-003-win-基于NTDS凭证获取1.md
│   │   ├── T1003-003-win-使用ntdsutil获得NTDS.dit文件.md
│   │   ├── T1003-003-win-基于应用日志检测Ntdsutil获取凭证.md
│   │   ├── T1003-004-win-LSA-mimikatz凭证转储.md
│   │   ├── T1003-005-win-DCC2-mimikatz凭证转储.md
│   │   ├── T1003-006-win-DCsysnc-凭证转储.md
│   │   ├── T1003-win-Procdump凭证转储.md
│   │   ├── T1003-win-vaultcmd获取系统凭证基本信息.md
│   │   ├── T1003-win-使用Windows任务管理器转储Lsass.exe内存.md
│   │   ├── T1003-win-使用comsvc​​s.dll转储Lsass.exe内存.md
│   │   ├── T1098-win-万能密码.md
│   │   ├── T1098-win-账户操作.md
│   │   ├── T1110-003-win-密码喷射.md
│   │   ├── T1110-暴力破解.md
│   │   ├── T1212-win-ms14-068-KEKEO.md
│   │   ├── T1212-win-ms14-068-PYKEK.md
│   │   ├── T1552-001-win-文件中的凭证.md
│   │   ├── T1552-002-win-注册表中的凭证.md
│   │   ├── T1552-006-win-GPP-凭证转储.md
│   │   ├── T1555-003-win-来自web浏览器的凭证.md
│   │   ├── T1555-005-win-cmdkey获取凭据(白名单).md
│   │   ├── T1555-005-win-命令行获取Finalshell软件保存的公钥.md
│   │   ├── T1555-005-win-常见凭据存放位置.md
│   │   ├── T1558-003-win-SPN-凭证转储.md
│   │   └── T1558-003-win-kerberosing.md
│   ├── 09发现
│   │   ├── T1007-win-系统服务发现.md
│   │   ├── T1010-win-应用程序窗口发现.md
│   │   ├── T1012-win-查询注册表.md
│   │   ├── T1016-win-系统网络配置发现.md
│   │   ├── T1018-win-检测nbtscan活动.md
│   │   ├── T1018-win-远程系统发现.md
│   │   ├── T1033-win-系统所有者及用户发现.md
│   │   ├── T1040-win-使用netsh进行网络嗅探.md
│   │   ├── T1049-win-bloodhound使用.md
│   │   ├── T1049-win-系统网络连接发现.md
│   │   ├── T1057-win-进程发现.md
│   │   ├── T1069-001-win-本地特权组用户枚举.md
│   │   ├── T1069-002-win-AD特权组用户枚举.md
│   │   ├── T1082-win-系统信息发现.md
│   │   ├── T1083-win-文件和目录发现.md
│   │   ├── T1120-win-周边设备发现.md
│   │   ├── T1124-win-系统时间发现.md
│   │   ├── T1135-win-网络共享发现.md
│   │   ├── T1201-win-密码策略发现.md
│   │   ├── T1482-win-活动目录信息获取检测.md
│   │   ├── T1518-001-win-利用wmic发现安全软件.md
│   │   ├── T1518-001-win-安全软件发现.md
│   │   └── T1518-win-发现安全软件.md
│   ├── 10横向移动
│   │   ├── T1021-001-win-使用Start_Rdp开启远程桌面服务.md
│   │   ├── T1021-002-win-基于PsExec执行payload(白名单).md
│   │   ├── T1021-002-win-管理员共享.md
│   │   ├── T1021-006-win-远程powershell会话.md
│   │   ├── T1210-win-异常的SMB链接行为.md
│   │   ├── T1210-win-检测到匿名计算机账户更改的使用.md
│   │   ├── T1550-002-win-哈希传递.md
│   │   └── T1563-002-win-远程服务会话劫持-RDP劫持.md
│   ├── 11收集
│   │   ├── T1056-001-win-键盘记录.md
│   │   ├── T1114-001-win-本地电子邮件收集.md
│   │   ├── T1119-win-Seatbelt自动收集信息.md
│   │   ├── T1119-win-自动收集.md
│   │   ├── T1123-win-使用AudioDeviceCmdlets进行音频收集.md
│   │   ├── T1123-win-使用soundrec进行音频收集.md
│   │   └── T1560-001-win-通过winrar压缩收集数据.md
│   ├── 12命令与控制
│   │   ├── T1008-备用通信通道.md
│   │   ├── T1071-001-应用层协议-网络协议.md
│   │   ├── T1071.002-win-内网FTP链接到公网行为.md
│   │   ├── T1071.004-win-内网主机向公网DNS发起可疑请求行为.md
│   │   ├── T1090.001-win-端口转发代理.md
│   │   ├── T1092-通过可移动媒介传播.md
│   │   ├── T1095-非应用层协议.md
│   │   ├── T1105-Windows Update可滥用于执行恶意程序行为检测.md
│   │   ├── T1105-win-利用cmdl32进行文件下载行为(白名单).md
│   │   ├── T1105-win-入口工具转移-AppInstaller.exe(白名单、失效).md
│   │   ├── T1105-win-入口工具转移-CertReq.exe(白名单).md
│   │   ├── T1105-win-入口工具转移-Finger.exe(白名单).md
│   │   ├── T1105-win-入口工具转移-IMEWDBLD.exe(白名单).md
│   │   ├── T1105-win-入口工具转移-desktopimgdownldr.exe(白名单).md
│   │   ├── T1105-win-入口工具转移-ieexec.exe (白名单).md
│   │   ├── T1105-win-命令提示符网络链接.md
│   │   ├── T1568-002-动态解析-域名生成算法（DGA）.md
│   │   ├── T1571-非标准端口.md
│   │   └── T1573-标准加密协议.md
│   ├── 13渗出
│   │   ├── T1020-win-自动渗出.md
│   │   └── T1567-win-通过Web服务进行渗透-DataSvcUtil.exe(白名单).md
│   └── 14影响
│       ├── T1489-win-停止服务.md
│       ├── T1490-win-禁止系统恢复.md
│       ├── T1529-win-系统关机或重启.md
│       └── T1531-win-账户访问权限删除.md
├── img
│   └── index.png
└── 整体目录结构.md



## Stargazers over time

[![Stargazers over time](https://starchart.cc/12306Bro/Threathunting-book.svg)](https://starchart.cc/12306Bro/Threathunting-book)
