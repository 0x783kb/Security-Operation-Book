# Security-operation-book

## 简介

Security-operation-book目前已覆盖106个TID，326个场景。主要涵盖Web、Windows AD、Linux，涉及ATT&CK技术、模拟测试、检测思路、检测所需数据源等。

![覆盖图](img/index.png)

## 规则说明

Web_Attck检测规则为Suricata、Sigma两种格式，端点检测规则为Sigma格式为主。


## 参考链接

### Mitre.Att&ck

- [attack.mitre](https://attack.mitre.org/)

### 数据&组件

- [Security-Datasets](https://github.com/OTRF/Security-Datasets/)
- [OTRF/OSSEM](https://github.com/OTRF/OSSEM)
- [Windows_Sysmon](https://github.com/SwiftOnSecurity/sysmon-config)
- [HELK](https://github.com/Cyb3rWard0g/HELK)
- [threathunters-io/laurel](https://github.com/threathunters-io/laurel)
- [Zeek](https://github.com/zeek/zeek)
- [Suricata](https://github.com/OISF/suricata)
- [Microsoft事件日志思维导图](https://github.com/mdecrevoisier/Microsoft-eventlog-mindmap)
- [Windows事件收集器部署工具](https://github.com/mdecrevoisier/Windows-WEC-server_auto-deploy#windows-event-collector-deployment-toolkit)
- [SELKS](https://github.com/StamusNetworks/SELKS)


### 开源规则

- [Sigma](https://github.com/Neo23x0/sigma) (by Neo23x0)
- [Elastic_detection-rules](https://github.com/elastic/detection-rules/tree/main/rules)
- [elastic-prebuilt-rules](https://www.elastic.co/guide/en/security/current/prebuilt-rules.html)
- [Splunk security_content](https://github.com/splunk/security_content/tree/develop/detections)
- [Splunk-detections](https://research.splunk.com/detections/)
- [Atomic Blue Detections](https://eqllib.readthedocs.io/en/latest/atomicblue.html)
- [Detecting ATT&CK techniques & tactics for Linux](https://github.com/Kirtar22/Litmus_Test) (by Kirtar22)
- [ThreatHunter-Playbook](https://github.com/OTRF/ThreatHunter-Playbook)

### 对手仿真

- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)  (by Red Canary)
- [Purple-team-attack-automation](https://github.com/praetorian-inc/purple-team-attack-automation/wiki/Available-Modules)
- [Mitre/caldera](https://github.com/mitre/caldera)
- ......

### 红队技术

- [RedTeam-Tactics-and-Techniques](https://github.com/mantvydasb/RedTeam-Tactics-and-Techniques) (by Mantvydas)
- [AD-Pentest-Notes](https://github.com/chriskaliX/AD-Pentest-Notes)
- [RedTeamNotes](https://github.com/biggerduck/RedTeamNotes)
- [RedTeamAttack](https://github.com/r0eXpeR/RedTeamAttack)
- [hassan0x/RedTeam](https://github.com/hassan0x/RedTeam)
- [Awesome-CobaltStrike](https://github.com/zer0yu/Awesome-CobaltStrike)
- [RedTeamCSharpScripts](https://github.com/Mr-Un1k0d3r/RedTeamCSharpScripts)
- [redteam-notebookPublic](https://github.com/foobarto/redteam-notebook)
- [学习的魔力](http://bitvijays.github.io/)
- ......

### 一些比较有意思的蓝队项目

- [JetBrains系列产品.idea钓鱼反制红队](https://github.com/CC11001100/idea-project-fish-exploit)
- [RedTeam_BlueTeam_HW](https://github.com/Mr-xn/RedTeam_BlueTeam_HW)
- [开源网络钓鱼工具包gophish](https://github.com/gophish/gophish)
- [MysqlHoneypot，获取攻击者微信ID](https://github.com/heikanet/MysqlHoneypot)
