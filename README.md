# ThreatHunting-book

## 简介

Threathunting-book目前已覆盖81个TID，258个场景。

主要涵盖Web_attck、Windows AD、Linux ATT&CK TTPs，涉及ATT&CK技术、模拟测试、检测思路、检测所需数据源等。

## 数据来源

### 数据源

本项目中涉及到的日志主要为Windows安全日志、Windows powershell日志、Windows sysmon日志、linux audit日志、Http_log以及其他日志(中间件日志，iis等)。其中需要值得注意的是相关日志需要开启相关审核策略或进行相关配置后，方可使用。

### 数据采集

数据采集部分可采用各类日志转发组件，如nxlog、rsyslog、winlogbeat、splunk日志转发器等。可根据自身需求及实际情况出发，选择适合自己的日志采集方法。

### 规则说明

Web_Attck检测规则为Suricata、Sigma两种格式，端点检测规则为Sigma格式。

## 致谢

特别感谢以下项目，没有下面的各个项目，本项目不会开展起来。由于本项目是通过其他项目进行转换为中文，可能存在差争议，当存在争议时，建议以原项目描述内容为准。

以下项目未按照特定顺序排序：

- [attack.mitre](https://attack.mitre.org/)

- [sigma](https://github.com/Neo23x0/sigma) (by Neo23x0)

- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)  (by Red Canary)

- [Atomic Blue Detections](https://eqllib.readthedocs.io/en/latest/atomicblue.html)

- [Detecting ATT&CK techniques & tactics for Linux](https://github.com/Kirtar22/Litmus_Test) (by Kirtar22)

- [RedTeam-Tactics-and-Techniques](https://github.com/mantvydasb/RedTeam-Tactics-and-Techniques) (by Mantvydas)
  
- [Microsoft-365-Defender-Hunting-Queries](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries)  (Microsoft Threat Protection team)

- [Security-Datasets](https://github.com/OTRF/Security-Datasets/)

- [elastic_detection-rules](https://github.com/elastic/detection-rules/tree/main/rules)
