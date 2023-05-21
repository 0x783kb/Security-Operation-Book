/**
 * 用于生成仓库目录的层级结构
 */
const path = require('path')
const fs = require('fs')

// 文件名在下面数组中项的都排除掉
const excludeFile = ['img', 'LICENSE', 'README.md', path.basename(__filename)]
// 文件名以下面数组中项为前缀开头的都排除掉
const excludePrefix = ['.']
// 所有文件的绝对全路径缓存数组
const absolutePath = []

// 获取所有文件路径
;(function getDirStruct(basePath = __dirname) {
  const files = fs.readdirSync(basePath)
  // 空文件夹处理
  if (files.length === 0) {
    return absolutePath.push(basePath)
  }
  files.forEach(file => {
    // 排除掉不想显示的文件
    if (excludeFile.indexOf(file) !== -1 || excludePrefix.some(pre => file.indexOf(pre) === 0)) return
    const fullPath = path.resolve(basePath, file)
    const fileStats = fs.statSync(fullPath)
    // 如果是文件夹，则继续遍历其子文件
    return fileStats.isDirectory() ? getDirStruct(fullPath) : absolutePath.push(fullPath)
  })
})()
// 文件的相对路径数组，用于拼接 url地址
const isWin = path.sep.indexOf('\\') !== -1
let relativePath = absolutePath.map(apath => {
  // 得到相对路径
  const rPath = path.relative(__dirname, apath)
  // 不同系统平台的分隔符处理
  return isWin ? rPath.replace(/\\/g, '/') : rPath
})

// 层级结构
const structs = {}
relativePath.forEach(filePath => {
  // 格式化路径为数组
  const fileArrs = filePath.split('/')
  let currentProp = eval('structs' + fileArrs.slice(0, -1).reduce((t, c) => {
    if (!eval('structs' + t + `['${c}']`)) {
      eval('structs' + t + `['${c}']` + '= {}')
    }
    return t + `['${c}']`
  }, ''))
  if (currentProp._children) {
    currentProp._children.push(fileArrs.slice(-1)[0])
  } else {
    currentProp._children = fileArrs.slice(-1)
  }
})

// README.md 中的内容
let readmeContent = `
# Security-operation-book

## 简介

Security-operation-book目前已覆盖106个TID，326个场景。主要涵盖Web、Windows AD、Linux，涉及ATT&CK技术、模拟测试、检测思路、检测所需数据源等。

![覆盖图](img/index.png)

## 规则说明

Web_Attck检测规则为Suricata、Sigma两种格式，端点检测规则为Sigma格式为主。

## 致谢

特别感谢以下项目，没有以下项目，本项目不会开展起来。致谢项目排序遵循指导思想、数据&组件、规则、对手仿真、红队技术逻辑进行排序。

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


### 开源规则

- [Sigma](https://github.com/Neo23x0/sigma) (by Neo23x0)
- [Elastic_detection-rules](https://github.com/elastic/detection-rules/tree/main/rules)
- [Splunk security_content](https://github.com/splunk/security_content/tree/develop/detections)
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

- ......


## Stargazers over time

[![Stargazers over time](https://starchart.cc/12306Bro/Threathunting-book.svg)](https://starchart.cc/12306Bro/Threathunting-book)

---

目录结构

`
// 整理输出结构
;(function formatLink(obj = structs, basePath = '', level = 1) {
  Object.keys(obj).forEach(k => {
    if (k === '_children') {
      // 这个是针对根目录下存在的独立文件
      return readmeContent += obj[k].reduce((t, c) => t + `- [${c}](/${c})\n`, '')
    }
    readmeContent += ('\t'.repeat(level - 1) + `- [${k}](${basePath}/${k})\n`)
    // 如果存在子层级，则遍历子层级
    if (obj[k]._children) {
      readmeContent += obj[k]._children.reduce((t, c) => {
        return t + '\t'.repeat(level) + `- [${c}](${basePath}/${k}/${c})\n`
      }, '')
    }
    const objKeys = Object.keys(obj[k])
    // 如果子层级存在并且不止一个，或者子层级只有一个但属性名不是 _children
    if (objKeys.length > 1 || (objKeys.length && objKeys[0] !== '_children')) {
      const tempObj = {}
      objKeys.filter(d1 => d1 !== '_children').forEach(d2 => {
        tempObj[d2] = obj[k][d2]
      })
      return formatLink(tempObj, `${basePath}/${k}`, level + 1)
    }
  })
})()

// 保存 README.md
fs.writeFile(path.resolve(__dirname, 'README.md'), readmeContent, () => {
  console.log('done')
})