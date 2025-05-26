# T1590-收集目标组织网络信息-DNS记录获取

## 来自 ATT&CK 的描述

在入侵目标组织之前，攻击者可能通过多种方式收集目标组织的 DNS 记录信息（T1590）。这些信息可用于目标定位、了解网络架构或指导后续攻击活动（如钓鱼 T1566、有效账号 T1078 或服务探测 T1046）。DNS 记录（如 A、MX、CNAME、TXT 等）通常通过公开渠道或内部权限获取，暴露目标组织的服务器、邮件系统或其他关键基础设施。由于这些活动可能在目标组织的视野之外（如攻击者的设备或公开 DNS 查询）或内部环境中（如利用已获得的权限）进行，检测具有一定挑战性。

在域渗透场景中，DNS 记录是了解目标域内网络架构的重要情报。例如，获取 MX 记录可揭示邮件服务器地址，A 记录可暴露主机 IP，CNAME 记录可揭示子域名关系。如果攻击者已获得域内权限（如管理员权限），DNS 记录可进一步帮助其识别关键资产或薄弱点，为横向移动（T1021）或数据泄露（T1537）提供支持。

**参考来源**：
- 3gstudent: 域渗透——DNS记录的获取
- Microsoft: dnscmd 文档

## 测试案例

以下测试案例展示了攻击者可能使用的 DNS 记录收集方法，聚焦于 Windows 环境下的操作（内部权限场景）和外部公开信息收集。

#### 测试案例 1：使用 dnscmd 获取 DNS 记录
**关联技术**：T1590（DNS 记录获取）  
**说明**：  
- 攻击者在已获得域内权限（如管理员权限）的情况下，使用 Windows 内置工具 `dnscmd` 查询 DNS 服务器的记录。  
**适用系统**：  
- Windows Server 2003/2008/2012（含 R2 版本）  
- Windows 7/10（需安装 Remote Server Administration Tools, RSAT）  
**示例操作**：
```cmd
:: 查询 DNS 区域信息
dnscmd . /ZoneInfo example.com
:: 枚举所有 DNS 区域
dnscmd . /EnumZones
:: 显示区域中的所有记录
dnscmd . /ZonePrint example.com
```
**输出示例**：
```
Zone: example.com
Type: Primary
Records:
  @ A 192.168.1.10
  mail A 192.168.1.20
  www CNAME web.example.com
  MX 10 mail.example.com
```
**说明**：  
- `dnscmd` 是 Windows Server 的命令行工具，用于管理 DNS 服务器，需管理员权限。  
- 关联 T1590：通过内部权限获取 DNS 记录。

#### 测试案例 2：使用 PowerShell 获取 DNS 记录
**关联技术**：T1590（DNS 记录获取）  
**说明**：  
- 攻击者在域内环境中使用 PowerShell 的 `DnsServer` 模块查询 DNS 记录，替代即将弃用的 `dnscmd`。  
**示例操作**：
```powershell
# 导入 DnsServer 模块
Import-Module DnsServer
# 查询 DNS 区域信息
Get-DnsServerZone -Name "example.com"
# 查询特定记录
Get-DnsServerResourceRecord -ZoneName "example.com"
```
**输出示例**：
```
ZoneName: example.com
ZoneType: Primary
Records:
  HostName: @, RecordType: A, Data: 192.168.1.10
  HostName: mail, RecordType: A, Data: 192.168.1.20
  HostName: www, RecordType: CNAME, Data: web.example.com
  HostName: @, RecordType: MX, Data: 10 mail.example.com
```
**说明**：  
- PowerShell 是 Microsoft 推荐的 `dnscmd` 替代工具，适用于 Windows Server 2012 及以上版本。  
- 关联 T1590：通过 PowerShell 获取 DNS 记录。

#### 测试案例 3：外部 DNS 查询（公开信息）
**关联技术**：T1590（DNS 记录获取）  
**说明**：  
- 攻击者通过外部工具（如 `nslookup`、`dig` 或在线服务）查询目标组织的公开 DNS 记录。  
**示例操作**：
```bash
:: 使用 nslookup 查询 MX 记录
nslookup -type=MX example.com
:: 使用 dig 查询所有记录
dig example.com ANY
```
**输出示例**：
```
;; ANSWER SECTION:
example.com. 3600 IN A 192.168.1.10
example.com. 3600 IN MX 10 mail.example.com
example.com. 3600 IN TXT "v=spf1 mx -all"
```
**说明**：  
- 公开 DNS 查询无需权限，可从攻击者的设备执行。  
- 关联 T1590：通过外部查询获取 DNS 记录。

#### 测试案例 4：使用 OSINT 工具收集 DNS 信息
**关联技术**：T1590（DNS 记录获取）  
**说明**：  
- 使用开源情报（OSINT）工具（如 The Harvester、dnsdumpster）收集目标组织的 DNS 记录和子域名。  
**示例操作**：
```bash
:: 使用 The Harvester 枚举子域名和 DNS 记录
theharvester -d example.com -b google,dnsdumpster
```
**输出示例**：
```
Subdomains:
- mail.example.com (A: 192.168.1.20)
- www.example.com (CNAME: web.example.com)
- vpn.example.com (A: 192.168.1.30)
```
**说明**：  
- OSINT 工具整合公开数据，适用于外部侦察阶段。  
- 关联 T1590：通过 OSINT 工具获取 DNS 记录。

#### 测试案例 5：查询数据泄露中的 DNS 信息
**关联技术**：T1590（DNS 记录获取）  
**说明**：  
- 攻击者通过数据泄露数据库或暗网市场获取目标组织的 DNS 相关信息（如子域名或服务器 IP）。  
**示例操作**：
- 访问 Pastebin 或暗网市场，搜索目标域名 `example.com`。
- 使用 Have I Been Pwned 检查与域名相关的泄露数据。
**输出示例**：
```
Pastebin Leak:
- Subdomain: internal.example.com, IP: 192.168.1.100
- MX: mail.example.com, IP: 192.168.1.20
```
**说明**：  
- 数据泄露可能暴露内部 DNS 记录或配置。  
- 关联 T1590：通过数据泄露获取 DNS 信息。

## 检测日志

DNS 记录获取可能发生在外部（公开查询）或内部（利用权限），检测日志因场景而异：
- **Windows 安全日志**（内部场景）：
  - **事件 ID 4688**（新进程创建）：记录 `dnscmd.exe` 或 PowerShell 进程的启动。
    - 示例：`New Process Name: C:\Windows\System32\dnscmd.exe`
  - **事件 ID 4674**（权限分配）：记录对 DNS 服务器的高权限操作。
- **DNS 服务器日志**：
  - 记录异常的 DNS 查询，如高频查询特定区域或记录类型（A、MX、TXT）。
  - 示例：`Query: example.com, Type: ANY, Source: 192.168.1.100`
- **网络流量日志**：
  - 外部查询可能产生异常的 DNS 请求（如高频 `ANY` 查询）。
  - 示例：`UDP 53, Source: 203.0.113.1, Query: mail.example.com`
- **Web 服务器日志**（OSINT 场景）：
  - 记录爬取公司官网的异常访问，可能与子域名推测相关。
  - 示例：`GET /sitemap.xml HTTP/1.1` 从异常 IP。

## 测试复现

### 内部场景（已获得权限）
1. **环境**：Windows Server 2016，域管理员权限。
2. **步骤**：
   - 安装 RSAT（若未预装 `dnscmd`）。
   - 执行 `dnscmd . /ZoneInfo example.com` 或 `Get-DnsServerZone -Name example.com`。
3. **预期结果**：返回 DNS 区域信息和记录（如 A、MX、CNAME）。

### 外部场景（公开信息收集）
1. **环境**：Kali Linux 或任何带有 `nslookup`/`dig` 的系统。
2. **步骤**：
   - 执行 `nslookup -type=MX example.com` 或 `dig example.com ANY`。
   - 使用 The Harvester：`theharvester -d example.com -b dnsdumpster`。
3. **预期结果**：返回公开的 DNS 记录和子域名。

**注意**：`dnscmd` 在 Windows Server 2016 及以上版本可能不默认支持，推荐使用 PowerShell 的 `DnsServer` 模块。

## 测试留痕

### 内部场景
- **Windows 安全日志**：
  ```
  Event ID: 4688
  Creator Subject:
    Security ID: EXAMPLE\admin
    Account Name: admin
    Account Domain: EXAMPLE
    Logon ID: 0x36D7FD
  Process Information:
    New Process ID: 0x111c
    New Process Name: C:\Windows\System32\dnscmd.exe
    Creator Process Name: C:\Windows\System32\cmd.exe
    Process Command Line: dnscmd /ZoneInfo example.com
  ```
- **DNS 服务器日志**：
  ```
  Query: example.com, Type: SOA, Source: 192.168.1.100
  ```

### 外部场景
- **DNS 查询日志**（若目标控制 DNS 服务器）：
  ```
  Query: mail.example.com, Type: A, Source: 203.0.113.1
  ```
- **Web 服务器日志**（若爬取官网）：
  ```
  203.0.113.1 - - [26/May/2025:08:01:00 +0000] "GET /sitemap.xml HTTP/1.1" 200 1234
  ```

## 检测规则/思路

### 检测规则
1. **监控 dnscmd 和 PowerShell 进程**：
   - 检查 Windows 事件 ID 4688，检测 `dnscmd.exe` 或 `powershell.exe` 的异常启动。
   - 示例规则（伪代码）：
     ```log
     if (EventID == 4688 and ProcessName == "dnscmd.exe" or ProcessName == "powershell.exe" and CommandLine contains "DnsServer") then alert
     ```
2. **DNS 查询异常**：
   - 监控 DNS 服务器日志，检测高频查询（如 `ANY` 类型或多个子域名）。
   - 示例规则（伪代码）：
     ```log
     if (DNS Query Type == ANY and Queries > 50/hour from single IP) then alert
     ```
3. **网络流量分析**：
   - 检测异常的 UDP 53 流量（如高频外部查询）。
   - 示例规则（伪代码）：
     ```log
     if (UDP Port 53 and Source IP not in Trusted_IPs and Queries > 100/hour) then alert
     ```
4. **Web 爬虫检测**：
   - 检查 Web 服务器日志，识别高频访问 sitemap.xml 或子域名相关页面的 IP。
   - 示例规则（伪代码）：
     ```log
     if (GET /sitemap.xml | /about > 100 requests/hour from single IP) then alert
     ```

### 检测思路
- **内部威胁**：重点监控域内管理员权限的使用，检测异常的 DNS 管理操作（如 `dnscmd` 或 PowerShell 命令）。
- **外部威胁**：分析 DNS 查询模式，识别异常的高频或广域查询（如 `ANY` 查询）。
- **SIEM 关联分析**：整合 Windows 安全日志、DNS 服务器日志和网络流量，检测异常模式。
- **威胁情报**：订阅外部情报，监控针对目标域名的 DNS 记录泄露或扫描活动。

## 建议

### 防御措施
1. **限制 DNS 记录公开**：
   - 最小化公开的 DNS 记录（如避免不必要的 TXT 或 CNAME 记录）。
   - 使用私有 DNS 服务器，限制外部查询（如仅允许信任的 IP）。
2. **加强权限管理**：
   - 限制对 DNS 服务器的管理权限，仅授权必要管理员使用 `dnscmd` 或 `DnsServer` 模块。
   - 启用多因素认证（MFA）保护域管理员账号。
3. **DNS 安全配置**：
   - 启用 DNSSEC（DNS 安全扩展）防止 DNS 记录篡改。
   - 配置防火墙，限制外部对 DNS 服务器的查询（UDP 53）。
4. **员工培训**：
   - 教育员工识别钓鱼邮件，避免泄露与 DNS 相关的配置信息。
   - 提高对社交工程攻击的警惕性，防止内部权限泄露。
5. **主动 OSINT 评估**：
   - 使用 The Harvester 或 dnsdumpster 模拟攻击者行为，评估公开 DNS 记录的暴露程度。
   - 定期检查 Pastebin 或暗网，识别泄露的 DNS 信息。

### 后续阶段监控
- **钓鱼攻击（T1566）**：
  - 监控邮件网关日志，检测利用 DNS 记录（如 MX 服务器）的钓鱼邮件。
  - 示例事件：Windows 事件 ID 4663（文件访问）。
- **服务探测（T1046）**：
  - 监控网络扫描活动，检测针对 DNS 记录暴露的服务器（如 `mail.example.com`）的探测。
  - 示例规则：`if (TCP SYN to 192.168.1.20 > 10/min from single IP) then alert`。
- **有效账号使用（T1078）**：
  - 检测异常的管理员登录，如 Windows 事件 ID 4624（登录成功）。

### 外部情报监控
- 订阅威胁情报服务，获取针对组织域名的 DNS 扫描或泄露预警。
- 监控暗网或 Pastebin，识别泄露的 DNS 记录或子域名。
- 与行业合作伙伴共享威胁情报，了解类似组织的攻击模式。

### 降低误报
- 区分合法的 DNS 查询（如员工或合作伙伴）与攻击者的扫描活动，结合 IP 地理位置、查询频率等上下文。
- 使用机器学习模型分析 DNS 流量，识别异常查询模式。
- 定期更新检测规则，避免误报正常的 DNS 管理操作。

## 参考推荐

- **MITRE ATT&CK - T1590**  
  <https://attack.mitre.org/techniques/T1590/>
- **域渗透——DNS记录的获取**  
  <https://3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-DNS%E8%AE%B0%E5%BD%95%E7%9A%84%E8%8E%B7%E5%8F%96>
- **Microsoft dnscmd 文档**  
  <https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc772069(v=ws.11)>
- **Microsoft RSAT 下载**  
  <https://www.microsoft.com/en-us/download/details.aspx?id=7887>
- **PowerShell DnsServer 模块文档**  
  <https://docs.microsoft.com/en-us/powershell/module/dnsserver/>
