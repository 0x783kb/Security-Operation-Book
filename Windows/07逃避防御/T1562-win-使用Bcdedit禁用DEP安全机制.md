# T1562-Win-使用Bcdedit禁用DEP安全机制

## 描述

攻击者可能会恶意修改被攻击环境的组件，以阻碍或禁用防御机制。这不仅涉及损害预防性防御（如防火墙和防病毒），还涉及防御者可用于审核活动和识别恶意行为的检测功能。

## 测试案例
### Windows安全机制-DEP（数据执行保护）

**数据执行保护(DEP)**的主要作用是阻止数据页（默认的堆、栈以及内存池页）执行代码。它分为软件DEP和硬件DEP，其中软件DEP通常指SafeSEH。而硬件DEP通过操作系统设置内存页的**NX/XD属性**（No-Execute/Execute Disable）来标记是否允许在该页执行指令。

DEP分为4种工作状态：

- **Optin**：默认仅保护Windows系统组件；
- **Optout**：为排除列表程序外的所有程序和服务启用DEP；
- **AlwaysOn**：对所有进程启用DEP保护；
- **AlwaysOff**：对所有进程都禁用DEP；

Visual Studio 2008之后默认开启DEP保护，编译的程序会在PE头中设置`IMAGE_DLLCHARACTERISTICS_NX_COMPAT`标识。这个标识位于结构体`IMAGE_OPTIONAL_HEADER`中的`DllCharacteristics`字段。如果该值被设为`0x0100`，则表示程序采用了DEP保护编译。

### 局限性

1.  并不是所有的CPU都支持DEP。
2.  由于兼容性问题，不可能对所有的进程都开启DEP保护，这样可能会导致程序异常。对一些第三方插件DLL和ATL7.1或以前的程序版本，不会默认开启DEP。
3.  编译器中的`/NXCOMPAT`选项生成的程序，只会在Windows Vista以上的系统有效，在之前的系统会被忽略。
4.  系统提供了某些API函数可以来控制DEP状态，早期的一些系统可以通过调用这些函数来修改。

### 测试命令

在Windows Server 2019系统上进行测试。

**测试命令：**

1.  **禁用DEP：**
    ```bash
    bcdedit.exe /set {current} nx Alwaysoff
    ```
2.  **启用DEP（恢复到Optin模式）：**
    ```bash
    bcdedit.exe /set {current} nx Optin
    ```

## 检测日志

Windows安全日志

## 测试复现

在命令提示符中执行禁用DEP的命令：

```powershell
C:\Users\Administrator>bcdedit.exe /set {current} nx Alwaysoff
操作成功完成。
```

---

## 测试留痕

在Windows安全日志中，当`bcdedit.exe`被执行时，会生成**事件ID 4688（进程创建）**。此事件将记录执行该命令的详细信息，包括父进程、新进程名称和完整的命令行参数。

```log
已创建新进程。

创建者主题:
    安全 ID:      JACKMA\Administrator
    帐户名:        Administrator
    帐户域:        JACKMA
    登录 ID:      0x73509

目标主题:
    安全 ID:      NULL SID
    帐户名:        -
    帐户域:        -
    登录 ID:      0x0

进程信息:
    新进程 ID:     0x15e4
    新进程名称:  C:\Windows\System32\bcdedit.exe
    令牌提升类型: %%1936
    强制性标签:      Mandatory Label\High Mandatory Level
    创建者进程 ID:   0xaf0
    创建者进程名称:    C:\Windows\System32\cmd.exe
    进程命令行:  bcdedit.exe  /set {current} nx Alwaysoff
```

**关键信息提取：**
* **新进程名称(New Process Name):**指向了`C:\Windows\System32\bcdedit.exe`。
* **创建者进程名称(Creator Process Name):**显示了启动该命令的父进程，在此示例中是`C:\Windows\System32\cmd.exe`。
* **进程命令行(Process Command Line):**记录了完整的执行命令行，如`bcdedit.exe /set {current} nx Alwaysoff`，这是识别DEP状态变更的关键。

## 检测规则/思路

为了检测攻击者使用`bcdedit.exe`禁用DEP安全机制的行为，可以监控进程创建事件，并根据其命令行参数进行过滤。

### Sigma规则

```yml
title: 使用bcdedit.exe关闭Windows DEP安全机制
status: experimental
logsource:
    product: windows
    service: security # 也可以配置为 sysmon，提供更丰富的数据
detection:
    selection:
        EventID: 4688 # Windows 安全日志，进程创建事件ID
        Image|endswith: '\bcdedit.exe' # 进程映像是 bcdedit.exe
        CommandLine|contains: # 命令行包含设置DEP状态的关键字
            - 'nx AlwaysOff'
            - 'nx Optin' # 监控Optin可能有助于识别异常的重新启用行为，但禁用更具恶意性
            - 'nx AlwaysOn' # 攻击者不常用，但可作为异常行为监控
    condition: selection
level: high # 攻击者禁用DEP是高危行为，应设置高等级告警
tags:
    - attack.defense_evasion
    - attack.t1562
```

### 建议

主要以**命令行参数**作为监测依据，因为`bcdedit.exe`的合法用途很多，但修改`nx`（DEP）设置通常是特权操作且不常见。发现异常后可结合上下文告警信息进行确认分析。

* **启用命令行审计：**确保在Windows安全日志中已启用**进程命令行审计(Event ID 4688)**，这是捕获`bcdedit.exe`详细参数的关键。
* **关联用户和父进程：** 分析执行`bcdedit.exe`的用户账户和父进程。非管理员用户尝试执行此命令通常会失败，但仍会生成事件。如果是来自非典型父进程（例如，不是`cmd.exe`或`powershell.exe`等交互式Shell）的`bcdedit`调用，则更应提高警惕。
* **基线化：** 了解环境中正常的`bcdedit.exe`使用情况。禁用DEP通常是系统管理员在解决特定兼容性问题时才会执行的操作，在生产环境中应极为罕见。
* **响应措施：** 一旦检测到DEP被禁用，应立即评估其影响并考虑恢复DEP设置，同时调查攻击的根本原因。

## 参考推荐

- MITRE-ATT&CK: T1562
  https://attack.mitre.org/techniques/T1562/
- Windows安全机制---数据执行保护：DEP机制
  https://blog.csdn.net/m0_37809075/article/details/83008617
