# T1123-Win-使用AudioDeviceCmdlets音频收集

## 描述

攻击者可能利用计算机的外围设备（如麦克风）或应用程序接口（如PowerShell模块）捕获音频记录，以窃听敏感对话或收集情报。恶意软件或脚本可通过操作系统提供的API（如Windows Audio Device API）或第三方模块（如AudioDeviceCmdlets）与麦克风交互，捕获音频数据。捕获的音频可能被保存为文件（如WAV、MP3）并通过网络泄露，供攻击者后续分析或利用。

## 测试案例

### 用例
- **音频窃听**：攻击者使用PowerShell模块`AudioDeviceCmdlets`捕获麦克风音频，记录环境中的敏感对话。
- **自动化录音**：脚本定期调用`AudioDeviceCmdlets`模块，保存音频文件并通过C2通道传输。
- **实时监控**：通过实时流式传输将音频数据发送到远程服务器。

### 示例场景
- 攻击者通过PowerShell安装并使用`AudioDeviceCmdlets`模块，启动录音并将音频保存为文件。
- 恶意脚本结合`AudioDeviceCmdlets`命令，控制录音时长并指定输出路径。

### 测试1：使用AudioDeviceCmdlets模块
通过PowerShell调用`AudioDeviceCmdlets`模块捕获音频：
```yml
powershell.exe -Command WindowsAudioDevice-Powershell-Cmdlet
```
或使用具体命令：
```powershell
Install-Module -Name AudioDeviceCmdlets
Get-AudioDevice -List
Set-AudioDevice -Index 1  # 选择麦克风设备
# 需额外脚本实现录音功能
```

### 所需权限
- 用户权限（运行PowerShell和访问麦克风）。
- 管理员权限（安装PowerShell模块，若未预安装）。

### 操作系统
- Windows 7、Windows 8、Windows 8.1、Windows 10、Windows 11、Windows Server 2008、2012、2016、2019、2022。

## 检测日志

### Windows安全日志
- **事件ID 4688**：记录PowerShell进程（`powershell.exe`）创建及命令行参数（需启用命令行审核）。

### Sysmon日志
- **事件ID 1**：捕获`powershell.exe`进程创建及命令行参数（如包含`AudioDeviceCmdlets`）。
- **事件ID 11**：记录音频文件（如`.wav`、`.mp3`）的创建事件。
- **事件ID 3**：记录可能的网络连接（若音频文件被传输）。

### PowerShell日志
- **事件ID 4104**：捕获PowerShell脚本块执行，记录`AudioDeviceCmdlets`模块的调用。

### 文件系统日志
- 监控新创建的音频文件及其路径（如`.wav`文件）。

## 测试复现

### 环境准备
- **靶机**：Windows 10/11。
- **权限**：用户权限（安装模块可能需要管理员权限）。
- **工具**：
  - PowerShell（系统自带）。
  - AudioDeviceCmdlets模块（需安装，参考https://github.com/frgnca/AudioDeviceCmdlets）。
  - Sysmon（用于进程和文件监控）。
  - Wireshark（若涉及网络传输，捕获流量）。
  - 测试麦克风（确保设备可用）。
- **网络**：隔离网络环境，允许PowerShell模块下载和可能的出站流量。
- **日志**：启用Windows安全日志、Sysmon日志和PowerShell日志。

### 攻击步骤
1. **安装AudioDeviceCmdlets模块**：
   ```powershell
   PS C:\> Install-Module -Name AudioDeviceCmdlets -Force
   ```
2. **列出音频设备**：
   ```powershell
   PS C:\> Get-AudioDevice -List
   ```
   - 输出示例（视环境而定）：
     ```
     Index: 1
     Name: Microphone (Realtek Audio)
     Type: Recording
     ```
3. **选择麦克风设备**：
   ```powershell
   PS C:\> Set-AudioDevice -Index 1
   ```
4. **模拟录音**（需额外脚本）：
   - AudioDeviceCmdlets本身不直接支持录音，需结合其他脚本或模块（如NAudio）：
     ```powershell
     # 示例伪代码，需第三方库支持
     Import-Module AudioDeviceCmdlets
     Start-AudioRecording -OutputFile "C:\Users\liyang\output.wav" -Duration 30
     ```
5. **验证结果**：
   - 检查音频文件（如`C:\Users\liyang\output.wav`）是否生成。
   - 使用Wireshark捕获网络流量（若文件通过网络传输）。
   - 验证Sysmon和PowerShell日志是否记录模块调用和文件创建。
6. **清理**：
   - 删除音频文件（如`Remove-Item C:\Users\liyang\output.wav`）。
   - 卸载模块（若需要）：
     ```powershell
     Uninstall-Module -Name AudioDeviceCmdlets
     ```

### 注意事项
- 虚拟机环境可能因缺少物理麦克风而无法捕获音频，建议在物理机或配置虚拟音频设备的环境中测试。
- `AudioDeviceCmdlets`需结合其他录音逻辑实现完整功能，测试时可参考GitHub文档。

## 测试留痕
以下为Windows安全日志示例（事件ID 4688）：
```yml
已创建新进程。

创建者主题:
 安全 ID: DESKTOP-PT656L6\liyang
 帐户名: liyang
 帐户域: DESKTOP-PT656L6
 登录 ID: 0x47126

目标主题:
 安全 ID: NULL SID
 帐户名: -
 帐户域: -
 登录 ID: 0x0

进程信息:
 新进程 ID: 0x1b3c
 新进程名称: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
 令牌提升类型: %%1938
 强制性标签: Mandatory Label\Medium Mandatory Level
 创建者进程 ID: 0x1410
 创建er进程名称: C:\Windows\System32\cmd.exe
 进程命令行: powershell.exe -Command Get-AudioDevice -List
```

以下为PowerShell日志示例（事件ID 4104）：
```yml
EventID: 4104
CreateTime: 2025-06-08 03:15:23
ScriptBlockText: Install-Module -Name AudioDeviceCmdlets -Force
ScriptBlockId: {a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d}
Path: Unknown
```

## 检测方法/思路

### Splunk规则
检测`AudioDeviceCmdlets`模块或PowerShell录音活动的Splunk查询：

```yml
index=windows SourceName="Microsoft-Windows-PowerShell" "*AudioDeviceCmdlets*"
| OR 
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" 
(EventCode=1 Image="*\\powershell.exe" CommandLine="*AudioDeviceCmdlets*") 
| OR 
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" 
(EventCode=11 TargetFilename="*.wav" OR TargetFilename="*.mp3")
```

### 检测思路
1. **进程监控**：
   - 检测`powershell.exe`进程的创建，尤其是命令行包含`AudioDeviceCmdlets`或相关cmdlet（如`Get-AudioDevice`、`Set-AudioDevice`）。
   - 监控异常父进程（如`cmd.exe`、`explorer.exe`）调用PowerShell。
2. **文件监控**：
   - 检测新创建的音频文件（如`.wav`、`.mp3`），尤其是位于用户目录或临时文件夹。
3. **PowerShell日志分析**：
   - 检查PowerShell事件ID 4104，捕获`AudioDeviceCmdlets`模块的加载或执行。
4. **网络监控**：
   - 检测音频文件通过网络传输的行为（如上传到C2服务器）。
5. **行为基线**：
   - 建立组织内PowerShell和录音模块的正常使用基线，识别异常行为（如夜间运行、非典型用户）。

### 检测建议
- **Sysmon配置**：配置Sysmon监控`powershell.exe`的进程创建（事件ID 1）和音频文件创建（事件ID 11）。
- **PowerShell日志**：启用PowerShell模块、脚本块和命令行日志，捕获`AudioDeviceCmdlets`相关活动。
- **EDR监控**：使用EDR工具（如Microsoft Defender for Endpoint）监控麦克风访问和音频文件创建。
- **误报过滤**：排除合法录音场景（如视频会议、语音备忘录），结合上下文（如用户身份、时间）降低误报率。

## 缓解措施
1. **设备访问控制**：
   - 限制普通用户对麦克风设备的访问，仅允许受信任应用程序。
   - 使用组策略禁用非必要录音功能。
2. **PowerShell限制**：
   - 配置PowerShell执行策略（如`Restricted`或`Constrained Language Mode`），限制未签名模块的加载。
   - 使用AppLocker或WDAC限制`powershell.exe`的执行。
3. **文件监控**：
   - 部署文件完整性监控（FIM）工具，检测异常音频文件创建。
4. **网络限制**：
   - 监控并限制音频文件通过网络传输的行为，阻止未经授权的数据泄露。
5. **用户培训**：
   - 教育用户识别可疑PowerShell脚本或录音行为，避免运行未知命令。

## 参考推荐
- MITRE ATT&CK T1123  
  https://attack.mitre.org/techniques/T1123  
- Atomic-red-team T1123  
  https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1123/T1123.md  
- AudioDeviceCmdlets  
  https://github.com/frgnca/AudioDeviceCmdlets
