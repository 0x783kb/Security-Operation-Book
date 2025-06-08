# T1123-Win-使用soundrec音频收集

## 描述

攻击者可能利用计算机的外围设备（如麦克风）或应用程序（如语音呼叫服务、录音软件）捕获音频记录，以窃听敏感对话或收集情报。恶意软件或脚本可通过操作系统提供的API（如Windows Audio Device API）或应用程序接口与麦克风交互，捕获音频数据。捕获的音频可能被保存为文件（如WAV、MP3）并通过网络泄露，供攻击者后续分析或利用。

## 测试案例

### 用例
- **音频窃听**：恶意软件通过调用`soundrec.exe`或其他录音工具，捕获环境中的敏感对话。
- **自动化录音**：脚本定期调用录音API，保存音频文件并通过C2通道传输。
- **实时监控**：攻击者通过实时流式传输将音频数据发送到远程服务器。

### 示例场景
- 攻击者使用Windows内置的`soundrec.exe`（Windows录音机）或PowerShell cmdlet（如`WindowsAudioDevice-Powershell-Cmdlet`）启动录音，捕获用户对话并保存为文件。
- 恶意脚本通过`/DURATION`和`/FILE`参数控制录音时长和输出文件。

### 路径
- Windows录音机（Sound Recorder）：
  ```yml
  - C:\Windows\System32\SoundRecorder.exe
  - shell:appsFolder\Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe!App
  ```

### 所需权限
- 用户权限（访问麦克风和文件系统）。

### 操作系统
- Windows 7、Windows 8、Windows 8.1、Windows 10、Windows 11、Windows Server 2008、2012、2016、2019、2022。

## 检测日志

### Windows安全日志
- **事件ID 4688**：记录`SoundRecorder.exe`或相关进程的创建及命令行参数（需启用命令行审核）。

### Sysmon日志
- **事件ID 1**：捕获`SoundRecorder.exe`或PowerShell进程的创建及命令行参数。
- **事件ID 11**：记录音频文件（如`.wav`、`.mp3`）的创建事件。
- **事件ID 3**：记录可能的网络连接（若音频文件被传输）。

### PowerShell日志
- **事件ID 4104**：捕获与录音相关的PowerShell cmdlet执行（如`WindowsAudioDevice-Powershell-Cmdlet`）。

### 文件系统日志
- 监控新创建的音频文件（如`.wav`、`.mp3`）及其路径。

## 测试复现

### 环境准备
- **靶机**：Windows 10/11。
- **权限**：用户权限。
- **工具**：
  - Windows录音机（`SoundRecorder.exe`，系统自带）。
  - PowerShell（用于调用录音API）。
  - Sysmon（用于进程和文件监控）。
  - Wireshark（若涉及网络传输，捕获流量）。
  - 测试麦克风（确保设备可用）。
- **网络**：隔离网络环境，若测试文件传输，需允许出站流量。
- **日志**：启用Windows安全日志、Sysmon日志和PowerShell日志。

### 攻击步骤
1. **启动录音**：
   - 使用Windows录音机：
     ```bash
     C:\Users\liyang>explorer.exe shell:appsFolder\Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe!App
     ```
   - 或使用PowerShell调用录音API：
     ```powershell
     $audioDevice = Get-CimInstance -Namespace root/cimv2 -ClassName Win32_SoundDevice
     Write-Output "Capturing audio using $audioDevice"
     # 模拟录音逻辑，需第三方模块支持
     ```
2. **保存音频文件**：
   - 使用命令行参数指定输出文件和录音时长：
     ```bash
     SoundRecorder.exe /FILE C:\Users\liyang\output.wav /DURATION 0000:00:30
     ```
     - 参数说明：`/FILE`指定输出文件，`/DURATION`设置录音时长（格式为`hhhh:mm:ss`）。
3. **验证结果**：
   - 检查`C:\Users\liyang\output.wav`是否生成。
   - 使用Wireshark捕获网络流量（若文件通过网络传输）。
   - 验证Sysmon日志是否记录进程和文件创建事件。
4. **清理**：
   - 删除音频文件（如`del C:\Users\liyang\output.wav`）。
   - 终止相关进程。

## 测试留痕
以下为Windows安全日志示例（事件ID 4688）：
```yml
已创建新进程。

创建者主题:
 安全 ID: DESKTOP-PT656L6\liyang
 帐户名: liyang
 帐户域: DESKTOP-PT656L6
 登录 ID: 0x47126

进程信息:
 新进程 ID: 0x1a2c
 新进程名称: C:\Windows\System32\SoundRecorder.exe
 令牌提升类型: %%1938
 强制性标签: Mandatory Label\Medium Mandatory Level
 创建者进程 ID: 0x1410
 创建者进程名称: C:\Windows\System32\explorer.exe
 进程命令行: SoundRecorder.exe /FILE C:\Users\liyang\output.wav /DURATION 0000:00:30
```

以下为Sysmon日志示例（事件ID 11）：
```yml
EventID: 11
UtcTime: 2025-06-08 03:10:45.123
ProcessGuid: {12345678-9abc-def0-1234-56789abcdef0}
ProcessId: 6704
Image: C:\Windows\System32\SoundRecorder.exe
TargetFilename: C:\Users\liyang\output.wav
CreationUtcTime: 2025-06-08 03:10:45.123
```

## 检测方法/思路

### Splunk规则
检测`SoundRecorder.exe`或PowerShell录音活动的Splunk查询：

```yml
index=windows SourceName="Microsoft-Windows-PowerShell" "*WindowsAudioDevice-Powershell-Cmdlet*" 
| OR 
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" 
(EventCode=1 Image="*\\explorer.exe" CommandLine="*WindowsSoundRecorder*") 
OR 
(EventCode=1 Image="*\\SoundRecorder.exe") 
| OR 
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" 
(EventCode=1 CommandLine="* /DURATION *") 
OR 
(EventCode=1 CommandLine="* /FILE *")
```

### 检测思路
1. **进程监控**：
   - 检测`SoundRecorder.exe`或PowerShell进程的创建，尤其是命令行包含`/FILE`或`/DURATION`参数。
   - 监控异常父进程（如`cmd.exe`、`powershell.exe`）调用录音工具。
2. **文件监控**：
   - 检测新创建的音频文件（如`.wav`、`.mp3`），尤其是位于用户目录或临时文件夹。
3. **API调用监控**：
   - 检测与麦克风交互的API调用（如`WindowsAudioDevice-Powershell-Cmdlet`）。
   - 使用EDR工具监控异常进程访问音频设备。
4. **网络监控**：
   - 检测音频文件通过网络传输的行为（如上传到C2服务器）。
5. **行为基线**：
   - 建立组织内录音工具的正常使用基线，识别异常录音行为（如夜间运行、非典型用户）。

### 检测建议
- **Sysmon配置**：配置Sysmon监控`SoundRecorder.exe`的进程创建（事件ID 1）和文件创建（事件ID 11）。
- **PowerShell日志**：启用PowerShell模块和脚本块日志，检测录音相关的cmdlet调用。
- **EDR监控**：使用EDR工具（如Microsoft Defender for Endpoint）监控麦克风访问和音频文件创建。
- **误报过滤**：排除合法录音场景（如视频会议、语音备忘录），结合上下文（如用户身份、时间）降低误报率。

## 缓解措施
1. **设备访问控制**：
   - 限制普通用户对麦克风设备的访问，仅允许受信任应用程序。
   - 使用组策略禁用非必要录音功能。
2. **应用白名单**：
   - 使用AppLocker或WDAC限制`SoundRecorder.exe`的执行，仅允许受信任用户或进程。
3. **文件监控**：
   - 部署文件完整性监控（FIM）工具，检测异常音频文件创建。
4. **网络限制**：
   - 监控并限制音频文件通过网络传输的行为，阻止未经授权的数据泄露。
5. **用户培训**：
   - 教育用户识别可疑录音行为，避免运行未知脚本或应用程序。

## 参考推荐
- MITRE ATT&CK T1123  
  https://attack.mitre.org/techniques/T1123