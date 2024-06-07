# T1548-002-Win-使用Dism删除Defender

## 来自ATT&CK的描述

攻击者可能会绕过UAC机制来提升系统上的进程权限。Windows用户帐户控制(UAC)允许程序提升其权限（按照从低到高的完整性级别进行跟踪）以在管理员级别权限下执行任务，可能是通过提示用户进行确认。对用户的影响范围从在严格强制下拒绝操作到允许用户执行操作（如果他们位于本地管理员组中并单击提示或允许他们输入管理员密码来完成操作）。

如果计算机的UAC保护级别设置为除最高级别之外的任何级别，则某些Windows程序可以提升权限或执行某些提升的组件对象模型对象，而无需通过UAC通知框提示用户。一个示例是使用Rundll32加载特制的DLL，该DLL加载自动提升的组件对象模型对象并在受保护的目录中执行文件操作，这通常需要提升的访问权限。恶意软件也可能被注入到受信任的进程中，以在不提示用户的情况下获得提升的权限。

## 测试案例

dism命令使用说明，（注意使用该程序需要管理员权限）

```bash
C:\Windows\system32>dism
部署映像服务和管理工具
版本: 10.0.10240.16384

DISM.exe [dism_options] {Imaging_command} [<Imaging_arguments>]
DISM.exe {/Image:<path_to_offline_image> | /Online} [dism_options]
         {servicing_command} [<servicing_arguments>]

描述:

DISM 枚举、安装、卸载、配置和更新Windows映像中的功能和程序包。可以使用的命令取决于提供的映像以及映像是处于脱机还是运行状态。

通用映像处理命令:

  /Split-Image            - 将现有 .wim 或 .ffu 文件拆分为多个
                               只读拆分 WIM/FFU 文件。
  /Apply-Image            - 应用一个映像。
  /Get-MountedImageInfo   - 显示有关安装的 WIM 和 VHD 映像的
                            信息。
  /Get-ImageInfo          - 显示有关 WIM 或 VHD 文件中映像的
                            信息。
  /Commit-Image           - 保存对装载的 WIM 或 VHD 映像的更改。
  /Unmount-Image          - 卸载已装载的 WIM 或 VHD 映像。
  /Mount-Image            - 从 WIM 或 VHD 文件装载映像。
  /Remount-Image          - 恢复孤立的映像装载目录。
  /Cleanup-Mountpoints    - 删除与损坏的已安装映像
                            关联的资源。
WIM 命令:

  /Apply-CustomDataImage  - 冻结自定义数据映像中包含的文件。
  /Capture-CustomImage    - 将自定义设置捕获到WIMBoot系统上的增量WIM文件中。
                            捕获的目录包括所有
                            子文件夹和数据。
  /Get-WIMBootEntry       - 显示指定磁盘卷的
                            WIMBoot 配置项。
  /Update-WIMBootEntry    - 更新指定磁盘卷的
                            WIMBoot 配置项。
  /List-Image             - 显示指定映像中的文件
                            和文件夹的列表。
  /Delete-Image           - 从具有多个卷映像的WIM文件
                            删除指定的卷映像。
  /Export-Image           - 将指定映像的副本导出到其他
                            文件。
  /Append-Image           - 将其他映像添加到WIM文件中。
  /Capture-Image          - 将驱动器的映像捕获到新的WIM文件中。
                            捕获的目录包含所有子文件夹和
                            数据。
  /Get-MountedWimInfo     - 显示有关安装的WIM映像的信息。
  /Get-WimInfo            - 显示有关WIM文件中的映像的信息。
  /Commit-Wim             - 保存对安装的WIM映像的更改。
  /Unmount-Wim            - 卸载安装的WIM映像。
  /Mount-Wim              - 从WIM文件安装映像。
  /Remount-Wim            - 恢复孤立的WIM安装目录。
  /Cleanup-Wim            - 删除与损坏的已安装WIM映像关联的资源。

映像规格:
  /Online                 - 以正在运行的操作系统为目标。
  /Image                  - 指定脱机 Windows 映像的根目录的路径。

DISM 选项:
  /English                - 用英文显示命令行输出。
  /Format                 - 指定报告输出格式。
  /WinDir                 - 指定 Windows 目录的路径。
  /SysDriveDir            - 指定名为 BootMgr 的系统加载程序文件的路径。

  /LogPath                - 指定日志文件路径。
  /LogLevel               - 指定日志(1-4)中所示的输出级别。
  /NoRestart              - 取消自动重新启动和重新启动提示。
  /Quiet                  - 取消除错误消息之外的所有输出。
  /ScratchDir             - 指定暂存目录的路径。

若要获得有关这些 DISM 选项及其参数的详细信息，请在紧挨着 /? 之前指定一个选项。
  示例:
    DISM.exe /Mount-Wim /?
    DISM.exe /ScratchDir /?
    DISM.exe /Image:C:\test\offline /?
    DISM.exe /Online /?
```

## 检测日志

Windows安全日志

## 测试复现

1.从HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\寻找所有包含`*Windows-Defender*`条目

2.通过该路径获取所有Windows Defender的包的名称并使用DISM命令从当前操作系统中移除（示例：Dism.exe /online /quiet /norestart /remove-package /packagename:Windows-Defender-AM-Default-Definitions-OptionalWrapper-Package~31bf3856ad364e35~amd64~~10.0.22621.1）

这里用上述示例进行测试(管理员权限)：

```bash
C:\Users\jackma>Dism.exe /online /quiet /norestart /remove-package /packagename:Windows-Defender-AM-Default-Definitions-OptionalWrapper-Package~31bf3856ad364e35~amd64~~10.0.22621.1

错误: 740

需要提升权限才能运行 DISM。
使用提升的命令提示符完成这些任务。
```

## 测试留痕

```yml
EventData 

  SubjectUserSid S-1-5-21-4139220405-2433135684-1686031733-1000 
  SubjectUserName jackma 
  SubjectDomainName MAJACKD3D7 
  SubjectLogonId 0x1f9f5 
  NewProcessId 0xa28 
  NewProcessName C:\Windows\System32\Dism.exe 
  TokenElevationType %%1938 
  ProcessId 0x69c 
  CommandLine Dism.exe /online /quiet /norestart /remove-package /packagename:Windows-Defender-AM-Default-Definitions-OptionalWrapper-Package~31bf3856ad364e35~amd64~~10.0.22621.1 
  TargetUserSid S-1-0-0 
  TargetUserName - 
  TargetDomainName - 
  TargetLogonId 0x0 
  ParentProcessName C:\Windows\System32\cmd.exe 
  MandatoryLabel S-1-16-8192 
```

## 检测规则/思路

### splunk规则

```sql
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=dism.exe (Processes.process="*/online*" AND Processes.process="*/disable-feature*" AND Processes.process="*Windows-Defender*" AND Processes.process="*/remove*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.original_file_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_dism_remove_defender_filter` 
```

### 建议

一些合法的管理工具利用dism.exe来操纵操作系统的包和功能，可根据实际需要进行过滤。

## 参考推荐

MITRE-ATT&CK-T1548-002

<https://attack.mitre.org/techniques/T1548/002/>

一点关于主流卸载Windows Defender/Microsoft Defender方式的分析

<https://bbs.kafan.cn/thread-2252937-1-1.html>
