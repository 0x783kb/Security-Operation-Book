T1070-004-Win-通过Rmdir删除Windows文件

## 来自ATT&CK的描述

攻击者可能会删除其入侵活动所留下的文件。攻击者在系统上丢弃创建的恶意软件、工具或其他可能会留下痕迹的非本机文件。这些文件的删除可以在入侵过程中进行，也可以作为入侵后的过程中进行，以最大程度地减少攻击者留下的足迹。

主机操作系统中提供了一些工具来执行清除，但攻击者也可以使用其他工具。其中包括本机cmd函数（例如DEL），安全删除工具（例如Windows Sysinternals SDelete）或其他第三方文件删除工具。

## 测试案例

rmdir命令是windows系统自带的一个命令，用于删除文件和目录。

```bash
C:\Users\jackma>help rmdir
删除一个目录。

RMDIR [/S] [/Q] [drive:]path
RD [/S] [/Q] [drive:]path
    /S      除目录本身外，还将删除指定目录下的所有子目录和
            文件。用于删除目录树。
    /Q      安静模式，带 /S 删除目录树时不要求确认
```

## 检测日志

Windows sysmon

## 测试复现

```bash
C:\Users\jackma>rmdir /S /Q C:\Users\jackma\Desktop\test
```

## 测试留痕

无，在实际的测试过程中，cmd命令行下并没有观测到Windows安全日志有所记录相关进程行为，因此未获取到留痕日志，建议使用Sysmon日志进行检测，或者其他具备可识别记录进程命令行参数的端点安全软件日志进行检测。

## 检测规则/思路

### Splunk

```sql
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process = "*rmdir*" Processes.process = "* /s *" Processes.process = "* /q *" by Processes.process_name Processes.original_file_name Processes.process Processes.process_id Processes.process_guid Processes.parent_process_name Processes.parent_process Processes.parent_process_guid Processes.dest Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_indicator_removal_via_rmdir_filter`
```

### 建议

暂无

## 参考推荐

MITRE-ATT&CK-T1070-004

<https://attack.mitre.org/techniques/T1070/004/>

rmdir

<https://learn.microsoft.com/zh-tw/windows-server/administration/windows-commands/rmdir>

Windows Indicator Removal Via Rmdir

<https://research.splunk.com/endpoint/c4566d2c-b094-48a1-9c59-d66e22065560/>
