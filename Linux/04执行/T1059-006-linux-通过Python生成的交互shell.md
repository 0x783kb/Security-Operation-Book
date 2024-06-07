# T1059-006-Linux-通过Python生成的交互shell

## 来自ATT&CK的描述

攻击者可能会滥用Python命令和脚本来执行。Python是一种非常流行的脚本编程语言，具有执行许多功能的能力。Python可以从命令行交互地执行（通过python.exe解释器）或通过可以编写和分发到不同系统的脚本（.py）。Python代码也可以编译成二进制可执行文件。

Python自带了很多内置的包来和底层系统交互，比如文件操作和设备I/O。攻击者可以使用这些库来下载和执行命令或其他脚本以及执行各种恶意行为。

## 测试案例

python交互式shell常见命令：

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/sh")'
python -c 'import pty; pty.spawn("/bin/dash")'
```

## 检测日志

未知

## 测试复现

无

## 测试留痕

无

## 检测规则/思路

### elastic 

```yml
query = '''
event.category:process and event.type:(start or process_started) and
  process.name:python* and
  process.args:("import pty; pty.spawn(\"/bin/sh\")" or
                "import pty; pty.spawn(\"/bin/dash\")" or
                "import pty; pty.spawn(\"/bin/bash\")")
'''
```

### 建议

对数据源要求较高，需要正确配置相关策略记录相关命令参数，才能够使用该规则。

## 参考推荐

MITRE-ATT&CK-T1059-006

<https://attack.mitre.org/techniques/T1059/006/>

Interactive Terminal Spawned via Python

<https://github.com/elastic/detection-rules/blob/main/rules/linux/execution_python_tty_shell.toml>

实现交互式shell的几种方式

<https://saucer-man.com/information_security/233.html>
